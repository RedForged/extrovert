/**
 * Extrovert MLS (Messaging Layer Security, RFC 9420) Client Engine
 * Integrates with /static/lib/mls.js (ts-mls) and Extrovert's DS/AS endpoints.
 */

(function (root) {
  'use strict';

  var DB_NAME = 'extrovert_crypto';
  var DB_VERSION = 4;
  var STORE_CRYPTO = 'crypto';
  var STORE_MLS_KEYS = 'mls_keys';
  var STORE_MLS_GROUPS = 'mls_groups';

  var ciphersuiteImpl = null;
  var deviceKey = null;
  var deviceId = null;
  var signingKeyPair = null;
  var clientCredential = null;
  var activeGroups = {}; // groupId -> ClientState

  function b64ToUint8(b64) {
    var bin = atob(b64);
    var u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }

  function uint8ToB64(u) {
    var s = '';
    for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s);
  }

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function currentUserId() {
    var meta = document.querySelector('meta[name="current-user-id"]');
    return meta ? parseInt(meta.getAttribute('content'), 10) : null;
  }

  function currentUsername() {
    var meta = document.querySelector('meta[name="current-username"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function openDB() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function (e) {
        var db = req.result;
        if (!db.objectStoreNames.contains(STORE_CRYPTO)) db.createObjectStore(STORE_CRYPTO);
        if (!db.objectStoreNames.contains(STORE_MLS_KEYS)) db.createObjectStore(STORE_MLS_KEYS);
        if (!db.objectStoreNames.contains(STORE_MLS_GROUPS)) db.createObjectStore(STORE_MLS_GROUPS);
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }

  function idbGet(storeName, key) {
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(storeName, 'readonly');
        var req = tx.objectStore(storeName).get(key);
        req.onsuccess = function () { resolve(req.result || null); };
        req.onerror = function () { reject(req.error); };
      });
    });
  }

  function idbSet(storeName, key, val) {
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(storeName, 'readwrite');
        var req = tx.objectStore(storeName).put(val, key);
        req.onsuccess = function () { resolve(); };
        req.onerror = function () { reject(req.error); };
      });
    });
  }

  function csrfFetch(url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    var token = getCsrfToken();
    if (token) opts.headers['x-csrf-token'] = token;
    opts.headers['content-type'] = 'application/json';
    return fetch(url, opts);
  }

  // --- Device Key (Kd) for at-rest IndexedDB encryption ---
  function getOrCreateDeviceKey() {
    return idbGet(STORE_CRYPTO, 'deviceKey').then(function (existing) {
      if (existing) {
        deviceKey = existing;
        return existing;
      }
      return crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      ).then(function (k) {
        deviceKey = k;
        return idbSet(STORE_CRYPTO, 'deviceKey', k).then(function () { return k; });
      });
    });
  }

  function encryptWithKd(data) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, deviceKey, bytes).then(function (ct) {
      var c = new Uint8Array(iv.length + ct.byteLength);
      c.set(iv);
      c.set(new Uint8Array(ct), iv.length);
      return uint8ToB64(c);
    });
  }

  function decryptWithKd(b64) {
    var c = b64ToUint8(b64);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: c.slice(0, 12) }, deviceKey, c.slice(12)).then(function (pt) {
      return new Uint8Array(pt);
    });
  }

  // --- MLS Engine Initialization ---
  function initEngine() {
    if (ciphersuiteImpl) return Promise.resolve(ciphersuiteImpl);
    if (!root.MLS) return Promise.reject(new Error('MLS library not loaded'));
    var cs = root.MLS.getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519');
    return root.MLS.getCiphersuiteImpl(cs).then(function (impl) {
      ciphersuiteImpl = impl;
      return impl;
    });
  }

  // --- Device Registration & KeyPackages ---
  function initDevice() {
    var uid = currentUserId();
    if (!uid) return Promise.resolve(null);

    return Promise.all([
      initEngine(),
      getOrCreateDeviceKey(),
      idbGet(STORE_MLS_KEYS, 'deviceId'),
      idbGet(STORE_MLS_KEYS, 'credential'),
    ]).then(function (res) {
      var storedDevId = res[2];
      var storedCred = res[3];

      if (storedDevId && storedCred) {
        deviceId = storedDevId;
        clientCredential = storedCred;
        return checkAndReplenishKeyPackages();
      }

      // Generate fresh device ID and leaf credential
      deviceId = 'dev_' + Math.random().toString(36).slice(2, 10);
      var credId = 'user:' + uid + ':dev:' + deviceId;
      clientCredential = {
        credentialType: 'basic',
        identity: new TextEncoder().encode(credId)
      };

      // Register device with server
      return csrfFetch('/mls/device/register', {
        method: 'POST',
        body: JSON.stringify({
          device_id: deviceId,
          device_name: navigator.userAgent.slice(0, 30) || 'Web Browser',
          signing_key_pub: 'ed25519_' + deviceId,
        })
      }).then(function (r) { return r.json(); }).then(function (regRes) {
        if (!regRes.ok) throw new Error(regRes.error || 'Failed to register MLS device');
        return Promise.all([
          idbSet(STORE_MLS_KEYS, 'deviceId', deviceId),
          idbSet(STORE_MLS_KEYS, 'credential', clientCredential),
        ]);
      }).then(function () {
        return replenishKeyPackages(20);
      });
    }).then(function () {
      return pollAndProcessWelcomes();
    });
  }

  function checkAndReplenishKeyPackages() {
    return csrfFetch('/mls/keypackages/status?device_id=' + encodeURIComponent(deviceId)).then(function (r) {
      return r.json();
    }).then(function (status) {
      if (status && status.available !== undefined && status.available < 5) {
        return replenishKeyPackages(15);
      }
    }).catch(function () {});
  }

  function replenishKeyPackages(count) {
    var mls = root.MLS;
    var pkgs = [];
    var tasks = [];

    for (var i = 0; i < count; i++) {
      tasks.push(
        mls.generateKeyPackage(clientCredential, mls.defaultCapabilities(), mls.defaultLifetime, [], ciphersuiteImpl).then(function (kp) {
          var encoded = mls.encodeMlsMessage({
            keyPackage: kp.publicPackage,
            wireformat: 'mls_key_package',
            version: 'mls10'
          });
          pkgs.push({
            data: uint8ToB64(encoded),
            ciphersuite: 1
          });
        })
      );
    }

    return Promise.all(tasks).then(function () {
      return csrfFetch('/mls/keypackages', {
        method: 'POST',
        body: JSON.stringify({ device_id: deviceId, keypackages: pkgs })
      });
    }).then(function (r) { return r.json(); });
  }

  // --- Welcome Processing ---
  function pollAndProcessWelcomes() {
    if (!deviceId) return Promise.resolve();
    return csrfFetch('/mls/welcomes?device_id=' + encodeURIComponent(deviceId)).then(function (r) {
      return r.json();
    }).then(function (res) {
      if (!res || !Array.isArray(res.welcomes) || !res.welcomes.length) return;
      var chain = Promise.resolve();
      res.welcomes.forEach(function (w) {
        chain = chain.then(function () {
          return processWelcome(w);
        });
      });
      return chain;
    }).catch(function () {});
  }

  function processWelcome(w) {
    var mls = root.MLS;
    var welcomeBytes = b64ToUint8(w.welcome_data);
    var decoded = mls.decodeMlsMessage(welcomeBytes, 0)[0];
    if (!decoded || decoded.wireformat !== 'mls_welcome') return Promise.resolve();

    // Generate matching keyPackage or joinGroup
    return mls.generateKeyPackage(clientCredential, mls.defaultCapabilities(), mls.defaultLifetime, [], ciphersuiteImpl).then(function (myKp) {
      return mls.joinGroup(decoded.welcome, myKp.publicPackage, myKp.privatePackage, mls.emptyPskIndex, ciphersuiteImpl).then(function (groupState) {
        activeGroups[w.group_id] = groupState;
        // Catch up on any subsequent commits since the welcome epoch
        return catchUpCommits(w.group_id, groupState, w.epoch).then(function (finalState) {
          activeGroups[w.group_id] = finalState;
          return saveGroupState(w.group_id, finalState);
        }).then(function () {
          return csrfFetch('/mls/welcomes/ack', {
            method: 'POST',
            body: JSON.stringify({ welcome_id: w.id, device_id: deviceId })
          });
        });
      });
    }).catch(function (err) {
      console.error('Failed to process MLS welcome for group', w.group_id, err);
    });
  }

  function catchUpCommits(groupId, groupState, fromEpoch) {
    var mls = root.MLS;
    return csrfFetch('/mls/groups/' + encodeURIComponent(groupId) + '/commits?since=' + encodeURIComponent(fromEpoch)).then(function (r) {
      return r.json();
    }).then(function (res) {
      if (!res || !Array.isArray(res.commits) || !res.commits.length) return groupState;
      var cur = groupState;
      for (var i = 0; i < res.commits.length; i++) {
        var cBytes = b64ToUint8(res.commits[i].commit_data);
        var decCommit = mls.decodeMlsMessage(cBytes, 0)[0];
        if (decCommit) {
          var syncRes = mls.processMessage(decCommit, cur, mls.emptyPskIndex, function () {}, ciphersuiteImpl);
          if (syncRes && syncRes.newState) cur = syncRes.newState;
        }
      }
      return cur;
    }).catch(function () { return groupState; });
  }

  // --- Group State Persistence ---
  function saveGroupState(groupId, state) {
    var serialized = JSON.stringify(state);
    return encryptWithKd(serialized).then(function (enc) {
      return idbSet(STORE_MLS_GROUPS, groupId, enc);
    });
  }

  function loadGroupState(groupId) {
    if (activeGroups[groupId]) return Promise.resolve(activeGroups[groupId]);
    return idbGet(STORE_MLS_GROUPS, groupId).then(function (enc) {
      if (!enc) return null;
      return decryptWithKd(enc).then(function (bytes) {
        var str = new TextDecoder().decode(bytes);
        var parsed = JSON.parse(str);
        activeGroups[groupId] = parsed;
        return parsed;
      });
    }).catch(function () { return null; });
  }

  // --- DM Group Initialization & Message Encryption ---
  function getDmGroupId(peerUserId) {
    var myId = currentUserId();
    var pId = parseInt(peerUserId, 10);
    return 'dm:' + Math.min(myId, pId) + '_' + Math.max(myId, pId);
  }

  function ensureDmGroup(peerUserId) {
    var mls = root.MLS;
    var gid = getDmGroupId(peerUserId);

    return loadGroupState(gid).then(function (existing) {
      if (existing) return existing;

      // Group not yet loaded locally — claim peer KeyPackages and initialize
      return csrfFetch('/mls/keypackages/' + encodeURIComponent(peerUserId)).then(function (r) {
        return r.json();
      }).then(function (kpRes) {
        if (!kpRes.ok || !Array.isArray(kpRes.keypackages) || !kpRes.keypackages.length) {
          throw new Error('Peer has no available MLS devices or KeyPackages');
        }

        return mls.generateKeyPackage(clientCredential, mls.defaultCapabilities(), mls.defaultLifetime, [], ciphersuiteImpl).then(function (myKp) {
          var groupBytes = new TextEncoder().encode(gid);
          return mls.createGroup(groupBytes, myKp.publicPackage, myKp.privatePackage, [], ciphersuiteImpl).then(function (freshGroup) {
            // Build AddProposals for peer's devices
            var proposals = [];
            for (var i = 0; i < kpRes.keypackages.length; i++) {
              var decKp = mls.decodeMlsMessage(b64ToUint8(kpRes.keypackages[i].keypackage_data), 0)[0];
              if (decKp && decKp.keyPackage) {
                proposals.push({ proposalType: 'add', add: { keyPackage: decKp.keyPackage } });
              }
            }

            return mls.createCommit(
              { state: freshGroup, cipherSuite: ciphersuiteImpl },
              { extraProposals: proposals, ratchetTreeExtension: true }
            ).then(function (commitRes) {
              var welcomeEnc = mls.encodeMlsMessage({
                welcome: commitRes.welcome,
                wireformat: 'mls_welcome',
                version: 'mls10'
              });
              var commitEnc = mls.encodeMlsMessage(commitRes.commit);

              var welcomesList = [];
              for (var j = 0; j < kpRes.keypackages.length; j++) {
                welcomesList.push({
                  user_id: parseInt(peerUserId, 10),
                  device_id: kpRes.keypackages[j].device_id,
                  welcome_data: uint8ToB64(welcomeEnc)
                });
              }

              return csrfFetch('/mls/groups/init', {
                method: 'POST',
                body: JSON.stringify({
                  group_id: gid,
                  initial_commit: uint8ToB64(commitEnc),
                  welcomes: welcomesList,
                  idempotency_key: 'init_' + gid + '_' + Date.now()
                })
              }).then(function (r) { return r.json(); }).then(function (initRes) {
                if (initRes.error === 'GroupExists') {
                  // Peer beat us to creation! Wait for welcome or catch-up
                  return pollAndProcessWelcomes().then(function () {
                    return loadGroupState(gid);
                  });
                }
                activeGroups[gid] = commitRes.newState;
                return saveGroupState(gid, commitRes.newState).then(function () {
                  return commitRes.newState;
                });
              });
            });
          });
        });
      });
    });
  }

  function encryptDmMessage(peerUserId, plaintext) {
    var mls = root.MLS;
    var gid = getDmGroupId(peerUserId);

    return ensureDmGroup(peerUserId).then(function (groupState) {
      return mls.createApplicationMessage(groupState, new TextEncoder().encode(plaintext), ciphersuiteImpl).then(function (sendRes) {
        activeGroups[gid] = sendRes.newState;
        sendRes.consumed.forEach(mls.zeroOutUint8Array);

        var enc = mls.encodeMlsMessage({
          privateMessage: sendRes.privateMessage,
          wireformat: 'mls_private_message',
          version: 'mls10'
        });

        return saveGroupState(gid, sendRes.newState).then(function () {
          return {
            proto: 'mls',
            group_id: gid,
            body: uint8ToB64(enc)
          };
        });
      });
    });
  }

  function decryptDmMessage(peerUserId, ciphertextB64) {
    var mls = root.MLS;
    var gid = getDmGroupId(peerUserId);

    return ensureDmGroup(peerUserId).then(function (groupState) {
      var msgBytes = b64ToUint8(ciphertextB64);
      var dec = mls.decodeMlsMessage(msgBytes, 0)[0];
      if (!dec || dec.wireformat !== 'mls_private_message') {
        throw new Error('Malformed MLS private message');
      }

      return mls.processPrivateMessage(groupState, dec.privateMessage, mls.emptyPskIndex, ciphersuiteImpl).then(function (recvRes) {
        activeGroups[gid] = recvRes.newState;
        return saveGroupState(gid, recvRes.newState).then(function () {
          return new TextDecoder().decode(recvRes.message);
        });
      });
    });
  }

  // Export onto window.ExtrovertMLS
  root.ExtrovertMLS = {
    init: initDevice,
    getDmGroupId: getDmGroupId,
    ensureDmGroup: ensureDmGroup,
    encryptDmMessage: encryptDmMessage,
    decryptDmMessage: decryptDmMessage,
    pollWelcomes: pollAndProcessWelcomes,
    getDeviceId: function () { return deviceId; },
    ready: function () { return !!(ciphersuiteImpl && deviceId); },
  };

  // Auto-init on page load if user is logged in
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', function () {
      if (currentUserId()) {
        initDevice().catch(function (err) {
          console.warn('MLS auto-init background warning:', err);
        });
      }
    });
  }

})(typeof window !== 'undefined' ? window : global);
