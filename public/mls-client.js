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
    if (typeof document === 'undefined') return '';
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function currentUserId() {
    if (typeof document === 'undefined') return root.__mlsCurrentUserId || null;
    var meta = document.querySelector('meta[name="current-user-id"]');
    return meta ? parseInt(meta.getAttribute('content'), 10) : (root.__mlsCurrentUserId || null);
  }

  function currentUsername() {
    if (typeof document === 'undefined') return root.__mlsCurrentUsername || '';
    var meta = document.querySelector('meta[name="current-username"]');
    return meta ? meta.getAttribute('content') : (root.__mlsCurrentUsername || '');
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

  function idbDelete(storeName, key) {
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(storeName, 'readwrite');
        var req = tx.objectStore(storeName).delete(key);
        req.onsuccess = function () { resolve(); };
        req.onerror = function () { reject(req.error); };
      });
    });
  }

  function uint8ToHex(u) {
    var s = '';
    for (var i = 0; i < u.length; i++) {
      var h = u[i].toString(16);
      s += (h.length === 1 ? '0' : '') + h;
    }
    return s;
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
    var storeTasks = [];

    for (var i = 0; i < count; i++) {
      (function () {
        var task = mls.generateKeyPackage(clientCredential, mls.defaultCapabilities(), mls.defaultLifetime, [], ciphersuiteImpl).then(function (kp) {
          return mls.makeKeyPackageRef(kp.publicPackage, ciphersuiteImpl.hash).then(function (refBytes) {
            var refHex = uint8ToHex(refBytes);
            var encoded = mls.encodeMlsMessage({
              keyPackage: kp.publicPackage,
              wireformat: 'mls_key_package',
              version: 'mls10'
            });

            // STORE BEFORE CONSUME: Persist privatePackage to IndexedDB first
            return idbSet(STORE_MLS_KEYS, 'kp:' + deviceId + ':' + refHex, {
              ref: refHex,
              keyPackage: kp.publicPackage,
              privatePackage: kp.privatePackage,
              created_at: Date.now()
            }).then(function () {
              pkgs.push({
                data: uint8ToB64(encoded),
                ciphersuite: 1,
                keypackage_ref: refHex
              });
            });
          });
        });
        storeTasks.push(task);
      })();
    }

    return Promise.all(storeTasks).then(function () {
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

    var welcomeObj = decoded.welcome;
    if (!welcomeObj || !Array.isArray(welcomeObj.secrets) || !welcomeObj.secrets.length) {
      return Promise.resolve();
    }

    // Match KeyPackageRef against local IndexedDB stored private packages
    var matchPromise = Promise.resolve(null);
    for (var i = 0; i < welcomeObj.secrets.length; i++) {
      (function (secret) {
        matchPromise = matchPromise.then(function (found) {
          if (found) return found;
          var newMemberHex = uint8ToHex(secret.newMember);
          var tombstoneKey = 'tombstone:' + deviceId + ':' + newMemberHex;
          var kpKey = 'kp:' + deviceId + ':' + newMemberHex;

          return idbGet(STORE_MLS_KEYS, tombstoneKey).then(function (tombstone) {
            if (tombstone) {
              // Already joined previously; acknowledge welcome and skip duplicate join
              return csrfFetch('/mls/welcomes/ack', {
                method: 'POST',
                body: JSON.stringify({ welcome_id: w.id, device_id: deviceId })
              }).then(function () {
                return { skipped: true };
              });
            }
            return idbGet(STORE_MLS_KEYS, kpKey).then(function (storedKp) {
              if (storedKp) {
                return { matched: storedKp, newMemberHex: newMemberHex };
              }
              return null;
            });
          });
        });
      })(welcomeObj.secrets[i]);
    }

    return matchPromise.then(function (matchRes) {
      if (!matchRes || matchRes.skipped) return;
      var storedKp = matchRes.matched;
      var newMemberHex = matchRes.newMemberHex;

      return mls.joinGroup(
        welcomeObj,
        storedKp.keyPackage,
        storedKp.privatePackage,
        mls.emptyPskIndex,
        ciphersuiteImpl
      ).then(function (groupState) {
        activeGroups[w.group_id] = groupState;

        // Catch up on any subsequent commits since the welcome epoch
        return catchUpCommits(w.group_id, groupState, w.epoch).then(function (finalState) {
          activeGroups[w.group_id] = finalState;
          return saveGroupState(w.group_id, finalState);
        }).then(function () {
          // Write tombstone BEFORE deleting the consumed private package
          return idbSet(STORE_MLS_KEYS, 'tombstone:' + deviceId + ':' + newMemberHex, {
            groupId: w.group_id,
            joinedAt: Date.now()
          });
        }).then(function () {
          // Clean up the consumed private package
          return idbDelete(STORE_MLS_KEYS, 'kp:' + deviceId + ':' + newMemberHex);
        }).then(function () {
          // Acknowledge the welcome to the Delivery Service
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
      var chain = Promise.resolve(groupState);
      res.commits.forEach(function (cRec) {
        chain = chain.then(function (cur) {
          var cBytes = b64ToUint8(cRec.commit_data);
          var decCommit = mls.decodeMlsMessage(cBytes, 0)[0];
          if (!decCommit) return cur;
          if (decCommit.wireformat === 'mls_private_message') {
            return mls.processPrivateMessage(cur, decCommit.privateMessage, mls.emptyPskIndex, ciphersuiteImpl).then(function (r) {
              return r && r.newState ? r.newState : cur;
            }).catch(function () { return cur; });
          } else {
            return mls.processMessage(decCommit, cur, mls.emptyPskIndex, function () {}, ciphersuiteImpl).then(function (r) {
              return r && r.newState ? r.newState : cur;
            }).catch(function () { return cur; });
          }
        });
      });
      return chain;
    }).catch(function () { return groupState; });
  }

  function restoreClientConfig(st) {
    if (st && !st.clientConfig) {
      var mls = root.MLS;
      st.clientConfig = {
        keyRetentionConfig: mls.defaultKeyRetentionConfig,
        lifetimeConfig: mls.defaultLifetimeConfig,
        keyPackageEqualityConfig: mls.defaultKeyPackageEqualityConfig,
        paddingConfig: mls.defaultPaddingConfig,
        authService: mls.defaultAuthenticationService,
      };
    }
    return st;
  }

  // --- Group State Persistence ---
  function saveGroupState(groupId, state) {
    if (!state) return Promise.resolve();
    try {
      var mls = root.MLS;
      var encoded = mls.encodeGroupState(state);
      return encryptWithKd(encoded).then(function (enc) {
        return idbSet(STORE_MLS_GROUPS, groupId, enc);
      });
    } catch (err) {
      console.error('Failed to encode and save MLS group state for', groupId, err);
      return Promise.reject(err);
    }
  }

  function loadGroupState(groupId) {
    if (activeGroups[groupId]) return Promise.resolve(activeGroups[groupId]);
    return idbGet(STORE_MLS_GROUPS, groupId).then(function (enc) {
      if (!enc) return null;
      return decryptWithKd(enc).then(function (bytes) {
        var mls = root.MLS;
        var decoded = mls.decodeGroupState(bytes, 0);
        if (!decoded || !decoded[0]) return null;
        var state = restoreClientConfig(decoded[0]);
        activeGroups[groupId] = state;
        return state;
      });
    }).catch(function (err) {
      console.warn('Failed to load/decode MLS group state for', groupId, err);
      return null;
    });
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
      if (existing) {
        var ep = existing.groupContext ? Number(existing.groupContext.epoch) : 0;
        return catchUpCommits(gid, existing, ep).then(function (finalState) {
          activeGroups[gid] = finalState;
          return saveGroupState(gid, finalState).then(function () { return finalState; });
        });
      }

      // First check if any Welcome is waiting for us
      return pollAndProcessWelcomes().then(function () {
        return loadGroupState(gid);
      }).then(function (joinedFromWelcome) {
        if (joinedFromWelcome) return joinedFromWelcome;

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
                  }).then(function (st) {
                    if (!st) {
                      throw new Error('MLS conversation exists on server, but no welcome was received for this device. Please refresh or retry.');
                    }
                    return st;
                  });
                }
                if (initRes.error) {
                  throw new Error(initRes.error || initRes.message || 'Server error initializing MLS group');
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
      if (!groupState) {
        throw new Error('Unable to resolve MLS conversation state for peer');
      }
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
      if (!groupState) {
        throw new Error('Unable to resolve MLS conversation state for peer');
      }
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

  // --- Room Group Initialization & Message Encryption ---
  var roomMlsSupportCache = {};
  var ROOM_MLS_CACHE_TTL = 60000;

  function getRoomGroupId(roomId) {
    return 'room:' + String(roomId);
  }

  function invalidateRoomMlsSupport(roomId) {
    if (roomId) {
      var gid = getRoomGroupId(roomId);
      var prefix = gid + ':';
      Object.keys(roomMlsSupportCache).forEach(function (k) {
        if (k === gid || k.startsWith(prefix)) {
          delete roomMlsSupportCache[k];
        }
      });
    } else {
      roomMlsSupportCache = {};
    }
  }

  function checkRoomMlsSupport(roomId, memberUserIds) {
    if (!ciphersuiteImpl || !deviceId) return Promise.resolve(false);
    var myId = currentUserId();
    var others = (memberUserIds || []).map(function (m) {
      return typeof m === 'object' && m !== null ? (m.id || m.user_id) : m;
    }).map(Number).filter(function (uid) {
      return uid && uid !== myId;
    });

    if (!others.length) return Promise.resolve(true);

    var gid = getRoomGroupId(roomId);
    if (activeGroups[gid]) return Promise.resolve(true);

    var cacheKey = gid + ':' + others.slice().sort().join(',');
    var cached = roomMlsSupportCache[cacheKey];
    if (cached && Date.now() - cached.ts < ROOM_MLS_CACHE_TTL) {
      return Promise.resolve(cached.hasMls);
    }

    return Promise.all(others.map(function (uid) {
      return fetch('/mls/devices?user_id=' + encodeURIComponent(uid), {
        headers: { 'Accept': 'application/json' },
        credentials: 'same-origin'
      }).then(function (r) { return r.json(); }).then(function (data) {
        return !!(data && data.ok && Array.isArray(data.devices) && data.devices.length > 0);
      }).catch(function () { return false; });
    })).then(function (results) {
      var allMls = results.every(Boolean);
      roomMlsSupportCache[cacheKey] = { hasMls: allMls, ts: Date.now() };
      return allMls;
    });
  }

  function ensureRoomGroup(roomId, memberUserIds) {
    var mls = root.MLS;
    var gid = getRoomGroupId(roomId);

    return loadGroupState(gid).then(function (existing) {
      if (existing) {
        var ep = existing.groupContext ? Number(existing.groupContext.epoch) : 0;
        return catchUpCommits(gid, existing, ep).then(function (finalState) {
          activeGroups[gid] = finalState;
          return saveGroupState(gid, finalState).then(function () { return finalState; });
        });
      }

      // First check if any Welcome is waiting for us
      return pollAndProcessWelcomes().then(function () {
        return loadGroupState(gid);
      }).then(function (joinedFromWelcome) {
        if (joinedFromWelcome) return joinedFromWelcome;

        // Group not yet loaded locally — claim member KeyPackages and initialize
        var membersP;
        if (Array.isArray(memberUserIds) && memberUserIds.length) {
          membersP = Promise.resolve(memberUserIds);
        } else {
          membersP = fetch('/rooms/' + encodeURIComponent(roomId) + '/channels/0/messages').then(function (r) {
            return r.json();
          }).then(function (d) {
            if (d && Array.isArray(d.members)) {
              return d.members.map(function (m) { return m.user_id; });
            }
            return [];
          }).catch(function () { return []; });
        }

        return membersP.then(function (rawMembers) {
          var myId = currentUserId();
          var otherMembers = (rawMembers || []).map(function (m) {
            return typeof m === 'object' && m !== null ? (m.id || m.user_id) : m;
          }).map(Number).filter(function (uid) {
            return uid && uid !== myId;
          });

          // Fetch KeyPackages for all other members
          var kpPromises = otherMembers.map(function (uid) {
            return csrfFetch('/mls/keypackages/' + encodeURIComponent(uid)).then(function (r) {
              return r.json();
            }).then(function (kpRes) {
              if (!kpRes.ok || !Array.isArray(kpRes.keypackages) || !kpRes.keypackages.length) {
                throw new Error('Room member ' + uid + ' has no available MLS devices or KeyPackages');
              }
              return { uid: uid, packages: kpRes.keypackages };
            });
          });

          return Promise.all(kpPromises).then(function (peerKps) {
            return mls.generateKeyPackage(clientCredential, mls.defaultCapabilities(), mls.defaultLifetime, [], ciphersuiteImpl).then(function (myKp) {
              var groupBytes = new TextEncoder().encode(gid);
              return mls.createGroup(groupBytes, myKp.publicPackage, myKp.privatePackage, [], ciphersuiteImpl).then(function (freshGroup) {
                var proposals = [];
                var welcomesList = [];
                var consumedKpIds = [];

                peerKps.forEach(function (peer) {
                  peer.packages.forEach(function (pkg) {
                    var decKp = mls.decodeMlsMessage(b64ToUint8(pkg.keypackage_data), 0)[0];
                    if (decKp && decKp.keyPackage) {
                      proposals.push({ proposalType: 'add', add: { keyPackage: decKp.keyPackage } });
                      consumedKpIds.push(pkg.id);
                    }
                  });
                });

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

                  peerKps.forEach(function (peer) {
                    peer.packages.forEach(function (pkg) {
                      welcomesList.push({
                        user_id: peer.uid,
                        device_id: pkg.device_id,
                        welcome_data: uint8ToB64(welcomeEnc)
                      });
                    });
                  });

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
                      return pollAndProcessWelcomes().then(function () {
                        return loadGroupState(gid);
                      }).then(function (st) {
                        if (!st) {
                          throw new Error('MLS room exists on server, but no welcome was received for this device. Please refresh or retry.');
                        }
                        return st;
                      });
                    }
                    if (initRes.error) {
                      throw new Error(initRes.error || initRes.message || 'Server error initializing MLS room');
                    }
                    if (consumedKpIds.length) {
                      csrfFetch('/mls/keypackages/consume', {
                        method: 'POST',
                        body: JSON.stringify({ keypackage_ids: consumedKpIds })
                      }).catch(function () {});
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
      });
    });
  }

  function addMemberToRoomGroup(roomId, targetUserId) {
    var mls = root.MLS;
    var gid = getRoomGroupId(roomId);

    return ensureRoomGroup(roomId).then(function (groupState) {
      return csrfFetch('/mls/keypackages/' + encodeURIComponent(targetUserId)).then(function (r) {
        return r.json();
      }).then(function (kpRes) {
        if (!kpRes.ok || !Array.isArray(kpRes.keypackages) || !kpRes.keypackages.length) {
          throw new Error('User has no available MLS devices or KeyPackages');
        }

        var pkg = kpRes.keypackages[0];
        var decKp = mls.decodeMlsMessage(b64ToUint8(pkg.keypackage_data), 0)[0];
        if (!decKp || !decKp.keyPackage) {
          throw new Error('Failed to decode target KeyPackage');
        }

        var addProposal = { proposalType: 'add', add: { keyPackage: decKp.keyPackage } };
        return mls.createCommit(
          { state: groupState, cipherSuite: ciphersuiteImpl },
          { extraProposals: [addProposal], ratchetTreeExtension: true }
        ).then(function (commitRes) {
          var welcomeEnc = mls.encodeMlsMessage({
            welcome: commitRes.welcome,
            wireformat: 'mls_welcome',
            version: 'mls10'
          });
          var commitEnc = mls.encodeMlsMessage(commitRes.commit);

          return csrfFetch('/mls/groups/' + encodeURIComponent(gid) + '/commit', {
            method: 'POST',
            body: JSON.stringify({
              current_epoch: Number(groupState.groupContext.epoch),
              commit_message: uint8ToB64(commitEnc),
              welcomes: [{
                user_id: parseInt(targetUserId, 10),
                device_id: pkg.device_id,
                welcome_data: uint8ToB64(welcomeEnc)
              }],
              members_added: [{
                user_id: parseInt(targetUserId, 10),
                device_id: pkg.device_id,
                role: 'member'
              }],
              idempotency_key: 'add_' + gid + '_' + targetUserId + '_' + Date.now()
            })
          }).then(function (r) { return r.json(); }).then(function (commitApiRes) {
            if (commitApiRes.error === 'EpochConflict') {
              return catchUpCommits(gid, groupState, Number(groupState.groupContext.epoch)).then(function (updatedState) {
                activeGroups[gid] = updatedState;
                return addMemberToRoomGroup(roomId, targetUserId);
              });
            }
            csrfFetch('/mls/keypackages/consume', {
              method: 'POST',
              body: JSON.stringify({ keypackage_ids: [pkg.id] })
            }).catch(function () {});
            activeGroups[gid] = commitRes.newState;
            return saveGroupState(gid, commitRes.newState).then(function () {
              return commitRes.newState;
            });
          });
        });
      });
    });
  }

  function removeMemberFromRoomGroup(roomId, targetUserId) {
    var mls = root.MLS;
    var gid = getRoomGroupId(roomId);

    return ensureRoomGroup(roomId).then(function (groupState) {
      var targetLeafIndex = -1;
      var targetDeviceId = null;
      var uidStr = String(targetUserId);

      if (Array.isArray(groupState.ratchetTree)) {
        for (var i = 0; i < groupState.ratchetTree.length; i += 2) {
          var node = groupState.ratchetTree[i];
          if (node && node.nodeType === 'leaf' && node.leaf && node.leaf.credential) {
            var ident = new TextDecoder().decode(node.leaf.credential.identity);
            if (ident === uidStr || ident.indexOf('user:' + uidStr + ':') === 0 || ident.indexOf(uidStr) !== -1) {
              targetLeafIndex = i / 2;
              var devMatch = ident.match(/dev:([a-zA-Z0-9_-]+)/);
              if (devMatch) targetDeviceId = devMatch[1];
              break;
            }
          }
        }
      }

      if (targetLeafIndex === -1) {
        throw new Error('Member not found in MLS group tree');
      }

      var removeProposal = {
        proposalType: 'remove',
        remove: { removed: targetLeafIndex }
      };

      return mls.createCommit(
        { state: groupState, cipherSuite: ciphersuiteImpl },
        { extraProposals: [removeProposal] }
      ).then(function (commitRes) {
        var commitEnc = mls.encodeMlsMessage(commitRes.commit);

        return csrfFetch('/mls/groups/' + encodeURIComponent(gid) + '/commit', {
          method: 'POST',
          body: JSON.stringify({
            current_epoch: Number(groupState.groupContext.epoch),
            commit_message: uint8ToB64(commitEnc),
            welcomes: [],
            members_added: [],
            members_removed: [{
              user_id: parseInt(targetUserId, 10),
              device_id: targetDeviceId || ''
            }],
            idempotency_key: 'rm_' + gid + '_' + targetUserId + '_' + Date.now()
          })
        }).then(function (r) { return r.json(); }).then(function (commitApiRes) {
          if (commitApiRes.error === 'EpochConflict') {
            return catchUpCommits(gid, groupState, Number(groupState.groupContext.epoch)).then(function (updatedState) {
              activeGroups[gid] = updatedState;
              return removeMemberFromRoomGroup(roomId, targetUserId);
            });
          }
          activeGroups[gid] = commitRes.newState;
          return saveGroupState(gid, commitRes.newState).then(function () {
            invalidateRoomMlsSupport(roomId);
            return commitRes.newState;
          });
        });
      });
    });
  }

  function leaveRoomGroup(roomId) {
    var mls = root.MLS;
    var gid = getRoomGroupId(roomId);
    var myId = currentUserId();

    return ensureRoomGroup(roomId).then(function (groupState) {
      var myLeafIndex = -1;
      var uidStr = String(myId);
      if (Array.isArray(groupState.ratchetTree)) {
        for (var i = 0; i < groupState.ratchetTree.length; i += 2) {
          var node = groupState.ratchetTree[i];
          if (node && node.nodeType === 'leaf' && node.leaf && node.leaf.credential) {
            var ident = new TextDecoder().decode(node.leaf.credential.identity);
            if (ident === uidStr || ident.indexOf('user:' + uidStr + ':') === 0 || ident.indexOf(uidStr) !== -1) {
              myLeafIndex = i / 2;
              break;
            }
          }
        }
      }

      if (myLeafIndex === -1) {
        delete activeGroups[gid];
        invalidateRoomMlsSupport(roomId);
        return idbDelete(STORE_MLS_GROUPS, gid);
      }

      var selfRemoveProposal = {
        proposalType: 'remove',
        remove: { removed: myLeafIndex }
      };

      return mls.createProposal(groupState, false, selfRemoveProposal, ciphersuiteImpl).then(function (propRes) {
        var encProp = mls.encodeMlsMessage(propRes.message);

        return csrfFetch('/mls/groups/' + encodeURIComponent(gid) + '/proposals', {
          method: 'POST',
          body: JSON.stringify({
            epoch: Number(groupState.groupContext.epoch),
            proposal_type: 'remove',
            proposal_data: uint8ToB64(encProp)
          })
        }).then(function () {
          delete activeGroups[gid];
          invalidateRoomMlsSupport(roomId);
          return idbDelete(STORE_MLS_GROUPS, gid);
        });
      });
    }).catch(function () {
      delete activeGroups[gid];
      invalidateRoomMlsSupport(roomId);
      return idbDelete(STORE_MLS_GROUPS, gid);
    });
  }

  function encryptRoomMessage(roomId, plaintext, memberUserIds) {
    var mls = root.MLS;
    var gid = getRoomGroupId(roomId);

    return ensureRoomGroup(roomId, memberUserIds).then(function (groupState) {
      if (!groupState) {
        throw new Error('Unable to resolve MLS conversation state for room');
      }
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

  function decryptRoomMessage(roomId, ciphertextB64) {
    var mls = root.MLS;
    var gid = getRoomGroupId(roomId);

    return ensureRoomGroup(roomId).then(function (groupState) {
      if (!groupState) {
        throw new Error('Unable to resolve MLS conversation state for room');
      }
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

  function revokeDevice(targetDeviceId) {
    var dev = targetDeviceId || deviceId;
    return csrfFetch('/mls/devices/' + encodeURIComponent(dev), {
      method: 'DELETE'
    }).then(function (r) {
      return r.json();
    }).then(function (res) {
      invalidateRoomMlsSupport(); // Flush capability cache immediately on device revocation
      return res;
    });
  }

  // Export onto window.ExtrovertMLS
  root.ExtrovertMLS = {
    init: initDevice,
    getDmGroupId: getDmGroupId,
    ensureDmGroup: ensureDmGroup,
    encryptDmMessage: encryptDmMessage,
    decryptDmMessage: decryptDmMessage,
    getRoomGroupId: getRoomGroupId,
    checkRoomMlsSupport: checkRoomMlsSupport,
    ensureRoomGroup: ensureRoomGroup,
    addMemberToRoomGroup: addMemberToRoomGroup,
    removeMemberFromRoomGroup: removeMemberFromRoomGroup,
    leaveRoomGroup: leaveRoomGroup,
    invalidateRoomMlsSupport: invalidateRoomMlsSupport,
    encryptRoomMessage: encryptRoomMessage,
    decryptRoomMessage: decryptRoomMessage,
    revokeDevice: revokeDevice,
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
