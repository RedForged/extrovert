/**
 * Extrovert MLS (Messaging Layer Security, RFC 9420) Client Engine
 * Integrates with /static/lib/mls.js (ts-mls) and Extrovert's DS/AS endpoints.
 */

(function (root) {
  'use strict';

  var DB_NAME = 'extrovert_crypto';
  var STORE_CRYPTO = 'crypto';
  var STORE_MLS_KEYS = 'mls_keys';
  var STORE_MLS_GROUPS = 'mls_groups';
  var STORE_MSG_CACHE = 'mls_msg_cache';
  var STORE_MLS_HISTORY = 'mls_history';
  var ALL_STORES = [STORE_CRYPTO, STORE_MLS_KEYS, STORE_MLS_GROUPS, STORE_MSG_CACHE, STORE_MLS_HISTORY];

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

  var dbPromise = null;

  function wireDb(db) {
    db.onversionchange = function () {
      db.close();
      dbPromise = null;
    };
    return db;
  }

  function openDB() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise(function (resolve, reject) {
      var req = indexedDB.open(DB_NAME);
      req.onupgradeneeded = function () {
        var db = req.result;
        ALL_STORES.forEach(function (s) {
          if (!db.objectStoreNames.contains(s)) db.createObjectStore(s);
        });
      };
      req.onsuccess = function () {
        var db = req.result;
        var missing = ALL_STORES.filter(function (s) { return !db.objectStoreNames.contains(s); });
        if (!missing.length) return resolve(wireDb(db));
        var target = db.version + 1;
        db.close();
        var up = indexedDB.open(DB_NAME, target);
        up.onupgradeneeded = function () {
          var udb = up.result;
          missing.forEach(function (s) {
            if (!udb.objectStoreNames.contains(s)) udb.createObjectStore(s);
          });
        };
        up.onsuccess = function () { resolve(wireDb(up.result)); };
        up.onerror = function () { dbPromise = null; reject(up.error); };
      };
      req.onerror = function () { dbPromise = null; reject(req.error); };
    }).catch(function (err) {
      dbPromise = null;
      throw err;
    });
    return dbPromise;
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

  function idbGetAll(storeName) {
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(storeName, 'readonly');
        var store = tx.objectStore(storeName);
        var keysReq = store.getAllKeys();
        var valsReq = store.getAll();
        var keys = null;
        var vals = null;
        function maybe() {
          if (keys && vals) {
            resolve(keys.map(function (k, i) { return { key: k, value: vals[i] }; }));
          }
        }
        keysReq.onsuccess = function () { keys = keysReq.result || []; maybe(); };
        valsReq.onsuccess = function () { vals = valsReq.result || []; maybe(); };
        keysReq.onerror = function () { reject(keysReq.error); };
        valsReq.onerror = function () { reject(valsReq.error); };
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

  function encryptWithKey(key, data) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, bytes).then(function (ct) {
      var c = new Uint8Array(iv.length + ct.byteLength);
      c.set(iv);
      c.set(new Uint8Array(ct), iv.length);
      return uint8ToB64(c);
    });
  }

  function decryptWithKey(key, b64) {
    var c = b64ToUint8(b64);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: c.slice(0, 12) }, key, c.slice(12)).then(function (pt) {
      return new Uint8Array(pt);
    });
  }

  function encryptWithKd(data) {
    return encryptWithKey(deviceKey, data);
  }

  function decryptWithKd(b64) {
    return decryptWithKey(deviceKey, b64);
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

  var initPromise = null;

  function initDevice() {
    if (initPromise) return initPromise;
    var uid = currentUserId();
    if (!uid) return Promise.resolve(null);

    initPromise = Promise.all([
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

      function registerDevice() {
        return csrfFetch('/mls/device/register', {
          method: 'POST',
          body: JSON.stringify({
            device_id: deviceId,
            device_name: (typeof navigator !== 'undefined' && navigator.userAgent) ? navigator.userAgent.slice(0, 30) : 'Web Browser',
            signing_key_pub: 'ed25519_' + deviceId,
          })
        }).then(function (r) { return r.json(); }).then(function (regRes) {
          if (!regRes.ok) {
            if (regRes.code === 'QUOTA_EXCEEDED' || (regRes.error && regRes.error.indexOf('quota') !== -1)) {
              // Automatically revoke oldest device to stay within quota
              return csrfFetch('/mls/devices').then(function (r) { return r.json(); }).then(function (dRes) {
                if (dRes && Array.isArray(dRes.devices) && dRes.devices.length) {
                  var oldest = dRes.devices[0].device_id;
                  return csrfFetch('/mls/devices/' + encodeURIComponent(oldest), { method: 'DELETE' }).then(function () {
                    return csrfFetch('/mls/device/register', {
                      method: 'POST',
                      body: JSON.stringify({
                        device_id: deviceId,
                        device_name: (typeof navigator !== 'undefined' && navigator.userAgent) ? navigator.userAgent.slice(0, 30) : 'Web Browser',
                        signing_key_pub: 'ed25519_' + deviceId,
                      })
                    }).then(function (r2) { return r2.json(); });
                  });
                }
                return regRes;
              });
            }
            throw new Error(regRes.error || 'Failed to register MLS device');
          }
          return regRes;
        });
      }

      return registerDevice().then(function (regRes) {
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
    }).then(function () {
      return loadBackupKey();
    }).then(function () {
      return loadDeletedMsgIds();
    }).then(function () {
      return resumeBackupUnlock();
    }).then(function () {
      return syncBackup();
    }).catch(function (err) {
      initPromise = null;
      throw err;
    });

    return initPromise;
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
    scheduleBackup();
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
        if (!decoded || !decoded[0]) throw new Error('Undecodable MLS group state');
        var state = restoreClientConfig(decoded[0]);
        activeGroups[groupId] = state;
        return state;
      });
    }).catch(function (err) {
      console.warn('Failed to load/decode MLS group state for', groupId, err);
      return idbDelete(STORE_MLS_GROUPS, groupId).then(function () {
        return null;
      }).catch(function () {
        return null;
      });
    });
  }

  // --- DM Group Initialization & Message Encryption ---
  function getDmGroupId(peerUserId) {
    var myId = currentUserId();
    var pId = parseInt(peerUserId, 10);
    return 'dm:' + Math.min(myId, pId) + '_' + Math.max(myId, pId);
  }

  function postGroupInit(body) {
    return csrfFetch('/mls/groups/init', {
      method: 'POST',
      body: JSON.stringify(body)
    }).then(function (r) {
      return r.json();
    });
  }

  function claimKeyPackagesFor(uid, excludeDevice) {
    var url = '/mls/keypackages/' + encodeURIComponent(uid);
    if (excludeDevice) url += '?exclude_device=' + encodeURIComponent(excludeDevice);
    return csrfFetch(url).then(function (r) {
      return r.json();
    }).then(function (res) {
      return (res && res.ok && Array.isArray(res.keypackages)) ? res.keypackages : [];
    });
  }

  function resolveGroupConflict(gid, initBody, conflictEpoch, newState, missingMsg) {
    function pollOrThrow() {
      return pollAndProcessWelcomes().then(function () {
        return loadGroupState(gid);
      }).then(function (st) {
        if (st) return st;
        throw new Error(missingMsg);
      });
    }

    return pollAndProcessWelcomes().then(function () {
      return loadGroupState(gid);
    }).then(function (st) {
      if (st) return st;
      // Local state is gone and no Welcome will arrive for this device: the
      // server-side group is unrecoverable. CAS-reset the dead group and
      // re-initialize with the same commit; peers converge via the Welcomes.
      var resetBody = {};
      for (var k in initBody) resetBody[k] = initBody[k];
      resetBody.reset_existing = true;
      resetBody.expected_epoch = conflictEpoch;
      return postGroupInit(resetBody).then(function (resetRes) {
        if (resetRes.error === 'GroupExists') return pollOrThrow();
        if (resetRes.error) {
          throw new Error(resetRes.error || resetRes.message || 'Server error initializing MLS group');
        }
        activeGroups[gid] = newState;
        return saveGroupState(gid, newState).then(function () {
          return newState;
        });
      });
    });
  }

  function ensureDmGroup(peerUserId) {
    return initDevice().then(function () {
      var mls = root.MLS;
      var gid = getDmGroupId(peerUserId);

      return loadGroupState(gid).then(function (existing) {
        if (existing) {
          return pollAndProcessWelcomes().then(function () {
            return loadGroupState(gid);
          }).then(function (st) {
            var base = st || existing;
            var ep = base.groupContext ? Number(base.groupContext.epoch) : 0;
            return catchUpCommits(gid, base, ep).then(function (finalState) {
              activeGroups[gid] = finalState;
              return saveGroupState(gid, finalState).then(function () { return finalState; });
            });
          });
        }

        // First check if any Welcome is waiting for us
        return pollAndProcessWelcomes().then(function () {
          return loadGroupState(gid);
        }).then(function (joinedFromWelcome) {
          if (joinedFromWelcome) return joinedFromWelcome;

          // Group not yet loaded locally — claim KeyPackages for the peer's
          // devices and our own other devices, then initialize
          return claimKeyPackagesFor(peerUserId).then(function (peerKps) {
            if (!peerKps.length) {
              throw new Error('Peer has no available MLS devices or KeyPackages');
            }
            return claimKeyPackagesFor(currentUserId(), deviceId).catch(function () {
              return [];
            }).then(function (ownKps) {
              var targets = [];
              peerKps.forEach(function (p) {
                targets.push({ user_id: parseInt(peerUserId, 10), pkg: p });
              });
              ownKps.forEach(function (p) {
                targets.push({ user_id: currentUserId(), pkg: p });
              });

              return mls.generateKeyPackage(clientCredential, mls.defaultCapabilities(), mls.defaultLifetime, [], ciphersuiteImpl).then(function (myKp) {
                var groupBytes = new TextEncoder().encode(gid);
                return mls.createGroup(groupBytes, myKp.publicPackage, myKp.privatePackage, [], ciphersuiteImpl).then(function (freshGroup) {
                  var addable = [];
                  targets.forEach(function (t) {
                    var decKp = mls.decodeMlsMessage(b64ToUint8(t.pkg.keypackage_data), 0)[0];
                    if (decKp && decKp.keyPackage) {
                      addable.push({ user_id: t.user_id, device_id: t.pkg.device_id, keyPackage: decKp.keyPackage });
                    }
                  });

                  var proposals = addable.map(function (a) {
                    return { proposalType: 'add', add: { keyPackage: a.keyPackage } };
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

                    var welcomesList = addable.map(function (a) {
                      return {
                        user_id: a.user_id,
                        device_id: a.device_id,
                        welcome_data: uint8ToB64(welcomeEnc)
                      };
                    });

                    var initBody = {
                      group_id: gid,
                      initial_commit: uint8ToB64(commitEnc),
                      welcomes: welcomesList,
                      idempotency_key: 'init_' + gid + '_' + Date.now()
                    };

                    return postGroupInit(initBody).then(function (initRes) {
                      if (initRes.error === 'GroupExists') {
                        return resolveGroupConflict(gid, initBody, initRes.epoch, commitRes.newState,
                          'MLS conversation exists on server, but no welcome was received for this device. Please refresh or retry.');
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
          return backupNow();
        }).then(function () {
          return {
            proto: 'mls',
            group_id: gid,
            body: uint8ToB64(enc)
          };
        });
      });
    });
  }

  function decryptWithState(groupState, ciphertextB64) {
    var mls = root.MLS;
    var dec = mls.decodeMlsMessage(b64ToUint8(ciphertextB64), 0)[0];
    if (!dec || dec.wireformat !== 'mls_private_message') {
      return Promise.reject(new Error('Malformed MLS private message'));
    }
    return mls.processPrivateMessage(groupState, dec.privateMessage, mls.emptyPskIndex, ciphersuiteImpl);
  }

  function loadHistoryStates(gid) {
    if (historyStates[gid]) return Promise.resolve(historyStates[gid]);
    return idbGet(STORE_MLS_HISTORY, gid).then(function (rows) {
      var mls = root.MLS;
      var entries = [];
      (rows || []).forEach(function (row) {
        try {
          var decoded = mls.decodeGroupState(b64ToUint8(row.bytes), 0);
          if (decoded && decoded[0]) {
            entries.push({ deviceId: row.deviceId, state: restoreClientConfig(decoded[0]) });
          }
        } catch (err) {}
      });
      historyStates[gid] = entries;
      return entries;
    }).catch(function () { return []; });
  }

  function tryHistoryDecrypt(gid, ciphertextB64) {
    return loadHistoryStates(gid).then(function (entries) {
      var chain = Promise.resolve(null);
      entries.forEach(function (entry) {
        chain = chain.then(function (found) {
          if (found !== null) return found;
          return decryptWithState(entry.state, ciphertextB64).then(function (recvRes) {
            return (recvRes && recvRes.kind === 'applicationMessage')
              ? new TextDecoder().decode(recvRes.message)
              : null;
          }).catch(function () { return null; });
        });
      });
      return chain;
    }).then(function (pt) {
      if (pt !== null) scheduleBackup();
      return pt;
    }).catch(function () { return null; });
  }

  function decryptGroupMessage(gid, ensureFn, missingMsg, ciphertextB64) {
    function withActiveState(state) {
      return decryptWithState(state, ciphertextB64).then(function (recvRes) {
        if (!recvRes || recvRes.kind !== 'applicationMessage') {
          throw new Error('Unexpected MLS handshake message in conversation');
        }
        activeGroups[gid] = recvRes.newState;
        return saveGroupState(gid, recvRes.newState).then(function () {
          return new TextDecoder().decode(recvRes.message);
        });
      });
    }

    function viaEnsure() {
      return ensureFn().then(function (groupState) {
        if (!groupState) throw new Error(missingMsg);
        return withActiveState(groupState);
      });
    }

    function historyOrEnsure() {
      return tryHistoryDecrypt(gid, ciphertextB64).then(function (pt) {
        return pt !== null ? pt : viaEnsure();
      });
    }

    return loadGroupState(gid).then(function (state) {
      if (!state) return historyOrEnsure();
      return withActiveState(state).catch(historyOrEnsure);
    });
  }

  function decryptDmMessage(peerUserId, ciphertextB64) {
    var gid = getDmGroupId(peerUserId);
    return decryptGroupMessage(gid, function () { return ensureDmGroup(peerUserId); },
      'Unable to resolve MLS conversation state for peer', ciphertextB64);
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
    return initDevice().then(function () {
      var mls = root.MLS;
      var gid = getRoomGroupId(roomId);

      return loadGroupState(gid).then(function (existing) {
        if (existing) {
          return pollAndProcessWelcomes().then(function () {
            return loadGroupState(gid);
          }).then(function (st) {
            var base = st || existing;
            var ep = base.groupContext ? Number(base.groupContext.epoch) : 0;
            return catchUpCommits(gid, base, ep).then(function (afterCatchUp) {
              return commitPendingProposals(gid, afterCatchUp);
            }).then(function (finalState) {
              activeGroups[gid] = finalState;
              return saveGroupState(gid, finalState).then(function () { return finalState; });
            });
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

            var kpPromises = otherMembers.map(function (uid) {
              return claimKeyPackagesFor(uid).then(function (kps) {
                return { uid: uid, packages: kps };
              });
            });
            kpPromises.push(claimKeyPackagesFor(myId, deviceId).catch(function () {
              return [];
            }).then(function (kps) {
              return { uid: myId, packages: kps };
            }));

            return Promise.all(kpPromises).then(function (peerKps) {
              return mls.generateKeyPackage(clientCredential, mls.defaultCapabilities(), mls.defaultLifetime, [], ciphersuiteImpl).then(function (myKp) {
                var groupBytes = new TextEncoder().encode(gid);
                return mls.createGroup(groupBytes, myKp.publicPackage, myKp.privatePackage, [], ciphersuiteImpl).then(function (freshGroup) {
                  var addable = [];
                  peerKps.forEach(function (peer) {
                    peer.packages.forEach(function (pkg) {
                      var decKp = mls.decodeMlsMessage(b64ToUint8(pkg.keypackage_data), 0)[0];
                      if (decKp && decKp.keyPackage) {
                        addable.push({ user_id: peer.uid, device_id: pkg.device_id, keyPackage: decKp.keyPackage });
                      }
                    });
                  });

                  var proposals = addable.map(function (a) {
                    return { proposalType: 'add', add: { keyPackage: a.keyPackage } };
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

                    var welcomesList = addable.map(function (a) {
                      return {
                        user_id: a.user_id,
                        device_id: a.device_id,
                        welcome_data: uint8ToB64(welcomeEnc)
                      };
                    });

                    var initBody = {
                      group_id: gid,
                      initial_commit: uint8ToB64(commitEnc),
                      welcomes: welcomesList,
                      idempotency_key: 'init_' + gid + '_' + Date.now()
                    };

                    return postGroupInit(initBody).then(function (initRes) {
                      if (initRes.error === 'GroupExists') {
                        return resolveGroupConflict(gid, initBody, initRes.epoch, commitRes.newState,
                          'MLS room exists on server, but no welcome was received for this device. Please refresh or retry.');
                      }
                      if (initRes.error) {
                        throw new Error(initRes.error || initRes.message || 'Server error initializing MLS room');
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
    });
  }
  function findUserLeaves(state, uidStr) {
    var found = [];
    var prefix = 'user:' + uidStr + ':dev:';
    if (state && Array.isArray(state.ratchetTree)) {
      for (var i = 0; i < state.ratchetTree.length; i += 2) {
        var node = state.ratchetTree[i];
        if (node && node.nodeType === 'leaf' && node.leaf && node.leaf.credential && node.leaf.credential.identity) {
          var ident = new TextDecoder().decode(node.leaf.credential.identity);
          if (ident.indexOf(prefix) === 0) {
            found.push({ leafIndex: i / 2, deviceId: ident.slice(prefix.length) });
          }
        }
      }
    }
    return found;
  }

  function commitPendingProposals(gid, groupState) {
    var mls = root.MLS;
    var ep = Number(groupState.groupContext.epoch);
    return csrfFetch('/mls/groups/' + encodeURIComponent(gid) + '/proposals?epoch=' + encodeURIComponent(ep)).then(function (r) {
      return r.json();
    }).then(function (res) {
      if (!res || !Array.isArray(res.proposals) || !res.proposals.length) return groupState;
      var extra = [];
      var refs = [];
      res.proposals.forEach(function (p) {
        var dec = mls.decodeMlsMessage(b64ToUint8(p.proposal_data), 0)[0];
        if (dec && dec.wireformat === 'mls_public_message' && dec.publicMessage && dec.publicMessage.content &&
            dec.publicMessage.content.contentType === 'proposal' && dec.publicMessage.content.proposal) {
          extra.push(dec.publicMessage.content.proposal);
          refs.push(p.proposal_ref);
        }
      });
      if (!extra.length) return groupState;

      return mls.createCommit(
        { state: groupState, cipherSuite: ciphersuiteImpl },
        { extraProposals: extra }
      ).then(function (commitRes) {
        var commitEnc = mls.encodeMlsMessage(commitRes.commit);
        return csrfFetch('/mls/groups/' + encodeURIComponent(gid) + '/commit', {
          method: 'POST',
          body: JSON.stringify({
            current_epoch: ep,
            commit_message: uint8ToB64(commitEnc),
            welcomes: [],
            proposals_consumed: refs,
            idempotency_key: 'prop_' + gid + '_' + ep + '_' + Date.now()
          })
        }).then(function (r) { return r.json(); }).then(function (apiRes) {
          if (apiRes && apiRes.error === 'EpochConflict') {
            return catchUpCommits(gid, groupState, ep);
          }
          return commitRes.newState;
        });
      });
    }).catch(function () {
      return groupState;
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

        var proposals = [];
        var welcomesList = [];
        var membersAdded = [];
        for (var i = 0; i < kpRes.keypackages.length; i++) {
          var pkg = kpRes.keypackages[i];
          var decKp = mls.decodeMlsMessage(b64ToUint8(pkg.keypackage_data), 0)[0];
          if (!decKp || !decKp.keyPackage) {
            throw new Error('Failed to decode target KeyPackage');
          }
          proposals.push({ proposalType: 'add', add: { keyPackage: decKp.keyPackage } });
          welcomesList.push({
            user_id: parseInt(targetUserId, 10),
            device_id: pkg.device_id,
            welcome_data: ''
          });
          membersAdded.push({
            user_id: parseInt(targetUserId, 10),
            device_id: pkg.device_id,
            role: 'member'
          });
        }

        return mls.createCommit(
          { state: groupState, cipherSuite: ciphersuiteImpl },
          { extraProposals: proposals, ratchetTreeExtension: true }
        ).then(function (commitRes) {
          var welcomeEnc = mls.encodeMlsMessage({
            welcome: commitRes.welcome,
            wireformat: 'mls_welcome',
            version: 'mls10'
          });
          var commitEnc = mls.encodeMlsMessage(commitRes.commit);
          for (var j = 0; j < welcomesList.length; j++) {
            welcomesList[j].welcome_data = uint8ToB64(welcomeEnc);
          }

          return csrfFetch('/mls/groups/' + encodeURIComponent(gid) + '/commit', {
            method: 'POST',
            body: JSON.stringify({
              current_epoch: Number(groupState.groupContext.epoch),
              commit_message: uint8ToB64(commitEnc),
              welcomes: welcomesList,
              members_added: membersAdded,
              idempotency_key: 'add_' + gid + '_' + targetUserId + '_' + Date.now()
            })
          }).then(function (r) { return r.json(); }).then(function (commitApiRes) {
            if (commitApiRes.error === 'EpochConflict') {
              return catchUpCommits(gid, groupState, Number(groupState.groupContext.epoch)).then(function (updatedState) {
                activeGroups[gid] = updatedState;
                return addMemberToRoomGroup(roomId, targetUserId);
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
  }

  function removeMemberFromRoomGroup(roomId, targetUserId) {
    var mls = root.MLS;
    var gid = getRoomGroupId(roomId);

    return ensureRoomGroup(roomId).then(function (groupState) {
      var leaves = findUserLeaves(groupState, String(targetUserId));
      if (!leaves.length) {
        throw new Error('Member not found in MLS group tree');
      }

      var proposals = leaves.map(function (l) {
        return { proposalType: 'remove', remove: { removed: l.leafIndex } };
      });

      return mls.createCommit(
        { state: groupState, cipherSuite: ciphersuiteImpl },
        { extraProposals: proposals }
      ).then(function (commitRes) {
        var commitEnc = mls.encodeMlsMessage(commitRes.commit);

        return csrfFetch('/mls/groups/' + encodeURIComponent(gid) + '/commit', {
          method: 'POST',
          body: JSON.stringify({
            current_epoch: Number(groupState.groupContext.epoch),
            commit_message: uint8ToB64(commitEnc),
            welcomes: [],
            members_added: [],
            members_removed: leaves.map(function (l) {
              return { user_id: parseInt(targetUserId, 10), device_id: l.deviceId };
            }),
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

    function dropLocalGroup() {
      delete activeGroups[gid];
      invalidateRoomMlsSupport(roomId);
      return idbDelete(STORE_MLS_GROUPS, gid);
    }

    return ensureRoomGroup(roomId).then(function (groupState) {
      var leaves = findUserLeaves(groupState, String(myId));
      if (!leaves.length) {
        return dropLocalGroup();
      }

      var chain = Promise.resolve();
      leaves.forEach(function (l) {
        chain = chain.then(function () {
          var selfRemoveProposal = {
            proposalType: 'remove',
            remove: { removed: l.leafIndex }
          };
          return mls.createProposal(groupState, true, selfRemoveProposal, ciphersuiteImpl).then(function (propRes) {
            var encProp = mls.encodeMlsMessage(propRes.message);

            return csrfFetch('/mls/groups/' + encodeURIComponent(gid) + '/proposals', {
              method: 'POST',
              body: JSON.stringify({
                epoch: Number(groupState.groupContext.epoch),
                sender_leaf: l.leafIndex,
                proposal_type: 'remove',
                proposal_data: uint8ToB64(encProp)
              })
            });
          });
        });
      });

      return chain.then(dropLocalGroup);
    }).catch(function () {
      return dropLocalGroup();
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
          return backupNow();
        }).then(function () {
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
    var gid = getRoomGroupId(roomId);
    return decryptGroupMessage(gid, function () { return ensureRoomGroup(roomId); },
      'Unable to resolve MLS conversation state for room', ciphertextB64);
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

  // --- Password-Restorable Message & State Backups ---
  var PBKDF2_ITERATIONS = 310000;
  var BACKUP_SESSION_KEY = 'extrovert_pending_backup';
  var historyStates = {};
  var deletedMsgIds = [];
  var backupKey = null;
  var backupKeyId = null;
  var backupKek = null;
  var backupKekSalt = null;
  var backupTimer = null;
  var backupBusy = false;
  var backupQueued = false;

  function loadBackupKey() {
    return idbGet(STORE_CRYPTO, 'backupKey').then(function (bk) {
      if (!bk) return null;
      backupKey = bk;
      return idbGet(STORE_CRYPTO, 'backupKekSalt').then(function (salt) {
        backupKekSalt = salt || null;
        return computeBackupKeyId();
      });
    }).catch(function () { return null; });
  }

  function loadDeletedMsgIds() {
    return idbGet(STORE_CRYPTO, 'deletedMsgIds').then(function (arr) {
      if (Array.isArray(arr)) deletedMsgIds = arr;
    }).catch(function () {});
  }

  function isDeletedKey(key) {
    var k = String(key);
    for (var i = 0; i < deletedMsgIds.length; i++) {
      if (k === deletedMsgIds[i] || k.indexOf(deletedMsgIds[i] + ':') === 0) return true;
    }
    return false;
  }

  function noteMessageDeleted(msgId) {
    var id = String(msgId);
    if (deletedMsgIds.indexOf(id) === -1) deletedMsgIds.push(id);
    return idbSet(STORE_CRYPTO, 'deletedMsgIds', deletedMsgIds).then(function () {
      return idbGetAll(STORE_MSG_CACHE);
    }).then(function (rows) {
      var chain = Promise.resolve();
      (rows || []).forEach(function (row) {
        if (isDeletedKey(row.key)) {
          chain = chain.then(function () { return idbDelete(STORE_MSG_CACHE, String(row.key)); });
        }
      });
      return chain;
    }).then(function () {
      return backupNow();
    }).catch(function () {});
  }

  function computeBackupKeyId() {
    return crypto.subtle.exportKey('raw', backupKey).then(function (raw) {
      return crypto.subtle.digest('SHA-256', raw);
    }).then(function (digest) {
      backupKeyId = uint8ToHex(new Uint8Array(digest)).slice(0, 16);
      return backupKeyId;
    });
  }

  function persistBackupKey() {
    return computeBackupKeyId().then(function () {
      return idbSet(STORE_CRYPTO, 'backupKey', backupKey);
    }).then(function () {
      return idbSet(STORE_CRYPTO, 'backupKekSalt', backupKekSalt || null);
    });
  }

  function generateBackupKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  function deriveBackupKek(password, saltBytes) {
    var salt = (saltBytes && saltBytes.length) ? saltBytes : crypto.getRandomValues(new Uint8Array(16));
    return crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'])
      .then(function (baseKey) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: PBKDF2_ITERATIONS },
          baseKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
      }).then(function (kek) {
        return { kek: kek, salt: salt };
      });
  }

  function wrapBackupKey() {
    return crypto.subtle.exportKey('raw', backupKey).then(function (raw) {
      return encryptWithKey(backupKek, new Uint8Array(raw));
    });
  }

  function unwrapBackupKey(wrappedB64) {
    return decryptWithKey(backupKek, wrappedB64).then(function (bytes) {
      return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
    });
  }

  function ensureBackupReady() {
    if (backupKey && backupKeyId) return Promise.resolve(true);
    return loadBackupKey().then(function () {
      if (backupKey && backupKeyId) return true;
      if (!backupKek) return false;
      return generateBackupKey().then(function (bk) {
        backupKey = bk;
        if (!backupKekSalt) backupKekSalt = crypto.getRandomValues(new Uint8Array(16));
        return persistBackupKey();
      }).then(function () { return true; });
    });
  }

  function packBackupPayload() {
    return idbGetAll(STORE_MSG_CACHE).then(function (cacheRows) {
      return idbGetAll(STORE_MLS_HISTORY).then(function (histRows) {
        return idbGetAll(STORE_MLS_GROUPS).then(function (stateRows) {
          var devices = {};
          histRows.forEach(function (row) {
            (row.value || []).forEach(function (e) {
              var d = devices[e.deviceId] || (devices[e.deviceId] = {});
              d[row.key] = e.bytes;
            });
          });
          var mine = devices[deviceId] || (devices[deviceId] = {});
          var chain = Promise.resolve();
          stateRows.forEach(function (row) {
            chain = chain.then(function () {
              return decryptWithKd(row.value).then(function (bytes) {
                mine[row.key] = uint8ToB64(bytes);
              }).catch(function () {});
            });
          });
          return chain.then(function () {
            var msgCache = {};
            cacheRows.forEach(function (row) {
              if (isDeletedKey(row.key)) return;
              msgCache[String(row.key)] = row.value;
            });
            return { updatedAt: Date.now(), devices: devices, msgCache: msgCache, deleted: deletedMsgIds.slice() };
          });
        });
      });
    });
  }

  function fetchBackupBlob() {
    return csrfFetch('/mls/backup').then(function (r) {
      return r.json();
    }).then(function (res) {
      return (res && res.ok && res.backup && res.backup.backup_data) ? res.backup : null;
    }).catch(function () { return null; });
  }

  function parseBackupBlob(backupDataB64) {
    return JSON.parse(new TextDecoder().decode(b64ToUint8(backupDataB64)));
  }

  function doBackup() {
    return ensureBackupReady().then(function (ready) {
      if (!ready) return null;
      return fetchBackupBlob().then(function (row) {
        var parsed = null;
        if (row) {
          try { parsed = parseBackupBlob(row.backup_data); } catch (err) { parsed = null; }
        }
        if (parsed && parsed.bk_id !== backupKeyId) {
          console.warn('MLS backup: server copy uses a different backup key; leaving it intact');
          return null;
        }
        var serverPayloadP = parsed
          ? decryptWithKey(backupKey, parsed.payload).then(function (b) {
              return JSON.parse(new TextDecoder().decode(b));
            }).catch(function () { return null; })
          : Promise.resolve(null);

        return serverPayloadP.then(function (serverPayload) {
          return packBackupPayload().then(function (localPayload) {
            var deleted = {};
            ((serverPayload && serverPayload.deleted) || []).forEach(function (id) { deleted[String(id)] = true; });
            (localPayload.deleted || []).forEach(function (id) { deleted[String(id)] = true; });
            deletedMsgIds = Object.keys(deleted);
            var merged = Object.assign({}, serverPayload ? serverPayload.msgCache : {}, localPayload.msgCache);
            var msgCache = {};
            Object.keys(merged).forEach(function (k) {
              if (!isDeletedKey(k)) msgCache[k] = merged[k];
            });
            var payload = {
              updatedAt: Date.now(),
              devices: Object.assign({}, serverPayload ? serverPayload.devices : {}),
              msgCache: msgCache,
              deleted: deletedMsgIds.slice(),
            };
            payload.devices[deviceId] = localPayload.devices[deviceId] || {};
            return encryptWithKey(backupKey, new TextEncoder().encode(JSON.stringify(payload)));
          }).then(function (payloadB64) {
            var wrapP = backupKek ? wrapBackupKey() : Promise.resolve(parsed ? parsed.wrappedBk : null);
            return wrapP.then(function (wrappedBk) {
              if (!wrappedBk) throw new Error('Backup key cannot be wrapped without the account password');
              var blob = { v: 1, bk_id: backupKeyId, wrappedBk: wrappedBk, payload: payloadB64 };
              return csrfFetch('/mls/backup', {
                method: 'POST',
                body: JSON.stringify({
                  backup_data: uint8ToB64(new TextEncoder().encode(JSON.stringify(blob))),
                  salt: backupKek ? uint8ToB64(backupKekSalt) : row.kek_salt
                })
              }).then(function (r) { return r.json(); });
            });
          });
        });
      });
    });
  }

  function backupNow() {
    if (!deviceId) return Promise.resolve(null);
    if (backupBusy) {
      backupQueued = true;
      return Promise.resolve(null);
    }
    backupBusy = true;
    return doBackup().catch(function (err) {
      console.warn('MLS backup upload skipped:', err && err.message);
      return null;
    }).then(function (res) {
      backupBusy = false;
      if (backupQueued) {
        backupQueued = false;
        return backupNow();
      }
      return res;
    });
  }

  function scheduleBackup() {
    if (backupTimer) clearTimeout(backupTimer);
    backupTimer = setTimeout(function () {
      backupTimer = null;
      backupNow();
    }, 4000);
  }

  function importBackupPayload(payload) {
    var deleted = {};
    deletedMsgIds.forEach(function (id) { deleted[String(id)] = true; });
    (payload.deleted || []).forEach(function (id) { deleted[String(id)] = true; });
    deletedMsgIds = Object.keys(deleted);

    var chain = idbSet(STORE_CRYPTO, 'deletedMsgIds', deletedMsgIds).then(function () {
      return idbGetAll(STORE_MSG_CACHE);
    }).then(function (rows) {
      var inner = Promise.resolve();
      (rows || []).forEach(function (row) {
        if (isDeletedKey(row.key)) {
          inner = inner.then(function () { return idbDelete(STORE_MSG_CACHE, String(row.key)); });
        }
      });
      return inner;
    });

    var msgIds = Object.keys(payload.msgCache || {});
    msgIds.forEach(function (id) {
      chain = chain.then(function () {
        if (isDeletedKey(id)) return null;
        return idbGet(STORE_MSG_CACHE, String(id)).then(function (existing) {
          if (existing) return null;
          return idbSet(STORE_MSG_CACHE, String(id), payload.msgCache[id]);
        });
      });
    });
    var devs = payload.devices || {};
    Object.keys(devs).forEach(function (devId) {
      Object.keys(devs[devId]).forEach(function (gid) {
        chain = chain.then(function () {
          return idbGet(STORE_MLS_HISTORY, gid).then(function (rows) {
            var list = (rows || []).filter(function (r) { return r.deviceId !== devId; });
            list.push({ deviceId: devId, bytes: devs[devId][gid] });
            return idbSet(STORE_MLS_HISTORY, gid, list);
          }).then(function () {
            delete historyStates[gid];
          });
        });
      });
    });
    return chain.then(function () {
      return { restored: true, messages: msgIds.length };
    });
  }

  function restoreFromPayload(payloadB64) {
    return decryptWithKey(backupKey, payloadB64).then(function (bytes) {
      return importBackupPayload(JSON.parse(new TextDecoder().decode(bytes)));
    });
  }

  function syncBackup() {
    if (!backupKey || !backupKeyId) return Promise.resolve(null);
    return fetchBackupBlob().then(function (row) {
      if (!row) return null;
      var parsed = null;
      try { parsed = parseBackupBlob(row.backup_data); } catch (err) { return null; }
      if (!parsed || parsed.bk_id !== backupKeyId) return null;
      return decryptWithKey(backupKey, parsed.payload).then(function (b) {
        return importBackupPayload(JSON.parse(new TextDecoder().decode(b)));
      }).catch(function () { return null; });
    }).catch(function () { return null; });
  }

  function unlockBackup(password) {
    if (!password) return Promise.resolve(null);
    return fetchBackupBlob().then(function (row) {
      var saltBytes = row && row.kek_salt ? b64ToUint8(row.kek_salt) : null;
      return deriveBackupKek(password, saltBytes).then(function (d) {
        backupKek = d.kek;
        backupKekSalt = d.salt;
        if (!row) {
          return generateBackupKey().then(function (bk) {
            backupKey = bk;
            return persistBackupKey();
          }).then(function () {
            return backupNow();
          }).then(function () { return { created: true }; });
        }
        var parsed = parseBackupBlob(row.backup_data);
        return unwrapBackupKey(parsed.wrappedBk).then(function (bk) {
          backupKey = bk;
          return persistBackupKey();
        }).then(function () {
          return restoreFromPayload(parsed.payload);
        });
      });
    });
  }

  function notePasswordForBackup(password) {
    try {
      root.sessionStorage.setItem(BACKUP_SESSION_KEY, JSON.stringify({ pw: password, ts: Date.now() }));
    } catch (err) {}
  }

  function resumeBackupUnlock() {
    var stashed = null;
    try {
      var raw = root.sessionStorage.getItem(BACKUP_SESSION_KEY);
      if (raw) root.sessionStorage.removeItem(BACKUP_SESSION_KEY);
      if (raw) {
        var parsed = JSON.parse(raw);
        if (parsed && parsed.pw && Date.now() - parsed.ts < 300000) stashed = parsed.pw;
      }
    } catch (err) {}
    if (!stashed) return Promise.resolve(null);
    return unlockBackup(stashed).catch(function () { return null; });
  }

  function bindBackupForms() {
    if (typeof document === 'undefined' || !document.querySelectorAll) return;
    var forms = document.querySelectorAll('form[action="/login"], form[action^="/register"]');
    Array.prototype.forEach.call(forms, function (form) {
      form.addEventListener('submit', function () {
        var input = form.querySelector('input[type="password"][name="password"]');
        if (input && input.value) notePasswordForBackup(input.value);
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
    unlockBackup: unlockBackup,
    backupNow: backupNow,
    syncBackup: syncBackup,
    noteMessageDeleted: noteMessageDeleted,
    getDeviceId: function () { return deviceId; },
    ready: function () { return !!(ciphersuiteImpl && deviceId); },
  };

  // Auto-init on page load if user is logged in
  if (typeof document !== 'undefined') {
    var kickOff = function () {
      bindBackupForms();
      if (currentUserId()) {
        initDevice().catch(function (err) {
          console.warn('MLS auto-init background warning:', err);
        });
      }
    };
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', kickOff);
    } else {
      kickOff();
    }
  }

})(typeof window !== 'undefined' ? window : global);
