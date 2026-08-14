(function () {
  'use strict';

  // === Olm (Matrix double-ratchet) E2EE for DMs ===
  //
  // Security model:
  //  - Each account has an Olm identity (Curve25519 + Ed25519) + one-time prekeys
  //    + a fallback key. Only PUBLIC material touches the server.
  //  - Each conversation has a Double-Ratchet Olm session (forward secrecy +
  //    post-compromise security). A self-session lets the sender read their own
  //    sent copies.
  //  - Seamless: on the same browser, a non-extractable device key (Kd) in IndexedDB
  //    decrypts the pickled Olm account — no password prompt.
  //  - Recovery: the account pickle is also stored on the server encrypted with a
  //    PBKDF2 key from the login password. New browser → enter password once.
  //  - Legacy: RSA-OAEP messages (proto='rsa') remain decryptable via the legacy
  //    path; new messages use Olm (proto='olm').

  var DB_NAME = 'extrovert-e2ee';
  var STORE_CRYPTO = 'cryptokeys';
  var STORE_OLM = 'olm';
  var STORE_SECURE = 'securemsgs';
  var KEY_DEVICE = 'deviceKey';
  var PICKLE_KEY = 'extrovert-olm-pickle-v1';

  var KEK_SESSION_KEY = 'extrovert_kek';
  var KEY_URL = '/chats/keys';
  var PREKEYS_URL = '/chats/prekeys';
  var PREKEYS_COUNT_URL = '/chats/prekeys/count';
  var PREKEYS_BACKUP_URL = '/chats/prekeys/backup';
  var REKEY_REQUEST_URL = '/chats/rekey/request';
  var REKEY_NEEDED_URL = '/chats/rekey/needed';
  var REKEY_ACK_URL = '/chats/rekey/ack';
  var PREKEY_THRESHOLD = 3;

  // Native clients (Tauri app) configure the crypto bridge before this script
  // loads: { apiBase, bearerToken, olmWasmUrl }. In the web app this is
  // undefined and everything behaves exactly as before (same-origin + CSRF).
  var NATIVE_CFG = window.ExtrovertE2EEConfig || null;

  // How often to poll for a peer's ratchet-reset request while an outbound
  // session is being reused (kept separate from the slower identity check).
  var REKEY_CHECK_MS = (NATIVE_CFG && NATIVE_CFG.rekeyCheckMs) || 15000;
  var rekeyLastCheck = {};
  var rekeyRequestedAt = {};

  // Runtime state
  var olmInitPromise = null;
  var deviceKey = null;        // non-extractable CryptoKey (Kd)
  var account = null;          // Olm.Account
  var myIdKeys = null;         // { curve25519, ed25519 }
  var sessions = {};           // otherUserId (string) -> Olm.Session (bidirectional)
  var selfOutbound = null;     // Olm.Session (to self, encrypts own copies)
  var selfInbound = null;      // Olm.Session (from self, decrypts own copies)
  // Stable baseline pickle of selfInbound (its state at creation). We always
  // persist THIS, never the advanced state — otherwise the ratchet moves past
  // history and old sent messages become undecryptable after a reload.
  var selfInboundBaseline = null;
  var kek = null;              // transient password-derived key (recovery only)
  var legacyPrivateKey = null; // RSA key for decrypting old proto='rsa' messages

  // ---- base64 / text ----
  function b64ToUint8(b64) {
    var bytes = atob(b64);
    var arr = new Uint8Array(bytes.length);
    for (var i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
    return arr;
  }
  function uint8ToB64(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
  }
  function enc(str) { return new TextEncoder().encode(str); }
  function dec(buf) { return new TextDecoder().decode(buf); }

  // ---- Storage ----
  // The web app keeps crypto state in IndexedDB (non-extractable device key,
  // one silent unlock per browser). Native clients opt into a file-backed
  // store (window.ExtrovertE2EEStorage bridges to Rust fs) because Android
  // WebView IndexedDB is not reliably persisted across app restarts — without
  // it every app start would re-prompt for the password.
  var USE_FILE_STORE = !!(NATIVE_CFG && NATIVE_CFG.fileStore);

  function fileGet(storageKey) {
    var s = window.ExtrovertE2EEStorage;
    if (!s || !s.get) return Promise.resolve(null);
    return Promise.resolve(s.get(storageKey));
  }
  function fileSet(storageKey, value) {
    var s = window.ExtrovertE2EEStorage;
    if (!s || !s.set) return Promise.reject(new Error('file storage bridge missing'));
    return Promise.resolve(s.set(storageKey, value));
  }
  function fileDelete(storageKey) {
    var s = window.ExtrovertE2EEStorage;
    if (!s || !s.delete) return Promise.resolve(null);
    return Promise.resolve(s.delete(storageKey));
  }

  function openDB() {
    var req = indexedDB.open(DB_NAME, 2);
    return new Promise(function (resolve, reject) {
      req.onupgradeneeded = function () {
        var db = req.result;
        if (!db.objectStoreNames.contains(STORE_CRYPTO)) db.createObjectStore(STORE_CRYPTO);
        if (!db.objectStoreNames.contains(STORE_OLM)) db.createObjectStore(STORE_OLM);
        if (!db.objectStoreNames.contains(STORE_SECURE)) db.createObjectStore(STORE_SECURE);
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }
  function idbGet(storeName, key) {
    if (USE_FILE_STORE) return fileGet(storeName + ':' + key);
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(storeName, 'readonly');
        var req = tx.objectStore(storeName).get(key);
        req.onsuccess = function () { resolve(req.result); };
        req.onerror = function () { reject(req.error); };
      });
    });
  }
  function idbSet(storeName, key, value) {
    if (USE_FILE_STORE) return fileSet(storeName + ':' + key, value);
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(storeName, 'readwrite');
        tx.objectStore(storeName).put(value, key);
        tx.oncomplete = function () { resolve(); };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  }
  function idbDelete(storeName, key) {
    if (USE_FILE_STORE) return fileDelete(storeName + ':' + key);
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(storeName, 'readwrite');
        tx.objectStore(storeName).delete(key);
        tx.oncomplete = function () { resolve(); };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  }

  // ---- Per-account crypto scope ----
  // All crypto state (account pickle, sessions, self-session pair) is
  // namespaced by the ACTIVE account so the multi-account feature keeps every
  // signed-in account's keys and sessions independent. The device key (Kd)
  // stays shared: it is the browser's own secret that wraps every pickle.
  function activeUserId() {
    var meta = document.querySelector('meta[name="current-user-id"]');
    if (meta && meta.getAttribute('content')) return String(meta.getAttribute('content'));
    var form = document.querySelector('.chat-form');
    return form ? String(form.getAttribute('data-current-user') || '') : '';
  }
  function acctKey() { return 'account:' + activeUserId(); }
  function selfOutKey() { return 'selfOutbound:' + activeUserId(); }
  function selfInKey() { return 'selfInbound:' + activeUserId(); }
  function sessionKey(idStr) { return 'session:' + activeUserId() + ':' + idStr; }
  function sessionBaseKey(idStr) { return 'sessionBase:' + activeUserId() + ':' + idStr; }
  function sessionIdentKey(idStr) { return 'sessionIdent:' + activeUserId() + ':' + idStr; }
  function groupOutKey(roomId) { return 'groupOut:' + activeUserId() + ':' + roomId; }
  function groupInKey(key) { return 'groupIn:' + activeUserId() + ':' + key; }

  // One-time migration: crypto state from before per-account scoping lived
  // under unnamespaced keys ('account', 'session:<peer>', ...). Move it under
  // the active account's namespace — but only if the legacy account actually
  // IS the active account (its identity matches the server identity), so a
  // second account on the same browser never inherits someone else's keys.
  function migrateLegacyCrypto() {
    if (USE_FILE_STORE) return Promise.resolve();
    var uid = activeUserId();
    if (!uid) return Promise.resolve();
    function has(storeName, key) {
      return openDB().then(function (db) {
        return new Promise(function (resolve, reject) {
          var req = db.transaction(storeName, 'readonly').objectStore(storeName).get(key);
          req.onsuccess = function () { resolve(req.result !== undefined); };
          req.onerror = function () { reject(req.error); };
        });
      });
    }
    function remap(storeName, mapFn) {
      return openDB().then(function (db) {
        return new Promise(function (resolve, reject) {
          var tx = db.transaction(storeName, 'readwrite');
          var store = tx.objectStore(storeName);
          var req = store.openCursor();
          req.onsuccess = function () {
            var cursor = req.result;
            if (!cursor) return;
            var k = String(cursor.key);
            var nk = mapFn(k);
            if (nk && nk !== k) {
              var getReq = store.get(nk);
              getReq.onsuccess = function () {
                if (getReq.result === undefined) store.put(cursor.value, nk);
                store.delete(k);
              };
            }
            cursor.continue();
          };
          tx.oncomplete = function () { resolve(); };
          tx.onerror = function () { reject(tx.error); };
        });
      });
    }
    return has(STORE_OLM, 'account').then(function (legacy) {
      if (!legacy) return;
      return has(STORE_OLM, acctKey()).then(function (scoped) {
        if (scoped) return;
        // Verify the legacy account belongs to the active account before
        // moving it: compare its identity against the published server one.
        return idbGet(STORE_OLM, 'account').then(function (enc) {
          return decryptWithKd(enc).then(function (pickle) {
            var probe = new Olm.Account();
            probe.unpickle(PICKLE_KEY, pickle);
            return JSON.parse(probe.identity_keys()).curve25519;
          }).catch(function () { return null; });
        }).then(function (legacyCurve) {
          return csrfFetch('/chats/prekeys/identity').then(function (r) { return r.json(); }).then(function (d) {
            var serverCurve = d && d.identity_key ? d.identity_key : null;
            if (serverCurve && legacyCurve && serverCurve !== legacyCurve) return; // belongs to another account
            var scopedUid = uid;
            return remap(STORE_OLM, function (k) {
              if (k === 'account') return 'account:' + scopedUid;
              if (k === 'selfOutbound') return 'selfOutbound:' + scopedUid;
              if (k === 'selfInbound') return 'selfInbound:' + scopedUid;
              if (k.indexOf('session:' + scopedUid + ':') === 0) return null;
              if (k.indexOf('session:') === 0) return 'session:' + scopedUid + ':' + k.slice('session:'.length);
              if (k.indexOf('sessionBase:' + scopedUid + ':') === 0) return null;
              if (k.indexOf('sessionBase:') === 0) return 'sessionBase:' + scopedUid + ':' + k.slice('sessionBase:'.length);
              if (k.indexOf('sessionIdent:' + scopedUid + ':') === 0) return null;
              if (k.indexOf('sessionIdent:') === 0) return 'sessionIdent:' + scopedUid + ':' + k.slice('sessionIdent:'.length);
              if (k.indexOf('groupOut:' + scopedUid + ':') === 0) return null;
              if (k.indexOf('groupOut:') === 0) return 'groupOut:' + scopedUid + ':' + k.slice('groupOut:'.length);
              if (k.indexOf('groupIn:' + scopedUid + ':') === 0) return null;
              if (k.indexOf('groupIn:') === 0) return 'groupIn:' + scopedUid + ':' + k.slice('groupIn:'.length);
              return null;
            }).then(function () {
              return remap(STORE_SECURE, function (k) {
                if (k.indexOf('conv:' + scopedUid + ':') === 0) return null;
                if (k.indexOf('conv:') === 0) return 'conv:' + scopedUid + ':' + k.slice('conv:'.length);
                return null;
              });
            });
          });
        });
      });
    }).catch(function () {});
  }

  // ---- PBKDF2 from password (legacy RSA unlock + server backup) ----
  function deriveKek(password, username) {
    var e = new TextEncoder();
    return crypto.subtle.importKey('raw', e.encode(password), 'PBKDF2', false, ['deriveKey']).then(function (k) {
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: e.encode(username.toLowerCase()), iterations: 600000, hash: 'SHA-256' },
        k, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
      );
    });
  }

  // ---- Non-extractable device key Kd ----
  function getOrCreateDeviceKey() {
    return idbGet(STORE_CRYPTO, KEY_DEVICE).then(function (existing) {
      if (existing) {
        if (typeof existing === 'string') {
          // File-backed store: the key was persisted as raw exported bytes.
          return crypto.subtle.importKey('raw', b64ToUint8(existing), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']).then(function (k) {
            deviceKey = k;
            return k;
          });
        }
        deviceKey = existing;
        return deviceKey;
      }
      return crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 }, !!USE_FILE_STORE, ['encrypt', 'decrypt']
      ).then(function (key) {
        deviceKey = key;
        if (USE_FILE_STORE) {
          return crypto.subtle.exportKey('raw', key).then(function (raw) {
            return uint8ToB64(new Uint8Array(raw));
          }).then(function (b64) {
            return idbSet(STORE_CRYPTO, KEY_DEVICE, b64).then(function () { return key; });
          });
        }
        return idbSet(STORE_CRYPTO, KEY_DEVICE, key).then(function () { return key; });
      });
    });
  }

  function encryptWithKd(plaintext) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, deviceKey, enc(plaintext)).then(function (ct) {
      var c = new Uint8Array(iv.length + ct.byteLength);
      c.set(iv); c.set(new Uint8Array(ct), iv.length);
      return uint8ToB64(c);
    });
  }
  function decryptWithKd(b64) {
    var c = b64ToUint8(b64);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: c.slice(0, 12) }, deviceKey, c.slice(12)).then(dec);
  }
  function encryptWithKek(plaintext, key) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc(plaintext)).then(function (ct) {
      var c = new Uint8Array(iv.length + ct.byteLength);
      c.set(iv); c.set(new Uint8Array(ct), iv.length);
      return uint8ToB64(c);
    });
  }
  function decryptWithKek(b64, key) {
    var c = b64ToUint8(b64);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: c.slice(0, 12) }, key, c.slice(12)).then(dec);
  }

  // ---- Olm ----
  function initOlm() {
    if (olmInitPromise) return olmInitPromise;
    var wasmUrl = (NATIVE_CFG && NATIVE_CFG.olmWasmUrl) || '/static/lib/olm.wasm?v=1';
    olmInitPromise = Olm.init({ locateFile: function () { return wasmUrl; } });
    return olmInitPromise;
  }

  function loadAccountFromStorage() {
    return idbGet(STORE_OLM, acctKey()).then(function (enc) {
      if (!enc) return null;
      return decryptWithKd(enc).then(function (pickle) {
        account = new Olm.Account();
        account.unpickle(PICKLE_KEY, pickle);
        var k = JSON.parse(account.identity_keys());
        myIdKeys = { curve25519: k.curve25519, ed25519: k.ed25519 };
        return account;
      });
    });
  }

  function saveAccount() {
    return encryptWithKd(account.pickle(PICKLE_KEY)).then(function (enc) {
      return idbSet(STORE_OLM, acctKey(), enc);
    });
  }

  function loadSession(idStr) {
    return idbGet(STORE_OLM, sessionKey(idStr)).then(function (enc) {
      if (!enc) return null;
      return decryptWithKd(enc).then(function (pickle) {
        var s = new Olm.Session();
        s.unpickle(PICKLE_KEY, pickle);
        sessions[idStr] = s;
        return s;
      });
    });
  }

  function saveSession(idStr, session) {
    sessions[idStr] = session;
    return encryptWithKd(session.pickle(PICKLE_KEY)).then(function (enc) {
      return idbSet(STORE_OLM, sessionKey(idStr), enc);
    });
  }

  // --- Session baselines ---
  // The persisted per-conversation session advances its receiving chain as it
  // decrypts, so after a send + reload it can no longer re-decrypt history. We
  // also persist a BASELINE copy (state at creation) and use it to decrypt stored
  // messages; the live session stays for sending + live incoming messages.
  var sessionBaselinePickles = {}; // idStr -> string (pickle)
  var sessionBaselines = {};        // idStr -> Olm.Session (recreated from baseline)

  function saveSessionBaseline(idStr, session) {
    var pickle = session.pickle(PICKLE_KEY);
    sessionBaselinePickles[idStr] = pickle;
    var fresh = new Olm.Session();
    fresh.unpickle(PICKLE_KEY, pickle);
    sessionBaselines[idStr] = fresh;
    return encryptWithKd(pickle).then(function (enc) {
      return idbSet(STORE_OLM, sessionBaseKey(idStr), enc);
    });
  }

  function loadSessionBaseline(idStr) {
    if (sessionBaselines[idStr]) return Promise.resolve(sessionBaselines[idStr]);
    if (sessionBaselinePickles[idStr]) {
      var fresh = new Olm.Session();
      fresh.unpickle(PICKLE_KEY, sessionBaselinePickles[idStr]);
      sessionBaselines[idStr] = fresh;
      return Promise.resolve(fresh);
    }
    return idbGet(STORE_OLM, sessionBaseKey(idStr)).then(function (enc) {
      if (!enc) return null;
      return decryptWithKd(enc).then(function (pickle) {
        sessionBaselinePickles[idStr] = pickle;
        var s = new Olm.Session();
        s.unpickle(PICKLE_KEY, pickle);
        sessionBaselines[idStr] = s;
        return s;
      });
    });
  }

  function resetSessionBaseline(idStr) {
    if (sessionBaselinePickles[idStr]) {
      try {
        var s = new Olm.Session();
        s.unpickle(PICKLE_KEY, sessionBaselinePickles[idStr]);
        sessionBaselines[idStr] = s;
      } catch (_) {}
    }
  }

  function resetSelfInboundBaseline() {
    if (selfInboundBaseline) {
      try {
        var s = new Olm.Session();
        s.unpickle(PICKLE_KEY, selfInboundBaseline);
        selfInbound = s;
      } catch (_) {}
    }
  }

  function loadSelfSessions() {
    function loadOne(storeKey) {
      return idbGet(STORE_OLM, storeKey).then(function (enc) {
        if (!enc) return null;
        return decryptWithKd(enc).then(function (pickle) {
          var s = new Olm.Session();
          s.unpickle(PICKLE_KEY, pickle);
          return s;
        });
      });
    }
    return Promise.all([
      selfOutbound ? Promise.resolve(selfOutbound) : loadOne(selfOutKey()).then(function (s) { selfOutbound = s; }),
      selfInbound ? Promise.resolve(selfInbound) : loadOne(selfInKey()).then(function (s) {
        selfInbound = s;
        // A fresh device has no self sessions yet (they're created on first
        // send); there's nothing to restore as a baseline.
        if (s) selfInboundBaseline = s.pickle(PICKLE_KEY);
        return s;
      }),
    ]);
  }

  function saveSelfSessions() {
    var ops = [];
    if (selfOutbound) ops.push(encryptWithKd(selfOutbound.pickle(PICKLE_KEY)).then(function (e) { return idbSet(STORE_OLM, selfOutKey(), e); }));
    // Persist the BASELINE inbound pickle, never the advanced in-memory state.
    var inboundPickle = selfInboundBaseline || (selfInbound ? selfInbound.pickle(PICKLE_KEY) : null);
    if (inboundPickle) ops.push(encryptWithKd(inboundPickle).then(function (e) { return idbSet(STORE_OLM, selfInKey(), e); }));
    return Promise.all(ops);
  }

  // ---- Additional Security: device-local message store ----
  // When a conversation has "Additional Security" enabled, secure messages are
  // deleted from the server once BOTH users have received them. Each device
  // keeps its own copy here (encrypted with the non-extractable device key Kd),
  // so history survives server-side deletion.
  function secureConvKey(otherIdStr) { return 'conv:' + activeUserId() + ':' + otherIdStr; }

  function secureLoadMessages(otherIdStr) {
    return idbGet(STORE_SECURE, secureConvKey(otherIdStr)).then(function (enc) {
      if (!enc) return [];
      return decryptWithKd(enc).then(function (json) {
        var msgs;
        try { msgs = JSON.parse(json); } catch (e) { msgs = []; }
        return Array.isArray(msgs) ? msgs : [];
      });
    });
  }

  function secureSaveMessages(otherIdStr, msgs) {
    return encryptWithKd(JSON.stringify(msgs)).then(function (enc) {
      return idbSet(STORE_SECURE, secureConvKey(otherIdStr), enc);
    });
  }

  // Serialize read-modify-write per conversation: parallel persist calls must not
  // clobber each other's merged state (each would otherwise read the same
  // pre-write snapshot and only the last write would survive).
  var secureWriteQueues = {};
  function securePersistMessage(otherIdStr, record) {
    var prev = secureWriteQueues[otherIdStr] || Promise.resolve();
    var next = prev.then(function () {
      return secureLoadMessages(otherIdStr).then(function (msgs) {
        var found = -1;
        for (var i = 0; i < msgs.length; i++) {
          if (String(msgs[i].id) === String(record.id)) { found = i; break; }
        }
        if (found === -1) msgs.push(record); else msgs[found] = record;
        msgs.sort(function (a, b) {
          return (a.created_at - b.created_at) || (Number(a.id) - Number(b.id));
        });
        return secureSaveMessages(otherIdStr, msgs);
      });
    });
    // Keep the chain alive even if one persist fails (callers still see the
    // rejection and skip the ack — persist-before-ack is preserved).
    secureWriteQueues[otherIdStr] = next.catch(function () {});
    return next;
  }

  function secureDeleteMessage(otherIdStr, msgId) {
    var prev = secureWriteQueues[otherIdStr] || Promise.resolve();
    var next = prev.then(function () {
      return secureLoadMessages(otherIdStr).then(function (msgs) {
        var filtered = msgs.filter(function (m) { return String(m.id) !== String(msgId); });
        return secureSaveMessages(otherIdStr, filtered).then(function () {
          scheduleHistorySync();
        });
      });
    });
    secureWriteQueues[otherIdStr] = next.catch(function () {});
    return next;
  }

  // Tell the server we received these secure messages. It deletes them once the
  // other side has acknowledged too. Best-effort: failures are non-fatal.
  function ackSecureMessages(otherUsername, ids) {
    ids = (ids || []).filter(Boolean);
    if (!ids.length || !otherUsername) return Promise.resolve();
    return csrfFetch('/chats/' + encodeURIComponent(otherUsername) + '/received', {
      method: 'POST',
      body: JSON.stringify({ message_ids: ids }),
    }).catch(function () {});
  }

  // ---- Device ID Management ----
  var myDeviceId = null;
  function getOrCreateDeviceId() {
    if (myDeviceId) return Promise.resolve(myDeviceId);
    var key = 'deviceId:' + activeUserId();
    return idbGet(STORE_CRYPTO, key).then(function (existing) {
      if (existing) {
        myDeviceId = String(existing);
        return myDeviceId;
      }
      var arr = new Uint8Array(12);
      crypto.getRandomValues(arr);
      var hex = '';
      for (var i = 0; i < arr.length; i++) {
        var h = arr[i].toString(16);
        hex += (h.length === 1 ? '0' : '') + h;
      }
      var id = 'dev_' + hex;
      myDeviceId = id;
      return idbSet(STORE_CRYPTO, key, id).then(function () { return id; });
    });
  }

  function createOlmAccount() {
    account = new Olm.Account();
    account.create();
    var k = JSON.parse(account.identity_keys());
    myIdKeys = { curve25519: k.curve25519, ed25519: k.ed25519 };
  }

  // Publish (or refresh) the per-device identity + prekey bundle.
  function publishPrekeys(force) {
    return getOrCreateDeviceId().then(function (devId) {
      var keys = JSON.parse(account.one_time_keys());
      var otks = Object.keys(keys.curve25519).map(function (id) {
        return { id: id, public_key: keys.curve25519[id] };
      });
      var fallback = JSON.parse(account.fallback_key());
      var fbKeys = Object.keys(fallback.curve25519 || {});
      if (!fbKeys.length) {
        try {
          account.generate_fallback_key();
          fallback = JSON.parse(account.fallback_key());
          fbKeys = Object.keys(fallback.curve25519 || {});
        } catch (_) {}
      }
      var fb = fbKeys.length ? fallback.curve25519[fbKeys[0]] : undefined;
      var devName = (typeof navigator !== 'undefined' && navigator.userAgent)
        ? (navigator.userAgent.indexOf('Mobile') !== -1 ? 'Mobile Browser' : 'Desktop Browser')
        : 'Browser';
      if (NATIVE_CFG) devName = 'Extrovert Native App';

      return csrfFetch('/chats/devices/register', {
        method: 'POST',
        body: JSON.stringify({
          device_id: devId,
          identity_key: myIdKeys.curve25519,
          ed25519_key: myIdKeys.ed25519,
          fallback_key: fb,
          device_name: devName,
          one_time_keys: otks
        })
      }).then(function (r) { return r.json(); }).then(function () {
        account.mark_keys_as_published();
        return saveAccount();
      });
    });
  }

  function createAndPublishAccount(force) {
    createOlmAccount();
    account.generate_fallback_key();
    account.generate_one_time_keys(5);
    return publishPrekeys(force);
  }

  function fetchBackup() {
    return csrfFetch(PREKEYS_BACKUP_URL).then(function (r) { return r.json(); });
  }

  function uploadBackup(accountPickle) {
    if (!kek) return Promise.resolve();
    var selfOutPickle = selfOutbound ? selfOutbound.pickle(PICKLE_KEY) : null;
    var selfInPickle = selfInboundBaseline || (selfInbound ? selfInbound.pickle(PICKLE_KEY) : null);
    return Promise.all([
      encryptWithKek(accountPickle, kek),
      selfOutPickle ? encryptWithKek(selfOutPickle, kek) : Promise.resolve(null),
      selfInPickle ? encryptWithKek(selfInPickle, kek) : Promise.resolve(null),
    ]).then(function (parts) {
      var payload;
      if (parts[1] || parts[2]) {
        payload = JSON.stringify({ v: 2, account: parts[0], selfOutbound: parts[1], selfInbound: parts[2] });
      } else {
        payload = parts[0];
      }
      return csrfFetch(PREKEYS_URL, {
        method: 'POST',
        body: JSON.stringify({ backup: payload, backup_identity: myIdKeys ? myIdKeys.curve25519 : undefined })
      }).then(function (r) { return r.json(); });
    });
  }

  function unwrapBackup(enc) {
    if (String(enc).indexOf('{') !== 0) return { account: enc };
    try {
      var parsed = JSON.parse(enc);
      if (parsed && parsed.v === 2) return parsed;
    } catch (e) {}
    return { account: enc };
  }

  function restoreSelfSessionsFromBackup(data) {
    var parsed = data && data.backup ? unwrapBackup(data.backup) : null;
    if (!parsed || parsed.v !== 2) return Promise.resolve();
    var restoreIn = parsed.selfInbound ? decryptWithKek(parsed.selfInbound, kek).then(function (pickle) {
      var s = new Olm.Session();
      s.unpickle(PICKLE_KEY, pickle);
      selfInbound = s;
      selfInboundBaseline = pickle;
    }).catch(function () {}) : Promise.resolve();
    var restoreOut = parsed.selfOutbound ? decryptWithKek(parsed.selfOutbound, kek).then(function (pickle) {
      var so = new Olm.Session();
      so.unpickle(PICKLE_KEY, pickle);
      selfOutbound = so;
    }).catch(function () {}) : Promise.resolve();
    return Promise.all([restoreIn, restoreOut]);
  }

  // Sync decrypted messages to /chats/history/backup (encrypted with password KEK)
  var historySyncTimer = null;
  function scheduleHistorySync() {
    if (!kek) return;
    if (historySyncTimer) clearTimeout(historySyncTimer);
    historySyncTimer = setTimeout(function () {
      syncHistoryBackup().catch(function () {});
    }, 2000);
  }

  function syncHistoryBackup() {
    if (!kek || USE_FILE_STORE) return Promise.resolve();
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE_SECURE, 'readonly');
        var store = tx.objectStore(STORE_SECURE);
        var req = store.openCursor();
        var allData = {};
        req.onsuccess = function () {
          var cursor = req.result;
          if (!cursor) {
            resolve(allData);
            return;
          }
          allData[cursor.key] = cursor.value;
          cursor.continue();
        };
        req.onerror = function () { reject(req.error); };
      });
    }).then(function (allData) {
      var json = JSON.stringify(allData);
      return encryptWithKek(json, kek);
    }).then(function (encryptedBackup) {
      return csrfFetch('/chats/history/backup', {
        method: 'POST',
        body: JSON.stringify({ backup_data: encryptedBackup })
      }).then(function (r) { return r.json(); });
    }).catch(function () {});
  }

  function restoreHistoryFromBackup() {
    if (!kek || USE_FILE_STORE) return Promise.resolve();
    return csrfFetch('/chats/history/backup').then(function (r) { return r.json(); }).then(function (d) {
      if (!d || !d.backup_data) return;
      return decryptWithKek(d.backup_data, kek).then(function (json) {
        var allData;
        try { allData = JSON.parse(json); } catch (_) { return; }
        if (!allData || typeof allData !== 'object') return;
        return openDB().then(function (db) {
          var tx = db.transaction(STORE_SECURE, 'readwrite');
          var store = tx.objectStore(STORE_SECURE);
          Object.keys(allData).forEach(function (k) {
            store.put(allData[k], k);
          });
          return new Promise(function (resolve) {
            tx.oncomplete = resolve;
            tx.onerror = resolve;
          });
        });
      });
    }).catch(function () {});
  }

  function maybeReplenishPrekeys() {
    return getOrCreateDeviceId().then(function (devId) {
      return csrfFetch(PREKEYS_COUNT_URL + '?device_id=' + encodeURIComponent(devId)).then(function (r) { return r.json(); }).then(function (data) {
        if (!data.available || data.available < PREKEY_THRESHOLD) {
          account.generate_one_time_keys(5);
          return publishPrekeys();
        }
      }).catch(function () {});
    });
  }

  function fetchBundle(otherUsername) {
    return e2eeFetch('/chats/' + encodeURIComponent(otherUsername) + '/bundle').then(function (r) { return r.json(); });
  }

  var OUTBOUND_SESSION_CHECK_MS = (NATIVE_CFG && NATIVE_CFG.sessionCheckMs) || 5 * 60 * 1000;
  var sessionIdentLastCheck = {};

  function getOrCreateDeviceOutboundSession(otherIdStr, deviceId, identityKey, fallbackKey, otk) {
    var fullKey = otherIdStr + ':' + deviceId;
    var freshOtkId = otk ? (otk.id || '') : '';
    // Session healing: rotate when the peer publishes a different fresh
    // one-time key (re-publish on login = implicit session reset) or when the
    // peer's IDENTITY changed (explicit key reset). Without this, a desynced
    // ratchet is reused forever and the pair can never decrypt again.
    return loadSession(fullKey).then(function (existing) {
      if (existing) {
        var checks = [];
        if (freshOtkId) {
          checks.push(idbGet(STORE_OLM, 'sessionOtk:' + fullKey).then(function (usedOtk) {
            return !!(usedOtk && String(usedOtk) !== String(freshOtkId));
          }));
        }
        if (identityKey) {
          checks.push(idbGet(STORE_OLM, sessionIdentKey(fullKey)).then(function (storedIdent) {
            return !!(storedIdent && String(storedIdent) !== String(identityKey));
          }));
        }
        if (!checks.length) return existing;
        return Promise.all(checks).then(function (flags) {
          if (flags.some(Boolean)) {
            delete sessions[fullKey];
            return Promise.all([
              idbDelete(STORE_OLM, 'session:' + fullKey),
              idbDelete(STORE_OLM, 'sessionBase:' + fullKey)
            ]).then(function () { return null; });
          }
          return existing;
        });
      }
      return null;
    }).then(function (existing) {
      if (existing) return existing;
      var theirOtk = otk ? otk.public_key : fallbackKey;
      if (!identityKey || !theirOtk) return null;
      var s = new Olm.Session();
      s.create_outbound(account, identityKey, theirOtk);
      return saveSessionBaseline(fullKey, s).then(function () {
        return saveSession(fullKey, s);
      }).then(function () {
        return idbSet(STORE_OLM, 'sessionOtk:' + fullKey, freshOtkId || 'fallback');
      }).then(function () {
        return idbSet(STORE_OLM, sessionIdentKey(fullKey), identityKey);
      }).then(function () { return s; });
    });
  }

  // Legacy single-target session getter
  function getOrCreateOutboundSession(otherId, otherIdStr, otherUsername) {
    if (sessions[otherIdStr]) {
      return Promise.resolve(sessions[otherIdStr]);
    }
    return loadSession(otherIdStr).then(function (existing) {
      if (existing) return existing;
      return createOutboundSession(otherId, otherIdStr, otherUsername);
    });
  }

  function createOutboundSession(otherId, otherIdStr, otherUsername) {
    return fetchBundle(otherUsername).then(function (bundle) {
      var recipientDevices = bundle.devices || [];
      var dev = recipientDevices[0] || null;
      var idKey = dev ? dev.identity_key : bundle.identity_key;
      var otk = dev ? (dev.one_time_key ? dev.one_time_key.public_key : dev.fallback_key) : (bundle.one_time_key ? bundle.one_time_key.public_key : bundle.fallback_key);
      if (!idKey || !otk) {
        throw new Error('Recipient has no encryption keys yet.');
      }
      var s = new Olm.Session();
      s.create_outbound(account, idKey, otk);
      return saveSessionBaseline(otherIdStr, s).then(function () {
        return saveSession(otherIdStr, s);
      }).then(function () {
        return idbSet(STORE_OLM, sessionIdentKey(otherIdStr), idKey);
      }).then(function () { return s; });
    });
  }

  // Self-session: lets the sender encrypt/decrypt their own sent copies.
  function ensureSelfSessions() {
    if (selfOutbound) return Promise.resolve();
    return loadSelfSessions().then(function () {
      if (selfOutbound) return;
      account.generate_one_time_keys(1);
      var keys = JSON.parse(account.one_time_keys());
      var otkIds = Object.keys(keys.curve25519);
      if (!otkIds.length) throw new Error('Could not generate self prekey.');
      selfOutbound = new Olm.Session();
      selfOutbound.create_outbound(account, myIdKeys.curve25519, keys.curve25519[otkIds[0]]);
      var initMsg = selfOutbound.encrypt('__e2ee_self_init__');
      selfInbound = new Olm.Session();
      selfInbound.create_inbound(account, initMsg.body);
      account.remove_one_time_keys(selfInbound);
      selfInboundBaseline = selfInbound.pickle(PICKLE_KEY);
      return saveSelfSessions().then(function () { return saveAccount(); }).then(function () {
        return uploadBackup(account.pickle(PICKLE_KEY));
      });
    });
  }

  // Multi-device fan-out DM encryption
  function encryptOlm(plaintext, otherId, otherIdStr, otherUsername) {
    return getOrCreateDeviceId().then(function (myDevId) {
      return fetchBundle(otherUsername).then(function (bundle) {
        var recipientDevices = bundle.devices || [];
        var senderDevices = bundle.sender_devices || [];
        if (!recipientDevices.length && bundle.identity_key) {
          recipientDevices = [{
            device_id: 'default',
            identity_key: bundle.identity_key,
            ed25519_key: bundle.ed25519_key,
            one_time_key: bundle.one_time_key,
            fallback_key: bundle.fallback_key,
          }];
        }
        if (!recipientDevices.length) {
          throw new Error('Recipient has no encryption keys yet.');
        }

        var deviceCiphertexts = {};
        var ops = [];

        // Encrypt for each active recipient device
        recipientDevices.forEach(function (dev) {
          var p = getOrCreateDeviceOutboundSession(
            otherIdStr, dev.device_id, dev.identity_key, dev.fallback_key, dev.one_time_key
          ).then(function (sess) {
            if (!sess) return;
            var enc = sess.encrypt(plaintext);
            deviceCiphertexts[dev.device_id] = { t: enc.type, b: enc.body };
            return saveSession(otherIdStr + ':' + dev.device_id, sess);
          }).catch(function (err) {
            console.warn('e2ee: error encrypting for recipient device', dev.device_id, err);
          });
          ops.push(p);
        });

        // Encrypt for sender's other devices
        senderDevices.forEach(function (dev) {
          if (dev.device_id === myDevId) return;
          var p = getOrCreateDeviceOutboundSession(
            activeUserId(), dev.device_id, dev.identity_key, dev.fallback_key, dev.one_time_key
          ).then(function (sess) {
            if (!sess) return;
            var enc = sess.encrypt(plaintext);
            deviceCiphertexts[dev.device_id] = { t: enc.type, b: enc.body };
            return saveSession(activeUserId() + ':' + dev.device_id, sess);
          }).catch(function (err) {
            console.warn('e2ee: error encrypting for sender device', dev.device_id, err);
          });
          ops.push(p);
        });

        // Self-session encryption for local history and backwards compatibility
        var selfOp = ensureSelfSessions().then(function () {
          var selfEnc = selfOutbound.encrypt(plaintext);
          return saveSelfSessions().then(function () {
            return { t: selfEnc.type, b: selfEnc.body };
          });
        });

        return Promise.all([Promise.all(ops), selfOp]).then(function (results) {
          var selfEncRes = results[1];
          var primaryKey = (recipientDevices[0] && recipientDevices[0].device_id) || 'default';
          var primaryCipher = deviceCiphertexts[primaryKey] || { t: 1, b: '' };

          var envelope = {
            v: 2,
            sender_device_id: myDevId,
            devices: deviceCiphertexts,
            t: primaryCipher.t,
            b: primaryCipher.b,
          };
          scheduleHistorySync();
          return {
            recipientCipher: JSON.stringify(envelope),
            senderCipher: JSON.stringify(selfEncRes),
          };
        });
      });
    });
  }

  // Multi-device DM Decryption
  function decryptSelfFallback(msg) {
    var rawSelf = msg.sender_ciphertext || msg.body;
    if (!rawSelf) return Promise.resolve('');
    try {
      var env2 = typeof rawSelf === 'string' ? JSON.parse(rawSelf) : rawSelf;
      if (!env2 || env2.t === undefined || !env2.b) {
        return Promise.resolve(typeof msg.body === 'string' ? msg.body : '');
      }
      return loadSelfSessions().then(function () {
        if (!selfInbound) return typeof msg.body === 'string' ? msg.body : '';
        try {
          var p = selfInbound.decrypt(env2.t, env2.b);
          return p || '';
        } catch (err) {
          if (selfInboundBaseline) {
            resetSelfInboundBaseline();
            try {
              var p2 = selfInbound.decrypt(env2.t, env2.b);
              return p2 || '';
            } catch (_) {}
          }
          return '[Unable to decrypt — encrypted for previous session]';
        }
      });
    } catch (_) {
      return Promise.resolve(typeof msg.body === 'string' ? msg.body : '');
    }
  }

  function decryptOlm(msg, isOwn, otherIdStr, theirCurve25519) {
    if (isOwn) {
      return getOrCreateDeviceId().then(function (myDevId) {
        var raw = msg.body;
        if (raw) {
          try {
            var env = typeof raw === 'string' ? JSON.parse(raw) : raw;
            if (env && env.v === 2 && env.devices && env.devices[myDevId]) {
              var targetCipher = env.devices[myDevId];
              var senderDevId = env.sender_device_id || 'default';
              var devKey = activeUserId() + ':' + senderDevId;
              return loadSession(devKey).then(function (live) {
                if (!live) return loadSession(activeUserId());
                return live;
              }).then(function (live) {
                if (live) {
                  try {
                    var p = live.decrypt(targetCipher.t, targetCipher.b);
                    if (p) {
                      return saveSession(devKey, live).then(function () { return p; });
                    }
                  } catch (_) {}
                }
                return loadSessionBaseline(devKey).then(function (base) {
                  if (base) {
                    try {
                      var pBase = base.decrypt(targetCipher.t, targetCipher.b);
                      if (pBase) return pBase;
                    } catch (_) {}
                  }
                  if (targetCipher.t === 0 || targetCipher.t === 2) {
                    var s = new Olm.Session();
                    try {
                      s.create_inbound(account, targetCipher.b);
                      account.remove_one_time_keys(s);
                      var pNew = s.decrypt(targetCipher.t, targetCipher.b);
                      return saveSession(devKey, s).then(function () { return saveAccount(); }).then(function () { return pNew; });
                    } catch (_) {}
                  }
                  return decryptSelfFallback(msg);
                });
              });
            }
          } catch (_) {}
        }
        return decryptSelfFallback(msg);
      });
    }

    return getOrCreateDeviceId().then(function (myDevId) {
      var e = typeof msg.body === 'string' ? JSON.parse(msg.body) : msg.body;
      var cipherToDecrypt = e;
      var senderDeviceId = 'default';

      if (e && e.v === 2 && e.devices) {
        senderDeviceId = e.sender_device_id || 'default';
        if (e.devices[myDevId]) {
          cipherToDecrypt = e.devices[myDevId];
        } else if (e.t !== undefined && e.b) {
          cipherToDecrypt = { t: e.t, b: e.b };
        } else {
          var devKeys = Object.keys(e.devices);
          if (devKeys.length) cipherToDecrypt = e.devices[devKeys[0]];
        }
      }

      var sessionKeyToUse = otherIdStr + ':' + senderDeviceId;

      return loadSession(sessionKeyToUse).then(function (live) {
        if (!live) return loadSession(otherIdStr);
        return live;
      }).then(function (live) {
        if (live) {
          var livePickle = live.pickle(PICKLE_KEY);
          try {
            var plain = live.decrypt(cipherToDecrypt.t, cipherToDecrypt.b);
            scheduleHistorySync();
            return saveSession(sessionKeyToUse, live).then(function () { return plain; });
          } catch (_) {
            try {
              var restored = new Olm.Session();
              restored.unpickle(PICKLE_KEY, livePickle);
              sessions[sessionKeyToUse] = restored;
            } catch (_) {}
          }
        }
        return loadSessionBaseline(sessionKeyToUse).then(function (base) {
          if (!base) return loadSessionBaseline(otherIdStr);
          return base;
        }).then(function (base) {
          if (base) {
            try {
              var plain2 = base.decrypt(cipherToDecrypt.t, cipherToDecrypt.b);
              scheduleHistorySync();
              return (live
                ? Promise.resolve(plain2)
                : saveSession(sessionKeyToUse, base).then(function () { return plain2; })
              );
            } catch (_) {}
          }
          if (cipherToDecrypt.t === 0 || cipherToDecrypt.t === 2) {
            var ns = new Olm.Session();
            try {
              ns.create_inbound(account, cipherToDecrypt.b);
              account.remove_one_time_keys(ns);
              var identWrite = theirCurve25519
                ? idbSet(STORE_OLM, sessionIdentKey(sessionKeyToUse), theirCurve25519)
                : Promise.resolve();
              return identWrite.then(function () {
                return saveSessionBaseline(sessionKeyToUse, ns);
              }).then(function () {
                return ns.decrypt(cipherToDecrypt.t, cipherToDecrypt.b);
              }).then(function (plain3) {
                scheduleHistorySync();
                return saveSession(sessionKeyToUse, ns).then(function () { return plain3; });
              }).then(function (plain3) {
                return saveAccount().then(function () { return plain3; });
              });
            } catch (createErr) {
              if (base) {
                try {
                  var pBase = base.decrypt(cipherToDecrypt.t, cipherToDecrypt.b);
                  scheduleHistorySync();
                  return (live
                    ? Promise.resolve(pBase)
                    : saveSession(sessionKeyToUse, base).then(function () { return pBase; })
                  );
                } catch (_) {}
              }
              requestRekeyFrom(otherIdStr);
              throw createErr;
            }
          }
          requestRekeyFrom(otherIdStr);
          throw new Error('No session for sender and message could not be decrypted.');
        });
      });
    });
  }

  // ---- Legacy RSA decrypt (old proto='rsa' messages only) ----
  function decryptLegacyRSA(bodyB64, keyB64) {
    if (!legacyPrivateKey) return Promise.reject(new Error('No legacy key'));
    var encKey = b64ToUint8(keyB64);
    return crypto.subtle.decrypt({ name: 'RSA-OAEP' }, legacyPrivateKey, encKey)
      .then(function (rawKey) {
        return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
      }).then(function (aesKey) {
        var data = b64ToUint8(bodyB64);
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, aesKey, data.slice(12));
      }).then(dec);
  }

  // ---- fetch helpers ----
  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }
  function e2eeFetch(url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (NATIVE_CFG && NATIVE_CFG.bearerToken) {
      opts.headers['Authorization'] = 'Bearer ' + NATIVE_CFG.bearerToken;
    } else {
      opts.credentials = 'same-origin';
      opts.headers['X-CSRF-Token'] = csrfToken();
    }
    var base = (NATIVE_CFG && NATIVE_CFG.apiBase) || '';
    return fetch(base + url, opts);
  }
  function csrfFetch(url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    opts.headers['Content-Type'] = opts.headers['Content-Type'] || 'application/json';
    return e2eeFetch(url, opts);
  }

  function interceptAuthForm(selector) {
    var form = document.querySelector(selector);
    if (!form) return;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var f = e.target;
      var btn = f.querySelector('button[type="submit"]');
      var done = false;
      var submitForm = function () {
        if (done) return;
        done = true;
        if (btn) btn.disabled = false;
        f.submit();
      };
      var pass = f.querySelector('input[name="password"]');
      var user = f.querySelector('input[name="username"]');
      if (pass && user && pass.value && user.value) {
        if (btn) btn.disabled = true;
        storeKek(pass.value, user.value).then(submitForm, submitForm);
        setTimeout(submitForm, 4000);
      } else {
        submitForm();
      }
    });
  }
  function interceptLoginForm() {
    interceptAuthForm('form[action^="/login"]');
  }
  function interceptRegisterForm() {
    interceptAuthForm('form[action^="/register"]');
  }
  function storeKek(password, username) {
    return deriveKek(password, username).then(function (k) {
      return crypto.subtle.exportKey('jwk', k);
    }).then(function (jwk) {
      sessionStorage.setItem(KEK_SESSION_KEY, btoa(JSON.stringify(jwk)));
    }).catch(function () {});
  }

  function loadLegacyKey(k) {
    return csrfFetch(KEY_URL).then(function (r) { return r.json(); }).then(function (data) {
      if (data.publicKey && data.encryptedPrivateKey) {
        var combined = b64ToUint8(data.encryptedPrivateKey);
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: combined.slice(0, 12) }, k, combined.slice(12))
          .then(function (decrypted) { return crypto.subtle.importKey('pkcs8', decrypted, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']); })
          .then(function (priv) { legacyPrivateKey = priv; })
          .catch(function () {});
      }
    });
  }

  function ensureReady(opts) {
    opts = opts || {};
    return getOrCreateDeviceKey().then(function () {
      return migrateLegacyCrypto();
    }).then(function () {
      return getOrCreateDeviceId();
    }).then(function () {
      return loadAccountFromStorage();
    }).then(function (acct) {
      var storedKek = sessionStorage.getItem(KEK_SESSION_KEY);
      if (acct) {
        return loadSelfSessions().then(function () { return maybeReplenishPrekeys(); }).then(function () {
          if (storedKek) {
            importKek(storedKek).then(function (k) {
              kek = k;
              return restoreHistoryFromBackup();
            }).catch(function () {});
          }
          if (opts.onReady) opts.onReady();
          return true;
        });
      }
      if (storedKek) {
        return importKek(storedKek).then(function (k) {
          kek = k;
          return loadLegacyKey(kek);
        }).then(function () {
          return restoreHistoryFromBackup();
        }).then(function () {
          return createAndPublishAccount().then(function () { return saveAccount(); });
        }).then(function () {
          return ensureSelfSessions();
        }).then(function () {
          if (opts.onReady) opts.onReady();
          return true;
        });
      }
      return initOlm().then(function () {
        return createAndPublishAccount().then(function () { return saveAccount(); });
      }).then(function () {
        return ensureSelfSessions();
      }).then(function () {
        if (opts.onReady) opts.onReady();
        return true;
      }).catch(function (err) {
        console.error('ensureReady fallback error', err);
        return false;
      });
    });
  }

  function importKek(b64) {
    try {
      var jwk = JSON.parse(atob(b64));
      return crypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']);
    } catch (e) { return Promise.resolve(null); }
  }

  // ---- Safety number ----
  function getSafetyNumber(otherUsername) {
    return e2eeFetch('/chats/' + encodeURIComponent(otherUsername) + '/safety')
      .then(function (r) { return r.json(); }).then(function (data) {
        if (!data.my_ed25519 || !data.their_ed25519) return null;
        var sorted = [data.my_ed25519, data.their_ed25519].sort().join('');
        var util = new Olm.Utility();
        var fp = util.sha256(sorted);
        util.free();
        var digits = '';
        for (var i = 0; i < fp.length; i++) digits += String(fp.charCodeAt(i) % 10);
        return digits.slice(0, 12);
      });
  }

  function renderSafetyNumber(otherUsername) {
    var container = document.getElementById('safety-number');
    if (!container) return;
    getSafetyNumber(otherUsername).then(function (num) {
      if (num) {
        container.textContent = num;
        container.style.display = 'inline-block';
      }
    }).catch(function () {});
  }

  // ---- Megolm group sessions (rooms) ----
  // One OutboundGroupSession per room (this device's sending session) plus one
  // InboundGroupSession per (room, sender, server session id) so that session
  // rotation never breaks history decryption.
  var groupOutbound = {};  // roomId -> Olm.OutboundGroupSession
  var groupOutIds = {};    // roomId -> server session id
  var groupInbound = {};   // 'roomId:senderId:sessionId' -> Olm.InboundGroupSession

  function loadGroupOutbound(roomId) {
    if (groupOutbound[roomId]) return Promise.resolve(groupOutbound[roomId]);
    return idbGet(STORE_OLM, groupOutKey(roomId)).then(function (enc) {
      if (!enc) return null;
      return decryptWithKd(enc).then(function (json) {
        var rec = JSON.parse(json);
        var s = new Olm.OutboundGroupSession();
        s.unpickle(PICKLE_KEY, rec.pickle);
        groupOutbound[roomId] = s;
        groupOutIds[roomId] = rec.id;
        return s;
      });
    });
  }
  function saveGroupOutbound(roomId, session, sessionId) {
    groupOutbound[roomId] = session;
    groupOutIds[roomId] = sessionId;
    return encryptWithKd(JSON.stringify({ id: sessionId, pickle: session.pickle(PICKLE_KEY) })).then(function (enc) {
      return idbSet(STORE_OLM, groupOutKey(roomId), enc);
    });
  }
  function loadGroupInbound(roomId, senderId, sessionId) {
    var key = roomId + ':' + senderId + ':' + sessionId;
    if (groupInbound[key]) return Promise.resolve(groupInbound[key]);
    return idbGet(STORE_OLM, groupInKey(key)).then(function (enc) {
      if (!enc) return null;
      return decryptWithKd(enc).then(function (pickle) {
        var s = new Olm.InboundGroupSession();
        s.unpickle(PICKLE_KEY, pickle);
        groupInbound[key] = s;
        return s;
      });
    });
  }
  function saveGroupInbound(roomId, senderId, sessionId, session) {
    var key = roomId + ':' + senderId + ':' + sessionId;
    groupInbound[key] = session;
    return encryptWithKd(session.pickle(PICKLE_KEY)).then(function (enc) {
      return idbSet(STORE_OLM, groupInKey(key), enc);
    });
  }

  // A room's outbound session must also exist as an inbound session for the
  // sender, or their own sent messages can never be decrypted.
  function saveSelfGroupInbound(roomId, myId, outbound) {
    var ig = new Olm.InboundGroupSession();
    ig.create(outbound.session_key());
    return saveGroupInbound(roomId, String(myId), String(outbound.session_id()), ig);
  }

  // Room-scoped prekey bundle (no mutual-follower requirement).
  function fetchRoomBundle(roomId, username) {
    return e2eeFetch('/rooms/' + encodeURIComponent(roomId) + '/bundle/' + encodeURIComponent(username))
      .then(function (r) { return r.json(); });
  }

  // Get-or-create a 1:1 Olm session with a room member (used to wrap group keys).
  function getOrCreateRoomOutboundSession(roomId, otherId, otherUsername) {
    var otherIdStr = String(otherId);
    if (sessions[otherIdStr]) return Promise.resolve(sessions[otherIdStr]);
    return loadSession(otherIdStr).then(function (s) { return s || null; }).then(function (existing) {
      if (existing) return existing;
      return fetchRoomBundle(roomId, otherUsername).then(function (bundle) {
        if (!bundle.identity_key || (!bundle.one_time_key && !bundle.fallback_key)) {
          throw new Error('Recipient has no encryption keys.');
        }
        var theirOtk = bundle.one_time_key ? bundle.one_time_key.public_key : bundle.fallback_key;
        var s = new Olm.Session();
        s.create_outbound(account, bundle.identity_key, theirOtk);
        return saveSessionBaseline(otherIdStr, s).then(function () {
          return saveSession(otherIdStr, s);
        }).then(function () { return s; });
      });
    });
  }

  function roomSessionKeyEnvelope(roomId, session, recipientId, recipientUsername) {
    return getOrCreateRoomOutboundSession(roomId, recipientId, recipientUsername).then(function (s) {
      var msg = s.encrypt(session.session_key());
      return saveSession(String(recipientId), s).then(function () {
        return JSON.stringify({ t: msg.type, b: msg.body });
      });
    });
  }

  // Publish (or rotate) this device's outbound Megolm session and share keys to members.
  function shareRoomSession(roomId, session, members, allMemberIds, rotate) {
    var perRecipient = members.map(function (m) {
      return roomSessionKeyEnvelope(roomId, session, m.id, m.username).then(function (enc) {
        return { recipient_id: m.id, encrypted_key: enc };
      }).catch(function (err) {
        console.warn('skipping room key share to member', m.id, err.message);
        return null;
      });
    });
    return Promise.all(perRecipient).then(function (keys) {
      keys = keys.filter(Boolean);
      return csrfFetch('/rooms/' + encodeURIComponent(roomId) + '/session', {
        method: 'POST',
        body: JSON.stringify({ keys: keys, member_ids: allMemberIds, rotate: !!rotate }),
      }).then(function (r) { return r.json(); }).then(function (d) {
        if (d.error) throw new Error(d.error);
        return d.session_id;
      });
    }).then(function (sessionId) {
      return saveGroupOutbound(roomId, session, sessionId);
    });
  }

  // Fetch + import pending Megolm session keys meant for us.
  function fetchAndImportRoomKeys(roomId, myId) {
    return csrfFetch('/rooms/' + encodeURIComponent(roomId) + '/session/keys').then(function (r) { return r.json(); }).then(function (data) {
      var keys = data.keys || [];
      var deliveredIds = [];
      var ops = keys.filter(function (k) { return String(k.room_id) === String(roomId) && String(k.sender_id) !== String(myId); })
        .map(function (k) {
          return loadSession(String(k.sender_id)).then(function (live) {
            var env = JSON.parse(k.encrypted_key);
            // Same discipline as decryptOlm: live session first so ratchet
            // advances are persisted, baseline only for replaying old key
            // shares (never overwriting live), and decrypt-before-persist on
            // the fresh-session branch.
            if (live) {
              var livePickle = live.pickle(PICKLE_KEY);
              try {
                var plain = live.decrypt(env.t, env.b);
                return saveSession(String(k.sender_id), live).then(function () { return plain; });
              } catch (_) {
                // A failed decrypt must not leave the in-memory session (also
                // used for sending) half-advanced: restore last-good state.
                try {
                  var restored = new Olm.Session();
                  restored.unpickle(PICKLE_KEY, livePickle);
                  sessions[String(k.sender_id)] = restored;
                } catch (_) {}
              }
            }
            return loadSessionBaseline(String(k.sender_id)).then(function (base) {
              if (base) {
                try {
                  var plain2 = base.decrypt(env.t, env.b);
                  return (live
                    ? Promise.resolve(plain2)
                    : saveSession(String(k.sender_id), base).then(function () { return plain2; })
                  );
                } catch (_) {}
              }
              if (env.t === 0 || env.t === 2) {
                var ns = new Olm.Session();
                try {
                  ns.create_inbound(account, env.b);
                  account.remove_one_time_keys(ns);
                  return saveSessionBaseline(String(k.sender_id), ns).then(function () {
                    return ns.decrypt(env.t, env.b);
                  }).then(function (plain3) {
                    return saveSession(String(k.sender_id), ns).then(function () { return plain3; });
                  }).then(function (plain3) {
                    return saveAccount().then(function () { return plain3; });
                  });
                } catch (createErr) {
                  if (base) {
                    try {
                      var pBase = base.decrypt(env.t, env.b);
                      return (live
                        ? Promise.resolve(pBase)
                        : saveSession(String(k.sender_id), base).then(function () { return pBase; })
                      );
                    } catch (_) {}
                  }
                  throw createErr;
                }
              }
              throw new Error('No session to decrypt room key');
            });
          }).then(function (sessionKey) {
            var ig = new Olm.InboundGroupSession();
            ig.create(sessionKey);
            return saveGroupInbound(k.room_id, k.sender_id, k.session_id, ig).then(function () {
              deliveredIds.push(k.key_id);
            });
          }).catch(function (err) { console.error('room key import failed', err); });
        });
      return Promise.all(ops).then(function () {
        if (!deliveredIds.length) return;
        return csrfFetch('/rooms/' + encodeURIComponent(roomId) + '/session/keys/delivered', {
          method: 'POST',
          body: JSON.stringify({ key_ids: deliveredIds }),
        }).catch(function () {});
      });
    });
  }

  // Full room sync: import pending keys, ensure our outbound session, and share
  // to any member missing it (rotating when the membership changed so the new
  // member never sees history).
  function syncRoomSessions(roomId, myId, members) {
    var others = members.filter(function (m) { return Number(m.id) !== Number(myId); });
    var allIds = members.map(function (m) { return Number(m.id); });
    return fetchAndImportRoomKeys(roomId, myId).then(function () {
      return loadGroupOutbound(roomId);
    }).then(function (out) {
      return csrfFetch('/rooms/' + encodeURIComponent(roomId) + '/session/status').then(function (r) { return r.json(); }).then(function (status) {
        var ok = out && groupOutIds[roomId] && String(groupOutIds[roomId]) === String(status.session_id);
        if (ok) {
          var have = (status.recipients || []).map(Number);
          var empty = (status.empty_keys_for || []).map(Number);
          // Members who joined after this session was created -> rotate so they
          // can never read history.
          var joined = others.filter(function (m) { return have.indexOf(Number(m.id)) === -1; });
          if (joined.length) {
            var fresh = new Olm.OutboundGroupSession();
            fresh.create();
            return saveSelfGroupInbound(roomId, myId, fresh).then(function () {
              return shareRoomSession(roomId, fresh, others, allIds, true);
            });
          }
          // Members who are covered but never got a real key (set up E2EE late) -> re-share.
          var needKey = others.filter(function (m) { return empty.indexOf(Number(m.id)) !== -1; });
          if (needKey.length) {
            return shareRoomSession(roomId, out, needKey, allIds, false);
          }
          return;
        }
        var fresh = new Olm.OutboundGroupSession();
        fresh.create();
        return saveSelfGroupInbound(roomId, myId, fresh).then(function () {
          return shareRoomSession(roomId, fresh, others, allIds, true);
        });
      });
    });
  }

  function encryptRoomMessage(roomId, plaintext) {
    if (!groupOutbound[roomId]) {
      return Promise.reject(new Error('No room session. Try reloading the room.'));
    }
    var ct = groupOutbound[roomId].encrypt(plaintext);
    var sid = groupOutIds[roomId];
    return saveGroupOutbound(roomId, groupOutbound[roomId], sid).then(function () {
      return { ciphertext: ct, group_session_id: String(sid) };
    });
  }

  function decryptRoomMessage(roomId, senderId, ciphertext, groupSessionId) {
    return loadGroupInbound(roomId, senderId, groupSessionId).then(function (ig) {
      if (!ig) throw new Error('No inbound group session for sender');
      var result = ig.decrypt(ciphertext);
      return saveGroupInbound(roomId, senderId, groupSessionId, ig).then(function () { return result.plaintext; });
    });
  }

  // ---- Decrypt messages already rendered in the DOM ----
  function decryptExistingMessages(otherIdStr, recipientCurve, otherUsername) {
    var securePending = []; // local device copies for Additional Security conversations
    var secureAckIds = [];
    var myId = currentUserId();

    return secureLoadMessages(otherIdStr).then(function (savedMsgs) {
      var localMap = {};
      (savedMsgs || []).forEach(function (m) {
        if (m && m.id && m.plaintext !== undefined) localMap[String(m.id)] = m.plaintext;
      });

      resetSelfInboundBaseline();
      resetSessionBaseline(otherIdStr);

      var msgElements = Array.prototype.slice.call(document.querySelectorAll('.chat-msg'));
      var chain = Promise.resolve();

      msgElements.forEach(function (el) {
        chain = chain.then(function () {
          var bubble = el.querySelector('.chat-bubble');
          if (!bubble || !bubble.childNodes.length) return;
          var body = el.getAttribute('data-body') || '';
          var keySender = el.getAttribute('data-key-sender') || '';
          var keyRecipient = el.getAttribute('data-key-recipient') || '';
          var proto = el.getAttribute('data-proto') || 'rsa';
          var senderCt = el.getAttribute('data-sender-ciphertext') || '';
          var isOwn = el.classList.contains('own');
          // Gate on the message's OWN secure flag, not the current toggle state: a
          // secure=1 message must be stored/acked even if the peer later disabled
          // the mode, otherwise it would linger flagged on the server forever.
          var msgSecure = el.getAttribute('data-secure') === '1';
          var msgId = el.getAttribute('data-msg-id');
          var createdAt = Number(el.getAttribute('data-ts')) || Date.now();

          var recordFor = function (plain) {
            return {
              id: msgId,
              from_id: isOwn ? myId : otherIdStr,
              created_at: createdAt,
              edited_at: null,
              proto: proto,
              plaintext: plain,
              own: isOwn,
            };
          };
          var markSecure = function (rec) { securePending.push(rec); secureAckIds.push(rec.id); };

          // Stickers: the body IS the plaintext (no ciphertext, no key).
          if (body.indexOf('/uploads/stickers/') === 0) {
            securePersistMessage(otherIdStr, recordFor(body));
            if (msgSecure) markSecure(recordFor(body));
            return;
          }

          // Check if already in local cache
          if (localMap[String(msgId)] !== undefined) {
            bubble.textContent = localMap[String(msgId)];
            if (msgSecure) markSecure(recordFor(localMap[String(msgId)]));
            return;
          }

          if (proto === 'olm') {
            var msg = { body: body, sender_ciphertext: senderCt };
            return decryptOlm(msg, isOwn, otherIdStr, recipientCurve).then(function (plain) {
              bubble.textContent = plain;
              localMap[String(msgId)] = plain;
              securePersistMessage(otherIdStr, recordFor(plain));
              if (msgSecure) markSecure(recordFor(plain));
            }).catch(function (err) {
              console.error('DM decrypt failed', isOwn ? 'own' : 'incoming', 'msg', el.getAttribute('data-msg-id'), err && err.message);
              blobFail(bubble);
            });
          }

          var keyForDecrypt = isOwn ? keySender : keyRecipient;
          if (body && keyForDecrypt) {
            return decryptLegacyRSA(body, keyForDecrypt).then(function (plain) {
              bubble.innerHTML = '';
              bubble.appendChild(document.createTextNode(plain));
              localMap[String(msgId)] = plain;
              securePersistMessage(otherIdStr, recordFor(plain));
              if (msgSecure) markSecure(recordFor(plain));
            }).catch(function () {});
          }
        });
      });

      return chain.then(function () {
        if (!securePending.length) return;
        var writes = securePending.map(function (rec) { return securePersistMessage(otherIdStr, rec); });
        return Promise.all(writes).then(function () {
          return ackSecureMessages(otherUsername, secureAckIds);
        });
      });
    });
  }

  function blobFail(bubble) {
    if (bubble.textContent === '[unable to decrypt]') return;
    bubble.textContent = '[unable to decrypt]';
  }

  function scrollChatBottom() {
    var scroller = document.querySelector('.chat-scroll');
    if (scroller) scroller.scrollTop = scroller.scrollHeight;
  }

  function addChatMsg(container, msg) {
    var div = document.createElement('div');
    div.className = 'chat-msg own';
    var bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    var sticker = msg.body && msg.body.indexOf('/uploads/stickers/') !== -1;
    if (sticker) {
      bubble.innerHTML = '<img src="' + esc(msg.body) + '" class="sticker-inline" style="max-width:120px;max-height:120px;vertical-align:middle" alt="sticker">';
    } else {
      bubble.appendChild(document.createTextNode(msg.body));
    }
    div.appendChild(bubble);
    var time = document.createElement('div');
    time.className = 'muted';
    time.style.cssText = 'font-size:0.7rem;padding:0 4px';
    time.textContent = window.relTime ? window.relTime(msg.created_at) : new Date(msg.created_at).toLocaleString();
    div.appendChild(time);
    container.appendChild(div);
    scrollChatBottom();
  }

  // Render an outgoing encrypted message with the known plaintext (the server
  // returns ciphertext, so we must not display msg.body for olm messages).
  function addOwnMsg(plaintext, msg) {
    var container = document.querySelector('.chat-messages');
    if (!container) return;
    var otherUsername = currentOtherUsername();
    var sendForm = document.querySelector('.chat-form');
    var otherIdStr = sendForm ? String(sendForm.getAttribute('data-recipient') || '') : '';
    if (otherIdStr && plaintext) {
      securePersistMessage(otherIdStr, {
        id: msg.id,
        from_id: currentUserId(),
        created_at: msg.created_at || Date.now(),
        edited_at: msg.edited_at || null,
        proto: msg.proto || 'olm',
        plaintext: plaintext,
        own: true,
      });
    }
    var div = document.createElement('div');
    div.className = 'chat-msg own';
    div.setAttribute('data-msg-id', String(msg.id));
    div.setAttribute('data-ts', String(msg.created_at));
    div.setAttribute('data-proto', msg.proto || 'olm');
    div.setAttribute('data-body', msg.body || '');
    if (msg.key_for_sender) div.setAttribute('data-key-sender', msg.key_for_sender);
    if (msg.key_for_recipient) div.setAttribute('data-key-recipient', msg.key_for_recipient);
    if (msg.sender_ciphertext) div.setAttribute('data-sender-ciphertext', msg.sender_ciphertext);
    if (msg.secure) div.setAttribute('data-secure', String(msg.secure));

    var bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    if (plaintext && plaintext.indexOf('/uploads/stickers/') === 0) {
      bubble.innerHTML = '<img src="' + esc(plaintext) + '" class="sticker-inline" style="max-width:120px;max-height:120px;vertical-align:middle" alt="sticker">';
    } else {
      bubble.textContent = plaintext;
    }
    div.appendChild(bubble);

    var time = document.createElement('div');
    time.className = 'muted';
    time.style.cssText = 'font-size:0.7rem;padding:0 4px';
    time.textContent = window.relTime ? window.relTime(msg.created_at) : new Date(msg.created_at).toLocaleString();

    var editBtn = document.createElement('button');
    editBtn.className = 'edit-msg-btn';
    editBtn.style.cssText = 'font-size:0.7rem;color:var(--text-muted);background:none;border:none;cursor:pointer;padding:0 2px;margin-left:4px;text-decoration:underline';
    editBtn.textContent = 'Edit';
    time.appendChild(editBtn);

    var delBtn = document.createElement('button');
    delBtn.className = 'delete-msg-btn';
    delBtn.setAttribute('data-msg-id', String(msg.id));
    delBtn.setAttribute('data-csrf', csrfToken());
    delBtn.setAttribute('data-action', '/chats/' + encodeURIComponent(otherUsername) + '/delete/' + encodeURIComponent(msg.id));
    delBtn.style.cssText = 'font-size:0.7rem;color:var(--text-muted);background:none;border:none;cursor:pointer;padding:0 2px;margin-left:4px;text-decoration:underline';
    delBtn.textContent = 'Delete';
    time.appendChild(delBtn);

    div.appendChild(time);

    var dataInput = document.createElement('input');
    dataInput.type = 'hidden';
    dataInput.className = 'edit-msg-data';
    dataInput.value = msg.body || '';
    dataInput.setAttribute('data-csrf', csrfToken());
    dataInput.setAttribute('data-action', '/chats/' + encodeURIComponent(otherUsername) + '/edit/' + encodeURIComponent(msg.id));
    div.appendChild(dataInput);

    container.appendChild(div);
    scrollChatBottom();
  }

  function esc(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  // ---- Additional Security: chat page wiring ----
  function currentUserId() {
    var form = document.querySelector('.chat-form');
    return form ? form.getAttribute('data-current-user') || '' : '';
  }
  function currentOtherUsername() {
    var form = document.querySelector('.chat-form');
    return form ? form.getAttribute('data-recipient-username') || '' : '';
  }

  // Build a chat bubble DOM node from a device-local message record.
  function makeLocalMsgDiv(m, myId) {
    var isOwn = (String(m.from_id) === String(myId)) || !!m.own;
    var div = document.createElement('div');
    div.className = 'chat-msg' + (isOwn ? ' own' : '');
    div.setAttribute('data-msg-id', String(m.id));
    div.setAttribute('data-ts', String(m.created_at));
    var bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    var text = m.plaintext || '';
    if (text.indexOf('/uploads/stickers/') === 0) {
      bubble.innerHTML = '<img src="' + esc(text) + '" class="sticker-inline" style="max-width:120px;max-height:120px;vertical-align:middle" alt="sticker">';
    } else {
      bubble.textContent = text;
    }
    div.appendChild(bubble);
    var time = document.createElement('div');
    time.className = 'muted';
    time.style.cssText = 'font-size:0.7rem;padding:0 4px';
    time.textContent = window.relTime ? window.relTime(m.created_at) : new Date(m.created_at).toLocaleString();
    if (m.edited_at) {
      var ed = document.createElement('span');
      ed.className = 'edited-indicator';
      ed.title = new Date(m.edited_at).toLocaleString();
      ed.textContent = '· edited';
      time.appendChild(ed);
    }
    if (isOwn) {
      var otherUsername = currentOtherUsername();
      var editBtn = document.createElement('button');
      editBtn.className = 'edit-msg-btn';
      editBtn.style.cssText = 'font-size:0.7rem;color:var(--text-muted);background:none;border:none;cursor:pointer;padding:0 2px;margin-left:4px;text-decoration:underline';
      editBtn.textContent = 'Edit';
      time.appendChild(editBtn);

      var delBtn = document.createElement('button');
      delBtn.className = 'delete-msg-btn';
      delBtn.setAttribute('data-msg-id', String(m.id));
      delBtn.setAttribute('data-csrf', csrfToken());
      delBtn.setAttribute('data-action', '/chats/' + encodeURIComponent(otherUsername) + '/delete/' + encodeURIComponent(m.id));
      delBtn.style.cssText = 'font-size:0.7rem;color:var(--text-muted);background:none;border:none;cursor:pointer;padding:0 2px;margin-left:4px;text-decoration:underline';
      delBtn.textContent = 'Delete';
      time.appendChild(delBtn);

      var dataInput = document.createElement('input');
      dataInput.type = 'hidden';
      dataInput.className = 'edit-msg-data';
      dataInput.value = m.plaintext || '';
      dataInput.setAttribute('data-csrf', csrfToken());
      dataInput.setAttribute('data-action', '/chats/' + encodeURIComponent(otherUsername) + '/edit/' + encodeURIComponent(m.id));
      div.appendChild(dataInput);
    }
    div.appendChild(time);
    return div;
  }

  // Render messages that were already deleted from the server (both sides
  // received them) from the device-local store, merged in chronological order
  // with whatever is still pending on the server.
  function renderLocalSecureMessages(otherIdStr) {
    var container = document.querySelector('.chat-messages');
    if (!container) return Promise.resolve();
    var myId = currentUserId();
    return secureLoadMessages(otherIdStr).then(function (msgs) {
      if (!msgs || !msgs.length) return;
      var existing = {};
      container.querySelectorAll('.chat-msg').forEach(function (el) {
        var id = el.getAttribute('data-msg-id');
        if (id) existing[id] = true;
      });
      // Purge deleted non-secure messages from local cache (messages that were deleted on the server)
      var deletedNonSecure = msgs.filter(function (m) {
        return !existing[String(m.id)] && !m.msg_secure && !m.secure;
      });
      if (deletedNonSecure.length > 0) {
        deletedNonSecure.forEach(function (d) {
          secureDeleteMessage(otherIdStr, d.id);
        });
      }

      // Only ephemeral/secure=1 messages are meant to be rendered when missing from server
      var missing = msgs.filter(function (m) {
        return !existing[String(m.id)] && (m.msg_secure || m.secure);
      });
      if (!missing.length) return;
      // Static snapshot of the server-rendered nodes (insertBefore keeps the
      // NodeList stale, so compute insertion points up front).
      var originals = [];
      container.querySelectorAll('.chat-msg').forEach(function (el) {
        originals.push({
          el: el,
          ts: Number(el.getAttribute('data-ts')) || 0,
          id: Number(el.getAttribute('data-msg-id')) || 0,
        });
      });
      var before = []; // originals index -> messages to insert before it
      var append = [];
      missing.forEach(function (m) {
        var idx = -1;
        for (var i = 0; i < originals.length; i++) {
          if (m.created_at < originals[i].ts || (m.created_at === originals[i].ts && Number(m.id) < originals[i].id)) {
            idx = i; break;
          }
        }
        if (idx === -1) append.push(m); else (before[idx] = before[idx] || []).push(m);
      });
      // Insert newest-first per slot so DOM order stays chronological.
      before.forEach(function (group, idx) {
        group.sort(function (a, b) { return (b.created_at - a.created_at) || (Number(b.id) - Number(a.id)); });
        group.forEach(function (m) {
          container.insertBefore(makeLocalMsgDiv(m, myId), originals[idx].el);
        });
      });
      append.sort(function (a, b) { return (a.created_at - b.created_at) || (Number(a.id) - Number(b.id)); });
      append.forEach(function (m) { container.appendChild(makeLocalMsgDiv(m, myId)); });
      scrollChatBottom();
    });
  }

  function securityLabel(security) {
    var label = document.getElementById('dm-security-label');
    if (label) {
      if (security.active) label.textContent = 'Secure DM: On';
      else if (security.mine) label.textContent = 'Secure DM: waiting for @' + currentOtherUsername();
      else label.textContent = 'Secure DM: Off';
    }
    var btn = document.getElementById('dm-security-toggle');
    if (btn) {
      btn.setAttribute('data-enabled', security.mine ? '1' : '0');
      btn.setAttribute('data-active', security.active ? '1' : '0');
    }
    var notice = document.getElementById('dm-security-notice');
    if (notice) notice.style.display = security.active ? 'block' : 'none';
    var form = document.querySelector('.chat-form');
    if (form) form.setAttribute('data-security-active', security.active ? '1' : '0');
  }

  function initSecurityToggle() {
    var btn = document.getElementById('dm-security-toggle');
    if (!btn) return;
    btn.addEventListener('click', function () {
      if (btn.disabled) return;
      btn.disabled = true;
      var mine = btn.getAttribute('data-enabled') === '1';
      csrfFetch('/chats/' + encodeURIComponent(btn.getAttribute('data-username')) + '/security', {
        method: 'POST',
        body: JSON.stringify({ enabled: mine ? 0 : 1 }),
      }).then(function (r) { return r.json(); }).then(function (d) {
        btn.disabled = false;
        if (d && d.ok && d.security) securityLabel(d.security);
      }).catch(function () { btn.disabled = false; });
    });
  }

  // ---- Chat page wiring ----
  function showRecipientNotice() {
    var notice = document.getElementById('e2ee-recipient-notice');
    var form = document.querySelector('.chat-form');
    var sendError = document.getElementById('chat-send-error');
    if (notice) notice.style.display = 'block';
    if (form) {
      var input = form.querySelector('input[name="body"]');
      var btn = form.querySelector('button[type="submit"]');
      if (input) input.disabled = true;
      if (btn) btn.disabled = true;
    }
    if (sendError) { sendError.textContent = ''; sendError.style.display = 'none'; }
  }

  function showSendError(msg) {
    var el = document.getElementById('chat-send-error');
    if (!el) return;
    el.textContent = msg;
    el.style.display = 'block';
    setTimeout(function () { el.style.display = 'none'; }, 6000);
  }

  function addLiveIncomingMsg(m, otherIdStr, senderCurve) {
    var container = document.querySelector('.chat-messages');
    if (!container) return;
    if (m && m.id && document.querySelector('.chat-msg[data-msg-id="' + m.id + '"]')) return;
    var emptyPlaceholder = container.querySelector('.center.muted');
    if (emptyPlaceholder) emptyPlaceholder.remove();

    var div = document.createElement('div');
    div.className = 'chat-msg';
    div.setAttribute('data-msg-id', String(m.id));
    div.setAttribute('data-ts', String(m.created_at));
    var bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    div.appendChild(bubble);
    var time = document.createElement('div');
    time.className = 'muted';
    time.style.cssText = 'font-size:0.7rem;padding:0 4px';
    time.textContent = window.relTime ? window.relTime(m.created_at) : new Date(m.created_at).toLocaleString();
    div.appendChild(time);
    container.appendChild(div);

    var proto = m.proto || 'rsa';
    var isSticker = m.body && m.body.indexOf('/uploads/stickers/') === 0;
    var decryptP;
    if (isSticker) {
      decryptP = Promise.resolve(m.body); // sticker body IS the plaintext
    } else if (proto === 'olm') {
      decryptP = decryptOlm({ body: m.body, sender_ciphertext: m.sender_ciphertext }, false, otherIdStr, senderCurve);
    } else {
      var keyForDecrypt = m.key_for_recipient;
      decryptP = keyForDecrypt ? decryptLegacyRSA(m.body, keyForDecrypt) : Promise.reject(new Error('no key'));
    }
    decryptP.then(function (plain) {
      if (isSticker) {
        bubble.innerHTML = '<img src="' + esc(plain) + '" class="sticker-inline" style="max-width:120px;max-height:120px;vertical-align:middle" alt="sticker">';
      } else {
        bubble.textContent = plain;
      }
      securePersistMessage(otherIdStr, {
        id: m.id,
        from_id: m.from_id,
        created_at: m.created_at,
        edited_at: m.edited_at || null,
        proto: isSticker ? 'plain' : (m.proto || 'olm'),
        plaintext: plain,
        own: false,
        msg_secure: Number(m.secure) === 1,
      }).then(function () {
        if (Number(m.secure) === 1) {
          return ackSecureMessages(currentOtherUsername(), [m.id]);
        }
      });
      scrollChatBottom();
    }).catch(function (err) {
      console.warn('Live message decrypt failed', err);
      bubble.textContent = '[unable to decrypt]';
      scrollChatBottom();
    });
    scrollChatBottom();
  }

  // Live DM delivery over the signaling WebSocket. The listener is registered as
  // early as possible and buffers messages until E2EE is ready, so nothing arriving
  // during key setup is dropped.
  var liveReady = false;
  var liveBuffer = [];
  var liveOtherIdStr = null;
  var liveSenderCurve = null;

  function initLiveBuffer(recipientId) {
    if (!window.ExtrovertCall || !window.ExtrovertCall.on) return;
    var myRecipient = String(recipientId);
    window.ExtrovertCall.on('new_dm', function (data) {
      var m = data.message;
      if (!m) return;
      var curUser = currentOtherUsername().toLowerCase();
      var fromUser = String(data.from_username || '').toLowerCase();
      var matchId = String(m.from_id || m.sender_id || '') === myRecipient;
      var matchUser = fromUser && curUser && fromUser === curUser;
      if (!matchId && !matchUser) return;
      if (!liveReady) { liveBuffer.push(data); return; }
      addLiveIncomingMsg(m, liveOtherIdStr || myRecipient, data.sender_curve || liveSenderCurve);
    });
    window.ExtrovertCall.on('delete_dm', function (data) {
      var mid = data.message_id;
      if (!mid) return;
      var el = document.querySelector('.chat-msg[data-msg-id="' + mid + '"]');
      if (el) el.remove();
      if (liveOtherIdStr || recipientId) {
        secureDeleteMessage(liveOtherIdStr || recipientId, mid);
      }
    });
  }

  function startLiveUpdates(otherIdStr, senderCurve) {
    liveOtherIdStr = otherIdStr;
    liveSenderCurve = senderCurve;
    liveReady = true;
    var pending = liveBuffer.splice(0, liveBuffer.length);
    pending.forEach(function (data) {
      addLiveIncomingMsg(data.message, liveOtherIdStr, data.sender_curve || liveSenderCurve);
    });
  }

  function initChatHandlers(recipientId, otherIdStr, otherUsername, recipientCurve) {
    var sendForm = document.querySelector('.chat-form');
    if (!sendForm) return;

    startLiveUpdates(otherIdStr, recipientCurve);

    sendForm.addEventListener('submit', function (e) {
      e.stopImmediatePropagation();
      e.preventDefault();
      var input = sendForm.querySelector('input[name="body"]');
      var plaintext = input.value.trim();
      if (!plaintext) return;

      if (plaintext.startsWith('/uploads/stickers/')) {
        input.disabled = true;
        var formData = new FormData(sendForm);
        formData.delete('proto');
        formData.delete('sender_ciphertext');
        fetch(sendForm.getAttribute('action'), {
          method: 'POST', credentials: 'same-origin',
          headers: { 'X-CSRF-Token': csrfToken(), 'X-Requested-With': 'XMLHttpRequest' },
          body: formData,
        }).then(function (r) { return r.json(); }).then(function (data) {
          if (data.message) {
            addChatMsg(document.querySelector('.chat-messages'), data.message);
            // Additional Security: persist our own device copy + ack receipt.
            if (Number(data.message.secure) === 1) {
              securePersistMessage(otherIdStr, {
                id: data.message.id,
                from_id: currentUserId(),
                created_at: data.message.created_at,
                edited_at: data.message.edited_at || null,
                proto: 'plain',
                plaintext: data.message.body,
                own: true,
              }).then(function () {
                return ackSecureMessages(otherUsername, [data.message.id]);
              });
            }
          }
          input.value = '';
          input.disabled = false;
        }).catch(function () { input.disabled = false; });
        return;
      }

      input.disabled = true;
      encryptOlm(plaintext, recipientId, otherIdStr, otherUsername).then(function (result) {
        var usp = new URLSearchParams();
        usp.set('proto', 'olm');
        usp.set('body', result.recipientCipher);
        usp.set('sender_ciphertext', result.senderCipher);
        fetch(sendForm.getAttribute('action'), {
          method: 'POST', credentials: 'same-origin',
          headers: { 'X-CSRF-Token': csrfToken(), 'X-Requested-With': 'XMLHttpRequest' },
          body: usp,
        }).then(function (r) { return r.json(); }).then(function (data) {
          if (data.error) { input.disabled = false; return; }
          if (data.message) {
            addOwnMsg(plaintext, data.message);
            securePersistMessage(otherIdStr, {
              id: data.message.id,
              from_id: currentUserId(),
              created_at: data.message.created_at,
              edited_at: data.message.edited_at || null,
              proto: 'olm',
              plaintext: plaintext,
              own: true,
              msg_secure: Number(data.message.secure) === 1,
            }).then(function () {
              if (Number(data.message.secure) === 1) {
                return ackSecureMessages(otherUsername, [data.message.id]);
              }
            });
          }
          input.value = '';
          input.disabled = false;
          maybeReplenishPrekeys();
        }).catch(function () { input.disabled = false; });
      }).catch(function (err) {
        console.error('E2EE encrypt error', err);
        input.disabled = false;
        if (err && /no encryption keys/i.test(err.message)) {
          showRecipientNotice();
        } else {
          showSendError('Could not encrypt this message. Please reload the chat and try again.');
        }
      });
    });

    document.addEventListener('click', function (e) {
      var editBtn = e.target.closest('.edit-msg-btn');
      if (editBtn) {
        e.preventDefault();
        editMessageInline(editBtn, recipientId, otherIdStr, otherUsername);
        return;
      }
      var delBtn = e.target.closest('.delete-msg-btn');
      if (delBtn) {
        e.preventDefault();
        var msgDiv = delBtn.closest('.chat-msg');
        if (!msgDiv) return;
        var msgId = delBtn.dataset.msgId || msgDiv.getAttribute('data-msg-id');
        var action = delBtn.dataset.action || ('/chats/' + encodeURIComponent(otherUsername) + '/delete/' + encodeURIComponent(msgId));
        var csrf = delBtn.dataset.csrf || csrfToken();
        if (!confirm('Delete this message?')) return;
        delBtn.disabled = true;
        fetch(action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf, 'X-Requested-With': 'XMLHttpRequest' },
          body: '_csrf=' + encodeURIComponent(csrf),
        }).then(function (r) { return r.json(); }).then(function (d) {
          if (d.ok) {
            msgDiv.remove();
            if (otherIdStr) {
              secureDeleteMessage(otherIdStr, msgId);
            }
          } else {
            delBtn.disabled = false;
            alert(d.error || 'Failed to delete message');
          }
        }).catch(function (err) {
          delBtn.disabled = false;
          console.error('Delete error', err);
        });
      }
    });
  }

  function editMessageInline(editBtn, recipientId, otherIdStr, otherUsername) {
    var msgDiv = editBtn.closest('.chat-msg');
    if (!msgDiv) return;
    var proto = msgDiv.getAttribute('data-proto') || 'rsa';
    var bubble = msgDiv.querySelector('.chat-bubble');
    var dataEl = msgDiv.querySelector('.edit-msg-data');
    if (!bubble || !dataEl) return;
    var action = dataEl.dataset.action;
    var csrf = dataEl.dataset.csrf;
    var origText = bubble.textContent;

    var input = document.createElement('input');
    input.type = 'text';
    input.className = 'chat-bubble-edit';
    input.value = origText;
    bubble.replaceWith(input);
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);

    var btnWrap = document.createElement('span');
    btnWrap.className = 'inline-edit-btns';
    btnWrap.style.cssText = 'display:inline-flex;gap:4px;margin-left:4px;vertical-align:middle';
    var saveBtn = document.createElement('button');
    saveBtn.className = 'btn inline-save-btn';
    saveBtn.textContent = 'Save';
    saveBtn.type = 'button';
    saveBtn.style.cssText = 'font-size:12px;padding:4px 12px;cursor:pointer';
    var cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn ghost inline-cancel-btn';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.type = 'button';
    cancelBtn.style.cssText = 'font-size:12px;padding:4px 12px;cursor:pointer';
    btnWrap.appendChild(saveBtn);
    btnWrap.appendChild(cancelBtn);
    input.parentNode.insertBefore(btnWrap, input.nextSibling);

    function restore(text) {
      var span = document.createElement('div');
      span.className = 'chat-bubble';
      span.textContent = text;
      input.replaceWith(span);
      if (btnWrap.parentNode) btnWrap.remove();
    }

    function doSave() {
      var val = input.value.trim();
      if (!val || val === origText) { restore(origText); return; }

      if (val.startsWith('/uploads/stickers/')) {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving…';
        fetch(action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf, 'X-Requested-With': 'XMLHttpRequest' },
          body: 'body=' + encodeURIComponent(val) + '&_csrf=' + encodeURIComponent(csrf),
        }).then(function (r) { return r.json(); }).then(function (d) {
          if (d.ok) { restore(val); } else { location.reload(); }
        });
        return;
      }

      saveBtn.disabled = true;
      saveBtn.textContent = 'Saving…';
      var req = { proto: 'olm', body: '', sender_ciphertext: '' };
      var cryptoP = encryptOlm(val, recipientId, otherIdStr, otherUsername).then(function (r) {
        req.body = r.recipientCipher;
        req.sender_ciphertext = r.senderCipher;
      });
      cryptoP.then(function () {
        var params = 'body=' + encodeURIComponent(req.body) +
          '&proto=' + encodeURIComponent(req.proto) +
          '&sender_ciphertext=' + encodeURIComponent(req.sender_ciphertext) +
          '&_csrf=' + encodeURIComponent(csrf);
        return fetch(action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf, 'X-Requested-With': 'XMLHttpRequest' },
          body: params,
        }).then(function (r) { return r.json(); }).then(function (d) {
          if (d.ok || d.message) { restore(val); } else { location.reload(); }
        });
      }).catch(function () {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save';
      });
    }

    saveBtn.onclick = doSave;
    cancelBtn.onclick = function () { restore(origText); };
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') { restore(origText); ev.preventDefault(); }
      if (ev.key === 'Enter') { doSave(); ev.preventDefault(); }
    });
    input.addEventListener('blur', function () {
      setTimeout(function () { if (input.parentNode) restore(origText); }, 200);
    });
  }

  // Password unlock — shared by the web overlay and native clients. Resolves
  // with the username passed in when successful; rejects on wrong password.
  function unlockWithPassword(password, username) {
    var pass = String(password || '').trim();
    if (!pass) return Promise.reject(new Error('password required'));
    return initOlm().then(function () {
      return deriveKek(pass, username).then(function (k) {
        kek = k;
        return loadLegacyKey(k);
      }).then(function () {
        return getOrCreateDeviceKey();
      }).then(function () {
        return loadAccountFromStorage();
      }).then(function (acct) {
        if (acct) return loadSelfSessions();
        return fetchBackup().then(function (data) {
          if (data.backup) {
            return decryptWithKek(unwrapBackup(data.backup).account, kek).then(function (pickle) {
                account = new Olm.Account();
                account.unpickle(PICKLE_KEY, pickle);
                var k = JSON.parse(account.identity_keys());
                myIdKeys = { curve25519: k.curve25519, ed25519: k.ed25519 };
                return restoreSelfSessionsFromBackup(data);
              }).catch(function () {
                throw new Error('Wrong password.');
              });
          }
          if (data && data.has_identity) {
            throw new Error('No valid backup is stored on the server — use "Reset keys" below.');
          }
          return createAndPublishAccount().then(function () {
            return uploadBackup(account.pickle(PICKLE_KEY));
          });
        }).then(function () {
          // Verify the restored account still matches the server's current
          // identity; a stale backup must not silently load an account that
          // can never decrypt anything.
          return csrfFetch('/chats/prekeys/identity').then(function (r) { return r.json(); }).then(function (d) {
            if (d && d.identity_key && myIdKeys && d.identity_key !== myIdKeys.curve25519) {
              account = null;
              myIdKeys = null;
              throw new Error('The backup belongs to a different encryption identity — use "Reset keys" below.');
            }
          });
        }).then(function () { return maybeReplenishPrekeys(); });
      }).then(function () {
        return saveAccount().then(function () { return loadSelfSessions(); });
      }).then(function () {
        sessionStorage.removeItem(KEK_SESSION_KEY);
        saveSelfSessions();
        return username;
      });
    });
  }

  // mode 'password' (default): a valid backup exists — ask for the password.
  // mode 'reset': no valid backup exists — a password can't help; show only
  // the reset option. "Not now" dismisses without acting; the dialog reappears
  // on the next chat page load until local keys exist.
  function showUnlockOverlay(onUnlocked, mode) {
    var overlay = document.getElementById('e2ee-unlock-overlay');
    if (!overlay) return;
    overlay.style.display = 'flex';
    var input = document.getElementById('e2ee-password');
    var btn = document.getElementById('e2ee-unlock-btn');
    var error = document.getElementById('e2ee-unlock-error');
    var title = document.getElementById('e2ee-unlock-title');
    var hint = overlay.querySelector('p.muted');
    var dismiss = document.getElementById('e2ee-unlock-dismiss');
    var resetOnly = mode === 'reset';
    if (title) title.textContent = resetOnly ? 'Encryption Keys Missing' : 'Unlock End-to-End Encryption';
    if (hint) hint.textContent = resetOnly
      ? 'Your encryption keys can\'t be recovered on this device (no valid backup on the server). Reset them to start fresh — your contacts reconnect automatically on their next message.'
      : 'Enter your password to decrypt your keys and enable secure messaging.';
    if (dismiss) {
      dismiss.style.display = '';
      dismiss.onclick = function (ev) { ev.preventDefault(); overlay.style.display = 'none'; };
    }
    if (input && btn) {
      input.style.display = resetOnly ? 'none' : '';
      btn.style.display = resetOnly ? 'none' : '';
    }
    if (!input || !btn || resetOnly) return;
    input.focus();

    function doUnlock() {
      var pass = input.value.trim();
      if (!pass) return;
      btn.disabled = true;
      btn.textContent = 'Unlocking…';
      var overlayEl = document.getElementById('e2ee-unlock-overlay');
      var username = overlayEl ? overlayEl.getAttribute('data-username') : '';
      unlockWithPassword(pass, username).then(function () {
        overlay.style.display = 'none';
        if (error) error.style.display = 'none';
        if (onUnlocked) onUnlocked();
      }).catch(function (err) {
        console.error('unlock failed', err);
        if (error) { error.textContent = (err && err.message) || 'Wrong password or unlock failed.'; error.style.display = 'block'; }
        btn.disabled = false;
        btn.textContent = 'Unlock';
        input.value = '';
        input.focus();
      });
    }

    btn.onclick = doUnlock;
    input.onkeydown = function (e) {
      if (e.key === 'Enter') { e.preventDefault(); doUnlock(); }
    };
  }

  // Explicit key reset ("Forgot password / can't unlock? Reset keys"): mint a
  // brand-new identity on purpose. This is the only sanctioned path to create a
  // new identity when the old one is unrecoverable — a silent mint would break
  // decryption of every peer message instead.
  function resetEncryptionKeys() {
    return initOlm().then(function () { return getOrCreateDeviceKey(); }).then(function () {
      // Drop every per-conversation session (and the self-session pair): they
      // are pinned to the old identity and would only keep failing. Peers
      // detect the identity rotation and rebuild their outbound sessions on
      // their next send (checkOutboundSessionIdentity), so the conversation
      // heals automatically.
      return purgeOlmSessions();
    }).then(function () {
      selfOutbound = null;
      selfInbound = null;
      selfInboundBaseline = null;
      sessions = {};
      sessionBaselinePickles = {};
      sessionBaselines = {};
      rekeyLastCheck = {};
      rekeyRequestedAt = {};
      sessionIdentLastCheck = {};
      return createAndPublishAccount(true); // force: the reset IS the sanctioned rotation
    }).then(function () {
      return ensureSelfSessions();
    }).then(function () {
      return uploadBackup(account.pickle(PICKLE_KEY));
    }).then(function () {
      window.location.reload();
    }).catch(function (err) {
      console.error('key reset failed', err);
      window.alert('Failed to reset encryption keys.');
    });
  }

  // Delete session-related pickles from STORE_OLM, keeping only the account
  // (and Megolm room-group keys, which stay decryptable). Used by the key
  // reset so a fresh identity starts without stale ratchets.
  function purgeOlmSessions() {
    if (USE_FILE_STORE) return Promise.resolve();
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE_OLM, 'readwrite');
        var req = tx.objectStore(STORE_OLM).openCursor();
        req.onsuccess = function () {
          var cursor = req.result;
          if (!cursor) return;
          var k = String(cursor.key);
          var u = activeUserId();
          if (k.indexOf('session:' + u + ':') === 0 || k.indexOf('sessionBase:' + u + ':') === 0 ||
              k.indexOf('sessionIdent:' + u + ':') === 0 || k.indexOf('selfOutbound:' + u) === 0 ||
              k.indexOf('selfInbound:' + u) === 0) {
            cursor.delete();
          }
          cursor.continue();
        };
        tx.oncomplete = function () { resolve(); };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  }

  // Multi-device verification: ensure our device is registered with the server.
  function checkOwnIdentity() {
    var notice = document.getElementById('e2ee-identity-mismatch');
    if (!notice) return Promise.resolve();
    return getOrCreateDeviceId().then(function (devId) {
      return csrfFetch('/chats/devices').then(function (r) { return r.json(); }).then(function (d) {
        var devices = d && d.devices ? d.devices : [];
        var found = false;
        for (var i = 0; i < devices.length; i++) {
          if (devices[i].device_id === devId) {
            found = true;
            break;
          }
        }
        if (!found && account) {
          return publishPrekeys();
        }
        notice.style.display = 'none';
      }).catch(function () {
        notice.style.display = 'none';
      });
    });
  }

  function initResetLink() {
    var links = document.querySelectorAll('.e2ee-reset-link');
    if (!links.length) return;
    links.forEach(function (link) {
      link.addEventListener('click', function (ev) {
        ev.preventDefault();
        if (!window.confirm('Reset encryption keys? Old messages from other devices can no longer be decrypted.')) return;
        resetEncryptionKeys();
      });
    });
  }

  // ---- Main ----
  // Background key setup on every authenticated page (not just chats/rooms), so
  // IndexedDB is populated right after login and no tab ever needs a prompt.
  function prewarm() {
    if (document.querySelector('form[action^="/login"]')) return; // login page
    if (document.querySelector('form[action^="/register"]')) return; // register page
    if (!document.querySelector('meta[name="csrf-token"]')) return; // not logged in
    initOlm().then(function () {
      return ensureReady({ onNeedsPassword: function () {} });
    }).catch(function () {});
  }

  // /chats list: decrypt each conversation's last-message preview client-side.
  function decryptChatPreviews() {
    var items = document.querySelectorAll('.chat-preview');
    if (!items.length) return;
    ensureReady({ onNeedsPassword: function () {} }).then(function (ok) {
      if (!ok) return;
      items.forEach(function (el) {
        var otherId = el.getAttribute('data-other-id') || '';
        var body = el.getAttribute('data-body') || '';
        if (!body || body.indexOf('/uploads/stickers/') === 0) return;
        var proto = el.getAttribute('data-proto') || 'rsa';
        var isOwn = el.getAttribute('data-own') === '1';
        var curve = el.getAttribute('data-curve') || '';
        var key = isOwn
          ? el.getAttribute('data-key-sender') || ''
          : el.getAttribute('data-key-recipient') || '';
        secureLoadMessages(otherId).then(function (saved) {
          if (saved && saved.length) {
            var last = saved[saved.length - 1];
            if (last && last.plaintext) {
              el.textContent = last.plaintext;
              return;
            }
          }
          var p;
          if (proto === 'olm') {
            p = decryptOlm(
              { body: body, sender_ciphertext: el.getAttribute('data-sender-ciphertext') || '' },
              isOwn, otherId, curve
            );
          } else {
            p = key ? decryptLegacyRSA(body, key) : Promise.reject(new Error('no key'));
          }
          p.then(function (plain) {
            el.textContent = plain;
            securePersistMessage(otherId, {
              id: 'preview-' + otherId,
              from_id: isOwn ? currentUserId() : otherId,
              created_at: Date.now(),
              edited_at: null,
              proto: proto,
              plaintext: plain,
              own: isOwn,
            });
          }).catch(function () {});
        });
      });
    }).catch(function () {});
  }

  document.addEventListener('DOMContentLoaded', function () {
    interceptLoginForm();
    interceptRegisterForm();
    initResetLink();

    var sendForm = document.querySelector('.chat-form');
    if (!sendForm) {
      if (document.querySelector('.chat-preview')) {
        decryptChatPreviews();
      } else {
        prewarm();
      }
      return; // not a chat page — login/register hooks + background setup attached
    }

    var otherUsername = sendForm.getAttribute('data-recipient-username') || '';
    var recipientId = sendForm.getAttribute('data-recipient') || '';
    var recipientCurve = sendForm.getAttribute('data-recipient-curve') || '';
    var otherIdStr = String(recipientId);

    scrollChatBottom();

    initLiveBuffer(recipientId);

    initOlm().then(function () {
      return ensureReady({
        onNeedsPassword: function () { showUnlockOverlay(function () { finishChatInit(recipientId, recipientCurve, otherIdStr, otherUsername); }); },
        onNeedsReset: function () { showUnlockOverlay(function () { finishChatInit(recipientId, recipientCurve, otherIdStr, otherUsername); }, 'reset'); },
      });
    }).then(function (ready) {
      if (ready) { finishChatInit(recipientId, recipientCurve, otherIdStr, otherUsername); }
    }).catch(function (err) {
      console.error('E2EE init failed:', err);
      showUnlockOverlay(function () { finishChatInit(recipientId, recipientCurve, otherIdStr, otherUsername); });
    });
  });

  function finishChatInit(recipientId, recipientCurve, otherIdStr, otherUsername) {
    decryptExistingMessages(otherIdStr, recipientCurve, otherUsername).then(function () {
      scrollChatBottom();
      return renderLocalSecureMessages(otherIdStr);
    });
    renderSafetyNumber(otherUsername);
    initSecurityToggle();
    initChatHandlers(recipientId, otherIdStr, otherUsername, recipientCurve);
    checkOwnIdentity();
  }

  // Room pages (and any future consumer) drive Megolm through this global.
  window.ExtrovertE2EE = {
    ensureReady: ensureReady,
    initOlm: initOlm,
    syncRoomSessions: syncRoomSessions,
    encryptRoomMessage: encryptRoomMessage,
    decryptRoomMessage: decryptRoomMessage,
    showUnlockOverlay: showUnlockOverlay,
    // ---- DM bridge (used by the native client; web pages use the DOM wiring) ----
    unlock: unlockWithPassword,
    encryptDm: encryptOlm,
    decryptDm: decryptOlm,
    decryptLegacyDm: decryptLegacyRSA,
    replenishPrekeys: maybeReplenishPrekeys,
    // ---- Additional Security: device-local copies + receipt acks ----
    persistSecureMessage: securePersistMessage,
    deleteSecureMessage: secureDeleteMessage,
    loadSecureMessages: secureLoadMessages,
    ackSecureMessages: ackSecureMessages,
    fetchRecipientBundle: fetchBundle,
    myEd25519: function () { return myIdKeys ? myIdKeys.ed25519 : null; },
    ready: function () { return !!account; },
  };
})();
