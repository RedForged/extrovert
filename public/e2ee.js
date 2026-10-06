(function () {
  'use strict';

  // === Pure MLS (RFC 9420) E2EE Client Engine ===

  var DB_NAME = 'extrovert_crypto';
  var DB_VERSION = 4;
  var STORE_MSG_CACHE = 'mls_msg_cache';

  // Cache plaintext of sent & received messages device-locally
  var memCache = {};

  function openCacheDB() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function (e) {
        var db = req.result;
        if (!db.objectStoreNames.contains(STORE_MSG_CACHE)) {
          db.createObjectStore(STORE_MSG_CACHE);
        }
      };
      req.onsuccess = function () {
        var db = req.result;
        if (!db.objectStoreNames.contains(STORE_MSG_CACHE)) {
          var v = db.version + 1;
          db.close();
          var upReq = indexedDB.open(DB_NAME, v);
          upReq.onupgradeneeded = function () {
            upReq.result.createObjectStore(STORE_MSG_CACHE);
          };
          upReq.onsuccess = function () { resolve(upReq.result); };
          upReq.onerror = function () { reject(upReq.error); };
        } else {
          resolve(db);
        }
      };
      req.onerror = function () { reject(req.error); };
    });
  }

  function getCachedMessage(msgId) {
    if (memCache[msgId]) return Promise.resolve(memCache[msgId]);
    return openCacheDB().then(function (db) {
      return new Promise(function (resolve) {
        var tx = db.transaction(STORE_MSG_CACHE, 'readonly');
        var req = tx.objectStore(STORE_MSG_CACHE).get(String(msgId));
        req.onsuccess = function () {
          var res = req.result || null;
          if (res) memCache[msgId] = res;
          resolve(res);
        };
        req.onerror = function () { resolve(null); };
      });
    }).catch(function () { return null; });
  }

  function cacheMessage(msgId, plaintext) {
    if (!msgId || !plaintext) return Promise.resolve();
    memCache[msgId] = plaintext;
    return openCacheDB().then(function (db) {
      return new Promise(function (resolve) {
        var tx = db.transaction(STORE_MSG_CACHE, 'readwrite');
        tx.objectStore(STORE_MSG_CACHE).put(plaintext, String(msgId));
        tx.oncomplete = function () { resolve(); };
        tx.onerror = function () { resolve(); };
      });
    }).catch(function () {});
  }

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function currentUserId() {
    var meta = document.querySelector('meta[name="current-user-id"]');
    if (meta) return parseInt(meta.getAttribute('content'), 10);
    var form = document.querySelector('.chat-form');
    return form ? parseInt(form.getAttribute('data-current-user'), 10) : 0;
  }

  function esc(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s || ''));
    return d.innerHTML;
  }

  function scrollChatBottom() {
    var container = document.querySelector('.chat-scroll') || document.querySelector('.chat-messages');
    if (container) container.scrollTop = container.scrollHeight;
  }

  function addOwnMsg(plaintext, msg, otherUsername) {
    var container = document.querySelector('.chat-messages');
    if (!container) return;

    if (msg.id) cacheMessage(msg.id, plaintext);

    var div = document.createElement('div');
    div.className = 'chat-msg own';
    div.setAttribute('data-msg-id', String(msg.id || ''));
    div.setAttribute('data-ts', String(msg.created_at || Date.now()));
    div.setAttribute('data-proto', 'mls');

    var bubble = document.createElement('div');
    bubble.className = 'chat-bubble';
    if (plaintext.indexOf('/uploads/stickers/') === 0) {
      bubble.innerHTML = '<img src="' + esc(plaintext) + '" class="sticker-inline" style="max-width:120px;max-height:120px;vertical-align:middle" alt="sticker">';
    } else {
      bubble.textContent = plaintext;
    }
    div.appendChild(bubble);

    var time = document.createElement('div');
    time.className = 'muted';
    time.style.cssText = 'font-size:0.7rem;padding:0 4px';
    time.textContent = window.relTime ? window.relTime(msg.created_at || Date.now()) : new Date(msg.created_at || Date.now()).toLocaleString();

    if (msg.id) {
      var delBtn = document.createElement('button');
      delBtn.className = 'delete-msg-btn';
      delBtn.setAttribute('data-msg-id', String(msg.id));
      delBtn.setAttribute('data-csrf', csrfToken());
      delBtn.setAttribute('data-action', '/chats/' + encodeURIComponent(otherUsername) + '/delete/' + encodeURIComponent(msg.id));
      delBtn.style.cssText = 'font-size:0.7rem;color:var(--text-muted);background:none;border:none;cursor:pointer;padding:0 2px;margin-left:4px;text-decoration:underline';
      delBtn.textContent = 'Delete';
      time.appendChild(delBtn);
    }

    div.appendChild(time);
    container.appendChild(div);
    scrollChatBottom();
  }

  function decryptExistingMessages(otherId) {
    var myId = currentUserId();
    var els = document.querySelectorAll('.chat-msg[data-proto="mls"]');

    els.forEach(function (el) {
      var msgId = el.getAttribute('data-msg-id');
      var body = el.getAttribute('data-body');
      var isOwn = el.classList.contains('own');
      var bubble = el.querySelector('.chat-bubble');
      if (!bubble) return;

      if (body && body.indexOf('/uploads/stickers/') === 0) return;

      getCachedMessage(msgId).then(function (cached) {
        if (cached) {
          bubble.textContent = cached;
          return;
        }

        if (isOwn) {
          // Sent by us on this or another device; if no cache, leave placeholder or show
          if (bubble.textContent === '…' || !bubble.textContent.trim()) {
            bubble.textContent = '[sent message]';
          }
          return;
        }

        if (!window.ExtrovertMLS || !window.ExtrovertMLS.ready()) {
          return;
        }

        window.ExtrovertMLS.decryptDmMessage(otherId, body).then(function (plain) {
          bubble.textContent = plain;
          cacheMessage(msgId, plain);
        }).catch(function (err) {
          console.warn('MLS DM decrypt failed for msg ' + msgId, err);
          bubble.textContent = '[unable to decrypt]';
        });
      });
    });
  }

  function initChat() {
    var sendForm = document.querySelector('.chat-form');
    if (!sendForm) return;

    var otherId = sendForm.getAttribute('data-recipient');
    var otherUsername = sendForm.getAttribute('data-recipient-username');
    var input = sendForm.querySelector('input[name="body"]');

    scrollChatBottom();

    if (window.ExtrovertMLS) {
      window.ExtrovertMLS.init().then(function () {
        decryptExistingMessages(otherId);
      }).catch(function () {});
    }

    sendForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var plaintext = input.value.trim();
      if (!plaintext) return;

      input.disabled = true;

      // Stickers bypass encryption
      if (plaintext.indexOf('/uploads/stickers/') === 0) {
        var fd = new FormData();
        fd.append('body', plaintext);
        fd.append('_csrf', csrfToken());

        fetch(sendForm.getAttribute('action'), {
          method: 'POST',
          headers: { 'X-Requested-With': 'XMLHttpRequest' },
          body: fd,
        }).then(function (r) { return r.json(); }).then(function (data) {
          if (data.message) {
            addOwnMsg(plaintext, data.message, otherUsername);
          }
          input.value = '';
          input.disabled = false;
          input.focus();
        }).catch(function () { input.disabled = false; });
        return;
      }

      // Pure MLS encryption
      if (!window.ExtrovertMLS) {
        alert('MLS encryption engine is not available. Please refresh the page.');
        input.disabled = false;
        return;
      }

      var initP = window.ExtrovertMLS.ready() ? Promise.resolve() : window.ExtrovertMLS.init();
      initP.then(function () {
        return window.ExtrovertMLS.encryptDmMessage(otherId, plaintext);
      }).then(function (res) {
        var usp = new URLSearchParams();
        usp.set('_csrf', csrfToken());
        usp.set('proto', 'mls');
        usp.set('body', res.body);

        return fetch(sendForm.getAttribute('action'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: usp.toString(),
        }).then(function (r) {
          if (r.status === 426) {
            alert('Extrovert has upgraded to modern MLS encryption (RFC 9420). Please refresh your browser tab to continue messaging.');
            location.reload();
            return { error: 'LegacyProtocolRetired' };
          }
          return r.json();
        }).then(function (data) {
          if (data.error) {
            alert('Send error: ' + (data.message || data.error));
            input.disabled = false;
            return;
          }
          if (data.message) {
            addOwnMsg(plaintext, data.message, otherUsername);
          }
          input.value = '';
          input.disabled = false;
          input.focus();
        });
      }).catch(function (err) {
        console.error('MLS DM encrypt error:', err);
        alert('Failed to encrypt message with MLS: ' + (err.message || err));
        input.disabled = false;
      });
    });

    // Start Live Updates via SSE
    initLiveUpdates(otherId, otherUsername);
  }

  function initLiveUpdates(otherId, otherUsername) {
    if (typeof EventSource === 'undefined') return;
    var es = new EventSource('/chats/events');

    es.addEventListener('dm', function (e) {
      try {
        var data = JSON.parse(e.data);
        if (!data || !data.message) return;
        var msg = data.message;
        var myId = currentUserId();

        if (String(msg.from_id) === String(myId)) return; // already rendered locally
        if (String(msg.from_id) !== String(otherId)) return; // belongs to another chat

        var container = document.querySelector('.chat-messages');
        if (!container) return;

        var div = document.createElement('div');
        div.className = 'chat-msg';
        div.setAttribute('data-msg-id', String(msg.id));
        div.setAttribute('data-proto', 'mls');

        var bubble = document.createElement('div');
        bubble.className = 'chat-bubble';
        bubble.textContent = '…';
        div.appendChild(bubble);

        var time = document.createElement('div');
        time.className = 'muted';
        time.style.cssText = 'font-size:0.7rem;padding:0 4px';
        time.textContent = window.relTime ? window.relTime(msg.created_at) : new Date(msg.created_at).toLocaleString();
        div.appendChild(time);

        container.appendChild(div);
        scrollChatBottom();

        if (msg.body && msg.body.indexOf('/uploads/stickers/') === 0) {
          bubble.innerHTML = '<img src="' + esc(msg.body) + '" class="sticker-inline" style="max-width:120px;max-height:120px;vertical-align:middle" alt="sticker">';
        } else if (window.ExtrovertMLS && window.ExtrovertMLS.ready()) {
          window.ExtrovertMLS.decryptDmMessage(otherId, msg.body).then(function (plain) {
            bubble.textContent = plain;
            cacheMessage(msg.id, plain);
          }).catch(function () {
            bubble.textContent = '[unable to decrypt]';
          });
        }
      } catch (err) {}
    });
  }

  // Compatibility stubs for any legacy callers
  window.ExtrovertE2EE = {
    ready: function () { return !!(window.ExtrovertMLS && window.ExtrovertMLS.ready()); },
    initOlm: function () { return window.ExtrovertMLS ? window.ExtrovertMLS.init() : Promise.resolve(); },
    ensureReady: function () { return Promise.resolve(true); },
    showUnlockOverlay: function () {},
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initChat);
  } else {
    initChat();
  }
})();
