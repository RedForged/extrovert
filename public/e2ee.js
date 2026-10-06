(function () {
  'use strict';

  // === Pure MLS (RFC 9420) E2EE Client Engine ===

  var DB_NAME = 'extrovert_crypto';
  var STORE_MSG_CACHE = 'mls_msg_cache';
  var ALL_STORES = ['crypto', 'mls_keys', 'mls_groups', STORE_MSG_CACHE, 'mls_history'];

  // Cache plaintext of sent & received messages device-locally
  var memCache = {};

  var cacheDbPromise = null;

  function wireCacheDb(db) {
    db.onversionchange = function () {
      db.close();
      cacheDbPromise = null;
    };
    return db;
  }

  function openCacheDB() {
    if (cacheDbPromise) return cacheDbPromise;
    cacheDbPromise = new Promise(function (resolve, reject) {
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
        if (!missing.length) return resolve(wireCacheDb(db));
        var target = db.version + 1;
        db.close();
        var up = indexedDB.open(DB_NAME, target);
        up.onupgradeneeded = function () {
          var udb = up.result;
          missing.forEach(function (s) {
            if (!udb.objectStoreNames.contains(s)) udb.createObjectStore(s);
          });
        };
        up.onsuccess = function () { resolve(wireCacheDb(up.result)); };
        up.onerror = function () { cacheDbPromise = null; reject(up.error); };
      };
      req.onerror = function () { cacheDbPromise = null; reject(req.error); };
    }).catch(function (err) {
      cacheDbPromise = null;
      throw err;
    });
    return cacheDbPromise;
  }

  function cacheKey(msgId, body) {
    var s = String(msgId) + '|' + String(body || '');
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return String(msgId) + ':' + h.toString(16);
  }

  function getCachedMessage(msgId, body) {
    var key = cacheKey(msgId, body);
    if (memCache[key]) return Promise.resolve(memCache[key]);
    return openCacheDB().then(function (db) {
      return new Promise(function (resolve) {
        var tx = db.transaction(STORE_MSG_CACHE, 'readonly');
        var req = tx.objectStore(STORE_MSG_CACHE).get(key);
        req.onsuccess = function () {
          var res = req.result || null;
          if (res) {
            memCache[key] = res;
            return resolve(res);
          }
          var legacy = tx.objectStore(STORE_MSG_CACHE).get(String(msgId));
          legacy.onsuccess = function () {
            var old = legacy.result || null;
            if (old) memCache[key] = old;
            resolve(old);
          };
          legacy.onerror = function () { resolve(null); };
        };
        req.onerror = function () { resolve(null); };
      });
    }).catch(function () { return null; });
  }

  function cacheMessage(msgId, plaintext, body) {
    if (!msgId || !plaintext) return Promise.resolve();
    var key = cacheKey(msgId, body);
    memCache[key] = plaintext;
    if (window.ExtrovertMLS && window.ExtrovertMLS.backupNow) window.ExtrovertMLS.backupNow();
    return openCacheDB().then(function (db) {
      return new Promise(function (resolve) {
        var tx = db.transaction(STORE_MSG_CACHE, 'readwrite');
        tx.objectStore(STORE_MSG_CACHE).put(plaintext, key);
        tx.oncomplete = function () { resolve(); };
        tx.onerror = function () { resolve(); };
      });
    }).catch(function () {});
  }

  function purgeLocalMessage(msgId) {
    var id = String(msgId);
    Object.keys(memCache).forEach(function (k) {
      if (k === id || k.indexOf(id + ':') === 0) delete memCache[k];
    });
    if (window.ExtrovertMLS && window.ExtrovertMLS.noteMessageDeleted) {
      window.ExtrovertMLS.noteMessageDeleted(id);
    }
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

  function appendMsgControls(timeEl, msgId, otherUsername) {
    var baseStyle = 'font-size:0.7rem;color:var(--text-muted);background:none;border:none;cursor:pointer;padding:0 2px;margin-left:4px;text-decoration:underline';
    var editBtn = document.createElement('button');
    editBtn.className = 'edit-msg-btn';
    editBtn.style.cssText = baseStyle;
    editBtn.textContent = 'Edit';
    var delBtn = document.createElement('button');
    delBtn.className = 'delete-msg-btn';
    delBtn.setAttribute('data-msg-id', String(msgId));
    delBtn.setAttribute('data-csrf', csrfToken());
    delBtn.setAttribute('data-action', '/chats/' + encodeURIComponent(otherUsername) + '/delete/' + encodeURIComponent(msgId));
    delBtn.style.cssText = baseStyle;
    delBtn.textContent = 'Delete';
    var data = document.createElement('input');
    data.type = 'hidden';
    data.className = 'edit-msg-data';
    data.value = '';
    data.setAttribute('data-csrf', csrfToken());
    data.setAttribute('data-action', '/chats/' + encodeURIComponent(otherUsername) + '/edit/' + encodeURIComponent(msgId));
    timeEl.appendChild(editBtn);
    timeEl.appendChild(delBtn);
    timeEl.appendChild(data);
  }

  function ensureEditedIndicator(msgEl) {
    var meta = msgEl.querySelector('.muted');
    if (!meta || meta.querySelector('.edited-indicator')) return;
    var span = document.createElement('span');
    span.className = 'edited-indicator';
    span.title = new Date().toLocaleString();
    span.textContent = '· edited';
    meta.insertBefore(span, meta.firstChild);
  }

  function addOwnMsg(plaintext, msg, otherUsername) {
    var container = document.querySelector('.chat-messages');
    if (!container) return;

    if (msg.id) cacheMessage(msg.id, plaintext, msg.body);

    var existing = msg.id ? container.querySelector('[data-msg-id="' + msg.id + '"]') : null;
    if (existing) {
      var existingBubble = existing.querySelector('.chat-bubble');
      if (existingBubble) {
        if (plaintext.indexOf('/uploads/stickers/') === 0) {
          existingBubble.innerHTML = '<img src="' + esc(plaintext) + '" class="sticker-inline" style="max-width:120px;max-height:120px;vertical-align:middle" alt="sticker">';
        } else {
          existingBubble.textContent = plaintext;
        }
      }
      scrollChatBottom();
      return;
    }

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
    div.appendChild(time);

    if (msg.id) {
      appendMsgControls(time, msg.id, otherUsername);
    }

    container.appendChild(div);
    scrollChatBottom();
  }

  var backupSyncOnce = null;
  function syncBackupOnce() {
    if (!backupSyncOnce) {
      backupSyncOnce = (window.ExtrovertMLS && window.ExtrovertMLS.syncBackup)
        ? window.ExtrovertMLS.syncBackup()
        : Promise.resolve(null);
    }
    return backupSyncOnce;
  }

  function resolveMsgText(msgId, isOwn, body, decryptFn) {
    return getCachedMessage(msgId, body).then(function (cached) {
      if (cached) return cached;
      return syncBackupOnce().then(function () {
        return getCachedMessage(msgId, body);
      }).then(function (cached2) {
        if (cached2) return cached2;
        if (!window.ExtrovertMLS || !window.ExtrovertMLS.ready() || !body) {
          return isOwn ? '[sent message]' : '[unable to decrypt]';
        }
        return decryptFn().then(function (plain) {
          cacheMessage(msgId, plain, body);
          return plain;
        }).catch(function () {
          return isOwn ? '[sent message]' : '[unable to decrypt]';
        });
      });
    });
  }

  function decryptExistingMessages(otherId) {
    var els = document.querySelectorAll('.chat-msg[data-proto="mls"]');

    els.forEach(function (el) {
      var msgId = el.getAttribute('data-msg-id');
      var body = el.getAttribute('data-body');
      var isOwn = el.classList.contains('own');
      var bubble = el.querySelector('.chat-bubble');
      if (!bubble) return;

      if (body && body.indexOf('/uploads/stickers/') === 0) return;

      resolveMsgText(msgId, isOwn, body, function () {
        return window.ExtrovertMLS.decryptDmMessage(otherId, body);
      }).then(function (text) {
        bubble.textContent = text;
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

    // Start Live Updates
    initMsgControls(otherId, otherUsername);
    initLiveUpdates(otherId, otherUsername);
  }

  function initMsgControls(otherId, otherUsername) {
    document.addEventListener('click', function (e) {
      var delBtn = e.target.closest('.delete-msg-btn');
      if (delBtn) {
        e.preventDefault();
        if (!confirm('Delete this message?')) return;
        var msgEl = delBtn.closest('.chat-msg');
        var msgId = delBtn.getAttribute('data-msg-id');
        var tok = delBtn.getAttribute('data-csrf');
        fetch(delBtn.getAttribute('data-action'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': tok, 'X-Requested-With': 'XMLHttpRequest' },
          body: '_csrf=' + encodeURIComponent(tok),
        }).then(function (r) { return r.json(); }).then(function (d) {
          if (d.ok) {
            if (msgEl) msgEl.remove();
            purgeLocalMessage(msgId);
          } else {
            alert('Delete failed: ' + (d.error || 'unknown error'));
          }
        });
        return;
      }

      var editBtn = e.target.closest('.edit-msg-btn');
      if (editBtn) {
        e.preventDefault();
        var msgEl = editBtn.closest('.chat-msg');
        if (!msgEl || msgEl.querySelector('.inline-edit-input')) return;
        var bubble = msgEl.querySelector('.chat-bubble');
        var dataEl = msgEl.querySelector('.edit-msg-data');
        if (!bubble || !dataEl) return;
        var body = msgEl.getAttribute('data-body') || '';
        var msgId = msgEl.getAttribute('data-msg-id');
        var tok = dataEl.getAttribute('data-csrf');
        var isOwn = msgEl.classList.contains('own');
        var delEl = msgEl.querySelector('.delete-msg-btn');
        var meta = msgEl.querySelector('.muted');

        resolveMsgText(msgId, isOwn, body, function () {
          return window.ExtrovertMLS.decryptDmMessage(otherId, body);
        }).then(function (currentText) {
          if (currentText.indexOf('[') === 0) currentText = '';
          var oldHtml = bubble.innerHTML;
          var input = document.createElement('input');
          input.type = 'text';
          input.className = 'inline-edit-input';
          input.value = currentText;
          input.style.cssText = 'width:100%;box-sizing:border-box;font:inherit';
          bubble.textContent = '';
          bubble.appendChild(input);
          editBtn.style.display = 'none';
          if (delEl) delEl.style.display = 'none';

          var baseStyle = 'font-size:0.7rem;color:var(--text-muted);background:none;border:none;cursor:pointer;padding:0 2px;margin-left:4px;text-decoration:underline';
          var saveBtn = document.createElement('button');
          saveBtn.className = 'inline-save-btn';
          saveBtn.style.cssText = baseStyle;
          saveBtn.textContent = 'Save';
          var cancelBtn = document.createElement('button');
          cancelBtn.className = 'inline-cancel-btn';
          cancelBtn.style.cssText = baseStyle;
          cancelBtn.textContent = 'Cancel';
          if (meta) { meta.appendChild(saveBtn); meta.appendChild(cancelBtn); }

          var done = false;
          function cleanup() {
            if (done) return;
            done = true;
            if (input.parentNode) input.parentNode.removeChild(input);
            if (saveBtn.parentNode) saveBtn.parentNode.removeChild(saveBtn);
            if (cancelBtn.parentNode) cancelBtn.parentNode.removeChild(cancelBtn);
            editBtn.style.display = '';
            if (delEl) delEl.style.display = '';
          }
          function cancel() {
            if (done) return;
            bubble.innerHTML = oldHtml;
            cleanup();
          }
          function save() {
            if (done) return;
            var newText = input.value.trim();
            if (!newText) { cancel(); return; }
            input.disabled = true;
            window.ExtrovertMLS.encryptDmMessage(otherId, newText).then(function (res) {
              return fetch(dataEl.getAttribute('data-action'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': tok, 'X-Requested-With': 'XMLHttpRequest' },
                body: 'body=' + encodeURIComponent(res.body) + '&proto=mls&_csrf=' + encodeURIComponent(tok),
              }).then(function (r) { return r.json(); }).then(function (d) {
                if (!d.message) throw new Error(d.error || 'edit failed');
                bubble.textContent = newText;
                msgEl.setAttribute('data-body', res.body);
                cacheMessage(msgId, newText, res.body);
                ensureEditedIndicator(msgEl);
                cleanup();
              });
            }).catch(function (err) {
              alert('Edit failed: ' + (err.message || err));
              input.disabled = false;
            });
          }
          saveBtn.addEventListener('click', save);
          cancelBtn.addEventListener('click', cancel);
          input.addEventListener('keydown', function (ev) {
            if (ev.key === 'Enter') { ev.preventDefault(); save(); }
            if (ev.key === 'Escape') { ev.preventDefault(); cancel(); }
          });
          input.focus();
        });
      }
    });
  }

  function initLiveUpdates(otherId, otherUsername) {
    var bus = window.ExtrovertCall;
    if (!bus || !bus.on) return;
    if (bus.connect) bus.connect();

    bus.on('new_dm', function (data) {
      try {
        if (!data || !data.message) return;
        var msg = data.message;
        if (data.to_username !== otherUsername && data.from_username !== otherUsername) return;

        var container = document.querySelector('.chat-messages');
        if (!container) return;
        if (container.querySelector('[data-msg-id="' + msg.id + '"]')) return;

        var myId = currentUserId();
        var isOwn = String(msg.from_id) === String(myId);
        var div = document.createElement('div');
        div.className = isOwn ? 'chat-msg own' : 'chat-msg';
        div.setAttribute('data-msg-id', String(msg.id));
        div.setAttribute('data-proto', 'mls');
        div.setAttribute('data-body', msg.body || '');

        var bubble = document.createElement('div');
        bubble.className = 'chat-bubble';
        bubble.textContent = '…';
        div.appendChild(bubble);

        var time = document.createElement('div');
        time.className = 'muted';
        time.style.cssText = 'font-size:0.7rem;padding:0 4px';
        time.textContent = window.relTime ? window.relTime(msg.created_at) : new Date(msg.created_at).toLocaleString();
        div.appendChild(time);
        if (isOwn && msg.id) appendMsgControls(time, msg.id, otherUsername);

        container.appendChild(div);
        scrollChatBottom();

        if (msg.body && msg.body.indexOf('/uploads/stickers/') === 0) {
          bubble.innerHTML = '<img src="' + esc(msg.body) + '" class="sticker-inline" style="max-width:120px;max-height:120px;vertical-align:middle" alt="sticker">';
          return;
        }

        resolveMsgText(String(msg.id), isOwn, msg.body, function () {
          return window.ExtrovertMLS.decryptDmMessage(otherId, msg.body);
        }).then(function (text) {
          bubble.textContent = text;
          if (isOwn && text.indexOf('[') === 0) {
            setTimeout(function () {
              resolveMsgText(String(msg.id), isOwn, msg.body, function () {
                return window.ExtrovertMLS.decryptDmMessage(otherId, msg.body);
              }).then(function (text2) {
                bubble.textContent = text2;
              });
            }, 800);
          }
        });
      } catch (err) {}
    });

    bus.on('delete_dm', function (data) {
      if (!data || data.message_id === undefined) return;
      var el = document.querySelector('.chat-msg[data-msg-id="' + data.message_id + '"]');
      if (el) el.remove();
      purgeLocalMessage(String(data.message_id));
    });

    bus.on('edit_dm', function (data) {
      if (!data || !data.message) return;
      var msg = data.message;
      var el = document.querySelector('.chat-msg[data-msg-id="' + msg.id + '"]');
      if (!el) return;
      el.setAttribute('data-body', msg.body || '');
      var bubble = el.querySelector('.chat-bubble');
      if (!bubble) return;
      if (msg.body && msg.body.indexOf('/uploads/stickers/') === 0) return;
      resolveMsgText(String(msg.id), el.classList.contains('own'), msg.body, function () {
        return window.ExtrovertMLS.decryptDmMessage(otherId, msg.body);
      }).then(function (text) {
        bubble.textContent = text;
        ensureEditedIndicator(el);
      });
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
