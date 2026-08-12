(function () {
  'use strict';

  var ready = false;
  var roomId = null;
  var myId = null;
  var username = '';
  var members = [];

  function init() {
    var msgArea = document.getElementById('room-messages');
    var membersEl = document.getElementById('room-members');
    if (!msgArea || !membersEl) return;

    roomId = msgArea.getAttribute('data-room-id') || membersEl.getAttribute('data-room-id');
    myId = parseInt(msgArea.getAttribute('data-user-id'), 10) || parseInt(membersEl.getAttribute('data-user-id'), 10) || 0;
    username = membersEl.getAttribute('data-username') || '';
    try {
      members = JSON.parse(membersEl.getAttribute('data-members') || '[]');
    } catch (e) { members = []; }

    window.ExtrovertRoomE2EE = {
      ready: function () { return ready; },
      encryptMessage: encryptMessage,
      decryptMessage: decryptMessage,
    };

    if (!window.ExtrovertE2EE) { setTimeout(init, 100); return; }
    boot();
  }

  function boot() {
    window.ExtrovertE2EE.initOlm().then(function () {
      return window.ExtrovertE2EE.ensureReady({
        onNeedsPassword: function () { showOverlay(); },
      });
    }).then(function (ok) {
      if (ok) return afterUnlock();
      showOverlay();
    }).catch(function (err) {
      console.error('room E2EE init failed', err);
      showOverlay();
    });
  }

  function showOverlay() {
    ensureOverlay();
    window.ExtrovertE2EE.showUnlockOverlay(function () { afterUnlock(); });
  }

  function afterUnlock() {
    setSendDisabled(true);
    return window.ExtrovertE2EE.syncRoomSessions(roomId, myId, members).then(function () {
      ready = true;
      setSendDisabled(false);
      decryptExistingMessages();
      watchForMessages();
    }).catch(function (err) {
      console.error('room session sync failed', err);
      setSendDisabled(true);
    });
  }

  // rooms.js re-renders the message list asynchronously (loadMessages), so decrypt
  // newly inserted megolm messages whenever they appear.
  function watchForMessages() {
    var msgArea = document.getElementById('room-messages');
    if (!msgArea || !window.MutationObserver) return;
    var observer = new MutationObserver(function () { decryptExistingMessages(); });
    observer.observe(msgArea, { childList: true, subtree: true });
  }

  function ensureOverlay() {
    if (document.getElementById('e2ee-unlock-overlay')) return;
    var overlay = document.createElement('div');
    overlay.id = 'e2ee-unlock-overlay';
    overlay.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:1000;align-items:center;justify-content:center';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', 'e2ee-room-unlock-title');
    overlay.innerHTML =
      '<div class="card" style="max-width:360px;width:90%;text-align:center">' +
        '<h3 id="e2ee-room-unlock-title">Unlock End-to-End Encryption</h3>' +
        '<p class="muted">Enter your password to decrypt your keys and enable encrypted room messages.</p>' +
        '<input type="password" id="e2ee-password" placeholder="Password" aria-label="Password" autocomplete="current-password" style="width:100%;margin-bottom:10px">' +
        '<button class="btn" id="e2ee-unlock-btn">Unlock</button>' +
        '<div id="e2ee-unlock-error" style="color:var(--danger);margin-top:8px;display:none"></div>' +
      '</div>';
    document.body.appendChild(overlay);
  }

  function decryptExistingMessages() {
    document.querySelectorAll('#room-messages .room-msg[data-proto="megolm"]').forEach(function (el) {
      var senderId = el.getAttribute('data-sender-id');
      var ciphertext = el.getAttribute('data-ciphertext');
      var gsid = el.getAttribute('data-group-session-id');
      var textEl = el.querySelector('.room-msg-text');
      if (!textEl) return;
      decryptMessage(senderId, ciphertext, gsid).then(function (plain) {
        textEl.textContent = plain;
        textEl.classList.remove('e2ee-pending');
      }).catch(function () {
        textEl.textContent = '[unable to decrypt]';
        textEl.classList.remove('e2ee-pending');
      });
    });
  }

  function encryptMessage(plaintext) {
    if (!ready) return Promise.reject(new Error('not ready'));
    return window.ExtrovertE2EE.encryptRoomMessage(roomId, plaintext);
  }

  function decryptMessage(senderId, ciphertext, gsid) {
    return window.ExtrovertE2EE.decryptRoomMessage(roomId, senderId, ciphertext, gsid);
  }

  function setSendDisabled(disabled) {
    var form = document.getElementById('room-send-form');
    if (!form) return;
    var btn = form.querySelector('button[type="submit"]');
    var input = form.querySelector('input[name="body"]');
    if (btn) btn.disabled = disabled;
    if (input) input.disabled = disabled;
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
