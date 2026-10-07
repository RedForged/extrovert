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

    boot();
  }

  function boot() {
    if (!window.ExtrovertMLS) {
      setTimeout(boot, 100);
      return;
    }

    window.ExtrovertMLS.init().then(function () {
      ready = true;
      setSendDisabled(false);
      decryptExistingMessages();
      watchForMessages();
    }).catch(function (err) {
      console.error('Room MLS initialization error:', err);
      // Still enable form if device can proceed
      ready = true;
      setSendDisabled(false);
    });
  }

  function watchForMessages() {
    var msgArea = document.getElementById('room-messages');
    if (!msgArea || !window.MutationObserver) return;
    var observer = new MutationObserver(function () { decryptExistingMessages(); });
    observer.observe(msgArea, { childList: true, subtree: true });
  }

  function decryptExistingMessages() {
    document.querySelectorAll('#room-messages .room-msg[data-proto="mls"]').forEach(function (el) {
      var msgId = el.getAttribute('data-msg-id');
      var senderId = el.getAttribute('data-sender-id');
      var ciphertext = el.getAttribute('data-ciphertext');
      var textEl = el.querySelector('.room-msg-text');
      if (!textEl) return;
      if (textEl.textContent && textEl.textContent !== '[unable to decrypt]' && textEl.textContent !== '…') return;
      if (!ciphertext) return;

      var mls = window.ExtrovertMLS;
      var cacheKey = mls && mls.roomCacheKey ? mls.roomCacheKey(msgId, ciphertext) : 'room:' + msgId;

      function finish(plain, cacheIt) {
        if (window.ExtrovertFiles && window.ExtrovertFiles.render) {
          window.ExtrovertFiles.render(textEl, plain);
        } else {
          textEl.textContent = plain;
        }
        textEl.classList.remove('e2ee-pending');
        if (cacheIt && mls && mls.rememberPlaintext) mls.rememberPlaintext(cacheKey, plain);
      }

      var recall = mls && mls.recallPlaintext
        ? mls.recallPlaintext(cacheKey)
        : Promise.resolve(null);

      recall.then(function (cached) {
        if (cached) return finish(cached, false);
        decryptMessage(senderId, ciphertext).then(function (plain) {
          finish(plain, true);
        }).catch(function () {
          textEl.textContent = '[unable to decrypt]';
          textEl.classList.remove('e2ee-pending');
        });
      });
    });
  }

  function encryptMessage(plaintext) {
    if (!window.ExtrovertMLS) {
      return Promise.reject(new Error('MLS library not loaded'));
    }
    return (window.ExtrovertMLS.ready() ? Promise.resolve() : window.ExtrovertMLS.init()).then(function () {
      return window.ExtrovertMLS.encryptRoomMessage(roomId, plaintext, members);
    }).then(function (res) {
      return {
        proto: 'mls',
        ciphertext: res.body,
      };
    });
  }

  function decryptMessage(senderId, ciphertext) {
    if (!window.ExtrovertMLS) {
      return Promise.reject(new Error('MLS library not loaded'));
    }
    return (window.ExtrovertMLS.ready() ? Promise.resolve() : window.ExtrovertMLS.init()).then(function () {
      return window.ExtrovertMLS.decryptRoomMessage(roomId, ciphertext);
    });
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
