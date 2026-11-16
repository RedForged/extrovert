(function () {
  'use strict';

  var ready = false;
  var membershipReady = false;
  var membershipBusy = false;
  var membershipQueued = false;
  var joinPollTimer = null;
  var roomId = null;
  var myId = null;
  var username = '';
  var members = [];

  var RETRY_MS = 5000;
  var failedDecrypts = {};
  var plaintextJobs = {};
  var lastAnnounce = 0;

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
      ready: function () { return ready && membershipReady; },
      encryptMessage: encryptMessage,
      decryptMessage: decryptMessage,
    };

    setSendDisabled(true);
    setMembershipStatus('Preparing end-to-end encryption…');
    watchMembership();
    boot();
  }

  function boot() {
    if (!window.ExtrovertMLS) {
      setTimeout(boot, 100);
      return;
    }

    window.ExtrovertMLS.init().then(function () {
      ready = true;
      watchForMessages();
      // Decrypt with whatever local state we have immediately. Waiting for
      // group reconciliation to succeed before showing messages means a slow
      // or failed reconcile hides the entire history. Reconcile after these
      // finish so the two do not mutate the same group state at once.
      decryptExistingMessages().then(attemptMembership);
    }).catch(function (err) {
      console.error('Room MLS initialization error:', err);
      setMembershipStatus('Could not initialize encryption: ' + ((err && err.message) || 'unknown error') + ' — retrying…');
      setTimeout(boot, RETRY_MS);
    });
  }

  // Adds room members who joined after the MLS group was created, and waits for
  // an existing member to add this device when it is not part of the group yet.
  function attemptMembership() {
    if (!roomId) return;
    if (membershipBusy) {
      membershipQueued = true;
      return;
    }
    membershipBusy = true;
    membershipQueued = false;
    window.ExtrovertMLS.reconcileRoomGroup(roomId, memberIds()).then(function (groupState) {
      membershipBusy = false;
      if (!groupState) throw new Error('Unable to open the room\'s encryption group');
      membershipReady = true;
      clearJoinPoll();
      setSendDisabled(false);
      setMembershipStatus('');
      decryptExistingMessages();
      if (membershipQueued) attemptMembership();
    }).catch(function (err) {
      membershipBusy = false;
      membershipReady = false;
      setSendDisabled(true);
      if (err && err.code === 'ROOM_NOT_JOINED') {
        setMembershipStatus('Waiting for a room member to add this device to the encrypted conversation…');
        announceReady();
      } else {
        console.error('Room MLS membership error:', err);
        setMembershipStatus('Encrypted messaging is not ready: ' + ((err && err.message) || 'unknown error') + ' — retrying…');
      }
      scheduleJoinPoll();
    });
  }

  function scheduleJoinPoll() {
    if (joinPollTimer) return;
    joinPollTimer = setTimeout(function () {
      joinPollTimer = null;
      if (!window.ExtrovertMLS) { scheduleJoinPoll(); return; }
      window.ExtrovertMLS.pollRoomGroup(roomId).then(function (state) {
        if (state) attemptMembership();
        else {
          announceReady();
          scheduleJoinPoll();
        }
      }).catch(function () { scheduleJoinPoll(); });
    }, RETRY_MS);
  }

  function clearJoinPoll() {
    if (joinPollTimer) {
      clearTimeout(joinPollTimer);
      joinPollTimer = null;
    }
  }

  // Broadcast that this device now has MLS keys, at most once every 30s, so
  // members currently viewing the room can add it to the group.
  function announceReady() {
    if (!roomId) return;
    var now = Date.now();
    if (now - lastAnnounce < 30000) return;
    lastAnnounce = now;
    var meta = document.querySelector('meta[name="csrf-token"]');
    var token = meta ? meta.getAttribute('content') : '';
    fetch('/rooms/' + encodeURIComponent(roomId) + '/mls-ready', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRF-Token': token
      },
      body: '_csrf=' + encodeURIComponent(token),
      credentials: 'same-origin'
    }).catch(function () {});
  }

  function memberIds() {
    return members.map(function (m) { return m.id || m.user_id; }).map(Number).filter(Boolean);
  }

  function fetchMembers() {
    var msgArea = document.getElementById('room-messages');
    var channelId = msgArea ? msgArea.getAttribute('data-channel-id') : '';
    if (!roomId || !channelId) return Promise.resolve(memberIds());
    return fetch('/rooms/' + encodeURIComponent(roomId) + '/channels/' + encodeURIComponent(channelId) + '/messages', {
      headers: { Accept: 'application/json' },
      credentials: 'same-origin'
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (data && Array.isArray(data.members) && data.members.length) {
        members = data.members.map(function (m) {
          return { id: m.user_id, username: m.username };
        });
      }
      return memberIds();
    }).catch(function () { return memberIds(); });
  }

  function watchMembership() {
    var bus = window.ExtrovertCall;
    if (!bus || !bus.on) return;
    if (bus.connect) bus.connect();
    bus.on('gateway_event', function (ev) {
      try {
        if (!ev || ev.topic !== 'room:' + roomId) return;
        if (ev.event !== 'member_join' && ev.event !== 'member_leave') return;
        if (window.ExtrovertMLS.clearRoomAddBackoff) window.ExtrovertMLS.clearRoomAddBackoff(roomId);
        fetchMembers().then(attemptMembership);
      } catch (e) {}
    });
  }

  function watchForMessages() {
    var msgArea = document.getElementById('room-messages');
    if (!msgArea || !window.MutationObserver) return;
    var observer = new MutationObserver(function () { decryptExistingMessages(); });
    observer.observe(msgArea, { childList: true, subtree: true });
  }

  function decryptExistingMessages() {
    var pending = [];
    document.querySelectorAll('#room-messages .room-msg[data-proto="mls"]').forEach(function (el) {
      var msgId = el.getAttribute('data-msg-id');
      var senderId = el.getAttribute('data-sender-id');
      var ciphertext = el.getAttribute('data-ciphertext');
      var textEl = el.querySelector('.room-msg-text');
      if (!textEl) return;
      var current = textEl.textContent;
      if (current && current !== '[unable to decrypt]' && current !== '…') return;
      if (!ciphertext) return;

      var mls = window.ExtrovertMLS;
      var cacheKey = mls && mls.roomCacheKey ? mls.roomCacheKey(msgId, ciphertext) : 'room:' + msgId;
      if (failedDecrypts[cacheKey]) {
        el.style.display = 'none';
        return;
      }
      el.style.display = '';

      function finish(plain) {
        if (window.ExtrovertFiles && window.ExtrovertFiles.render) {
          window.ExtrovertFiles.render(textEl, plain);
        } else {
          textEl.textContent = plain;
        }
        textEl.classList.remove('e2ee-pending');
      }

      // Share one decrypt per message. Two elements (server-rendered and
      // client-rendered) or an observer plus the membership callback can ask
      // for the same message at once, and MLS plaintext is single-use.
      var job = plaintextJobs[cacheKey];
      if (!job) {
        var recall = mls && mls.recallPlaintext
          ? mls.recallPlaintext(cacheKey)
          : Promise.resolve(null);
        job = recall.then(function (cached) {
          if (cached) return cached;
          return decryptMessage(senderId, ciphertext).then(function (plain) {
            if (mls && mls.rememberPlaintext) {
              return Promise.resolve(mls.rememberPlaintext(cacheKey, plain)).catch(function () {}).then(function () {
                return plain;
              });
            }
            return plain;
          });
        });
        plaintextJobs[cacheKey] = job;
        job.then(function () { delete plaintextJobs[cacheKey]; }, function () { delete plaintextJobs[cacheKey]; });
      }

      job.then(function (plain) {
        finish(plain);
      }).catch(function () {
        // A failure before the device is in the group is not final — retry
        // once reconciliation succeeds instead of hiding the history.
        if (!membershipReady) {
          textEl.textContent = '…';
          textEl.classList.add('e2ee-pending');
          return;
        }
        failedDecrypts[cacheKey] = true;
        el.style.display = 'none';
      });
      pending.push(job.then(function () {}, function () {}));
    });
    return Promise.all(pending);
  }

  function encryptMessage(plaintext) {
    if (!window.ExtrovertMLS) {
      return Promise.reject(new Error('MLS library not loaded'));
    }
    if (!membershipReady) {
      return Promise.reject(new Error('Waiting for this device to be added to the room\'s encrypted conversation'));
    }
    return window.ExtrovertMLS.encryptRoomMessage(roomId, plaintext, members).then(function (res) {
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

  function setMembershipStatus(text) {
    var el = document.getElementById('room-e2ee-status');
    if (el) el.textContent = text || '';
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
