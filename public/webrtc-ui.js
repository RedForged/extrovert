(function () {
  'use strict';

  var incomingOverlay = null;
  var activeCallBar = null;
  var callTimerInterval = null;
  var ringingAudioCtx = null;
  var ringingTimeout = null;
  var pendingIncoming = null;

  var onlineStatuses = {};

  document.addEventListener('DOMContentLoaded', function () {
    if (!window.ExtrovertCall) return;

    createIncomingOverlay();
    createActiveCallBar();
    initCallButtons();

    ExtrovertCall.on('incoming_call', onIncomingCall);
    ExtrovertCall.on('calling', onCalling);
    ExtrovertCall.on('calling_offline', onCallingOffline);
    ExtrovertCall.on('call_unanswered', onCallUnanswered);
    ExtrovertCall.on('call_connected', onCallConnected);
    ExtrovertCall.on('call_ended', onCallEnded);
    ExtrovertCall.on('call_declined', onCallDeclined);
    ExtrovertCall.on('user_online', onUserOnline);
    ExtrovertCall.on('user_offline', onUserOffline);
    ExtrovertCall.on('remote_stream', onRemoteStream);
    ExtrovertCall.on('error', onError);

    ExtrovertCall.connect();
  });

  function createIncomingOverlay() {
    incomingOverlay = document.createElement('div');
    incomingOverlay.id = 'call-incoming-overlay';
    incomingOverlay.style.cssText = 'display:none;position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;align-items:center;justify-content:center;flex-direction:column;gap:16px';
    incomingOverlay.innerHTML =
      '<div style="font-size:2rem;font-weight:700" id="call-incoming-label">Incoming call...</div>' +
      '<div style="font-size:1.2rem;color:var(--text-muted)" id="call-incoming-from"></div>' +
      '<div style="font-size:0.9rem;color:var(--text-muted);min-height:1.2em" id="call-incoming-hint"></div>' +
      '<div style="display:flex;gap:16px;margin-top:8px">' +
        '<button id="call-answer-btn" style="padding:12px 32px;background:#22c55e;color:#fff;border:none;border-radius:var(--radius-lg);font-size:1.1rem;cursor:pointer">Answer</button>' +
        '<button id="call-decline-btn" style="padding:12px 32px;background:var(--danger);color:#fff;border:none;border-radius:var(--radius-lg);font-size:1.1rem;cursor:pointer">Decline</button>' +
      '</div>';
    document.body.appendChild(incomingOverlay);

    document.getElementById('call-answer-btn').addEventListener('click', function () {
      if (pendingIncoming) {
        createRemoteAudioEl();
        ExtrovertCall.answerCall(pendingIncoming.username, pendingIncoming.sdp);
        pendingIncoming = null;
        hideIncomingOverlay();
      }
    });

    document.getElementById('call-decline-btn').addEventListener('click', function () {
      if (pendingIncoming) {
        ExtrovertCall.declineCall(pendingIncoming.username);
        pendingIncoming = null;
        hideIncomingOverlay();
      }
    });
  }

  function createActiveCallBar() {
    activeCallBar = document.createElement('div');
    activeCallBar.id = 'call-active-bar';
    activeCallBar.style.cssText = 'display:none;position:fixed;bottom:0;left:0;right:0;background:var(--surface);border-top:1px solid var(--border);z-index:9998;padding:8px 16px;align-items:center;justify-content:space-between';
    activeCallBar.innerHTML =
      '<div style="display:flex;align-items:center;gap:12px">' +
        '<span id="call-bar-ico" style="display:inline-flex;color:var(--secondary,var(--accent))"></span>' +
        '<div>' +
          '<div style="font-weight:600" id="call-bar-label">In call</div>' +
          '<div style="font-size:0.85rem;color:var(--text-muted)" id="call-bar-timer">00:00</div>' +
        '</div>' +
      '</div>' +
      '<div style="display:flex;align-items:center;gap:8px">' +
        '<button id="call-mute-btn" style="padding:8px 16px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius);cursor:pointer;font-size:0.9rem">Mute</button>' +
        '<button id="call-hangup-btn" style="padding:8px 24px;background:var(--danger);color:#fff;border:none;border-radius:var(--radius);cursor:pointer;font-size:0.9rem;font-weight:600">Hang Up</button>' +
      '</div>';
    document.body.appendChild(activeCallBar);
    var barIco = document.getElementById('call-bar-ico');
    if (barIco && window.DSHIcons) barIco.appendChild(window.DSHIcons.icon('speaker', 18));

    var muted = false;
    document.getElementById('call-mute-btn').addEventListener('click', function () {
      muted = ExtrovertCall.toggleMute();
      this.textContent = muted ? 'Unmute' : 'Mute';
      this.style.background = muted ? 'var(--danger)' : 'var(--surface-2)';
      this.style.color = muted ? '#fff' : '';
    });

    document.getElementById('call-hangup-btn').addEventListener('click', function () {
      ExtrovertCall.endCall();
    });
  }

  function initCallButtons() {
    document.querySelectorAll('.call-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var username = btn.dataset.username;
        if (username) {
          createRemoteAudioEl();
          ExtrovertCall.startCall(username);
        }
      });
    });
  }

  function createRemoteAudioEl() {
    if (!remoteAudioEl) {
      remoteAudioEl = document.createElement('audio');
      remoteAudioEl.autoplay = true;
      remoteAudioEl.playsinline = true;
      remoteAudioEl.style.display = 'none';
      document.body.appendChild(remoteAudioEl);
      remoteAudioEl.play().catch(function () {});
    }
  }

  function onIncomingCall(username, displayName, sdp, channelId) {
    if (channelId) return;
    pendingIncoming = { username: username, sdp: sdp };
    document.getElementById('call-incoming-from').textContent = displayName || username;
    var hintEl = document.getElementById('call-incoming-hint');
    var answerBtn = document.getElementById('call-answer-btn');
    if (sdp) {
      if (hintEl) hintEl.textContent = '';
      if (answerBtn) { answerBtn.disabled = false; answerBtn.style.opacity = '1'; answerBtn.style.cursor = 'pointer'; }
    } else {
      if (hintEl) hintEl.textContent = 'connecting…';
      if (answerBtn) { answerBtn.disabled = true; answerBtn.style.opacity = '0.5'; answerBtn.style.cursor = 'default'; }
    }
    incomingOverlay.style.display = 'flex';
    showRingingOverlay();
    startRinging();
    if (ringingTimeout) { clearTimeout(ringingTimeout); ringingTimeout = null; }
    ringingTimeout = setTimeout(function () {
      if (pendingIncoming) {
        ExtrovertCall.declineCall(pendingIncoming.username);
        pendingIncoming = null;
        hideIncomingOverlay();
        stopRinging();
      }
    }, 45000);
  }

  function onCalling(username) {
    showCallingBar(username);
  }

  function onCallingOffline(username) {
    showCallingOfflineBar(username);
  }

  function onCallUnanswered(username) {
    stopRinging();
    hideIncomingOverlay();
    hideActiveCallBar();
    cleanupRemoteAudio();
    stopCallTimer();
    showFlash(username + ' didn\'t come online');
  }

  function onCallConnected(username) {
    stopRinging();
    hideIncomingOverlay();
    showConnectedBar(username);
  }

  function onCallEnded(username) {
    stopRinging();
    hideIncomingOverlay();
    hideActiveCallBar();
    stopCallTimer();
    cleanupRemoteAudio();
  }

  function onCallDeclined(username) {
    stopRinging();
    hideIncomingOverlay();
    hideActiveCallBar();
    cleanupRemoteAudio();
    stopCallTimer();
  }

  function onUserOnline(username, displayName) {
    onlineStatuses[username] = true;
    updateOnlineDots();
    updateCallButtons();
  }

  function onUserOffline(username) {
    onlineStatuses[username] = false;
    updateOnlineDots();
    updateCallButtons();
  }

  var remoteAudioEl = null;

  function onRemoteStream(username, stream) {
    if (remoteAudioEl) {
      remoteAudioEl.srcObject = stream;
    }
  }

  function onError(message) {
    console.error('Call error:', message);
  }

  function showRingingOverlay() {
    var label = document.getElementById('call-incoming-label');
    label.textContent = 'Incoming call...';
    if (window.DSHIcons && !label.querySelector('svg')) {
      var ico = window.DSHIcons.icon('phoneIncoming', 26);
      ico.style.verticalAlign = '-4px';
      ico.style.marginRight = '8px';
      label.insertBefore(ico, label.firstChild);
    }
  }

  function startRinging() {
    try {
      ringingAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
      var osc = ringingAudioCtx.createOscillator();
      var gain = ringingAudioCtx.createGain();
      osc.type = 'sine';
      osc.frequency.value = 440;
      gain.gain.setValueAtTime(0.3, ringingAudioCtx.currentTime);
      osc.connect(gain);
      gain.connect(ringingAudioCtx.destination);
      osc.start();
      osc.onended = function () { try { ringingAudioCtx.close(); } catch {} };
      setTimeout(function () { try { osc.stop(); } catch {} }, 2000);
    } catch {}
  }

  function stopRinging() {
    if (ringingTimeout) { clearTimeout(ringingTimeout); ringingTimeout = null; }
    if (ringingAudioCtx) { try { ringingAudioCtx.close(); } catch {} ringingAudioCtx = null; }
  }

  function hideIncomingOverlay() {
    incomingOverlay.style.display = 'none';
  }

  function showCallingBar(username) {
    document.getElementById('call-bar-label').textContent = 'Calling ' + username + '...';
    activeCallBar.style.display = 'flex';
  }

  function showCallingOfflineBar(username) {
    document.getElementById('call-bar-label').textContent = 'Calling ' + username + '… (offline — will ring when they\'re back)';
    activeCallBar.style.display = 'flex';
  }

  function showFlash(text) {
    var el = document.createElement('div');
    el.textContent = text;
    el.style.cssText = 'position:fixed;bottom:64px;left:50%;transform:translateX(-50%);background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:var(--radius);padding:8px 16px;z-index:9997;font-size:0.9rem;box-shadow:0 2px 12px rgba(0,0,0,0.2)';
    document.body.appendChild(el);
    setTimeout(function () {
      el.style.transition = 'opacity 0.4s';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 400);
    }, 3000);
  }

  function showConnectedBar(username) {
    document.getElementById('call-bar-label').textContent = 'Call with ' + username;
    activeCallBar.style.display = 'flex';
    startCallTimer();
  }

  function hideActiveCallBar() {
    activeCallBar.style.display = 'none';
  }

  function cleanupRemoteAudio() {
    if (remoteAudioEl) {
      remoteAudioEl.pause();
      remoteAudioEl.srcObject = null;
      remoteAudioEl.remove();
      remoteAudioEl = null;
    }
  }

  function startCallTimer() {
    stopCallTimer();
    var el = document.getElementById('call-bar-timer');
    callTimerInterval = setInterval(function () {
      var s = Math.floor((Date.now() - (ExtrovertCall.getState().callStartTime || Date.now())) / 1000);
      var m = Math.floor(s / 60);
      s = s % 60;
      el.textContent = (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
    }, 1000);
  }

  function stopCallTimer() {
    if (callTimerInterval) { clearInterval(callTimerInterval); callTimerInterval = null; }
  }

  function updateOnlineDots() {
    document.querySelectorAll('.online-dot').forEach(function (dot) {
      var user = dot.dataset.user;
      if (onlineStatuses[user] !== undefined) {
        dot.classList.toggle('online', !!onlineStatuses[user]);
      }
    });
  }

  function updateCallButtons() {
    document.querySelectorAll('.call-btn').forEach(function (btn) {
      var user = btn.dataset.username;
      if (onlineStatuses[user] !== undefined) {
        // Offline users can still be called (offline-call flow). Keep the
        // button enabled; dim it slightly and hint at the behaviour.
        btn.disabled = false;
        btn.style.opacity = onlineStatuses[user] ? '1' : '0.7';
        btn.title = onlineStatuses[user]
          ? 'Call ' + user
          : user + ' is offline — they\'ll be notified and rung when they\'re back';
      }
    });
  }
})();
