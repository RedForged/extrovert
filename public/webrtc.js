(function () {
  'use strict';

  var STUN_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

  var ws = null;
  var reconnectTimeout = null;
  var reconnectAttempts = 0;

  var state = {
    callState: 'idle',
    peerConnections: {},
    localStream: null,
    peerUsername: null,
    channelId: null,
    channelMembers: {},
    callStartTime: null,
    pendingCall: null,
    callWaitTimeout: null,
  };

  var listeners = {};

  function on(event, fn) {
    if (!listeners[event]) listeners[event] = [];
    listeners[event].push(fn);
  }

  function off(event, fn) {
    if (!listeners[event]) return;
    listeners[event] = listeners[event].filter(function (f) { return f !== fn; });
  }

  function emit(event) {
    var args = Array.prototype.slice.call(arguments, 1);
    var fns = listeners[event];
    if (!fns) return;
    for (var i = 0; i < fns.length; i++) {
      try { fns[i].apply(null, args); } catch (e) { console.error('webrtc listener error:', e); }
    }
  }

  function wsUrl() {
    var proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return proto + '//' + window.location.host + '/ws';
  }

  function connect() {
    if (ws && ws.readyState === WebSocket.OPEN) return;
    try { ws = new WebSocket(wsUrl()); } catch (e) { scheduleReconnect(); return; }

    ws.onopen = function () {
      reconnectAttempts = 0;
      console.log('WebRTC WS connected');
      send({ type: 'ping' });
      var params = new URLSearchParams(window.location.search);
      var callUser = params.get('call');
      if (callUser && state.callState === 'idle') {
        startCall(callUser);
      }
    };

    ws.onmessage = function (e) {
      var msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      console.log('WS recv:', msg.type, msg.from || '');
      handleMessage(msg);
    };

    ws.onclose = function (event) {
      console.log('WebRTC WS closed:', event.code, event.reason);
      cleanupAll();
      scheduleReconnect();
    };

    ws.onerror = function (err) {
      console.error('WebRTC WS error');
    };
  }

  function scheduleReconnect() {
    if (reconnectTimeout) return;
    reconnectAttempts++;
    if (reconnectAttempts > 20) {
      console.log('WebRTC WS: max reconnect attempts reached, stopping');
      return;
    }
    var delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
    reconnectTimeout = setTimeout(function () {
      reconnectTimeout = null;
      connect();
    }, delay);
  }

  function send(data) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      console.log('WS send:', data.type, data.to || '');
      try { ws.send(JSON.stringify(data)); } catch {}
    } else {
      console.log('WS send FAILED (not open):', data.type, data.to || '');
    }
  }

  function handleMessage(msg) {
    switch (msg.type) {
      case 'pong':
        break;

      case 'incoming_call':
        if (state.callState === 'calling') {
          Object.keys(state.peerConnections).forEach(closePeerConnection);
          state.peerConnections = {};
        }
        state.callState = 'ringing';
        state.peerUsername = msg.from;
        state.channelId = msg.channel_id || null;
        emit('incoming_call', msg.from, msg.from_display || msg.from, msg.sdp, msg.channel_id);
        break;

      case 'callee_available':
        // Callee is online and free: produce the real WebRTC offer now.
        if (state.callState === 'calling' && state.peerUsername) {
          produceOfferAndSend(state.peerUsername);
        }
        break;

      case 'calling_offline':
        // Callee is offline: queued for ring-on-reconnect. Wait without media.
        if (state.callState === 'calling') {
          state.pendingCall = msg.to;
          emit('calling_offline', msg.to);
          if (state.callWaitTimeout) clearTimeout(state.callWaitTimeout);
          var waitMs = msg.expires_at ? Math.min(60000, Math.max(0, msg.expires_at - Date.now())) : 60000;
          state.callWaitTimeout = setTimeout(function () {
            state.callWaitTimeout = null;
            if (state.callState === 'calling' && state.pendingCall) {
              emit('call_unanswered', state.pendingCall);
              send({ type: 'call_cancel', to: state.pendingCall });
              endCallInternal();
            }
          }, waitMs);
        }
        break;

      case 'callee_ringing':
        // Callee just came online; server has rung them. Send the real offer.
        if (state.callWaitTimeout) { clearTimeout(state.callWaitTimeout); state.callWaitTimeout = null; }
        state.pendingCall = null;
        if (state.callState === 'calling' && state.peerUsername) {
          produceOfferAndSend(state.peerUsername);
        }
        break;

      case 'user_offline':
        emit('call_declined', msg.from);
        endCallInternal();
        break;

      case 'call_unanswered':
        if (state.callWaitTimeout) { clearTimeout(state.callWaitTimeout); state.callWaitTimeout = null; }
        emit('call_unanswered', msg.to || msg.from);
        endCallInternal();
        break;

      case 'call_answered':
        state.callState = 'connected';
        state.callStartTime = Date.now();
        setRemoteDescription(msg.from, msg.sdp);
        emit('call_connected', msg.from);
        break;

      case 'ice_candidate':
        if (msg.candidate && state.peerConnections[msg.from]) {
          try {
            state.peerConnections[msg.from].addIceCandidate(new RTCIceCandidate(msg.candidate));
          } catch {}
        }
        break;

      case 'call_ended':
        if (state.callState !== 'idle') {
          emit('call_ended', msg.from);
          endCallInternal();
        }
        break;

      case 'call_declined':
        emit('call_declined', msg.from);
        endCallInternal();
        break;

      case 'user_busy':
        emit('call_declined', msg.from);
        endCallInternal();
        break;

      case 'user_online':
        emit('user_online', msg.username, msg.display_name);
        break;

      case 'user_offline':
        emit('user_offline', msg.username);
        break;

      case 'channel_joined':
        state.channelId = msg.channel_id;
        state.callState = 'connected';
        state.callStartTime = Date.now();
        emit('channel_joined', msg.channel_id, msg.self, msg.members);
        break;

      case 'user_joined_channel':
        emit('user_joined_channel', msg.channel_id, msg.username, msg.display_name);
        break;

      case 'user_left_channel':
        closePeerConnection(msg.username);
        emit('user_left_channel', msg.channel_id, msg.username);
        break;

      case 'new_dm':
        emit('new_dm', msg);
        break;

      case 'delete_dm':
        emit('delete_dm', msg);
        break;

      case 'error':
        emit('error', msg.message);
        break;
    }
  }

  function getMedia() {
    if (state.localStream) return Promise.resolve(state.localStream);
    return navigator.mediaDevices.getUserMedia({ audio: true, video: false })
      .then(function (stream) {
        state.localStream = stream;
        return stream;
      });
  }

  function createPeerConnection(username) {
    if (state.peerConnections[username]) return Promise.resolve(state.peerConnections[username]);

    var pc = new RTCPeerConnection({ iceServers: STUN_SERVERS });

    pc.onicecandidate = function (e) {
      if (e.candidate) {
        var target = state.channelId ? username : state.peerUsername;
        send({ type: 'ice_candidate', to: target, candidate: e.candidate.toJSON(), channel_id: state.channelId || undefined, room_id: state.channelId ? '1' : undefined });
      }
    };

    pc.ontrack = function (e) {
      emit('remote_stream', username, e.streams[0]);
    };

    pc.oniceconnectionstatechange = function () {
      if (state.callState === 'idle') return;
      if (pc.iceConnectionState === 'disconnected' || pc.iceConnectionState === 'failed') {
        emit('call_ended', username);
        if (state.channelId) {
          closePeerConnection(username);
        } else {
          endCallInternal();
        }
      }
    };

    if (state.localStream) {
      state.localStream.getTracks().forEach(function (track) {
        pc.addTrack(track, state.localStream);
      });
    }

    state.peerConnections[username] = pc;
    return Promise.resolve(pc);
  }

  function closePeerConnection(username) {
    var pc = state.peerConnections[username];
    if (pc) {
      pc.close();
      delete state.peerConnections[username];
    }
  }

  function setRemoteDescription(username, sdp) {
    var pc = state.peerConnections[username];
    if (!pc) return;
    pc.setRemoteDescription(new RTCSessionDescription(JSON.parse(sdp))).catch(function () {});
  }

  function produceOfferAndSend(username) {
    return getMedia().then(function () {
      return createPeerConnection(username);
    }).then(function (pc) {
      return pc.createOffer().then(function (offer) {
        return pc.setLocalDescription(offer);
      }).then(function () {
        if (state.callState !== 'calling') {
          console.log('produceOfferAndSend aborted: state changed to', state.callState);
          return;
        }
        send({
          type: 'call_offer',
          to: username,
          sdp: JSON.stringify(pc.localDescription),
        });
        emit('calling', username);
      });
    }).catch(function (err) {
      if (state.callState === 'calling') {
        state.callState = 'idle';
      }
      emit('error', 'Failed to start call: ' + err.message);
    });
  }

  function startCall(username) {
    if (state.callState !== 'idle') {
      console.log('startCall ignored: state is', state.callState);
      return;
    }
    state.callState = 'calling';
    state.peerUsername = username;
    send({ type: 'call_request', to: username });
    emit('calling', username);
  }

  function answerCall(username, sdp) {
    if (state.callState !== 'ringing') {
      console.log('answerCall ignored: state is', state.callState);
      return;
    }
    if (!sdp) {
      // Ringing invite hasn't delivered the offer yet; wait for it.
      console.log('answerCall ignored: no SDP yet');
      return;
    }
    state.peerUsername = username;

    getMedia().then(function () {
      return createPeerConnection(username);
    }).then(function (pc) {
      return pc.setRemoteDescription(new RTCSessionDescription(JSON.parse(sdp))).then(function () {
        return pc.createAnswer();
      }).then(function (answer) {
        return pc.setLocalDescription(answer);
      }).then(function () {
        if (state.callState !== 'ringing') return;
        state.callState = 'connected';
        state.callStartTime = Date.now();
        send({
          type: 'call_answer',
          to: username,
          sdp: JSON.stringify(pc.localDescription),
        });
        emit('call_connected', username);
      });
    }).catch(function (err) {
      if (state.callState === 'ringing') {
        state.callState = 'idle';
      }
      emit('error', 'Failed to answer call: ' + err.message);
    });
  }

  function declineCall(username) {
    send({ type: 'call_decline', to: username });
    emit('call_declined', username);
    state.callState = 'idle';
    state.peerUsername = null;
  }

  function endCall() {
    if (state.channelId) {
      send({ type: 'leave_channel', channel_id: state.channelId });
      emit('call_ended', '');
      endCallInternal();
    } else if (state.pendingCall && Object.keys(state.peerConnections).length === 0) {
      // Waiting on an offline callee who hasn't reconnected yet: cancel.
      send({ type: 'call_cancel', to: state.pendingCall });
      emit('call_ended', state.pendingCall);
      endCallInternal();
    } else {
      var peer = state.peerUsername || '';
      send({ type: 'call_end', to: peer });
      emit('call_ended', peer);
      endCallInternal();
    }
  }

  function endCallInternal() {
    state.callState = 'idle';
    state.peerUsername = null;
    state.channelId = null;
    state.callStartTime = null;
    state.channelMembers = {};
    state.pendingCall = null;
    if (state.callWaitTimeout) { clearTimeout(state.callWaitTimeout); state.callWaitTimeout = null; }
    Object.keys(state.peerConnections).forEach(closePeerConnection);
    state.peerConnections = {};
    if (state.localStream) {
      state.localStream.getTracks().forEach(function (t) { t.stop(); });
      state.localStream = null;
    }
  }

  function cleanupAll() {
    endCallInternal();
  }

  function joinChannel(roomId, channelId) {
    send({ type: 'join_channel', room_id: roomId, channel_id: channelId });
  }

  function leaveChannel(channelId) {
    send({ type: 'leave_channel', channel_id: channelId });
    endCallInternal();
  }

  function initiateCallToMember(username) {
    if (state.peerConnections[username]) return;
    getMedia().then(function () {
      return createPeerConnection(username);
    }).then(function (pc) {
      return pc.createOffer().then(function (offer) {
        return pc.setLocalDescription(offer);
      }).then(function () {
        send({
          type: 'call_offer',
          to: username,
          sdp: JSON.stringify(pc.localDescription),
          channel_id: state.channelId,
          room_id: '1',
        });
      });
    }).catch(function () {});
  }

  function toggleMute() {
    if (!state.localStream) return true;
    var audioTrack = state.localStream.getAudioTracks()[0];
    if (!audioTrack) return true;
    audioTrack.enabled = !audioTrack.enabled;
    return audioTrack.enabled;
  }

  function getState() { return state; }

  window.ExtrovertCall = {
    on: on,
    off: off,
    connect: connect,
    startCall: startCall,
    answerCall: answerCall,
    declineCall: declineCall,
    endCall: endCall,
    joinChannel: joinChannel,
    leaveChannel: leaveChannel,
    initiateCallToMember: initiateCallToMember,
    toggleMute: toggleMute,
    getState: getState,
  };
})();
