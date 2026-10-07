(function () {
  'use strict';

  var voiceJoinButtons = {};
  var voiceMemberLists = {};
  var joinedChannelId = null;
  var remoteAudioEls = {};

  document.addEventListener('DOMContentLoaded', function () {
    if (!window.ExtrovertCall) return;

    document.querySelectorAll('.voice-join-btn').forEach(function (btn) {
      var cid = parseInt(btn.dataset.channelId, 10);
      voiceJoinButtons[cid] = btn;
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        var cid = parseInt(this.dataset.channelId, 10);
        toggleVoiceChannel(cid);
      });
    });

    document.querySelectorAll('.voice-members').forEach(function (el) {
      var cid = parseInt(el.id.replace('voice-members-', ''), 10);
      voiceMemberLists[cid] = el;
    });

    ExtrovertCall.on('channel_joined', onChannelJoined);
    ExtrovertCall.on('user_joined_channel', onUserJoinedChannel);
    ExtrovertCall.on('user_left_channel', onUserLeftChannel);
    ExtrovertCall.on('call_ended', onVoiceCallEnded);
    ExtrovertCall.on('incoming_call', onVoiceIncomingCall);
    ExtrovertCall.on('remote_stream', onVoiceRemoteStream);
    ExtrovertCall.on('speaking', onVoiceSpeaking);
  });

  function attachRemoteAudio(username, stream) {
    var el = remoteAudioEls[username];
    if (!el) {
      el = document.createElement('audio');
      el.autoplay = true;
      el.playsInline = true;
      el.style.display = 'none';
      document.body.appendChild(el);
      remoteAudioEls[username] = el;
    }
    el.srcObject = stream;
    el.play().catch(function () {});
  }

  function detachRemoteAudio(username) {
    var el = remoteAudioEls[username];
    if (!el) return;
    el.pause();
    el.srcObject = null;
    el.remove();
    delete remoteAudioEls[username];
  }

  function detachAllRemoteAudio() {
    Object.keys(remoteAudioEls).forEach(detachRemoteAudio);
  }

  function toggleVoiceChannel(channelId) {
    if (joinedChannelId === channelId) {
      leaveVoiceChannel();
    } else {
      if (joinedChannelId) leaveVoiceChannel();
      ExtrovertCall.joinChannel(getRoomId(), channelId);
    }
  }

  function leaveVoiceChannel() {
    if (joinedChannelId) {
      ExtrovertCall.leaveChannel(joinedChannelId);
      resetVoiceChannelUI();
    }
  }

  function resetVoiceChannelUI() {
    if (!joinedChannelId) return;
    var cid = joinedChannelId;
    joinedChannelId = null;
    var btn = voiceJoinButtons[cid];
    if (btn) btn.textContent = 'Join';
    var list = voiceMemberLists[cid];
    if (list) { list.classList.remove('active'); list.innerHTML = ''; }
    var count = document.getElementById('voice-count-' + cid);
    if (count) count.textContent = '0';
    detachAllRemoteAudio();
  }

  function onChannelJoined(channelId, self, members) {
    joinedChannelId = channelId;
    var btn = voiceJoinButtons[channelId];
    if (btn) btn.textContent = 'Leave';
    var list = voiceMemberLists[channelId];
    if (list) {
      list.classList.add('active');
      list.innerHTML = '';
      if (self) addMemberToList(channelId, self.username, self.display_name, true);
      members.forEach(function (m) {
        addMemberToList(channelId, m.username, m.display_name, false);
      });
    }
    updateVoiceCount(channelId, members.length + 1);
    var barLabel = document.getElementById('call-bar-label');
    if (barLabel) {
      var chName = getChannelName(channelId);
      barLabel.textContent = 'Voice: ' + (chName || 'Channel');
    }
    members.forEach(function (m) {
      ExtrovertCall.initiateCallToMember(m.username);
    });
  }

  function onUserJoinedChannel(channelId, username, displayName) {
    addMemberToList(channelId, username, displayName, false);
    updateVoiceCount(channelId);
  }

  function onUserLeftChannel(channelId, username) {
    var el = document.getElementById('voice-member-' + channelId + '-' + username);
    if (el) el.remove();
    detachRemoteAudio(username);
    updateVoiceCount(channelId);
  }

  function onVoiceCallEnded(peer) {
    if (joinedChannelId && !peer) {
      resetVoiceChannelUI();
    }
  }

  function onVoiceRemoteStream(username, stream) {
    if (joinedChannelId) attachRemoteAudio(username, stream);
  }

  function onVoiceSpeaking(username, active) {
    if (!joinedChannelId) return;
    var list = voiceMemberLists[joinedChannelId];
    if (!list) return;
    var el = username
      ? document.getElementById('voice-member-' + joinedChannelId + '-' + username)
      : list.querySelector('.voice-member[data-self]');
    if (el) el.classList.toggle('speaking', !!active);
  }

  function onVoiceIncomingCall(username, displayName, sdp, channelId) {
    if (joinedChannelId && channelId && String(channelId) === String(joinedChannelId)) {
      ExtrovertCall.answerCall(username, sdp);
    }
  }

  function addMemberToList(channelId, username, displayName, isSelf) {
    var list = voiceMemberLists[channelId];
    if (!list) return;
    var existing = document.getElementById('voice-member-' + channelId + '-' + username);
    if (existing) return;
    var div = document.createElement('div');
    div.className = 'voice-member';
    div.id = 'voice-member-' + channelId + '-' + username;
    if (isSelf) div.setAttribute('data-self', '1');
    div.innerHTML = '<span class="voice-member-speaking"></span><span class="voice-member-name">' + escapeHtml(displayName || username) + '</span>' + (isSelf ? ' <span class="voice-member-you">you</span>' : '');
    var speakEl = div.querySelector('.voice-member-speaking');
    if (speakEl && window.DSHIcons) speakEl.appendChild(window.DSHIcons.icon('speaker', 12));
    list.appendChild(div);
  }

  function updateVoiceCount(channelId, explicitCount) {
    var countEl = document.getElementById('voice-count-' + channelId);
    if (!countEl) return;
    if (explicitCount !== undefined) {
      countEl.textContent = explicitCount;
      return;
    }
    var list = voiceMemberLists[channelId];
    if (list) {
      countEl.textContent = list.querySelectorAll('.voice-member').length;
    }
  }

  function getRoomId() {
    var parts = window.location.pathname.split('/');
    return parts[2];
  }

  function getChannelName(channelId) {
    var el = document.querySelector('.voice-channel[data-channel-id="' + channelId + '"] .voice-name');
    return el ? el.textContent : null;
  }

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
})();
