document.addEventListener('DOMContentLoaded', function() {
  var msgArea = document.getElementById('room-messages');
  var currentUserId = msgArea ? parseInt(msgArea.dataset.userId, 10) : 0;
  var sendForm = document.getElementById('room-send-form');
  var channelList = document.getElementById('channel-list');
  var channelName = document.getElementById('channel-name');
  var reportOverlay = document.getElementById('report-overlay');
  var reportForm = document.getElementById('report-form');

  if (!msgArea || !sendForm || !channelList) return;

  var selfUsername = metaContent('current-username');
  var selfName = metaContent('current-user-name') || selfUsername;
  var selfAvatar = metaContent('current-user-avatar');
  var pendingSends = [];
  var lastMaxByChannel = {};
  var lastRender = null;

  loadMessages(msgArea.dataset.channelId);

  if (window.ExtrovertCall && window.ExtrovertCall.on) {
    if (window.ExtrovertCall.connect) window.ExtrovertCall.connect();
    if (window.ExtrovertCall.subscribe) window.ExtrovertCall.subscribe('room:' + roomId());
    window.ExtrovertCall.on('gateway_event', function (ev) {
      try {
        if (!ev || ev.topic !== 'room:' + roomId()) return;
        if (ev.event === 'message_create' && ev.data && ev.data.client_msg_id && ev.data.id) {
          var sent = findPending(ev.data.client_msg_id);
          if (sent) markPendingSent(sent, ev.data.id, ev.data.ciphertext || sent.ciphertext);
        }
        if (ev.event !== 'message_create' && ev.event !== 'message_update' && ev.event !== 'message_delete') return;
        var cid = sendForm ? sendForm.dataset.channelId : msgArea.dataset.channelId;
        if (ev.data && ev.data.channel_id && String(ev.data.channel_id) !== String(cid)) return;
        loadMessages(cid);
      } catch (e) {}
    });
  }

  channelList.addEventListener('click', function(e) {
    var link = e.target.closest('.room-channel');
    if (!link) return;
    if (link.dataset.channelType === 'voice') return;
    e.preventDefault();
    channelList.querySelectorAll('.room-channel').forEach(function(c) { c.classList.remove('active'); });
    link.classList.add('active');
    var cid = link.dataset.channelId;
    switchChannel(cid, link.querySelector('span').textContent);
  });

  // Staged attachment for the room: sealed in the browser before upload, with
  // the key travelling inside the room's encrypted message.
  var roomStagedFile = null;

  function clearRoomStaged() {
    roomStagedFile = null;
    var chip = document.getElementById('room-attach-chip');
    if (chip) { chip.hidden = true; chip.textContent = ''; }
    var inp = document.getElementById('room-attach-input');
    if (inp) inp.value = '';
  }

  function sealAndUploadRoomFile(file, text) {
    return window.ExtrovertFiles.seal(file).then(function (sealed) {
      var fd = new FormData();
      fd.append('_csrf', getCsrf());
      fd.append('file', sealed.blob, 'sealed.bin');
      return fetch('/drive/upload?sealed=1', {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest', Accept: 'application/json' },
        body: fd,
      }).then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (!r.ok) throw new Error(j && j.message ? j.message : 'Upload failed (' + r.status + ')');
          return window.ExtrovertFiles.envelope({
            u: j.url, k: sealed.key, i: sealed.iv, s: j.size,
            n: file.name, m: file.type || 'application/octet-stream', t: text,
          });
        });
      });
    });
  }

  var roomAttachBtn = document.getElementById('room-attach-btn');
  var roomAttachInput = document.getElementById('room-attach-input');
  var roomAttachChip = document.getElementById('room-attach-chip');
  if (roomAttachBtn && roomAttachInput) {
    roomAttachBtn.addEventListener('click', function () { roomAttachInput.click(); });
    roomAttachInput.addEventListener('change', function () {
      var f = roomAttachInput.files && roomAttachInput.files[0];
      roomStagedFile = f || null;
      if (roomAttachChip) {
        roomAttachChip.hidden = !f;
        roomAttachChip.textContent = f
          ? f.name + ' · ' + (window.ExtrovertFiles ? window.ExtrovertFiles.humanSize(f.size) : '') + ' — sealed in your browser (click to remove)'
          : '';
      }
    });
  }
  if (roomAttachChip) {
    roomAttachChip.addEventListener('click', function () { clearRoomStaged(); });
  }

  sendForm.addEventListener('submit', function(e) {
    e.preventDefault();
    var cid = sendForm.dataset.channelId;
    if (!cid) return;
    var input = sendForm.querySelector('input[name="body"]');
    var body = input.value.trim();
    var staged = roomStagedFile;
    if (!body && !staged) return;

    var clientMsgId = 'r' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    var pending = {
      clientMsgId: clientMsgId,
      channelId: String(cid),
      body: body,
      fileName: staged ? staged.name : '',
      plaintext: body,
      ciphertext: null,
      status: 'sending',
      baselineId: lastMaxByChannel[cid] || 0,
      createdAt: Date.now()
    };
    pendingSends.push(pending);

    input.value = '';
    clearRoomStaged();
    input.focus();
    refreshMessages();

    var csrf = getCsrf();
    var url = '/rooms/' + roomId() + '/channels/' + cid + '/send';
    var baseParams = 'client_msg_id=' + encodeURIComponent(clientMsgId);

    var fail = function(message) {
      pending.status = 'failed';
      pending.error = message || 'Failed to send';
      refreshMessages();
      alert('Send error: ' + pending.error);
      input.focus();
    };

    var doPost = function(params) {
      fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf },
        body: baseParams + '&' + params
      }).then(function(r) {
        if (r.status === 426) {
          alert('Extrovert has upgraded to modern MLS encryption (RFC 9420). Please refresh your browser tab to continue messaging.');
          location.reload();
          return { error: 'LegacyProtocolRetired' };
        }
        return r.json();
      }).then(function(d) {
        if (d.error) {
          fail(d.message || d.error);
          return;
        }
        if (d.id) markPendingSent(pending, d.id, pending.ciphertext);
        refreshMessages();
        loadMessages(cid);
      }).catch(function() {
        fail('Network error — the message was not sent.');
      });
    };

    var e2ee = window.ExtrovertRoomE2EE;
    if (e2ee) {
      var prep = (staged && window.ExtrovertFiles)
        ? sealAndUploadRoomFile(staged, body)
        : Promise.resolve(body);
      prep.then(function (payload) {
        pending.plaintext = payload;
        return e2ee.encryptMessage(payload);
      }).then(function(r) {
        pending.ciphertext = r.ciphertext;
        doPost('proto=mls&ciphertext=' + encodeURIComponent(r.ciphertext));
      }).catch(function(err) {
        fail('Could not encrypt message: ' + ((err && err.message) || 'MLS not ready yet — try again.'));
      });
      return;
    }
    doPost('body=' + encodeURIComponent(body));
  });

  // Edit button: delegation
  msgArea.addEventListener('click', function(e) {
    var editBtn = e.target.closest('.room-msg-edit');
    if (editBtn) {
      var msgDiv = editBtn.closest('.room-msg');
      var textSpan = msgDiv.querySelector('.room-msg-text');
      var currentText = textSpan.textContent;
      // Replace text with input field
      var input = document.createElement('input');
      input.type = 'text';
      input.className = 'room-msg-edit-input';
      input.value = currentText;
      textSpan.replaceWith(input);
      editBtn.textContent = 'Save';
      editBtn.classList.add('room-msg-save');
      editBtn.classList.remove('room-msg-edit');
      // Add cancel button
      var cancelBtn = document.createElement('span');
      cancelBtn.className = 'room-msg-cancel';
      cancelBtn.textContent = 'Cancel';
      cancelBtn.style.cssText = 'cursor:pointer;font-size:11px;padding:0 6px;color:var(--text-muted)';
      editBtn.parentNode.insertBefore(cancelBtn, editBtn.nextSibling);
      input.focus();
      // Cancel on Escape
      input.addEventListener('keydown', function(ev) {
        if (ev.key === 'Escape') { cancelEditRoomMsg(msgDiv, editBtn, currentText); ev.preventDefault(); }
      });
      cancelBtn.addEventListener('click', function() { cancelEditRoomMsg(msgDiv, editBtn, currentText); });
      return;
    }
    var saveBtn = e.target.closest('.room-msg-save');
    if (saveBtn) {
      var msgDiv = saveBtn.closest('.room-msg');
      var input = msgDiv.querySelector('.room-msg-edit-input');
      if (!input) return;
      var newBody = input.value.trim();
      if (!newBody) return;
      var msgId = saveBtn.dataset.msgId;
      var cid = sendForm ? sendForm.dataset.channelId : '';
      var csrf = getCsrf();
      var url = '/rooms/' + roomId() + '/channels/' + cid + '/messages/' + msgId + '/edit';
      var doEditPost = function(params) {
        fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf },
          body: params
        }).then(function(r) {
          if (r.status === 426) {
            alert('Extrovert has upgraded to modern MLS encryption (RFC 9420). Please refresh your browser tab to continue messaging.');
            location.reload();
            return { error: 'LegacyProtocolRetired' };
          }
          return r.json();
        }).then(function(d) {
          if (d.ok) {
            loadMessages(cid);
          } else {
            alert('Edit error: ' + (d.message || d.error || 'Failed to edit'));
            cancelEditRoomMsg(msgDiv, saveBtn, newBody);
          }
        });
      };
      var e2ee = window.ExtrovertRoomE2EE;
      if (e2ee) {
        e2ee.encryptMessage(newBody).then(function(r) {
          if (window.ExtrovertMLS && window.ExtrovertMLS.rememberPlaintext) {
            window.ExtrovertMLS.rememberPlaintext(window.ExtrovertMLS.roomCacheKey(msgId, r.ciphertext), newBody);
          }
          doEditPost('proto=mls&ciphertext=' + encodeURIComponent(r.ciphertext));
        }).catch(function(err) {
          alert('Could not encrypt edit: ' + ((err && err.message) || 'MLS not ready yet — try again.'));
          cancelEditRoomMsg(msgDiv, saveBtn, newBody);
        });
        return;
      }
      doEditPost('body=' + encodeURIComponent(newBody));
      return;
    }
    var delBtn = e.target.closest('.room-msg-delete');
    if (delBtn) {
      var msgId = delBtn.dataset.msgId;
      if (!confirm('Delete this message?')) return;
      var csrf = getCsrf();
      var cid = sendForm ? sendForm.dataset.channelId : '';
      fetch('/rooms/' + roomId() + '/channels/' + cid + '/messages/' + msgId + '/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf }
      }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.ok) {
          if (window.ExtrovertMLS && window.ExtrovertMLS.noteMessageDeleted) {
            window.ExtrovertMLS.noteMessageDeleted('room:' + msgId);
          }
          loadMessages(cid);
        }
      });
      return;
    }
    var reportBtn = e.target.closest('.room-msg-report');
    if (!reportBtn) return;
    var msgId = reportBtn.dataset.msgId;
    var msgDiv = reportBtn.closest('.room-msg');
    var msgText = msgDiv ? msgDiv.querySelector('.room-msg-text') : null;
    var preview = document.getElementById('report-message-preview');
    if (preview && msgText) preview.textContent = msgText.textContent;
    document.getElementById('report-msg-id').value = msgId;
    document.getElementById('report-reason').value = '';
    if (reportOverlay) reportOverlay.style.display = 'flex';
  });

  // Close report overlay
  document.addEventListener('click', function(e) {
    if (e.target.closest('.close-report-overlay')) {
      if (reportOverlay) reportOverlay.style.display = 'none';
    }
  });

  // Submit report
  if (reportForm) {
    reportForm.addEventListener('submit', function(e) {
      e.preventDefault();
      var msgId = document.getElementById('report-msg-id').value;
      var reason = document.getElementById('report-reason').value.trim();
      if (!msgId || !reason) return;
      var csrf = getCsrf();
      var cid = sendForm ? sendForm.dataset.channelId : '';
      fetch('/rooms/' + roomId() + '/channels/' + cid + '/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf },
        body: 'message_id=' + encodeURIComponent(msgId) + '&reason=' + encodeURIComponent(reason)
      }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.ok) {
          if (reportOverlay) reportOverlay.style.display = 'none';
          alert('Report submitted.');
        }
      }).catch(function() {});
    });
  }

  function switchChannel(cid, name) {
    msgArea.dataset.channelId = cid;
    sendForm.dataset.channelId = cid;
    channelName.textContent = name;
    sendForm.querySelector('input[name="body"]').placeholder = 'Message #' + name;
    loadMessages(cid);
  }

  function loadMessages(cid) {
    if (!cid) return;
    fetch('/rooms/' + roomId() + '/channels/' + cid + '/messages')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (String(sendForm.dataset.channelId) !== String(cid)) return;
        renderMessages(cid, data.messages || [], data.roleMap || {}, data.canDelete);
      });
  }

  function refreshMessages() {
    var cid = sendForm.dataset.channelId;
    if (!cid) return;
    if (lastRender && String(lastRender.cid) === String(cid)) {
      renderMessages(lastRender.cid, lastRender.messages, lastRender.roleMap, lastRender.canDelete);
    } else {
      loadMessages(cid);
    }
  }

  function renderMessages(cid, messages, roleMap, canDelete) {
    var all = messages || [];
    var maxId = 0;
    all.forEach(function(m) {
      var id = Number(m.id) || 0;
      if (id > maxId) maxId = id;
    });
    lastMaxByChannel[cid] = Math.max(lastMaxByChannel[cid] || 0, maxId);

    var pendings = pendingSends.filter(function(p) { return String(p.channelId) === String(cid); });
    var hasSending = pendings.some(function(p) { return p.status === 'sending'; });

    // Once nothing is in flight, swap confirmed optimistic bubbles for the
    // stored messages as soon as the server list contains them.
    if (!hasSending) {
      pendingSends = pendingSends.filter(function(p) {
        if (String(p.channelId) !== String(cid) || p.status !== 'sent') return true;
        return !all.some(function(m) { return String(m.id) === String(p.msgId); });
      });
      pendings = pendingSends.filter(function(p) { return String(p.channelId) === String(cid); });
    }

    var baseline = -1;
    pendings.forEach(function(p) {
      if (p.status === 'sending' && (baseline < 0 || p.baselineId < baseline)) baseline = p.baselineId;
    });
    var visible = baseline < 0 ? all : all.filter(function(m) {
      return !(m.user_id === currentUserId && (Number(m.id) || 0) > baseline);
    });

    lastRender = { cid: cid, messages: all, roleMap: roleMap, canDelete: canDelete };

    if (!visible.length && !pendings.length) {
      msgArea.innerHTML = '<div class="room-msg"><div class="room-msg-body"><div class="room-msg-body-inner"><span class="muted">No messages to show</span></div></div></div>';
      return;
    }

    msgArea.innerHTML = '';
    visible.forEach(function(m) {
      msgArea.appendChild(buildMessageEl(m, roleMap, canDelete));
    });
    pendings.forEach(function(p) {
      msgArea.appendChild(buildMessageEl(pendingMessage(p), roleMap, canDelete));
    });
    msgArea.scrollTop = msgArea.scrollHeight;
  }

  function pendingMessage(p) {
    return {
      tempId: p.clientMsgId,
      user_id: currentUserId,
      username: selfUsername,
      display_name: selfName,
      avatar: selfAvatar,
      body: p.body,
      proto: 'plain',
      created_at: p.createdAt,
      pendingStatus: p.status,
      pendingError: p.error,
      attachmentName: p.fileName
    };
  }

  function buildMessageEl(m, roleMap, canDelete) {
    var isSelf = m.user_id === currentUserId;
    var isPending = !!m.pendingStatus;
    var div = document.createElement('div');
    div.className = 'room-msg' + (isSelf ? ' self' : '') + (isPending ? ' room-msg-pending' : '');
    if (isPending) div.setAttribute('data-pending-id', m.tempId);
    else div.setAttribute('data-msg-id', m.id);

    var bodyDiv = document.createElement('div');
    bodyDiv.className = 'room-msg-body';

    var rowDiv = document.createElement('div');
    rowDiv.className = 'room-msg-row';
    var wrap = document.createElement('div');
    wrap.className = 'room-msg-avatar-wrap';
    if (m.avatar) {
      var img = document.createElement('img');
      img.className = 'room-msg-avatar';
      img.src = m.avatar;
      img.alt = '';
      img.addEventListener('error', function() { this.style.display = 'none'; });
      wrap.appendChild(img);
    } else {
      var letter = document.createElement('span');
      letter.className = 'room-msg-avatar room-msg-avatar-letter';
      letter.textContent = String(m.display_name || m.username || '?')[0].toUpperCase();
      wrap.appendChild(letter);
    }
    rowDiv.appendChild(wrap);

    var innerDiv = document.createElement('div');
    innerDiv.className = 'room-msg-body-inner';

    var headerDiv = document.createElement('div');
    headerDiv.className = 'room-msg-header';
    var color = roleMap[m.user_id] || '#ccc';
    if (!/^#[0-9a-fA-F]{6}$/.test(color)) color = '#ccc';
    var author = document.createElement('span');
    author.className = 'room-msg-author';
    author.style.color = color;
    author.textContent = m.display_name || m.username;
    var time = document.createElement('span');
    time.className = 'room-msg-time';
    time.textContent = relTime(m.created_at);
    headerDiv.appendChild(author);
    headerDiv.appendChild(time);
    if (isSelf) headerDiv.appendChild(messageStatus(m.pendingStatus || 'sent', m.pendingError));
    innerDiv.appendChild(headerDiv);

    var textSpan = document.createElement('span');
    textSpan.className = 'room-msg-text';
    if (m.proto === 'megolm') {
      div.setAttribute('data-proto', 'megolm');
      div.setAttribute('data-sender-id', m.user_id);
      div.setAttribute('data-ciphertext', m.ciphertext || '');
      div.setAttribute('data-group-session-id', m.group_session_id || '');
      textSpan.textContent = '';
    } else if (m.proto === 'mls') {
      div.setAttribute('data-proto', 'mls');
      div.setAttribute('data-sender-id', m.user_id);
      div.setAttribute('data-ciphertext', m.ciphertext || '');
      textSpan.textContent = '';
    } else {
      textSpan.textContent = m.body;
    }
    innerDiv.appendChild(textSpan);
    if (isPending && m.attachmentName) {
      var att = document.createElement('span');
      att.className = 'room-msg-attachment';
      att.textContent = m.attachmentName;
      innerDiv.appendChild(att);
    }
    if (m.edited_at) {
      var editedSpan = document.createElement('span');
      editedSpan.className = 'edited-indicator';
      editedSpan.textContent = '(edited)';
      editedSpan.title = new Date(m.edited_at).toLocaleString();
      innerDiv.appendChild(editedSpan);
    }
    rowDiv.appendChild(innerDiv);
    bodyDiv.appendChild(rowDiv);

    if (!isPending) {
      var actionsDiv = document.createElement('div');
      actionsDiv.className = 'room-msg-actions';
      var menuWrap = document.createElement('span');
      menuWrap.className = 'comment-menu-container room-msg-menu';
      var menuBtn = document.createElement('button');
      menuBtn.className = 'comment-menu-btn';
      menuBtn.title = 'More actions';
      menuBtn.setAttribute('aria-label', 'More actions');
      if (window.DSHIcons) menuBtn.appendChild(window.DSHIcons.icon('more', 14));
      var menu = document.createElement('div');
      menu.className = 'comment-menu';
      menu.style.display = 'none';
      if (m.user_id === currentUserId) {
        var editBtn = document.createElement('button');
        editBtn.className = 'edit-comment-btn room-msg-edit';
        editBtn.dataset.msgId = m.id;
        editBtn.textContent = 'Edit';
        menu.appendChild(editBtn);
      }
      if (m.user_id === currentUserId || canDelete) {
        var delBtn = document.createElement('button');
        delBtn.className = 'delete-comment-btn room-msg-delete';
        delBtn.dataset.msgId = m.id;
        delBtn.textContent = 'Delete';
        menu.appendChild(delBtn);
      }
      var reportBtn = document.createElement('button');
      reportBtn.type = 'button';
      reportBtn.className = 'report-item';
      reportBtn.setAttribute('data-report', 'room_message');
      reportBtn.setAttribute('data-report-id', String(m.id));
      reportBtn.setAttribute('data-report-snapshot', '.room-msg-text');
      reportBtn.textContent = 'Report';
      menu.appendChild(reportBtn);
      menuWrap.appendChild(menuBtn);
      menuWrap.appendChild(menu);
      actionsDiv.appendChild(menuWrap);
      bodyDiv.appendChild(actionsDiv);
    }

    div.appendChild(bodyDiv);
    return div;
  }

  function messageStatus(state, error) {
    var span = document.createElement('span');
    span.className = 'room-msg-status ' + state;
    var label = state === 'sending' ? 'Sending…' : state === 'failed' ? (error || 'Failed to send') : 'Sent';
    span.title = label;
    span.setAttribute('role', 'img');
    span.setAttribute('aria-label', label);
    if (window.DSHIcons) {
      var name = state === 'sending' ? 'clock' : state === 'failed' ? 'alert' : 'checkDouble';
      span.appendChild(window.DSHIcons.icon(name, 13));
    }
    return span;
  }

  function findPending(clientMsgId) {
    for (var i = 0; i < pendingSends.length; i++) {
      if (pendingSends[i].clientMsgId === clientMsgId) return pendingSends[i];
    }
    return null;
  }

  function markPendingSent(pending, msgId, ciphertext) {
    if (!pending) return;
    pending.status = 'sent';
    pending.msgId = String(msgId);
    if (pending.plaintext && ciphertext && window.ExtrovertMLS && window.ExtrovertMLS.rememberPlaintext) {
      window.ExtrovertMLS.rememberPlaintext(window.ExtrovertMLS.roomCacheKey(msgId, ciphertext), pending.plaintext);
    }
  }

  function metaContent(name) {
    var el = document.querySelector('meta[name="' + name + '"]');
    return el ? el.getAttribute('content') : '';
  }

  function cancelEditRoomMsg(msgDiv, btn, originalText) {
    var input = msgDiv.querySelector('.room-msg-edit-input');
    if (input) {
      var span = document.createElement('span');
      span.className = 'room-msg-text';
      span.textContent = originalText;
      input.replaceWith(span);
    }
    var cancelBtn = msgDiv.querySelector('.room-msg-cancel');
    if (cancelBtn) cancelBtn.remove();
    btn.textContent = 'Edit';
    btn.classList.remove('room-msg-save');
    btn.classList.add('room-msg-edit');
  }

  function escHtml(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function getCsrf() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) return meta.content;
    var inp = sendForm.querySelector('input[name="_csrf"]');
    return inp ? inp.value : '';
  }
  function roomId() { return window.location.pathname.split('/')[2]; }

function relTime(ts) {
    var s = Math.max(1, Math.floor((Date.now() - ts) / 1000));
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm';
    if (s < 86400) return Math.floor(s / 3600) + 'h';
    if (s < 604800) return Math.floor(s / 86400) + 'd';
    return new Date(ts).toLocaleDateString();
  }
});