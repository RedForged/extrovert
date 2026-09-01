document.addEventListener('DOMContentLoaded', function() {
  var msgArea = document.getElementById('room-messages');
  var currentUserId = msgArea ? parseInt(msgArea.dataset.userId, 10) : 0;
  var sendForm = document.getElementById('room-send-form');
  var channelList = document.getElementById('channel-list');
  var channelName = document.getElementById('channel-name');
  var reportOverlay = document.getElementById('report-overlay');
  var reportForm = document.getElementById('report-form');

  if (!msgArea || !sendForm || !channelList) return;

  loadMessages(msgArea.dataset.channelId);

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

  sendForm.addEventListener('submit', function(e) {
    e.preventDefault();
    var cid = sendForm.dataset.channelId;
    if (!cid) return;
    var input = sendForm.querySelector('input[name="body"]');
    var body = input.value.trim();
    if (!body) return;
    input.disabled = true;

    var csrf = getCsrf();
    var url = '/rooms/' + roomId() + '/channels/' + cid + '/send';
    var doPost = function(params) {
      fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf },
        body: params
      }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.error) { input.disabled = false; return; }
        input.value = '';
        input.disabled = false;
        input.focus();
        loadMessages(cid);
      }).catch(function() { input.disabled = false; });
    };

    var e2ee = window.ExtrovertRoomE2EE;
    if (e2ee && e2ee.ready()) {
      e2ee.encryptMessage(body).then(function(r) {
        doPost('proto=megolm&ciphertext=' + encodeURIComponent(r.ciphertext) + '&group_session_id=' + encodeURIComponent(r.group_session_id));
      }).catch(function() { input.disabled = false; });
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
        }).then(function(r) { return r.json(); }).then(function(d) {
          if (d.ok) {
            loadMessages(cid);
          } else {
            cancelEditRoomMsg(msgDiv, saveBtn, newBody);
          }
        });
      };
      var e2ee = window.ExtrovertRoomE2EE;
      if (e2ee && e2ee.ready()) {
        e2ee.encryptMessage(newBody).then(function(r) {
          doEditPost('proto=megolm&ciphertext=' + encodeURIComponent(r.ciphertext) + '&group_session_id=' + encodeURIComponent(r.group_session_id));
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
        if (d.ok) loadMessages(cid);
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
        renderMessages(data.messages || [], data.roleMap || {}, data.canDelete);
      });
  }

  function renderMessages(messages, roleMap, canDelete) {
    if (!messages || !messages.length) {
      msgArea.innerHTML = '<div class="room-msg"><div class="room-msg-body"><div class="room-msg-body-inner"><span class="muted">No messages yet</span></div></div></div>';
      return;
    }
      msgArea.innerHTML = '';
    messages.forEach(function(m) {
      var div = document.createElement('div');
      div.className = 'room-msg' + (m.user_id === currentUserId ? ' self' : '');
      div.setAttribute('data-msg-id', m.id);
      var bodyDiv = document.createElement('div');
      bodyDiv.className = 'room-msg-body';
      var headerDiv = document.createElement('div');
      headerDiv.className = 'room-msg-header';
      var color = roleMap[m.user_id] || '#ccc';
      headerDiv.innerHTML = '<span class="room-msg-author" style="color:' + color + '">' + escHtml(m.display_name || m.username) + '</span><span class="room-msg-time">' + relTime(m.created_at) + '</span>';
      bodyDiv.appendChild(headerDiv);
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
        letter.textContent = (m.display_name || m.username)[0].toUpperCase();
        wrap.appendChild(letter);
      }
      rowDiv.appendChild(wrap);
      var innerDiv = document.createElement('div');
      innerDiv.className = 'room-msg-body-inner';
      innerDiv.appendChild(headerDiv);
      var textSpan = document.createElement('span');
      textSpan.className = 'room-msg-text';
      if (m.proto === 'megolm') {
        div.setAttribute('data-proto', 'megolm');
        div.setAttribute('data-sender-id', m.user_id);
        div.setAttribute('data-ciphertext', m.ciphertext || '');
        div.setAttribute('data-group-session-id', m.group_session_id || '');
        textSpan.textContent = '';
      } else {
        textSpan.textContent = m.body;
      }
      innerDiv.appendChild(textSpan);
      if (m.edited_at) {
        var editedSpan = document.createElement('span');
        editedSpan.className = 'edited-indicator';
        editedSpan.textContent = '(edited)';
        editedSpan.title = new Date(m.edited_at).toLocaleString();
        innerDiv.appendChild(editedSpan);
      }
      rowDiv.appendChild(innerDiv);
      bodyDiv.appendChild(rowDiv);
      var actionsDiv = document.createElement('div');
      actionsDiv.className = 'room-msg-actions';
      if (m.user_id === currentUserId) {
        var editSpan = document.createElement('span');
        editSpan.className = 'room-msg-edit';
        editSpan.dataset.msgId = m.id;
        editSpan.textContent = 'Edit';
        actionsDiv.appendChild(editSpan);
      }
      if (m.user_id === currentUserId || canDelete) {
        var delSpan = document.createElement('span');
        delSpan.className = 'room-msg-delete';
        delSpan.dataset.msgId = m.id;
        delSpan.textContent = 'Delete';
        actionsDiv.appendChild(delSpan);
      }
      var reportSpan = document.createElement('span');
      reportSpan.className = 'room-msg-report';
      reportSpan.dataset.msgId = m.id;
      reportSpan.textContent = 'Report';
      actionsDiv.appendChild(reportSpan);
      bodyDiv.appendChild(actionsDiv);
      div.appendChild(bodyDiv);
      msgArea.appendChild(div);
    });
    msgArea.scrollTop = msgArea.scrollHeight;
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