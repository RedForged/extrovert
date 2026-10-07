(function () {
  'use strict';

  // One report flow for the whole app: any element with data-report opens a
  // modal, and the POST goes to /report. For end-to-end encrypted messages the
  // reporter's own view of the text is included, because the server can't read
  // it — data-report-snapshot names the element holding that text.

  var TYPE_LABELS = {
    post: 'post',
    comment: 'comment',
    user: 'profile',
    room_message: 'message',
    dm_message: 'message',
  };

  function csrf() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  var overlay = null;

  function buildModal() {
    overlay = document.createElement('div');
    overlay.className = 'report-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', 'report-title');
    overlay.hidden = true;
    overlay.innerHTML =
      '<div class="card report-card">' +
      '  <h3 id="report-title" style="margin-top:0">Report</h3>' +
      '  <p class="muted report-preview" id="report-preview" hidden></p>' +
      '  <label for="report-reason">What is wrong with it?</label>' +
      '  <input type="text" id="report-reason" maxlength="500" placeholder="Be specific — a human reads this" required>' +
      '  <div class="report-actions">' +
      '    <button class="btn" type="button" id="report-send">Send report</button>' +
      '    <button class="btn ghost" type="button" id="report-cancel">Cancel</button>' +
      '  </div>' +
      '  <p class="muted report-status" id="report-status" hidden></p>' +
      '</div>';
    document.body.appendChild(overlay);
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) close();
    });
    document.getElementById('report-cancel').addEventListener('click', close);
    document.getElementById('report-send').addEventListener('click', send);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') close();
    });
  }

  var current = null;

  function close() {
    if (!overlay) return;
    overlay.hidden = true;
    current = null;
    var status = document.getElementById('report-status');
    if (status) { status.hidden = true; status.textContent = ''; }
    var reason = document.getElementById('report-reason');
    if (reason) reason.value = '';
  }

  function open(btn) {
    if (!overlay) buildModal();
    var type = btn.getAttribute('data-report');
    var id = btn.getAttribute('data-report-id');
    if (!type || !id) return;

    var snapshot = '';
    var sel = btn.getAttribute('data-report-snapshot');
    if (sel) {
      var scope = btn.closest('.room-msg, .chat-msg, [data-report-scope]') || document;
      var el = scope.querySelector(sel);
      snapshot = el ? (el.textContent || '').trim().slice(0, 2000) : '';
    }

    current = {
      target_type: type,
      target_id: id,
      room_id: btn.getAttribute('data-room-id') || '',
      channel_id: btn.getAttribute('data-channel-id') || '',
      snapshot: snapshot,
    };

    document.getElementById('report-title').textContent = 'Report ' + (TYPE_LABELS[type] || 'content');
    var preview = document.getElementById('report-preview');
    if (snapshot) {
      preview.textContent = '"' + snapshot.slice(0, 300) + '"';
      preview.hidden = false;
    } else {
      preview.hidden = true;
    }
    var status = document.getElementById('report-status');
    status.hidden = true;
    overlay.hidden = false;
    var reason = document.getElementById('report-reason');
    if (reason) reason.focus();
  }

  function send() {
    if (!current) return;
    var reasonEl = document.getElementById('report-reason');
    var statusEl = document.getElementById('report-status');
    var reason = (reasonEl.value || '').trim();
    if (!reason) {
      statusEl.textContent = 'Please say what is wrong.';
      statusEl.hidden = false;
      reasonEl.focus();
      return;
    }

    var body = new URLSearchParams();
    body.set('_csrf', csrf());
    body.set('target_type', current.target_type);
    body.set('target_id', current.target_id);
    if (current.room_id) body.set('room_id', current.room_id);
    if (current.channel_id) body.set('channel_id', current.channel_id);
    if (current.snapshot) body.set('snapshot', current.snapshot);
    body.set('reason', reason);

    var sendBtn = document.getElementById('report-send');
    sendBtn.disabled = true;
    fetch('/report', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest',
        Accept: 'application/json',
      },
      body: body.toString(),
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j && j.error ? j.error : 'Report failed (' + r.status + ')');
        statusEl.textContent = 'Thanks — a moderator will review it.';
        statusEl.hidden = false;
        sendBtn.disabled = false;
        setTimeout(close, 1400);
      });
    }).catch(function (err) {
      sendBtn.disabled = false;
      statusEl.textContent = (err && err.message) || 'Report failed.';
      statusEl.hidden = false;
    });
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-report]');
    if (!btn) return;
    e.preventDefault();
    open(btn);
  });
})();
