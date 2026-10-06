(function () {
  'use strict';

  window.addEventListener('pageshow', function (e) {
    if (e.persisted) location.reload();
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  function init() {
    var list = document.getElementById('chats-list');
    if (!list) return;

    var bus = window.ExtrovertCall;
    if (!bus || !bus.on) return;
    if (bus.connect) bus.connect();

    bus.on('new_dm', function (data) {
      try {
        if (!data || !data.message) return;
        var msg = data.message;
        var row = rowFor(data.from_username) || rowFor(data.to_username);
        if (!row) {
          location.reload();
          return;
        }
        var preview = row.querySelector('.chat-preview');
        if (preview && msg.body) {
          preview.setAttribute('data-body', msg.body);
          preview.setAttribute('data-proto', msg.proto || 'mls');
          preview.textContent = msg.body.indexOf('/uploads/stickers/') === 0 ? 'Sticker' : '…';
        }
        var myId = (document.querySelector('meta[name="current-user-id"]') || {}).content;
        var badge = row.querySelector('.badge');
        if (String(msg.from_id) !== String(myId)) {
          var count = badge ? (parseInt(badge.textContent, 10) || 0) + 1 : 1;
          if (badge) {
            badge.textContent = count;
          } else {
            badge = document.createElement('sup');
            badge.className = 'badge';
            badge.textContent = count;
            row.appendChild(badge);
          }
        }
        list.insertBefore(row, list.firstChild);
      } catch (err) {}
    });

    bus.on('edit_dm', function (data) {
      try {
        if (!data || !data.message) return;
        var msg = data.message;
        var row = rowFor(data.from_username) || rowFor(data.to_username);
        if (!row) return;
        var preview = row.querySelector('.chat-preview');
        if (preview && msg.body) {
          preview.setAttribute('data-body', msg.body);
          preview.textContent = msg.body.indexOf('/uploads/stickers/') === 0 ? 'Sticker' : '…';
        }
      } catch (err) {}
    });
  }

  function rowFor(username) {
    if (!username) return null;
    return document.querySelector('#chats-list a.conv-row[href="/chats/' + username + '"]');
  }
})();
