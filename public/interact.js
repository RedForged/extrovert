document.addEventListener('DOMContentLoaded', function(){
  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';
  var relTime = window.relTime || function(t){ return new Date(t).toLocaleString(); };

  document.addEventListener('submit', function(e){
    var form = e.target;
    var confirmMsg = form.getAttribute('data-confirm');
    if (confirmMsg && !confirm(confirmMsg)) { e.preventDefault(); return; }
    var action = form.getAttribute('action') || '';
    var m = action.match(/^\/posts\/(\d+)\/(like|share|repost|follow-from|comment|delete)$/);
    if (!m) return;

    var postId = m[1], verb = m[2];
    var postEl = form.closest('.post');
    if (!postEl) return;
    e.preventDefault();

    var body = {};
    if (verb === 'comment') {
      var input = form.querySelector('input[name="body"]');
      if (!input || !input.value.trim()) return;
      body.body = input.value;
    }

    fetch(action, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRF-Token': csrfToken,
      },
      body: verb === 'comment' ? JSON.stringify(body) : undefined,
    })
    .then(function(r){ return r.json(); })
    .then(function(data){
      if (data.error) return;
      switch (verb) {
        case 'like':
          updateStats(postEl, 'like', data.liked, data.likeCount);
          toggleBtn(form, data.liked ? 'Liked' : 'Like', data.liked, 'heart');
          break;
        case 'share':
          updateStats(postEl, 'share', data.shared, data.shareCount);
          toggleBtn(form, 'Share', data.shared, 'share');
          break;
        case 'repost':
          showToast('Reposted!');
          break;
        case 'follow-from':
          form.remove();
          break;
        case 'comment':
          if (data.comment) {
            addCommentHtml(postEl, data.comment, relTime);
            var inp = form.querySelector('input[name="body"]');
            if (inp) inp.value = '';
          }
          break;
        case 'delete':
          postEl.remove();
          break;
      }
    })
    .catch(function(){});
  });

  // Icon names per stat type, matching partials/post.ejs which tags each stat
  // span with data-stat="like|comment|share" and renders the same SVG icons.
  var STAT_ICONS = { like: 'heart', comment: 'comment', share: 'share' };

  function statSpan(stats, type) {
    return stats.querySelector('span[data-stat="' + type + '"]');
  }

  function setStatCount(span, iconName, count) {
    span.textContent = '';
    if (window.DSHIcons) {
      var ico = document.createElement('span');
      ico.className = 'ico';
      ico.style.display = 'inline-flex';
      ico.appendChild(window.DSHIcons.icon(iconName, 14));
      span.appendChild(ico);
    }
    span.appendChild(document.createTextNode(' ' + count));
  }

  function updateStats(postEl, type, active, count){
    var stats = postEl.querySelector('.post-stats');
    if (!stats) return;
    var span = statSpan(stats, type);
    if (!span) return;
    if (type === 'like') {
      var icoEl = span.querySelector('.ico');
      if (icoEl && window.DSHIcons) {
        icoEl.replaceChildren(window.DSHIcons.icon(active ? 'heartFilled' : 'heart', 14));
      }
    }
    // Update only the trailing count node so the SVG icon stays intact.
    var last = span.lastChild;
    if (last && last.nodeType === Node.TEXT_NODE) last.textContent = ' ' + count;
    else setStatCount(span, STAT_ICONS[type], count);
  }

  function toggleBtn(form, text, active, iconName){
    var btn = form.querySelector('button');
    if (!btn) return;
    btn.textContent = text;
    if (iconName && window.DSHIcons) {
      var fillable = !!window.DSHIcons.PATHS[iconName + 'Filled'];
      btn.insertBefore(window.DSHIcons.icon(active && fillable ? iconName + 'Filled' : iconName, 15, 'ico'), btn.firstChild);
    }
    if (active) btn.classList.add('active');
    else btn.classList.remove('active');
  }

  function addCommentHtml(postEl, c, timeFn){
    var commentsDiv = postEl.querySelector('.post-comments');
    if (!commentsDiv) return;
    var form = commentsDiv.querySelector('.comment-form');
    var postIdMatch = form ? form.getAttribute('action').match(/\/posts\/(\d+)/) : null;
    var postIdVal = postIdMatch ? postIdMatch[1] : '';
    var div = document.createElement('div');
    div.className = 'comment';
    div.dataset.commentId = c.id;
    var t = typeof timeFn === 'function' ? timeFn(c.created_at) : new Date(c.created_at).toLocaleString();
    var sticker = c.body && c.body.indexOf('/uploads/stickers/') !== -1;
    var editedHtml = c.edited_at ? ' <a href="/posts/' + c.id + '/history?type=comment&post_id=' + postIdVal + '" class="edited-link">(edited)</a>' : '';
    var ownMenuHtml = '<div class="comment-menu-container"><button class="comment-menu-btn" title="More"></button><div class="comment-menu" style="display:none"><button class="edit-comment-btn">Edit</button><form method="post" action="/posts/' + postIdVal + '/comments/' + c.id + '/delete" class="delete-comment-form"><input type="hidden" name="_csrf" value="' + csrfToken + '"><button class="delete-comment-btn">Delete</button></form></div></div>';
    var dataHtml = '<input type="hidden" class="edit-comment-data" value="' + esc(c.body) + '" data-csrf="' + csrfToken + '" data-action="/posts/' + postIdVal + '/comments/' + c.id + '/edit">';
    div.innerHTML = '<div class="comment-head"><div><b>' + esc(c.display_name) + '</b> <span class="post-handle">@' + esc(c.username) + '</span> <span class="post-time">· ' + t + '</span>' + editedHtml + '</div>' + ownMenuHtml + '</div><span class="comment-body">' + (sticker ? '<img src="' + esc(c.body) + '" class="sticker-inline" style="max-width:120px;max-height:120px;vertical-align:middle" alt="sticker">' : esc(c.body)) + '</span>' + dataHtml;
    var menuBtn = div.querySelector('.comment-menu-btn');
    if (menuBtn && window.DSHIcons) menuBtn.appendChild(window.DSHIcons.icon('more', 16));
    if (form) commentsDiv.insertBefore(div, form);
    else commentsDiv.appendChild(div);
    // Update comment count in stats.
    var stats = postEl.querySelector('.post-stats');
    if (stats) {
      var span = statSpan(stats, 'comment');
      if (span) {
        var current = parseInt(span.textContent.replace(/[^0-9]/g, ''), 10) || 0;
        setStatCount(span, STAT_ICONS.comment, current + 1);
      }
    }
  }

  function esc(s){
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  // Close all comment menus
  function closeCommentMenus() {
    document.querySelectorAll('.comment-menu').forEach(function(m){ m.style.display = 'none'; });
  }

  // Inline editing helpers
  function replaceWithInput(el, className, multiline, saveFn, cancelFn, noButtons) {
    var origText = el.textContent.trim();
    var input;
    if (multiline) {
      input = document.createElement('textarea');
    } else {
      input = document.createElement('input');
      input.type = 'text';
    }
    input.className = 'inline-edit-input ' + className;
    input.value = origText;
    el.replaceWith(input);

    // Save and Cancel buttons
    if (!noButtons) {
      var btnWrap = document.createElement('span');
      btnWrap.className = 'inline-edit-btns';
      btnWrap.style.cssText = 'display:inline-flex;gap:4px;margin-left:4px;vertical-align:middle';
      if (multiline) {
        btnWrap.style.cssText = 'display:flex;gap:6px;margin-top:6px';
      }

      var saveBtn = document.createElement('button');
      saveBtn.className = 'btn inline-save-btn';
      saveBtn.textContent = 'Save';
      saveBtn.type = 'button';
      saveBtn.style.cssText = 'font-size:12px;padding:4px 12px;cursor:pointer';
      saveBtn.addEventListener('click', function() { finish(true); });

      var cancelBtn = document.createElement('button');
      cancelBtn.className = 'btn ghost inline-cancel-btn';
      cancelBtn.textContent = 'Cancel';
      cancelBtn.type = 'button';
      cancelBtn.style.cssText = 'font-size:12px;padding:4px 12px;cursor:pointer';
      cancelBtn.addEventListener('click', function() { finish(false); });

      btnWrap.appendChild(saveBtn);
      btnWrap.appendChild(cancelBtn);
      input.parentNode.insertBefore(btnWrap, input.nextSibling);
    }

    input.focus();
    if (!multiline) input.setSelectionRange(input.value.length, input.value.length);

    function finish(save) {
      if (save) {
        var val = input.value.trim();
        if (val && val !== origText) {
          if (!noButtons) { saveBtn.disabled = true; saveBtn.textContent = 'Saving…'; }
          saveFn(val, function() {
            var span = document.createElement(el.tagName);
            span.className = el.className;
            span.textContent = val;
            restore(span);
          }, function() {
            if (!noButtons) { saveBtn.disabled = false; saveBtn.textContent = 'Save'; }
            input.value = origText;
            cancel();
          });
          return;
        }
      }
      cancel();
    }

    function cancel() {
      var span = document.createElement(el.tagName);
      span.className = el.className;
      span.textContent = origText;
      restore(span);
      if (cancelFn) cancelFn();
    }

    function restore(span) {
      input.replaceWith(span);
      if (btnWrap) btnWrap.remove();
    }

    input.addEventListener('keydown', function(ev) {
      if (ev.key === 'Escape') { finish(false); ev.preventDefault(); }
      if (ev.key === 'Enter' && !multiline) { finish(true); ev.preventDefault(); }
    });
    input.addEventListener('blur', function() {
      setTimeout(function() { if (!input.parentNode) return; finish(false); }, 200);
    });
    return { input, finish, cancel };
  }

  // Edit post / comment / chat message toggles
  document.addEventListener('click', function(e){
    // Close menus on outside click
    if (!e.target.closest('.comment-menu-container')) {
      closeCommentMenus();
    }

    var commentMenuBtn = e.target.closest('.comment-menu-btn');
    if (commentMenuBtn) {
      e.preventDefault();
      e.stopPropagation();
      var menu = commentMenuBtn.parentNode.querySelector('.comment-menu');
      if (!menu) return;
      var isOpen = menu.style.display !== 'none';
      closeCommentMenus();
      menu.style.display = isOpen ? 'none' : 'block';
      return;
    }

    // --- Inline post editing ---
    var editPostBtn = e.target.closest('.edit-post-btn');
    if (editPostBtn) {
      e.preventDefault();
      var postEl = editPostBtn.closest('.post');
      if (!postEl || postEl.querySelector('.inline-edit-input')) return;
      var bodyEl = postEl.querySelector('.post-body');
      var dataEl = postEl.querySelector('.edit-post-data');
      if (!bodyEl || !dataEl) return;
      var action = dataEl.dataset.action;
      var csrf = dataEl.dataset.csrf;
      editPostBtn.style.display = 'none';
      var deleteBtn = postEl.querySelector('.post-actions .btn.ghost.danger');
      if (deleteBtn) deleteBtn.style.display = 'none';
      var postActions = postEl.querySelector('.post-actions');
      var editActions = document.createElement('span');
      editActions.className = 'inline-edit-btns';
      editActions.style.marginLeft = 'auto';
      var saveBtn = document.createElement('button');
      saveBtn.className = 'btn inline-save-btn';
      saveBtn.textContent = 'Save';
      saveBtn.type = 'button';
      var cancelBtn = document.createElement('button');
      cancelBtn.className = 'btn ghost inline-cancel-btn';
      cancelBtn.textContent = 'Cancel';
      cancelBtn.type = 'button';
      editActions.appendChild(saveBtn);
      editActions.appendChild(cancelBtn);
      postActions.appendChild(editActions);
      function showEditBtn() {
        editPostBtn.style.display = '';
        if (deleteBtn) deleteBtn.style.display = '';
        if (editActions.parentNode) editActions.remove();
      }
      var editState = replaceWithInput(bodyEl, 'post-body-edit', true,
        function(val, onSuccess) {
          fetch(action, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf },
            body: 'body=' + encodeURIComponent(val) + '&_csrf=' + encodeURIComponent(csrf),
          }).then(function(r){ return r.json(); }).then(function(d){
            if (d.ok) { onSuccess(); showEditBtn(); } else { location.reload(); }
          });
        },
        showEditBtn,
        true
      );
      saveBtn.addEventListener('click', function() { editState.finish(true); });
      cancelBtn.addEventListener('click', function() { editState.finish(false); });
      return;
    }

    // --- Inline comment editing ---
    var editCommentBtn = e.target.closest('.edit-comment-btn');
    if (editCommentBtn) {
      e.preventDefault();
      closeCommentMenus();
      var commentDiv = editCommentBtn.closest('.comment');
      if (!commentDiv || commentDiv.querySelector('.inline-edit-input')) return;
      var bodyEl = commentDiv.querySelector('.comment-body');
      var dataEl = commentDiv.querySelector('.edit-comment-data');
      if (!bodyEl || !dataEl) return;
      var action = dataEl.dataset.action;
      var csrf = dataEl.dataset.csrf;
      var origText = bodyEl.textContent.trim();

      var r = replaceWithInput(bodyEl, 'comment-body-edit', false,
        function(val, onSuccess) {
          fetch(action, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrf },
            body: 'body=' + encodeURIComponent(val) + '&_csrf=' + encodeURIComponent(csrf),
          }).then(function(r){ return r.json(); }).then(function(d){
            if (d.ok) { onSuccess(); } else { r.cancel(); }
          });
        }
      );
      return;
    }

    // --- Delete comment ---
    var deleteCommentBtn = e.target.closest('.delete-comment-btn');
    if (deleteCommentBtn) {
      e.preventDefault();
      closeCommentMenus();
      if (!confirm('Delete this comment?')) return;
      var form = deleteCommentBtn.closest('.delete-comment-form');
      var commentDiv = deleteCommentBtn.closest('.comment');
      var postEl = commentDiv ? commentDiv.closest('.post') : null;
      fetch(form.getAttribute('action'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-Token': csrfToken },
        body: new URLSearchParams(Array.from(new FormData(form))),
      }).then(function(r){ return r.json(); }).then(function(d){
        if (d.ok) {
          if (commentDiv) commentDiv.remove();
          var stats = postEl ? postEl.querySelector('.post-stats') : null;
          if (stats) {
            var span = statSpan(stats, 'comment');
            if (span) {
              var current = parseInt(span.textContent.replace(/[^0-9]/g, ''), 10) || 0;
              setStatCount(span, STAT_ICONS.comment, Math.max(0, current - 1));
            }
          }
        }
      });
      return;
    }

  });

  function showToast(msg){
    var el = document.createElement('div');
    el.textContent = msg;
    el.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:8px 16px;border-radius:8px;font-size:14px;z-index:9999;opacity:0;transition:opacity .3s';
    document.body.appendChild(el);
    requestAnimationFrame(function(){ el.style.opacity = '1'; });
    setTimeout(function(){ el.style.opacity = '0'; setTimeout(function(){ el.remove(); }, 300); }, 1500);
  }
});
