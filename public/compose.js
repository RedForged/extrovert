(function(){
  var tabs = document.querySelectorAll('#typeTabs button');
  var field = document.getElementById('typeField');
  var wrap = document.getElementById('mediaWrap');
  if (!tabs.length || !field || !wrap) return;
  tabs.forEach(function(b){
    b.addEventListener('click', function(){
      tabs.forEach(function(x){ x.classList.remove('active'); });
      b.classList.add('active');
      field.value = b.dataset.type;
      wrap.style.display = (b.dataset.type === 'text') ? 'none' : 'block';
    });
  });
})();

// @mention autocomplete — a gentle chat bubble that appears under the @,
// tail pointing at the caret so friends can be mentioned without full names.
(function(){
  var input = document.getElementById('post-body');
  if (!input) return;
  var box = null, hideTimer = null, timer = null, items = [], sel = -1;

  function currentQuery() {
    var upto = input.value.slice(0, input.selectionStart);
    var m = upto.match(/(^|\s)@([a-zA-Z0-9_]{1,20})$/);
    return m ? m[2] : null;
  }

  function caretPoint() {
    var style = window.getComputedStyle(input);
    var div = document.createElement('div');
    div.style.cssText = 'position:absolute;top:0;left:0;visibility:hidden;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:break-word;';
    ['fontFamily', 'fontSize', 'fontWeight', 'letterSpacing', 'lineHeight', 'textTransform', 'textIndent',
     'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft', 'borderTopWidth', 'borderLeftWidth', 'boxSizing'
    ].forEach(function(p) { div.style[p] = style[p]; });
    div.style.width = input.offsetWidth + 'px';
    div.textContent = input.value.slice(0, input.selectionStart);
    var marker = document.createElement('span');
    marker.textContent = '\u200b';
    div.appendChild(marker);
    document.body.appendChild(div);
    var lineH = parseFloat(style.lineHeight) || (parseFloat(style.fontSize) * 1.5);
    var r = input.getBoundingClientRect();
    var pt = {
      x: r.left + window.scrollX + marker.offsetLeft - input.scrollLeft,
      y: r.top + window.scrollY + marker.offsetTop - input.scrollTop + lineH,
    };
    div.remove();
    return pt;
  }

  function hide() {
    items = []; sel = -1;
    if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
    if (!box) return;
    var el = box;
    box = null;
    el.classList.remove('visible');
    setTimeout(function() { el.remove(); }, 140);
  }

  function select(i) {
    sel = i;
    if (!box) return;
    var rows = box.querySelectorAll('.mention-suggest-item');
    Array.prototype.forEach.call(rows, function(el, idx) {
      el.classList.toggle('active', idx === i);
    });
  }

  function insert(username) {
    var caret = input.selectionStart;
    var before = input.value.slice(0, caret).replace(/(^|\s)@[a-zA-Z0-9_]{1,20}$/, '$1@' + username + ' ');
    input.value = before + input.value.slice(caret);
    input.setSelectionRange(before.length, before.length);
    input.focus();
    hide();
  }

  function show(users) {
    if (!users.length) { hide(); return; }
    items = users;
    if (box) box.remove();
    box = document.createElement('div');
    box.className = 'mention-suggest';
    users.forEach(function(u, i) {
      var row = document.createElement('button');
      row.type = 'button';
      row.className = 'mention-suggest-item';
      if (u.avatar) {
        var img = document.createElement('img');
        img.className = 'mention-avatar';
        img.src = u.avatar;
        img.alt = '';
        row.appendChild(img);
      } else {
        var av = document.createElement('span');
        av.className = 'mention-avatar mention-avatar-letter';
        av.textContent = (u.display_name || u.username).slice(0, 1).toUpperCase();
        row.appendChild(av);
      }
      var name = document.createElement('strong');
      name.textContent = '@' + u.username;
      var disp = document.createElement('span');
      disp.className = 'mention-display';
      disp.textContent = u.display_name || '';
      row.appendChild(name);
      row.appendChild(disp);
      row.addEventListener('mousedown', function(e) { e.preventDefault(); insert(u.username); });
      row.addEventListener('mouseenter', function() { select(i); });
      box.appendChild(row);
    });
    document.body.appendChild(box);

    var pt = caretPoint();
    var r = input.getBoundingClientRect();
    var bubbleW = box.offsetWidth;
    var left = Math.min(Math.max(pt.x - 18, r.left + window.scrollX), r.right + window.scrollX - bubbleW);
    var top = pt.y + 10;
    box.style.left = left + 'px';
    box.style.top = top + 'px';
    box.style.setProperty('--tail-x', Math.min(Math.max(pt.x - left - 6, 14), bubbleW - 26) + 'px');

    select(0);
    requestAnimationFrame(function() {
      if (box) box.classList.add('visible');
    });
  }

  function schedule() {
    clearTimeout(timer);
    var q = currentQuery();
    if (!q) { hide(); return; }
    if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
    timer = setTimeout(function() {
      fetch('/search/suggest?q=' + encodeURIComponent(q), {
        headers: { 'Accept': 'application/json' },
        credentials: 'same-origin'
      }).then(function(r) { return r.json(); })
        .then(function(d) { show((d && d.users) || []); })
        .catch(function() {});
    }, 150);
  }

  input.addEventListener('input', schedule);
  input.addEventListener('scroll', function() { if (box) hide(); });
  input.addEventListener('keydown', function(e) {
    if (!box) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); select(Math.min(sel + 1, items.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); select(Math.max(sel - 1, 0)); }
    else if ((e.key === 'Enter' || e.key === 'Tab') && sel >= 0) { e.preventDefault(); insert(items[sel].username); }
    else if (e.key === 'Escape') { hide(); }
  });
  input.addEventListener('blur', function() {
    hideTimer = setTimeout(hide, 140);
  });
  window.addEventListener('resize', function() { if (box) hide(); });
})();

// Live @mention highlight — a mirror layer under the textarea paints @tokens
// in the detail color while typing; the real caret keeps drawing on top.
(function(){
  var input = document.getElementById('post-body');
  if (!input) return;
  var mirror = document.createElement('div');
  mirror.className = 'compose-mirror';
  mirror.setAttribute('aria-hidden', 'true');
  input.classList.add('compose-highlight');
  var parent = input.parentNode;
  if (window.getComputedStyle(parent).position === 'static') parent.style.position = 'relative';
  parent.appendChild(mirror);

  function fit() {
    var style = window.getComputedStyle(input);
    ['fontFamily', 'fontSize', 'fontWeight', 'letterSpacing', 'lineHeight', 'textTransform', 'textIndent',
     'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft', 'borderTopWidth', 'borderRightWidth',
     'borderBottomWidth', 'borderLeftWidth', 'boxSizing'
    ].forEach(function(p) { mirror.style[p] = style[p]; });
    mirror.style.top = input.offsetTop + 'px';
    mirror.style.left = input.offsetLeft + 'px';
    mirror.style.width = input.offsetWidth + 'px';
    mirror.style.height = input.offsetHeight + 'px';
  }

  function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function paint() {
    var text = input.value;
    var re = /(^|[^\w@\/])(@[a-zA-Z0-9_]*)/g;
    var html = '';
    var last = 0;
    var m;
    while ((m = re.exec(text)) !== null) {
      var start = m.index + m[1].length;
      html += esc(text.slice(last, start));
      html += '<span class="mention-live">' + esc(m[2]) + '</span>';
      last = start + m[2].length;
    }
    html += esc(text.slice(last));
    mirror.innerHTML = html + '\n';
    mirror.scrollTop = input.scrollTop;
  }

  input.addEventListener('input', paint);
  input.addEventListener('scroll', function() { mirror.scrollTop = input.scrollTop; });
  window.addEventListener('resize', function() { fit(); paint(); });
  fit();
  paint();
})();
