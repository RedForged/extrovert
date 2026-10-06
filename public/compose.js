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

// @mention autocomplete for the post body
(function(){
  var input = document.getElementById('post-body');
  if (!input) return;
  var box = null, timer = null, items = [], sel = -1;

  function currentQuery() {
    var upto = input.value.slice(0, input.selectionStart);
    var m = upto.match(/(^|\s)@([a-zA-Z0-9_]{1,20})$/);
    return m ? m[2] : null;
  }

  function hide() {
    if (box) { box.remove(); box = null; }
    items = []; sel = -1;
  }

  function positionBox() {
    var r = input.getBoundingClientRect();
    box.style.left = r.left + window.scrollX + 'px';
    box.style.top = (r.bottom + window.scrollY + 4) + 'px';
    box.style.width = Math.min(r.width, 360) + 'px';
  }

  function select(i) {
    sel = i;
    if (!box) return;
    Array.prototype.forEach.call(box.children, function(el, idx) {
      el.style.background = idx === i ? 'rgba(127,127,127,0.15)' : 'none';
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
    hide();
    if (!users.length) return;
    items = users;
    box = document.createElement('div');
    box.className = 'mention-suggest';
    box.style.cssText = 'position:absolute;z-index:1000;background:var(--surface);border:1px solid var(--border);border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,0.35);overflow:hidden';
    users.forEach(function(u, i) {
      var row = document.createElement('button');
      row.type = 'button';
      row.style.cssText = 'display:flex;align-items:baseline;gap:8px;width:100%;padding:8px 10px;background:none;border:none;cursor:pointer;text-align:left;font:inherit;color:inherit';
      var name = document.createElement('strong');
      name.textContent = '@' + u.username;
      var disp = document.createElement('span');
      disp.className = 'muted';
      disp.style.cssText = 'font-size:0.8rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
      disp.textContent = u.display_name || '';
      row.appendChild(name);
      row.appendChild(disp);
      row.addEventListener('click', function() { insert(u.username); });
      row.addEventListener('mouseenter', function() { select(i); });
      box.appendChild(row);
    });
    document.body.appendChild(box);
    positionBox();
    select(0);
  }

  function schedule() {
    clearTimeout(timer);
    var q = currentQuery();
    if (!q) { hide(); return; }
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
  input.addEventListener('keydown', function(e) {
    if (!box) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); select(Math.min(sel + 1, items.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); select(Math.max(sel - 1, 0)); }
    else if (e.key === 'Enter' && sel >= 0) { e.preventDefault(); insert(items[sel].username); }
    else if (e.key === 'Escape') { hide(); }
  });
  input.addEventListener('blur', function() { setTimeout(hide, 150); });
  window.addEventListener('resize', function() { if (box) positionBox(); });
})();
