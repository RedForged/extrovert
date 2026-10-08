// Easy Editing — a styling tool for the profile page.
//
// You don't edit HTML boxes here. You click a named PART of the page (post,
// post text, avatar, bio, …) and change it with real controls — colour, edges,
// spacing, type, effects. Live content is styled with a CSS RULE keyed by the
// part's selector, so one edit restyles every post/comment; your own authored
// elements are styled inline. Everything still compiles to plain CSS/HTML, so
// Advanced mode shows exactly the same document.
//
// External script only (CSP: script-src 'self', no inline handlers).
(function () {
  'use strict';

  var VOID_TAGS = { br: 1, hr: 1, img: 1, col: 1 };

  var THEME_SWATCHES = [
    ['--primary', 'Primary'], ['--primary-strong', 'Primary +'], ['--secondary', 'Cyan'],
    ['--accent', 'Gold'], ['--success', 'Green'], ['--danger', 'Red'],
    ['--text', 'Text'], ['--text-secondary', 'Text 2'], ['--text-muted', 'Text muted'],
    ['--surface', 'Surface'], ['--surface-2', 'Surface 2'], ['--border', 'Border'],
  ];

  var GRADIENTS = [
    ['Soft primary', 'linear-gradient(135deg, var(--primary-soft), var(--secondary-soft))'],
    ['Surfaces', 'linear-gradient(135deg, var(--surface), var(--surface-2))'],
    ['Primary', 'linear-gradient(135deg, var(--primary), var(--secondary))'],
  ];

  var WEIGHTS = [
    ['Default', ''], ['Light 300', '300'], ['Regular 400', '400'], ['Medium 500', '500'],
    ['Semi 600', '600'], ['Bold 700', '700'],
  ];

  var FONTS = [
    ['App body', ''], ['Display serif', 'var(--font-display)'],
    ['Monospace', 'ui-monospace, SFMono-Regular, Menlo, monospace'],
  ];

  var SHADOWS = [
    ['None', 'none'], ['Soft', '0 1px 2px rgba(0,0,0,0.3)'],
    ['Lifted', '0 8px 24px rgba(0,0,0,0.35)'], ['Glow', '0 0 0 3px var(--primary-soft)'],
  ];

  // Friendly, selector-backed parts. Deepest match wins when you click.
  var PARTS = [
    { label: 'Profile header', group: 'Header', selector: '.profile-header' },
    { label: 'Avatar', group: 'Header', selector: '[data-ev-slot="avatar"] img, [data-ev-slot="avatar"] .avatar' },
    { label: 'Display name', group: 'Header', selector: '.profile-header h1' },
    { label: 'Handle', group: 'Header', selector: '[data-ev-slot="handle"]' },
    { label: 'Pronouns', group: 'Header', selector: '.pronouns' },
    { label: 'Bio', group: 'Header', selector: '.bio' },
    { label: 'Follower stats', group: 'Header', selector: '.profile-stats' },
    { label: 'Follow button', group: 'Header', selector: '[data-ev-slot="follow"] .btn' },

    { label: 'Posts list', group: 'Posts', selector: '.ev-posts-wrap' },
    { label: 'Post card', group: 'Posts', selector: '.post' },
    { label: 'Post author', group: 'Posts', selector: '.post-name' },
    { label: 'Post handle / time', group: 'Posts', selector: '.post-handle, .post-time' },
    { label: 'Post text', group: 'Posts', selector: '.post-body' },
    { label: 'Post image / video', group: 'Posts', selector: '.post-media' },
    { label: 'Post stats', group: 'Posts', selector: '.post-stats' },
    { label: 'Post buttons', group: 'Posts', selector: '.post-actions button' },

    { label: 'Comments', group: 'Comments', selector: '.comment' },
    { label: 'Comment text', group: 'Comments', selector: '.comment-body' },
    { label: 'Comment box', group: 'Comments', selector: '.comment-form input' },
    { label: 'Comment button', group: 'Comments', selector: '.comment-form button' },

    { label: 'Page background', group: 'Page', selector: 'body' },
  ];

  var SLOT_LABELS = {
    avatar: 'Avatar', displayName: 'Display name', handle: 'Handle', pronouns: 'Pronouns',
    bio: 'Bio', stats: 'Follower stats', follow: 'Follow button', chat: 'Chat link',
    report: 'Report menu', botBadge: 'Bot badge', posts: 'Posts list',
  };

  var currentState = null;

  // ---------- init ----------

  function init() {
    var root = document.querySelector('.pfx-page');
    var toggle = document.getElementById('ev-edit-toggle');
    if (!root || !toggle) return;
    var username = meta('current-username');
    if (!username) return;

    var state = {
      root: root, editing: false, username: username, csrf: meta('csrf-token'),
      styleEl: document.getElementById('ev-user-css'),
      target: null, lastElement: null, hoverTarget: null, raf: null,
      dirty: false, saveTimer: null, statusEl: null, fontFamily: '',
      ui: null, panel: null, outline: null, hover: null, nodes: {},
    };
    currentState = state;
    var fieldsEl = document.getElementById('ev-fields');
    if (fieldsEl && fieldsEl.dataset && fieldsEl.dataset.fontFamily) state.fontFamily = fieldsEl.dataset.fontFamily;

    // Heal a stylesheet broken by an earlier pasted-rule edit, so the page and
    // future edits work again.
    if (state.styleEl) {
      var rawCss = state.styleEl.textContent;
      var normCss = normalizeStylesheet(rawCss);
      if (normCss !== rawCss) { setUserCss(state, normCss); queueSave(state); }
    }

    toggle.addEventListener('click', function (e) {
      if (e && e.preventDefault) e.preventDefault();
      setEditing(state, !state.editing);
    });
    if (/[?&]edit=1(?:&|$)/.test(location.search)) setEditing(state, true);
  }

  function meta(name) {
    var el = document.querySelector('meta[name="' + name + '"]');
    return el ? el.getAttribute('content') : '';
  }

  function setEditing(state, on) {
    if (state.editing === on) return;
    state.editing = on;
    document.body.classList.toggle('ev-editing', on);
    if (on) {
      buildUI(state);
      state.ui.hidden = false;
      select(state, null);
      startLoop(state);
    } else {
      if (state.raf) { cancelAnimationFrame(state.raf); state.raf = null; }
      state.hoverTarget = null;
      flush(state);
      if (state.ui) state.ui.hidden = true;
      hideOverlay(state);
      select(state, null);
    }
    var t = document.getElementById('ev-edit-toggle');
    if (t) t.textContent = on ? 'Exit editing' : 'Edit styles';
  }

  // ---------- chrome ----------

  function buildUI(state) {
    if (state.ui) return;

    var bar = document.createElement('div');
    bar.className = 'ev-bar';
    var status = document.createElement('span');
    status.className = 'ev-status';
    status.textContent = 'All changes saved';
    state.statusEl = status;
    bar.appendChild(status);
    bar.appendChild(elBtn('Exit', function () { setEditing(state, false); }));

    var panel = document.createElement('div');
    panel.className = 'ev-panel';
    panel.innerHTML = '<div id="ev-body"></div>';

    var outline = ovl('ev-outline');
    var hover = ovl('ev-hover');

    var ui = document.createElement('div');
    ui.id = 'ev-ui';
    ui.hidden = true;
    ui.appendChild(bar);
    ui.appendChild(panel);
    document.body.appendChild(ui);
    document.body.appendChild(outline);
    document.body.appendChild(hover);

    state.ui = ui;
    state.panel = panel;
    state.outline = outline;
    state.hover = hover;
    state.nodes.body = panel.querySelector('#ev-body');

    state.root.addEventListener('click', onClick, true);
    state.root.addEventListener('mousemove', onHover);
    state.root.addEventListener('mouseleave', function () {
      state.hoverTarget = null;
      if (state.hover) state.hover.hidden = true;
    });
    window.addEventListener('scroll', function () { paintOutline(state); }, true);
    window.addEventListener('resize', function () { paintOutline(state); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') select(state, null); });
    bindFields(state);
  }

  // ---------- auto-save ----------

  function setStatus(state, cls, text) {
    if (!state.statusEl) return;
    state.statusEl.className = 'ev-status' + (cls ? ' ' + cls : '');
    state.statusEl.textContent = text;
  }

  function queueSave(state) {
    state.dirty = true;
    setStatus(state, 'saving', 'Saving…');
    clearTimeout(state.saveTimer);
    state.saveTimer = setTimeout(function () { saveAll(state); }, 600);
  }

  function post(state, url, body) {
    return fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': state.csrf,
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json',
      },
      body: JSON.stringify(body),
    }).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r; });
  }

  function collectProfile() {
    var q = function (sel) { var el = document.querySelector(sel); return el ? el.value : ''; };
    var pronouns = Array.prototype.slice.call(document.querySelectorAll('#pronounRows input')).map(function (i) { return i.value; });
    return {
      displayName: q('#ev-displayName'),
      bio: q('#ev-bio'),
      effect: q('#ev-effect'),
      pronoun: pronouns,
    };
  }

  function saveAll(state) {
    if (!state.dirty) return;
    state.dirty = false;
    clearTimeout(state.saveTimer);
    var base = '/u/' + encodeURIComponent(state.username);
    var jobs = [post(state, base + '/edit/visual', { html: serialize(state), css: getUserCss(state) })];
    if (document.getElementById('ev-fields')) jobs.push(post(state, base + '/edit/profile', collectProfile()));
    Promise.all(jobs).then(function () {
      setStatus(state, 'saved', 'All changes saved');
    }).catch(function () {
      state.dirty = true;
      setStatus(state, 'error', "Couldn't save");
    });
  }

  function flush(state) {
    if (state.dirty) saveAll(state);
  }

  // The left panel's profile fields: auto-save on change (debounced), reload
  // for uploads. The raw HTML box is another view of the same template.
  function bindFields(state) {
    var fields = document.getElementById('ev-fields');
    if (!fields || fields.dataset.bound) return;
    fields.dataset.bound = '1';

    // Delegated, so dynamically added pronoun rows are covered too.
    function onFieldChange(e) {
      if (e.target && e.target.id === 'ev-html-box') return; // handled below
      queueSave(state);
    }
    fields.addEventListener('input', onFieldChange);
    fields.addEventListener('change', onFieldChange);

    var htmlBox = document.getElementById('ev-html-box');
    if (htmlBox) {
      htmlBox.addEventListener('change', function () {
        // Apply to the live DOM so styling and the HTML box stay one document.
        state.root.innerHTML = htmlBox.value;
        select(state, null);
        queueSave(state);
      });
    }

    var resetForm = document.getElementById('ev-reset');
    if (resetForm) {
      resetForm.addEventListener('submit', function (e) {
        if (!window.confirm('Reset all profile HTML, CSS and effect back to the defaults? This cannot be undone.')) {
          e.preventDefault();
        }
      });
    }

    window.addEventListener('beforeunload', function (e) {
      if (!state.dirty) return;
      flush(state);
      e.preventDefault();
      e.returnValue = '';
    });
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'hidden') flush(state);
    });
  }

  function ovl(id) {
    var d = document.createElement('div');
    d.id = id;
    d.hidden = true;
    return d;
  }

  function elBtn(label, fn, cls) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'ev-btn' + (cls ? ' ' + cls : '');
    b.textContent = label;
    b.addEventListener('click', function (e) { e.preventDefault(); fn(); });
    return b;
  }

  // ---------- parts ----------

  function partForNode(node) {
    for (var i = 0; i < PARTS.length; i++) {
      try { if (node.matches(PARTS[i].selector)) return PARTS[i]; } catch (e) {}
    }
    return null;
  }

  function resolveTarget(state, el) {
    var node = el;
    while (node && node !== state.root) {
      var part = partForNode(node);
      if (part) return { kind: 'rule', selector: part.selector, part: part, el: node };
      node = node.parentNode;
    }
    var slot = closestSlot(state.root, el);
    if (slot) {
      var name = slot.getAttribute('data-ev-slot');
      return {
        kind: 'rule', selector: '[data-ev-slot="' + name + '"]', el: slot,
        part: { label: SLOT_LABELS[name] || name, group: 'Live', selector: '[data-ev-slot="' + name + '"]' },
      };
    }
    var cls = (el.className && typeof el.className === 'string') ? ('.' + el.className.trim().split(/\s+/)[0]) : '';
    return {
      kind: 'inline', selector: null, el: el,
      part: { label: 'Your element (' + el.tagName.toLowerCase() + cls + ')', group: 'Yours', selector: null },
    };
  }

  function onHover(e) {
    var state = currentState;
    if (!state || !state.editing) return;
    var el = e.target;
    if (el === state.root || !state.root.contains(el)) {
      state.hoverTarget = null;
      if (state.hover) state.hover.hidden = true;
      return;
    }
    state.hoverTarget = resolveTarget(state, el);
    setLayer(state.hover, targetElements(state, state.hoverTarget), 'hover', state.hoverTarget.part.label || '');
  }

  function onClick(e) {
    var state = currentState;
    if (!state || !state.editing) return;
    e.preventDefault();
    e.stopPropagation();
    var el = e.target;
    if (el === state.root) return select(state, null);
    if (!state.root.contains(el)) return;
    var t = resolveTarget(state, el);
    t.el = t.kind === 'inline' ? el : t.el;
    state.lastElement = el;
    select(state, t);
  }

  function select(state, target) {
    state.target = target;
    paintOutline(state);
    renderPanel(state);
  }

  // A target is one object across the page: a rule target highlights *every*
  // matching element (all posts), an inline target just the one element.
  function targetElements(state, target) {
    if (!target) return [];
    if (target.kind === 'inline') return [target.el];
    var els = [];
    try { els = Array.prototype.slice.call(state.root.querySelectorAll(target.selector)); } catch (e) {}
    if (!els.length && target.selector === 'body') els = [document.body];
    if (!els.length && target.el) els = [target.el];
    return els;
  }

  function paintOutline(state) {
    if (!state.target) { if (state.outline) state.outline.hidden = true; return; }
    setLayer(state.outline, targetElements(state, state.target), 'sel', state.target.part.label || '');
  }

  function setLayer(layer, els, kind, label) {
    if (!layer) return;
    var rects = [];
    (els || []).forEach(function (el) {
      if (!el || !el.getBoundingClientRect) return;
      var r = el.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) return;
      rects.push(r);
    });
    var n = rects.length;
    while (layer.children.length < n) {
      var b = document.createElement('div');
      b.className = 'ev-box';
      layer.appendChild(b);
    }
    while (layer.children.length > n) layer.removeChild(layer.lastChild);
    for (var i = 0; i < n; i++) {
      var box = layer.children[i];
      var r = rects[i];
      var cls = 'ev-box ' + kind + (i === 0 && label ? ' labeled' : '');
      if (box.className !== cls) box.className = cls;
      var top = r.top + 'px', left = r.left + 'px', w = r.width + 'px', h = r.height + 'px';
      if (box.style.top !== top) box.style.top = top;
      if (box.style.left !== left) box.style.left = left;
      if (box.style.width !== w) box.style.width = w;
      if (box.style.height !== h) box.style.height = h;
      var txt = (i === 0 && label) ? label : '';
      if (box.textContent !== txt) box.textContent = txt;
    }
    layer.hidden = n === 0;
  }

  // Keep the frames glued to their elements: any style edit, reflow, font swap
  // or scroll moves content, so re-sync every animation frame while editing.
  function startLoop(state) {
    if (state.raf) return;
    function tick() {
      if (!state.editing) { state.raf = null; return; }
      if (state.target) {
        setLayer(state.outline, targetElements(state, state.target), 'sel', state.target.part.label || '');
      } else if (state.outline) {
        state.outline.hidden = true;
      }
      if (state.hoverTarget) {
        setLayer(state.hover, targetElements(state, state.hoverTarget), 'hover', state.hoverTarget.part.label || '');
      } else if (state.hover) {
        state.hover.hidden = true;
      }
      state.raf = requestAnimationFrame(tick);
    }
    state.raf = requestAnimationFrame(tick);
  }

  function hideOverlay(state) {
    if (state.outline) state.outline.hidden = true;
    if (state.hover) state.hover.hidden = true;
  }

  // ---------- value read/write (rule vs inline) ----------

  function parseDecls(text) {
    return String(text || '').split(';').map(function (s) { return s.trim(); }).filter(Boolean).map(function (d) {
      var i = d.indexOf(':');
      return i === -1 ? { prop: d, value: '' } : { prop: d.slice(0, i).trim(), value: d.slice(i + 1).trim() };
    });
  }
  function serializeDecls(list) {
    return list.filter(function (d) { return d.prop; })
      .map(function (d) { return '  ' + d.prop + ': ' + d.value + ';'; }).join('\n');
  }

  function getVal(state, prop) {
    var t = state.target;
    if (!t) return '';
    if (t.kind === 'rule') {
      var decls = parseDecls(findRuleDecls(getUserCss(state), t.selector));
      for (var i = 0; i < decls.length; i++) if (decls[i].prop === prop) return decls[i].value;
    } else if (t.el) {
      var inline = t.el.style.getPropertyValue(prop);
      if (inline) return inline.trim();
    }
    return t.el ? window.getComputedStyle(t.el).getPropertyValue(prop).trim() : '';
  }

  function setVal(state, prop, value) {
    var t = state.target;
    if (!t) return;
    if (t.kind === 'rule') {
      var decls = parseDecls(findRuleDecls(getUserCss(state), t.selector));
      var found = false;
      decls.forEach(function (d) { if (d.prop === prop) { d.value = value; found = true; } });
      if (!found) decls.push({ prop: prop, value: value });
      setRuleDecls(state, t.selector, serializeDecls(decls));
    } else if (t.el) {
      t.el.style.setProperty(prop, value);
    }
    paintOutline(state);
    queueSave(state);
  }

  function clearVal(state, prop) {
    var t = state.target;
    if (!t) return;
    if (t.kind === 'rule') {
      var decls = parseDecls(findRuleDecls(getUserCss(state), t.selector))
        .filter(function (d) { return d.prop !== prop; });
      setRuleDecls(state, t.selector, serializeDecls(decls));
    } else if (t.el) {
      t.el.style.removeProperty(prop);
    }
    paintOutline(state);
    queueSave(state);
  }

  // ---------- panel ----------

  // Font choices, including the user's uploaded custom font when they have one.
  function fontOptions(state) {
    var opts = FONTS.slice();
    if (state.fontFamily) {
      opts.push([state.fontFamily + ' (yours)', "'" + String(state.fontFamily).replace(/'/g, '') + "'"]);
    }
    return opts;
  }

  function renderPanel(state) {
    var body = state.nodes.body;
    body.textContent = '';
    body.appendChild(partPicker(state));
    if (!state.target) {
      body.appendChild(note('Click a part of your profile to style it — or pick one above.'));
      return;
    }
    var t = state.target;
    var head = document.createElement('div');
    head.className = 'ev-part-title';
    head.textContent = t.part.label;
    body.appendChild(head);
    var n = targetElements(state, t).length;
    body.appendChild(note(t.kind === 'inline'
      ? 'Applies to this element only.'
      : (n > 1
        ? 'One shared template — this restyles all ' + n + ' matching elements on your page.'
        : 'Shared style — applies wherever this part appears.')));

    if (t.kind === 'inline' && isTextOnly(t.el)) {
      body.appendChild(textControl(state, 'Text', '@text'));
    }

    section(state, body, 'Colour', [
      colorControl(state, 'Text colour', 'color'),
      backgroundControl(state),
    ]);
    section(state, body, 'Edges', [
      pxControl(state, 'Border width', 'border-width', 0, 8),
      segmentedControl(state, 'Border style', 'border-style', [['none', 'none'], ['solid', 'solid'], ['dashed', 'dashed'], ['dotted', 'dotted']]),
      colorControl(state, 'Border colour', 'border-color', {}),
      pxControl(state, 'Corner radius', 'border-radius', 0, 40),
    ]);
    section(state, body, 'Spacing', [
      pxControl(state, 'Padding', 'padding', 0, 64, true),
      pxControl(state, 'Margin', 'margin', 0, 64, true),
    ]);
    section(state, body, 'Text', [
      pxControl(state, 'Font size', 'font-size', 8, 48),
      selectControl(state, 'Weight', 'font-weight', WEIGHTS),
      selectControl(state, 'Font', 'font-family', fontOptions(state)),
      segmentedControl(state, 'Align', 'text-align', [['left', 'Left'], ['center', 'Center'], ['right', 'Right']]),
      textControl(state, 'Line height', 'line-height'),
      textControl(state, 'Letter spacing', 'letter-spacing'),
    ]);
    section(state, body, 'Effects', [
      pxControl(state, 'Opacity', 'opacity', 0, 100, false, '%'),
      selectControl(state, 'Shadow', 'box-shadow', SHADOWS),
    ]);
    section(state, body, 'Layout', [
      selectControl(state, 'Display', 'display', [['', 'Default'], ['block', 'block'], ['inline-block', 'inline-block'], ['flex', 'flex'], ['inline-flex', 'inline-flex'], ['none', 'hidden']]),
      textControl(state, 'Width', 'width'),
      textControl(state, 'Max width', 'max-width'),
      textControl(state, 'Height', 'height'),
      textControl(state, 'Gap', 'gap'),
    ]);

    body.appendChild(sectionTitle('More'));
    body.appendChild(customPropControl(state));
    body.appendChild(rawCss(state));
  }

  function section(state, body, title, rows) {
    body.appendChild(sectionTitle(title));
    rows.forEach(function (r) { body.appendChild(r); });
  }

  function partPicker(state) {
    var wrap = document.createElement('label');
    wrap.className = 'ev-field';
    var span = document.createElement('span');
    span.textContent = 'Part';
    wrap.appendChild(span);
    var sel = document.createElement('select');
    sel.className = 'ev-part-picker';
    var opt = document.createElement('option');
    opt.value = '';
    opt.textContent = '— choose a part —';
    sel.appendChild(opt);
    var groups = {};
    PARTS.forEach(function (p) { (groups[p.group] = groups[p.group] || []).push(p); });
    Object.keys(groups).forEach(function (g) {
      var og = document.createElement('optgroup');
      og.label = g;
      groups[g].forEach(function (p) {
        var o = document.createElement('option');
        o.value = p.selector;
        o.textContent = p.label;
        og.appendChild(o);
      });
      sel.appendChild(og);
    });
    if (state.target && state.target.kind === 'rule') sel.value = state.target.selector;
    sel.addEventListener('change', function () {
      var part = null;
      for (var i = 0; i < PARTS.length; i++) if (PARTS[i].selector === sel.value) part = PARTS[i];
      if (!part) return select(state, null);
      var elq = null;
      try { elq = state.root.querySelector(part.selector); } catch (e) {}
      select(state, { kind: 'rule', selector: part.selector, part: part, el: elq });
    });
    wrap.appendChild(sel);
    return wrap;
  }

  // ---------- controls ----------

  function row(labelText) {
    var wrap = document.createElement('div');
    wrap.className = 'ev-field';
    var span = document.createElement('span');
    span.textContent = labelText;
    wrap.appendChild(span);
    return wrap;
  }
  function sectionTitle(t) {
    var h = document.createElement('h4');
    h.className = 'ev-section';
    h.textContent = t;
    return h;
  }
  function note(t) {
    var p = document.createElement('p');
    p.className = 'ev-note';
    p.textContent = t;
    return p;
  }

  // Value set on our own rule/inline style only (no computed fallback) — used
  // where mixing in the theme's value would be misleading, e.g. background.
  function ruleDecl(state, prop) {
    var t = state.target;
    if (!t) return '';
    if (t.kind === 'rule') {
      var decls = parseDecls(findRuleDecls(getUserCss(state), t.selector));
      for (var i = 0; i < decls.length; i++) if (decls[i].prop === prop) return decls[i].value;
      return '';
    }
    return t.el ? (t.el.style.getPropertyValue(prop) || '').trim() : '';
  }

  function colorControl(state, label, prop) {
    var box = document.createElement('div');
    var wrap = row(label);
    var val = getVal(state, prop);
    var text = document.createElement('input');
    text.type = 'text'; text.value = val; text.placeholder = 'none';
    var pick = document.createElement('input');
    pick.type = 'color'; pick.className = 'ev-swatch';
    pick.value = toHex(val) || '#000000';

    function write(v) { if (v) setVal(state, prop, v); else clearVal(state, prop); }
    text.addEventListener('change', function () { write(text.value.trim()); });
    pick.addEventListener('input', function () { text.value = pick.value; write(pick.value); });
    wrap.appendChild(text);
    wrap.appendChild(pick);
    box.appendChild(wrap);

    var pal = document.createElement('div');
    pal.className = 'ev-palette';
    THEME_SWATCHES.forEach(function (s) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'ev-chip'; b.title = s[1];
      b.style.background = 'var(' + s[0] + ')';
      b.addEventListener('click', function () { text.value = 'var(' + s[0] + ')'; write(text.value); });
      pal.appendChild(b);
    });
    box.appendChild(pal);
    return box;
  }

  // Background needs to tell colour from image: gradients are invalid on
  // background-color, so they must go to background-image (or the element ends
  // up with no background at all).
  function backgroundControl(state) {
    var box = document.createElement('div');
    var wrap = row('Background');
    var current = ruleDecl(state, 'background-image') || ruleDecl(state, 'background-color') || '';
    var text = document.createElement('input');
    text.type = 'text'; text.value = current; text.placeholder = 'none';
    var pick = document.createElement('input');
    pick.type = 'color'; pick.className = 'ev-swatch';
    pick.value = toHex(current) || '#000000';

    function write(raw) {
      var v = String(raw || '').trim();
      if (!v || v === 'none') {
        clearVal(state, 'background-image');
        clearVal(state, 'background-color');
        return;
      }
      if (/gradient\(|url\(/i.test(v)) {
        setVal(state, 'background-image', v);
        // clean up a gradient that an earlier version wrote to background-color
        if (/gradient\(|url\(/i.test(ruleDecl(state, 'background-color'))) clearVal(state, 'background-color');
      } else {
        setVal(state, 'background-color', v);
        clearVal(state, 'background-image');
      }
    }
    text.addEventListener('change', function () { write(text.value); });
    pick.addEventListener('input', function () { text.value = pick.value; write(pick.value); });
    wrap.appendChild(text);
    wrap.appendChild(pick);
    box.appendChild(wrap);

    var pal = document.createElement('div');
    pal.className = 'ev-palette';
    THEME_SWATCHES.forEach(function (s) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'ev-chip'; b.title = s[1];
      b.style.background = 'var(' + s[0] + ')';
      b.addEventListener('click', function () { text.value = 'var(' + s[0] + ')'; write(text.value); });
      pal.appendChild(b);
    });
    pal.appendChild(chip('none', function () { text.value = ''; write(''); }));
    box.appendChild(pal);

    var g = document.createElement('div');
    g.className = 'ev-palette';
    GRADIENTS.forEach(function (gr) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'ev-chip wide'; b.title = gr[0];
      b.style.background = gr[1];
      b.addEventListener('click', function () { text.value = gr[1]; write(gr[1]); });
      g.appendChild(b);
    });
    box.appendChild(g);
    return box;
  }

  function chip(label, fn) {
    var b = document.createElement('button');
    b.type = 'button'; b.className = 'ev-chip text';
    b.textContent = label;
    b.addEventListener('click', fn);
    return b;
  }

  // A px slider + number. `shorthand` writes a single value for padding/margin.
  function pxControl(state, label, prop, min, max, shorthand, unit) {
    unit = unit || 'px';
    var wrap = row(label);
    var val = getVal(state, prop);
    var num = document.createElement('input');
    num.type = 'number'; num.min = String(min); num.max = String(max);
    var parsed = parseFloat(val);
    num.value = isNaN(parsed) ? '' : String(parsed);
    var range = document.createElement('input');
    range.type = 'range'; range.min = String(min); range.max = String(max);
    range.value = isNaN(parsed) ? String(min) : String(parsed);
    range.className = 'ev-range';

    function write(v) {
      if (v === '' || v === null) clearVal(state, prop);
      else setVal(state, prop, v + unit);
    }
    range.addEventListener('input', function () { num.value = range.value; write(range.value); });
    num.addEventListener('change', function () { range.value = num.value || String(min); write(num.value); });
    wrap.appendChild(range);
    wrap.appendChild(num);
    return wrap;
  }

  function segmentedControl(state, label, prop, options) {
    var wrap = row(label);
    var val = getVal(state, prop);
    var group = document.createElement('div');
    group.className = 'ev-seg';
    options.forEach(function (o) {
      var b = document.createElement('button');
      b.type = 'button';
      b.textContent = o[1];
      if (val === o[0]) b.className = 'on';
      b.addEventListener('click', function () { setVal(state, prop, o[0]); refreshSeg(group, b); });
      group.appendChild(b);
    });
    function refreshSeg(g, active) {
      Array.prototype.forEach.call(g.children, function (c) { c.className = ''; });
      active.className = 'on';
    }
    wrap.appendChild(group);
    return wrap;
  }

  function selectControl(state, label, prop, options) {
    var wrap = row(label);
    var val = getVal(state, prop);
    var sel = document.createElement('select');
    options.forEach(function (o) {
      var op = document.createElement('option');
      op.value = o[1]; op.textContent = o[0];
      sel.appendChild(op);
    });
    sel.value = val;
    sel.addEventListener('change', function () {
      if (sel.value === '') clearVal(state, prop); else setVal(state, prop, sel.value);
    });
    wrap.appendChild(sel);
    return wrap;
  }

  function textControl(state, label, prop) {
    var wrap = row(label);
    var isText = prop === '@text';
    var input = document.createElement('input');
    input.type = 'text';
    input.value = isText ? (state.target.el.textContent || '') : getVal(state, prop);
    input.spellcheck = false;
    input.addEventListener('change', function () {
      if (isText) {
        state.target.el.textContent = input.value;
        paintOutline(state);
        queueSave(state);
      } else if (input.value.trim()) setVal(state, prop, input.value.trim());
      else clearVal(state, prop);
    });
    wrap.appendChild(input);
    return wrap;
  }

  function customPropControl(state) {
    var box = document.createElement('div');
    var wrap = row('Add property');
    var p = document.createElement('input');
    p.type = 'text'; p.placeholder = 'e.g. text-shadow'; p.className = 'ev-prop-name';
    var v = document.createElement('input');
    v.type = 'text'; v.placeholder = 'value';
    var b = elBtn('＋', function () {
      var name = p.value.trim();
      if (name && v.value.trim()) { setVal(state, name, v.value.trim()); p.value = ''; v.value = ''; }
    }, 'ev-tiny');
    wrap.appendChild(p); wrap.appendChild(v); wrap.appendChild(b);
    box.appendChild(wrap);
    return box;
  }

  function rawCss(state) {
    var d = document.createElement('details');
    d.className = 'ev-raw';
    var s = document.createElement('summary');
    s.textContent = state.target.kind === 'rule' ? 'Raw CSS for this part' : 'Raw style';
    d.appendChild(s);
    var ta = document.createElement('textarea');
    ta.rows = 5; ta.spellcheck = false;
    ta.placeholder = 'color: red;';
    ta.value = state.target.kind === 'rule'
      ? findRuleDecls(getUserCss(state), state.target.selector)
      : (state.target.el.getAttribute('style') || '');
    ta.addEventListener('change', function () {
      var v = normalizeDecls(ta.value);
      ta.value = v;
      if (state.target.kind === 'rule') setRuleDecls(state, state.target.selector, v);
      else if (v.trim()) state.target.el.setAttribute('style', v);
      else state.target.el.removeAttribute('style');
      paintOutline(state);
      queueSave(state);
    });
    d.appendChild(ta);
    var hint = document.createElement('small');
    hint.className = 'muted';
    hint.textContent = state.target.kind === 'rule'
      ? 'Declarations only (color: red;). Pasting a whole .selector { … } block works too.'
      : 'Inline declarations only.';
    d.appendChild(hint);
    return d;
  }

  // ---------- serialization ----------

  function serialize(state) {
    var out = '';
    for (var i = 0; i < state.root.childNodes.length; i++) out += serializeNode(state.root.childNodes[i]);
    return out;
  }
  function serializeNode(node) {
    if (node.nodeType === 3) return escapeText(node.nodeValue);
    if (node.nodeType !== 1) return '';
    var tag = node.tagName.toLowerCase();
    if (tag === 'script' || tag === 'style') return '';
    var open = '<' + tag + serializeAttrs(node);
    if (VOID_TAGS[tag]) return open + '>';
    if (isSlot(node)) return open + '></' + tag + '>';
    var inner = '';
    for (var i = 0; i < node.childNodes.length; i++) inner += serializeNode(node.childNodes[i]);
    return open + '>' + inner + '</' + tag + '>';
  }
  function serializeAttrs(node) {
    var order = ['id', 'class', 'style', 'title', 'dir', 'lang', 'href', 'name', 'target', 'rel',
      'src', 'alt', 'width', 'height', 'loading', 'colspan', 'rowspan', 'span', 'datetime', 'data-ev-slot'];
    var out = '';
    for (var i = 0; i < order.length; i++) {
      var v = node.getAttribute(order[i]);
      if (v === null) continue;
      if (order[i] === 'style') { v = v.trim(); if (!v) continue; }
      out += ' ' + order[i] + '="' + escapeAttr(v) + '"';
    }
    return out;
  }
  function escapeText(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function escapeAttr(s) {
    return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function isSlot(el) { return el.hasAttribute && el.hasAttribute('data-ev-slot'); }
  function closestSlot(root, el) {
    var n = el;
    while (n && n !== root) {
      if (n.nodeType === 1 && n.hasAttribute('data-ev-slot')) return n;
      n = n.parentNode;
    }
    return null;
  }
  function isTextOnly(el) {
    for (var i = 0; i < el.childNodes.length; i++) if (el.childNodes[i].nodeType === 1) return false;
    return !isSlot(el) && el.textContent.trim() !== '';
  }

  // ---------- page CSS helpers ----------

  function getUserCss(state) { return state.styleEl ? state.styleEl.textContent : ''; }
  function setUserCss(state, text) { if (state.styleEl) state.styleEl.textContent = text; }

  function findRuleDecls(css, selector) {
    var loc = findRule(css, selector);
    return loc ? css.slice(loc.open + 1, loc.close).trim() : '';
  }

  // The rule textareas hold declarations, but people paste a whole rule
  // (".post { color: red }"). Take just the inside and drop stray braces, so we
  // can never author nested/invalid CSS that breaks the stylesheet.
  function normalizeDecls(text) {
    var s = String(text || '');
    var m = s.match(/\{([\s\S]*)\}/);
    if (m) s = m[1];
    return s.replace(/[{}]/g, '');
  }

  function matchBrace(css, open) {
    var depth = 0;
    for (var i = open; i < css.length; i++) {
      if (css[i] === '{') depth++;
      else if (css[i] === '}') { depth--; if (depth === 0) return i; }
    }
    return -1;
  }

  // Canonicalise a stylesheet: hoist the contents of any non-at rule whose block
  // contains another block (a bogus wrapper left by a pasted rule), strip stray
  // braces from declaration blocks, and close an unbalanced rule. Returns the
  // rules text; equal to the input when it is already fine.
  function normalizeStylesheet(css) {
    var out = '', i = 0;
    while (i < css.length) {
      var open = css.indexOf('{', i);
      if (open === -1) break; // trailing text with no rule — dropped
      var selector = css.slice(i, open);
      var close = matchBrace(css, open);
      if (close === -1) close = css.length; // missing close: salvage, treat end as the close
      var block = css.slice(open + 1, close);
      var at = selector.trim().charAt(0) === '@';
      if (!at && block.indexOf('{') !== -1) out += normalizeStylesheet(block);
      else out += selector + '{' + (at ? block : normalizeDecls(block)) + '}';
      i = close + 1;
    }
    return out;
  }

  function setRuleDecls(state, selector, decls) {
    decls = normalizeDecls(decls);
    var css = getUserCss(state);
    var loc = findRule(css, selector);
    if (loc) css = css.slice(0, loc.open + 1) + '\n' + decls + '\n' + css.slice(loc.close);
    else css = css.replace(/\s*$/, '') + '\n' + selector + ' {\n' + decls + '\n}\n';
    var norm = normalizeStylesheet(css);
    setUserCss(state, norm !== css ? norm : css);
  }
  function depthAt(css, idx) {
    var d = 0;
    for (var i = 0; i < idx; i++) {
      if (css[i] === '{') d++;
      else if (css[i] === '}') d--;
    }
    return d;
  }
  function findRule(css, selector) {
    var from = 0, pos;
    while ((pos = css.indexOf(selector, from)) !== -1) {
      var open = css.indexOf('{', pos);
      if (open === -1) return null;
      var between = css.slice(pos + selector.length, open);
      if (/^[\s,]*$/.test(between) && depthAt(css, pos) === 0) {
        var d = 0, close = -1, i = open;
        while (i < css.length) {
          if (css[i] === '{') d++;
          else if (css[i] === '}') { d--; if (d === 0) { close = i; break; } }
          i++;
        }
        if (close === -1) return null;
        return { open: open, close: close };
      }
      from = pos + selector.length;
    }
    return null;
  }

  // ---------- misc ----------

  function toHex(value) {
    if (!value) return '';
    value = String(value).trim();
    if (/^#[0-9a-f]{6}$/i.test(value)) return value;
    if (/^#[0-9a-f]{3}$/i.test(value)) return '#' + value[1] + value[1] + value[2] + value[2] + value[3] + value[3];
    var m = value.match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i);
    if (m) {
      return '#' + [m[1], m[2], m[3]].map(function (n) {
        return ('0' + Math.min(255, parseInt(n, 10)).toString(16)).slice(-2);
      }).join('');
    }
    return '';
  }

  document.addEventListener('DOMContentLoaded', init);
})();
