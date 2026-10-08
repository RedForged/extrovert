// Easy Editing — a WYSIWYG editor for the profile page.
//
// The profile page is the live rendering of the user's stored HTML/CSS: the
// whole page (header + content) is authored by the user, with live data placed
// through slot elements (<div data-ev-slot="posts"></div>). This script lets the
// owner click elements, edit attributes/styles, drag to reorder or nest, and
// create/duplicate/delete elements — all against the real page. On save it
// serializes the DOM back to the same HTML that Advanced mode edits, so the two
// modes are 100% translatable.
//
// External script only (CSP: script-src 'self', no inline handlers). Editor
// chrome lives outside the editable root so it never leaks into the saved HTML.
(function () {
  'use strict';

  var ALLOWED_TAGS = [
    'div', 'span', 'p', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'a', 'img', 'b', 'i', 'em', 'strong', 'u', 's', 'strike', 'small', 'mark',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'blockquote', 'pre', 'code',
    'table', 'thead', 'tbody', 'tr', 'th', 'td', 'caption', 'colgroup', 'col',
    'section', 'article', 'header', 'footer', 'nav', 'aside', 'main', 'figure', 'figcaption',
    'details', 'summary', 'abbr', 'address', 'cite', 'q', 'sub', 'sup', 'time', 'kbd', 'var',
  ];

  var ALLOWED_ATTRS = {
    '*': ['class', 'id', 'style', 'title', 'dir', 'lang', 'data-ev-slot'],
    a: ['href', 'name', 'target', 'rel'],
    img: ['src', 'alt', 'width', 'height', 'loading'],
    td: ['colspan', 'rowspan'],
    th: ['colspan', 'rowspan'],
    col: ['span'],
    colgroup: ['span'],
    time: ['datetime'],
  };

  var VOID_TAGS = { br: 1, hr: 1, img: 1, col: 1 };
  var SLOT_NAMES = [
    'avatar', 'displayName', 'botBadge', 'handle', 'pronouns', 'bio',
    'stats', 'follow', 'chat', 'report', 'posts',
  ];

  var STYLE_PROPS = [
    { p: 'display', label: 'Display' },
    { p: 'position', label: 'Position' },
    { p: 'width', label: 'Width' },
    { p: 'height', label: 'Height' },
    { p: 'color', label: 'Text color', color: true },
    { p: 'background-color', label: 'Background', color: true },
    { p: 'font-size', label: 'Font size' },
    { p: 'font-weight', label: 'Font weight' },
    { p: 'font-family', label: 'Font family' },
    { p: 'text-align', label: 'Text align' },
    { p: 'padding', label: 'Padding' },
    { p: 'margin', label: 'Margin' },
    { p: 'border', label: 'Border' },
    { p: 'border-radius', label: 'Radius' },
    { p: 'gap', label: 'Gap' },
    { p: 'opacity', label: 'Opacity' },
  ];

  var currentState = null;

  function init() {
    var root = document.querySelector('.pfx-page');
    var toggle = document.getElementById('ev-edit-toggle');
    if (!root || !toggle) return;

    var username = meta('current-username');
    if (!username) return;
    var state = {
      root: root,
      editing: false,
      selected: null,
      dragged: null,
      dropTarget: null,
      dropRel: null,
      username: username,
      csrf: meta('csrf-token'),
      styleEl: document.getElementById('ev-user-css'),
      ui: null,
      outline: null,
      indicator: null,
      nodes: {},
    };
    currentState = state;

    toggle.hidden = false;
    toggle.addEventListener('click', function (e) {
      // The toggle is a real link (?edit=1) so it works without JS; enhance it
      // to switch in place instead of reloading.
      if (e && e.preventDefault) e.preventDefault();
      setEditing(state, !state.editing);
    });
    if (/[?&]edit=1(?:&|$)/.test(location.search)) setEditing(state, true);
  }

  function meta(name) {
    var el = document.querySelector('meta[name="' + name + '"]');
    return el ? el.getAttribute('content') : '';
  }

  // ---------- edit mode ----------

  function setEditing(state, on) {
    if (state.editing === on) return;
    state.editing = on;
    document.body.classList.toggle('ev-editing', on);
    if (on) {
      buildUI(state);
      state.ui.hidden = false;
      state.outline.hidden = false;
      setDraggable(state, true);
      select(state, null);
    } else {
      if (state.ui) state.ui.hidden = true;
      state.outline.hidden = true;
      clearIndicator(state);
      setDraggable(state, false);
      select(state, null);
    }
  }

  function setDraggable(state, on) {
    var els = state.root.querySelectorAll('*');
    for (var i = 0; i < els.length; i++) {
      if (on) els[i].setAttribute('draggable', 'true');
      else els[i].removeAttribute('draggable');
    }
    if (on) {
      state.root.setAttribute('draggable', 'false');
    } else {
      state.root.removeAttribute('draggable');
    }
  }

  // ---------- editor chrome ----------

  function buildUI(state) {
    if (state.ui) return;

    var ui = document.createElement('div');
    ui.id = 'ev-ui';
    ui.hidden = true;

    var bar = document.createElement('div');
    bar.className = 'ev-bar';
    bar.appendChild(button('+ Add', function () {
      var tag = state.nodes.addSelect.value;
      addElement(state, tag);
    }));
    var addSelect = document.createElement('select');
    addSelect.className = 'ev-add-select';
    addSelect.setAttribute('aria-label', 'Element to add');
    for (var i = 0; i < ALLOWED_TAGS.length; i++) {
      var opt = document.createElement('option');
      opt.value = ALLOWED_TAGS[i];
      opt.textContent = ALLOWED_TAGS[i];
      addSelect.appendChild(opt);
    }
    bar.appendChild(addSelect);
    bar.appendChild(button('Duplicate', function () { duplicate(state); }));
    bar.appendChild(button('Delete', function () { removeSelected(state); }));
    bar.appendChild(button('Wrap', function () { wrapSelected(state); }));
    var spacer = document.createElement('span');
    spacer.className = 'ev-bar-spacer';
    bar.appendChild(spacer);
    bar.appendChild(button('Save', function () { save(state); }, 'ev-primary'));
    var adv = document.createElement('a');
    adv.className = 'ev-bar-link';
    adv.href = '/u/' + encodeURIComponent(state.username) + '/edit';
    adv.textContent = 'Advanced';
    bar.appendChild(adv);
    bar.appendChild(button('Exit', function () { setEditing(state, false); }));
    ui.appendChild(bar);

    var panel = document.createElement('div');
    panel.className = 'ev-panel';
    panel.innerHTML =
      '<p class="ev-crumb" id="ev-crumb"></p>' +
      '<div id="ev-body"></div>';
    ui.appendChild(panel);

    var outline = document.createElement('div');
    outline.id = 'ev-outline';
    outline.hidden = true;

    var indicator = document.createElement('div');
    indicator.id = 'ev-drop';
    indicator.hidden = true;

    document.body.appendChild(ui);
    document.body.appendChild(outline);
    document.body.appendChild(indicator);

    state.ui = ui;
    state.outline = outline;
    state.indicator = indicator;
    state.nodes.addSelect = addSelect;
    state.nodes.crumb = panel.querySelector('#ev-crumb');
    state.nodes.body = panel.querySelector('#ev-body');

    state.root.addEventListener('click', onClick, true);
    state.root.addEventListener('dragstart', onDragStart);
    state.root.addEventListener('dragover', onDragOver);
    state.root.addEventListener('drop', onDrop);
    state.root.addEventListener('dragend', onDragEnd);
    window.addEventListener('scroll', function () { paintOutline(state); }, true);
    window.addEventListener('resize', function () { paintOutline(state); });
    document.addEventListener('keydown', onKey);
  }

  function button(label, fn, cls) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'ev-btn' + (cls ? ' ' + cls : '');
    b.textContent = label;
    b.addEventListener('click', function (e) { e.preventDefault(); fn(); });
    return b;
  }

  // ---------- selection ----------

  function onClick(e) {
    var state = currentState;
    if (!state || !state.editing) return;
    e.preventDefault();
    e.stopPropagation();
    var el = e.target;
    if (el === state.root) return select(state, null);
    if (!state.root.contains(el)) return;
    select(state, el);
  }

  function select(state, el) {
    state.selected = el;
    paintOutline(state);
    renderPanel(state);
  }

  function paintOutline(state) {
    var o = state.outline;
    if (!o) return;
    var el = state.selected;
    if (!el || !state.editing) { o.hidden = true; return; }
    var r = el.getBoundingClientRect();
    o.hidden = false;
    o.style.top = r.top + 'px';
    o.style.left = r.left + 'px';
    o.style.width = r.width + 'px';
    o.style.height = r.height + 'px';
    o.textContent = el.tagName.toLowerCase() + (isSlot(el) ? ' · ' + el.getAttribute('data-ev-slot') : '');
  }

  // ---------- inspector panel ----------

  function renderPanel(state) {
    var body = state.nodes.body;
    var crumb = state.nodes.crumb;
    body.textContent = '';
    crumb.textContent = '';
    var el = state.selected;
    if (!el) {
      body.appendChild(note('Click an element on the page to edit it. Drag elements to move them.'));
      renderPageCss(state, body);
      return;
    }

    // Breadcrumb: root > ... > selected
    var chain = [el];
    while (chain[0].parentNode && chain[0].parentNode !== state.root) chain.unshift(chain[0].parentNode);
    chain.forEach(function (node, i) {
      if (i) crumb.appendChild(document.createTextNode(' > '));
      var a = document.createElement('a');
      a.href = '#';
      a.textContent = node.tagName.toLowerCase();
      a.addEventListener('click', function (e) { e.preventDefault(); select(state, node); });
      crumb.appendChild(a);
    });

    if (isSlot(el)) {
      body.appendChild(note('Slot "' + el.getAttribute('data-ev-slot') + '" — live content. You can move and style it, but not edit inside it.'));
    } else if (isTextOnly(el)) {
      body.appendChild(field('Text', 'text', el.textContent, function (v) {
        el.textContent = v;
        paintOutline(state);
      }));
    }

    body.appendChild(sectionTitle('Attributes'));
    renderAttrs(state, body, el);

    body.appendChild(sectionTitle('Style (this element)'));
    var styleBox = document.createElement('div');
    body.appendChild(styleBox);
    STYLE_PROPS.forEach(function (spec) { styleBox.appendChild(styleRow(state, el, spec)); });

    body.appendChild(sectionTitle('Page CSS'));
    renderPageCss(state, body);
  }

  function renderAttrs(state, body, el) {
    var tag = el.tagName.toLowerCase();
    var attrs = (ALLOWED_ATTRS['*'] || []).concat(ALLOWED_ATTRS[tag] || []);
    attrs.forEach(function (name) {
      if (name === 'data-ev-slot') return;
      var val = el.getAttribute(name);
      if (val === null) val = '';
      var input;
      if (name === 'style') input = field('style', 'textarea', val, function (v) {
        if (v.trim()) el.setAttribute('style', v); else el.removeAttribute('style');
        paintOutline(state);
      });
      else input = field(name, 'text', val, function (v) {
        if (v === '') el.removeAttribute(name); else el.setAttribute(name, v);
        paintOutline(state);
      });
      body.appendChild(input);
    });
  }

  // A row of label + input. Returns the wrapper element.
  function field(labelText, type, value, onChange) {
    var wrap = document.createElement('label');
    wrap.className = 'ev-field';
    var span = document.createElement('span');
    span.textContent = labelText;
    wrap.appendChild(span);
    var input = document.createElement(type === 'textarea' ? 'textarea' : 'input');
    if (type !== 'textarea') input.type = type;
    input.value = value;
    if (type === 'textarea') input.rows = 3;
    input.spellcheck = false;
    input.addEventListener('input', function () { onChange(input.value); });
    input.addEventListener('change', function () { onChange(input.value); });
    wrap.appendChild(input);
    return wrap;
  }

  function styleRow(state, el, spec) {
    var row = document.createElement('div');
    row.className = 'ev-field';
    var span = document.createElement('span');
    span.textContent = spec.label;
    row.appendChild(span);
    var input = document.createElement('input');
    input.type = 'text';
    input.value = el.style.getPropertyValue(spec.p);
    input.placeholder = spec.p;
    input.addEventListener('input', function () {
      if (input.value.trim()) el.style.setProperty(spec.p, input.value);
      else el.style.removeProperty(spec.p);
      paintOutline(state);
    });
    row.appendChild(input);
    if (spec.color) {
      var swatch = document.createElement('input');
      swatch.type = 'color';
      swatch.className = 'ev-swatch';
      swatch.value = toHex(el.style.getPropertyValue(spec.p)) || '#000000';
      swatch.addEventListener('input', function () {
        input.value = swatch.value;
        el.style.setProperty(spec.p, swatch.value);
      });
      row.appendChild(swatch);
    }
    return row;
  }

  function renderPageCss(state, body) {
    if (!state.styleEl) { body.appendChild(note('No stylesheet yet.')); return; }
    var rules = listStyleRules(state);
    var row = document.createElement('div');
    row.className = 'ev-field';
    var label = document.createElement('span');
    label.textContent = 'Rule';
    row.appendChild(label);
    var sel = document.createElement('select');
    var optNone = document.createElement('option');
    optNone.value = '';
    optNone.textContent = '— pick a selector —';
    sel.appendChild(optNone);
    rules.forEach(function (r) {
      var o = document.createElement('option');
      o.value = r.selector;
      o.textContent = r.selector;
      sel.appendChild(o);
    });
    row.appendChild(sel);
    body.appendChild(row);

    var editor = document.createElement('div');
    editor.hidden = true;
    body.appendChild(editor);

    sel.addEventListener('change', function () {
      var chosen = sel.value;
      editor.textContent = '';
      if (!chosen) { editor.hidden = true; return; }
      editor.hidden = false;
      var cssText = findRuleDecls(getUserCss(state), chosen) || '';
      editor.appendChild(field('CSS declarations', 'textarea', cssText, function (v) {
        setRuleDecls(state, chosen, v);
      }));
    });
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

  // ---------- element operations ----------

  function targetContainer(state) {
    var el = state.selected;
    if (el && !VOID_TAGS[el.tagName.toLowerCase()]) return el;
    return state.root;
  }

  function addElement(state, tag) {
    var el = document.createElement(tag);
    if (tag === 'img') { el.setAttribute('src', '/static/placeholder.png'); el.setAttribute('alt', ''); }
    else if (tag === 'a') { el.setAttribute('href', '#'); el.textContent = 'Link'; }
    else if (VOID_TAGS[tag]) { /* empty */ }
    else if (['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'span', 'li', 'td', 'th', 'blockquote', 'code', 'em', 'strong', 'b', 'i', 'u', 'small', 'mark', 'cite', 'q', 'kbd', 'var', 'summary', 'figcaption', 'caption', 'dt', 'dd', 'address', 'abbr'].indexOf(tag) !== -1) {
      el.textContent = 'Text';
    }
    var container = targetContainer(state);
    container.appendChild(el);
    el.setAttribute('draggable', 'true');
    select(state, el);
  }

  function duplicate(state) {
    if (!state.selected) return;
    var copy = state.selected.cloneNode(true);
    copy.removeAttribute('draggable');
    state.selected.parentNode.insertBefore(copy, state.selected.nextSibling);
    select(state, copy);
  }

  function removeSelected(state) {
    if (!state.selected) return;
    var el = state.selected;
    if (isSlot(el) && !window.confirm('Remove the "' + el.getAttribute('data-ev-slot') + '" slot? That live content will stop appearing.')) return;
    var parent = el.parentNode;
    el.parentNode.removeChild(el);
    select(state, parent === state.root ? null : parent);
  }

  function wrapSelected(state) {
    if (!state.selected) return;
    var el = state.selected;
    var div = document.createElement('div');
    el.parentNode.insertBefore(div, el);
    div.appendChild(el);
    div.setAttribute('draggable', 'true');
    select(state, div);
  }

  // ---------- drag & drop ----------

  function onDragStart(e) {
    var state = currentState;
    if (!state || !state.editing) return;
    var el = e.target;
    if (el === state.root || !state.root.contains(el)) { e.preventDefault(); return; }
    state.dragged = el;
    e.dataTransfer.effectAllowed = 'move';
    try { e.dataTransfer.setData('text/plain', el.tagName); } catch (_) {}
  }

  function onDragOver(e) {
    var state = currentState;
    if (!state || !state.editing || !state.dragged) return;
    var t = e.target;
    if (!t || t === state.dragged || state.dragged.contains(t)) { clearIndicator(state); return; }
    if (t !== state.root && !state.root.contains(t)) { clearIndicator(state); return; }
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (t === state.root) {
      state.dropTarget = t; state.dropRel = 'inside';
      showIndicator(state, t, 'inside');
      return;
    }
    var r = t.getBoundingClientRect();
    var y = e.clientY - r.top;
    var rel = y < r.height * 0.28 ? 'before' : (y > r.height * 0.72 ? 'after' : 'inside');
    state.dropTarget = t; state.dropRel = rel;
    showIndicator(state, t, rel);
  }

  function onDrop(e) {
    var state = currentState;
    if (!state || !state.editing || !state.dragged || !state.dropTarget) return;
    e.preventDefault();
    var dragged = state.dragged;
    var target = state.dropTarget;
    var rel = state.dropRel;
    if (rel === 'inside') {
      target.appendChild(dragged);
    } else {
      var parent = target.parentNode;
      parent.insertBefore(dragged, rel === 'before' ? target : target.nextSibling);
    }
    clearIndicator(state);
    select(state, dragged);
  }

  function onDragEnd() {
    var state = currentState;
    if (!state) return;
    state.dragged = null;
    state.dropTarget = null;
    clearIndicator(state);
  }

  function showIndicator(state, target, rel) {
    var ind = state.indicator;
    if (!ind) return;
    var r = target.getBoundingClientRect();
    ind.hidden = false;
    if (rel === 'inside') {
      ind.className = 'ev-drop-inside';
      ind.style.top = r.top + 'px';
      ind.style.left = r.left + 'px';
      ind.style.width = r.width + 'px';
      ind.style.height = r.height + 'px';
    } else {
      ind.className = 'ev-drop-line';
      ind.style.left = r.left + 'px';
      ind.style.width = r.width + 'px';
      ind.style.top = (rel === 'before' ? r.top : r.bottom) + 'px';
      ind.style.height = '2px';
    }
  }

  function clearIndicator(state) {
    if (state && state.indicator) state.indicator.hidden = true;
  }

  function onKey(e) {
    var state = currentState;
    if (!state || !state.editing) return;
    if (e.key === 'Escape') select(state, null);
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
    var tag = node.tagName.toLowerCase();
    var order = ['id', 'class', 'style', 'title', 'dir', 'lang']
      .concat((ALLOWED_ATTRS[tag] || []))
      .concat(['data-ev-slot']);
    var seen = {};
    var out = '';
    for (var i = 0; i < order.length; i++) {
      var name = order[i];
      if (seen[name]) continue;
      seen[name] = 1;
      var v = node.getAttribute(name);
      if (v === null) continue;
      if (name === 'style') { v = v.trim(); if (!v) continue; }
      out += ' ' + name + '="' + escapeAttr(v) + '"';
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
  function isTextOnly(el) {
    for (var i = 0; i < el.childNodes.length; i++) {
      if (el.childNodes[i].nodeType === 1) return false;
    }
    return !isSlot(el);
  }

  // ---------- page CSS ----------

  function getUserCss(state) { return state.styleEl ? state.styleEl.textContent : ''; }
  function setUserCss(state, text) { if (state.styleEl) state.styleEl.textContent = text; }

  function listStyleRules(state) {
    var out = [];
    var sheet = state.styleEl && state.styleEl.sheet;
    if (!sheet) return out;
    var rules;
    try { rules = sheet.cssRules; } catch (e) { return out; }
    for (var i = 0; i < rules.length; i++) {
      if (rules[i].selectorText) out.push({ selector: rules[i].selectorText });
    }
    return out;
  }

  function findRuleDecls(css, selector) {
    var loc = findRule(css, selector);
    return loc ? css.slice(loc.open + 1, loc.close).trim() : '';
  }

  function setRuleDecls(state, selector, decls) {
    var css = getUserCss(state);
    var loc = findRule(css, selector);
    if (loc) css = css.slice(0, loc.open + 1) + '\n' + decls + '\n' + css.slice(loc.close);
    else css = css.replace(/\s*$/, '') + '\n' + selector + ' {\n' + decls + '\n}\n';
    setUserCss(state, css);
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
        var d = 0, close = -1;
        var i = open;
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

  // ---------- save ----------

  function save(state) {
    if (!state.csrf) { toast('Missing CSRF token — reload the page.'); return; }
    var payload = { html: serialize(state), css: getUserCss(state) };
    fetch('/u/' + encodeURIComponent(state.username) + '/edit/visual', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-CSRF-Token': state.csrf,
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: JSON.stringify(payload),
    }).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function () {
      toast('Profile saved');
      setDraggable(state, true);
    }).catch(function (err) {
      toast('Save failed: ' + err.message);
    });
  }

  // ---------- small helpers ----------

  function toHex(value) {
    if (!value) return '';
    value = value.trim();
    if (/^#[0-9a-f]{6}$/i.test(value)) return value;
    if (/^#[0-9a-f]{3}$/i.test(value)) {
      return '#' + value[1] + value[1] + value[2] + value[2] + value[3] + value[3];
    }
    var m = value.match(/^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i);
    if (m) {
      return '#' + [m[1], m[2], m[3]].map(function (n) {
        return ('0' + Math.min(255, parseInt(n, 10)).toString(16)).slice(-2);
      }).join('');
    }
    return '';
  }

  var toastEl = null;
  function toast(msg) {
    if (!toastEl) {
      toastEl = document.createElement('div');
      toastEl.className = 'ev-toast';
      document.body.appendChild(toastEl);
    }
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { toastEl.classList.remove('show'); }, 2600);
  }

  document.addEventListener('DOMContentLoaded', init);
})();
