'use strict';

// Move a profile's CSS off the profile: rewrite a user's stylesheet so it only
// applies inside one scoped wrapper (a post shown in the feed), never the page.
// Pure string work — no DOM.

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function matchBrace(css, open) {
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    if (css[i] === '{') depth++;
    else if (css[i] === '}') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

// Split a selector list on top-level commas (ignoring commas inside (...) / [...]).
function splitSelectors(sel) {
  const parts = [];
  let depth = 0, cur = '';
  for (let i = 0; i < sel.length; i++) {
    const c = sel[i];
    if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth = Math.max(0, depth - 1);
    if (c === ',' && depth === 0) { parts.push(cur); cur = ''; }
    else cur += c;
  }
  parts.push(cur);
  return parts.map(s => s.trim()).filter(Boolean);
}

// `body` / `html` / `:root` mean "the page" — inside a post they map onto the
// wrapper itself, so a profile's page font/colour/background reach the post.
function scopeSelector(s, scope) {
  const m = s.match(/^(body|html|:root)(?![\w-])\s*/);
  if (m) {
    const rest = s.slice(m[0].length).trim();
    return rest ? scope + ' ' + rest : scope;
  }
  return scope + ' ' + s;
}

// A post must never be able to cover the app: neutralise viewport escapes.
function stripEscapeDecls(block) {
  return block.replace(/position\s*:\s*(fixed|sticky)\b/gi, 'position: static');
}

function rewriteAnimations(block, renames) {
  if (!renames.length) return block;
  return block.replace(/(animation(?:-name)?\s*:\s*)([^;}]+)/gi, (m, pre, val) => {
    let out = val;
    renames.forEach(([from, to]) => { out = out.replace(new RegExp('\\b' + escapeRe(from) + '\\b', 'g'), to); });
    return pre + out;
  });
}

function collectKeyframes(css, prefix) {
  const renames = [];
  const re = /@(-webkit-)?keyframes\s+([A-Za-z_][\w-]*)/g;
  let m;
  while ((m = re.exec(css))) renames.push([m[2], prefix + '-' + m[2]]);
  return renames;
}

function transformRules(css, scope, renames, prefix) {
  let out = '';
  let i = 0;
  while (i < css.length) {
    const open = css.indexOf('{', i);
    if (open === -1) break;
    const selector = css.slice(i, open).trim();
    const close = matchBrace(css, open);
    if (close === -1) break; // unbalanced — stop, drop the rest
    const block = css.slice(open + 1, close);

    if (selector.charAt(0) === '@') {
      const at = selector.split(/\s+/)[0].toLowerCase();
      if (at === '@media' || at === '@supports' || at === '@layer' || at === '@container') {
        out += selector + '{' + transformRules(block, scope, renames, prefix) + '}';
      } else if (at === '@keyframes' || at === '@-webkit-keyframes') {
        const parts = selector.split(/\s+/);
        const name = parts[parts.length - 1];
        parts[parts.length - 1] = prefix + '-' + name;
        out += parts.join(' ') + '{' + block + '}';
      }
      // @font-face (and anything else): dropped when scoped.
    } else {
      const sel = splitSelectors(selector).map(s => scopeSelector(s, scope)).join(', ');
      if (sel) out += sel + '{' + rewriteAnimations(stripEscapeDecls(block), renames) + '}';
    }
    i = close + 1;
  }
  return out;
}

// Rewrite `css` so every rule applies only inside `scope`. When the author has a
// custom font, pass its `fontFamily` and the per-author `fontPrefix` so CSS
// references are renamed to the prefixed family we inject.
function scopeProfileCss(css, scope, opts) {
  opts = opts || {};
  let source = String(css || '');
  if (!source.trim()) return '';
  const prefix = opts.fontPrefix || 'ev';
  if (opts.fontFamily && opts.fontPrefix) source = source.split(opts.fontFamily).join(prefix);
  const renames = collectKeyframes(source, prefix);
  return transformRules(source, scope, renames, prefix);
}

// Same family derivation the font route uses (file name -> usable family).
function fontFamilyFromName(name, fallback) {
  const base = String(name || '').replace(/\.[a-z0-9]+$/i, '');
  const clean = base.replace(/["'\\<>{};()]/g, '').replace(/\s+/g, ' ').trim().slice(0, 40);
  return clean || fallback;
}

module.exports = { scopeProfileCss, fontFamilyFromName };
