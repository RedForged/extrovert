'use strict';

const sanitizeHtml = require('sanitize-html');
const postcss = require('postcss');

const BLOCKED_AT_RULES = /^@(?:charset|import|namespace|document|-moz-document)(?=\s|$)/i;
const URL_BEARING_FUNCTIONS = /(?:^|[^\w-])(?:-webkit-)?(?:image-set|cross-fade)\s*\(/i;

function decodeCssEscapes(value) {
  return String(value || '').replace(
    /\\(?:([0-9a-fA-F]{1,6})(?:\r\n|[ \n\r\t\f])?|([^\n\r\f0-9a-fA-F]))/g,
    (_match, hex, literal) => {
      if (hex) {
        const codePoint = parseInt(hex, 16);
        if (!codePoint || codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
          return '\ufffd';
        }
        return String.fromCodePoint(codePoint);
      }
      if (literal === '\r' || literal === '\n' || literal === '\f') return '';
      return literal;
    }
  );
}

function stripCssComments(value) {
  return String(value || '').replace(/\/\*[\s\S]*?\*\//g, '');
}

// Only same-origin references are safe in user CSS. The origin is deliberately
// fake: relative paths resolve on it, while scheme-relative and absolute URLs
// resolve to their real origin and are rejected after backslash normalization.
function isSafeCssUrl(value) {
  const target = String(value || '').trim();
  if (!target) return true;
  if (/[\u0000-\u001f\u007f]/.test(target)) return false;
  try {
    return new URL(target, 'https://extrovert.invalid/').origin === 'https://extrovert.invalid';
  } catch {
    return false;
  }
}

function declarationValueIsSafe(value) {
  const decoded = stripCssComments(decodeCssEscapes(value));
  if (/\bexpression\s*\(/i.test(decoded)) return false;
  if (/\bprogid\s*:/i.test(decoded)) return false;
  // image-set()/cross-fade() accept bare quoted URLs as well as url(), so a
  // URL-token-only check would miss them. They are not needed for profile or
  // room styling and are rejected as a class.
  if (URL_BEARING_FUNCTIONS.test(decoded)) return false;

  const urlPattern = /url\s*\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)/gi;
  let match;
  while ((match = urlPattern.exec(decoded))) {
    const target = match[1] !== undefined ? match[1] : (match[2] !== undefined ? match[2] : match[3]);
    if (!isSafeCssUrl(target)) return false;
  }
  return true;
}

// CSS is parsed before validation so escaped syntax is interpreted the same way
// as it is by the browser. Declarations that can load remote resources are
// removed; safe local assets (profile fonts and uploaded images) still work.
function sanitizeCSS(css) {
  if (!css) return '';
  let root;
  try {
    root = postcss.parse(String(css), { from: undefined });
  } catch {
    return '';
  }

  root.walkComments((comment) => comment.remove());
  root.walkAtRules((rule) => {
    const text = decodeCssEscapes(stripCssComments(rule.toString())).trim();
    if (BLOCKED_AT_RULES.test(text)) {
      rule.remove();
      return;
    }
    if (!declarationValueIsSafe(rule.params || '')) rule.remove();
  });
  root.walkRules((rule) => {
    const selector = stripCssComments(decodeCssEscapes(rule.selector || ''));
    // :has() lets otherwise harmless selectors branch on secret-bearing
    // attributes elsewhere in the document. Custom CSS does not need it.
    if (/:(?:has)\s*\(/i.test(selector)) rule.remove();
  });
  root.walkDecls((decl) => {
    const prop = decodeCssEscapes(decl.prop || '').trim().toLowerCase();
    if (prop === 'behavior' || prop === '-moz-binding') {
      decl.remove();
      return;
    }
    if (!declarationValueIsSafe(decl.value || '')) decl.remove();
  });

  // PostCSS preserves string contents. Make sure even an unusual node that
  // survived the walk cannot terminate the surrounding <style> raw-text block.
  return root.toString().replace(/<\/(style|script)/gi, '<\\/$1');
}

const ALLOWED_TAGS = [
  'div', 'span', 'p', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'a', 'img', 'b', 'i', 'em', 'strong', 'u', 's', 'strike', 'small', 'mark',
  'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'blockquote', 'pre', 'code',
  'table', 'thead', 'tbody', 'tr', 'th', 'td', 'caption', 'colgroup', 'col',
  'section', 'article', 'header', 'footer', 'nav', 'aside', 'main', 'figure', 'figcaption',
  'details', 'summary', 'abbr', 'address', 'cite', 'q', 'sub', 'sup', 'time', 'kbd', 'var',
];

const ALLOWED_ATTRS = {
  '*': ['class', 'id', 'style', 'title', 'dir', 'lang', 'data-ev-slot'],
  a: ['href', 'name', 'target', 'rel'],
  img: ['src', 'alt', 'width', 'height', 'loading'],
  td: ['colspan', 'rowspan'],
  th: ['colspan', 'rowspan'],
  col: ['span'],
  colgroup: ['span'],
  time: ['datetime'],
};

function sanitizeProfileHTML(html) {
  if (!html) return '';
  let clean = sanitizeHtml(html, {
    allowedTags: ALLOWED_TAGS,
    allowedAttributes: ALLOWED_ATTRS,
    allowedSchemes: ['http', 'https', 'mailto'],
    allowedSchemesByTag: { img: ['http', 'https'] },
    // No <script>, no on* handlers, no javascript: URLs — enforce hard.
    disallowedTagsMode: 'discard',
  });
  // Belt-and-suspenders: scrub inline style="" contents for CSS vectors.
  clean = clean.replace(/\bstyle\s*=\s*"([^"]*)"/gi, (m, body) =>
    `style="${sanitizeCSS(body).replace(/"/g, '&quot;')}"`
  );
  clean = clean.replace(/\bstyle\s*=\s*'([^']*)'/gi, (m, body) =>
    `style="${sanitizeCSS(body).replace(/"/g, '&quot;')}"`
  );
  return clean;
}

// ---------- profile template slots ----------
// Live profile data is rendered through named placeholder elements, e.g.
// <div data-ev-slot="posts"></div>. They survive sanitization (the attribute
// is allowed above); the server injects the matching fragment after sanitizing.
// Slots are empty by convention, so a user can move/restyle them but not edit
// their contents. Unknown slot names render empty.
const SLOT_NAMES = [
  'avatar', 'displayName', 'botBadge', 'handle', 'pronouns', 'bio',
  'stats', 'follow', 'chat', 'report', 'posts',
];

// Find the start index of the closing tag matching an already-opened element,
// respecting nesting of the same tag. Returns -1 when unbalanced.
function findMatchingClose(html, from, tag) {
  const openRe = new RegExp('<' + tag + '(?=[\\s/>])', 'gi');
  const closeRe = new RegExp('</' + tag + '\\s*>', 'gi');
  let depth = 1;
  let i = from;
  while (i < html.length) {
    openRe.lastIndex = i;
    closeRe.lastIndex = i;
    const o = openRe.exec(html);
    const c = closeRe.exec(html);
    if (!c) return -1;
    if (o && o.index < c.index) {
      const gt = html.indexOf('>', o.index);
      if (gt !== -1 && html[gt - 1] === '/') { i = gt + 1; continue; }
      depth++;
      i = o.index + o[0].length;
    } else {
      depth--;
      if (depth === 0) return c.index;
      i = c.index + c[0].length;
    }
  }
  return -1;
}

// Rewrite the inner HTML of every slot element using `innerFor(name)`.
function transformSlots(html, innerFor) {
  if (!html) return html || '';
  const re = /<([a-zA-Z][a-zA-Z0-9-]*)\b[^>]*\bdata-ev-slot\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*>/g;
  let out = '';
  let last = 0;
  let m;
  while ((m = re.exec(html))) {
    const tag = m[1].toLowerCase();
    const slotName = (m[2] !== undefined ? m[2] : m[3] || '').trim();
    const openTag = m[0];
    const openEnd = m.index + openTag.length;
    const fragment = innerFor(slotName) || '';
    if (/\/\s*>$/.test(openTag)) {
      out += html.slice(last, m.index) + openTag.replace(/\/\s*>$/, '>') + fragment + '</' + tag + '>';
      last = openEnd;
      re.lastIndex = openEnd;
      continue;
    }
    const closeStart = findMatchingClose(html, openEnd, tag);
    if (closeStart === -1) continue;
    const gt = html.indexOf('>', closeStart);
    if (gt === -1) continue;
    const elementEnd = gt + 1;
    out += html.slice(last, m.index) + openTag + fragment + html.slice(closeStart, elementEnd);
    last = elementEnd;
    re.lastIndex = elementEnd;
  }
  out += html.slice(last);
  return out;
}

// Replace each slot with its rendered fragment. Values are trusted,
// server-rendered HTML injected after user HTML has been sanitized.
function substituteSlots(html, fragments) {
  const map = fragments || {};
  return transformSlots(html, (name) => map[name]);
}

// Empty every slot's children (used on write so substitution is deterministic,
// and so users cannot smuggle markup into a slot body).
function normalizeSlots(html) {
  return transformSlots(html, () => '');
}

// Pronouns are free text (e.g. "he/him", "they/them" or something custom),
// stored as a JSON array of up to 6 short strings.
const PRONOUN_FIELDS_MAX = 6;
const PRONOUN_LENGTH_MAX = 24;

// Read side: stored JSON -> array of usable strings. Never throws.
function parsePronouns(stored) {
  if (!stored) return [];
  let list;
  try { list = JSON.parse(stored); } catch (e) { return []; }
  if (!Array.isArray(list)) return [];
  return list
    .filter((p) => typeof p === 'string' && p.trim())
    .map((p) => p.trim().slice(0, PRONOUN_LENGTH_MAX))
    .slice(0, PRONOUN_FIELDS_MAX);
}

// Write side: form fields (one or many) -> the JSON string to store. Returns
// undefined for input that isn't a string or an array of them, so callers can
// tell "clear them" (empty string/array) apart from "ignore this".
function sanitizePronouns(input) {
  if (typeof input !== 'string' && !Array.isArray(input)) return undefined;
  const list = typeof input === 'string' ? [input] : input;
  const clean = list
    .filter((p) => typeof p === 'string')
    .map((p) => p.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, PRONOUN_LENGTH_MAX))
    .filter(Boolean)
    .slice(0, PRONOUN_FIELDS_MAX);
  return JSON.stringify(clean);
}

module.exports = {
  sanitizeProfileHTML, sanitizeCSS,
  parsePronouns, sanitizePronouns, PRONOUN_FIELDS_MAX, PRONOUN_LENGTH_MAX,
  SLOT_NAMES, substituteSlots, normalizeSlots,
};
