'use strict';

const sanitizeHtml = require('sanitize-html');

// CSS that can execute script (old IE) or load script-bearing resources is
// neutralized. Modern CSS alone cannot run JavaScript, so this is mostly about
// legacy vectors and keeping profiles self-contained.
function sanitizeCSS(css) {
  if (!css) return '';
  let out = css;
  out = out.replace(/expression\s*\(/gi, 'expression-disabled(');
  out = out.replace(/url\s*\(\s*['"]?\s*javascript:[^)]*\)/gi, 'url()');
  out = out.replace(/url\s*\(\s*['"]?\s*data:[^)]*\)/gi, 'url()');
  out = out.replace(/-moz-binding\s*:/gi, 'disabled-binding:');
  out = out.replace(/behavior\s*:/gi, 'disabled-behavior:');
  out = out.replace(/@import[^;]+;/gi, '');
  out = out.replace(/<\/?script[^>]*>/gi, '');
  out = out.replace(/url\s*\(\s*['"]?\s*https?:\/\/[^)]*\)/gi, 'url()');
  // Prevent breaking out of the <style> element.
  out = out.replace(/<\/style/gi, '<\\/style');
  return out;
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
