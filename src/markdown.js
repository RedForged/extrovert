'use strict';

const MarkdownIt = require('markdown-it');
const sanitizeHtml = require('sanitize-html');

// Mentions: @username (human) or %botname (bot namespace) — 3-20 [a-zA-Z0-9_],
// at a boundary never preceded by a word character, @, % or / — so emails
// (foo@bar.com) and paths never match. The sigil is part of the handle.
const MENTION_RE = /(^|[^\w@\/%])([@%])([a-zA-Z0-9_]{3,20})\b/g;

const md = new MarkdownIt({
  html: false,        // Escape HTML tags in source
  xhtmlOut: false,
  breaks: true,       // Convert '\n' in paragraphs into <br>
  langPrefix: 'language-',
  linkify: true,      // Autoconvert URL-like text to links
  typographer: false,
});

// Configure links to open in a new tab with safe security attributes.
// Internal links (mention profiles) stay in the same tab.
const defaultLinkOpen = md.renderer.rules.link_open || function(tokens, idx, options, env, self) {
  return self.renderToken(tokens, idx, options);
};

md.renderer.rules.link_open = function(tokens, idx, options, env, self) {
  const href = tokens[idx].attrGet('href') || '';
  if (href.indexOf('/u/') !== 0) {
    tokens[idx].attrSet('target', '_blank');
    tokens[idx].attrSet('rel', 'noopener noreferrer nofollow');
  }
  return defaultLinkOpen(tokens, idx, options, env, self);
};

// Linkify @mentions in inline text tokens. Operates on renderer tokens (never
// on raw HTML), so it cannot bypass sanitization; code spans and URLs are not
// plain text tokens and are never touched.
md.core.ruler.after('linkify', 'mentions', function (state) {
  for (const block of state.tokens) {
    if (block.type !== 'inline' || !block.children) continue;
    const out = [];
    for (const child of block.children) {
      if (child.type !== 'text' || !/[@%]/.test(child.content)) {
        out.push(child);
        continue;
      }
      const text = child.content;
      const re = new RegExp(MENTION_RE.source, 'g');
      let last = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const start = m.index + m[1].length;
        if (start > last) {
          const before = new state.Token('text', '', 0);
          before.content = text.slice(last, start);
          out.push(before);
        }
        const handle = m[2] + m[3];
        // Humans link to their bare username; bots live at their %handle.
        const lookupName = m[2] === '%' ? handle : m[3];
        const open = new state.Token('link_open', 'a', 1);
        open.attrs = [['href', '/u/' + encodeURIComponent(lookupName)], ['class', 'mention']];
        out.push(open);
        const label = new state.Token('text', '', 0);
        label.content = handle;
        out.push(label);
        out.push(new state.Token('link_close', 'a', -1));
        last = start + handle.length;
      }
      if (last === 0) {
        out.push(child);
      } else if (last < text.length) {
        const tail = new state.Token('text', '', 0);
        tail.content = text.slice(last);
        out.push(tail);
      }
    }
    block.children = out;
  }
  return true;
});

const ALLOWED_TAGS = [
  'p', 'br', 'strong', 'b', 'em', 'i', 's', 'strike', 'del',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'ul', 'ol', 'li',
  'blockquote', 'pre', 'code',
  'hr',
  'table', 'thead', 'tbody', 'tr', 'th', 'td',
  'a', 'img', 'span', 'sub', 'sup'
];

const ALLOWED_ATTRS = {
  a: ['href', 'target', 'rel', 'title', 'class'],
  img: ['src', 'alt', 'title'],
  code: ['class'],
  pre: ['class'],
  th: ['align'],
  td: ['align'],
};

/**
 * Render Markdown content to safe, sanitized HTML.
 *
 * @param {string} content - Raw markdown text
 * @returns {string} Sanitized HTML string
 */
function renderMarkdown(content) {
  if (!content || typeof content !== 'string') return '';
  const rawHtml = md.render(content);
  return sanitizeHtml(rawHtml, {
    allowedTags: ALLOWED_TAGS,
    allowedAttributes: ALLOWED_ATTRS,
    allowedSchemes: ['http', 'https', 'mailto'],
    allowedSchemesByTag: { img: ['http', 'https'] },
    disallowedTagsMode: 'discard',
  });
}

/**
 * Extract unique mentions from raw text as full handles ("@alice", "%echo_bot"
 * — the sigil is the namespace), case-insensitive dedupe, first spelling kept.
 *
 * @param {string} content
 * @returns {string[]} mentioned handles with sigil
 */
function parseMentions(content) {
  if (!content || typeof content !== 'string') return [];
  const found = new Map();
  const re = new RegExp(MENTION_RE.source, 'g');
  let m;
  while ((m = re.exec(content)) !== null) {
    const handle = m[2] + m[3];
    const key = handle.toLowerCase();
    if (!found.has(key)) found.set(key, handle);
  }
  return [...found.values()];
}

module.exports = { renderMarkdown, parseMentions };
