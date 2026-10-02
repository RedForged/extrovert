'use strict';

const MarkdownIt = require('markdown-it');
const sanitizeHtml = require('sanitize-html');

const md = new MarkdownIt({
  html: false,        // Escape HTML tags in source
  xhtmlOut: false,
  breaks: true,       // Convert '\n' in paragraphs into <br>
  langPrefix: 'language-',
  linkify: true,      // Autoconvert URL-like text to links
  typographer: false,
});

// Configure links to open in a new tab with safe security attributes
const defaultLinkOpen = md.renderer.rules.link_open || function(tokens, idx, options, env, self) {
  return self.renderToken(tokens, idx, options);
};

md.renderer.rules.link_open = function(tokens, idx, options, env, self) {
  tokens[idx].attrSet('target', '_blank');
  tokens[idx].attrSet('rel', 'noopener noreferrer nofollow');
  return defaultLinkOpen(tokens, idx, options, env, self);
};

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
  a: ['href', 'target', 'rel', 'title'],
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

module.exports = { renderMarkdown };
