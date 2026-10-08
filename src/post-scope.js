'use strict';

// Build the scoped CSS for posts shown off-profile (feed, single post): each
// author's profile stylesheet, rewritten to apply to that author's posts only.
// One <style> worth of rules per distinct author, deduped across the page.

const { getCustomization, getUserById, getUserFileByPath, splitStoredPath } = require('./db');
const { sanitizeCSS } = require('./sanitize');
const { scopeProfileCss, fontFamilyFromName } = require('./profile-css');

function authorFont(user) {
  const split = user && user.custom_font ? splitStoredPath(user.custom_font) : null;
  if (!split) return null;
  const row = getUserFileByPath(split.root, split.path);
  return { family: fontFamilyFromName(row && row.name, user.username), id: row ? row.id : 0 };
}

function buildPostScopeCss(items) {
  const seen = Object.create(null);
  let out = '';
  (items || []).forEach((item) => {
    const username = item && item.authorUsername;
    if (!username || seen[username]) return;
    seen[username] = true;

    const user = getUserById(item.authorId);
    if (!user) return;
    const custom = getCustomization(user.id);
    const font = authorFont(user);
    const isDefault = !custom.css || !custom.css.trim();
    if (isDefault && !font) return; // nothing customised — the app default already shows

    const prefix = 'ev-' + String(username).replace(/[^A-Za-z0-9_-]/g, '');
    const scope = '.ev-scope[data-ev-author="' + username + '"]';
    if (!isDefault) {
      out += scopeProfileCss(sanitizeCSS(custom.css), scope, {
        fontFamily: font && font.family,
        fontPrefix: prefix,
      }) + '\n';
    }
    if (font) {
      out += "@font-face { font-family: '" + prefix + "'; src: url('/u/"
        + encodeURIComponent(username) + "/font?v=" + font.id + "'); font-display: swap; }\n";
    }
  });
  return out;
}

module.exports = { buildPostScopeCss };
