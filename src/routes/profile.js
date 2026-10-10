'use strict';

const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
const {
  getUserByUsername, getCustomization, setCustomization, setCustomizationEffect, updateUserProfile,
  getDisplayPost, getUserById, postsByUser, hasLiked, hasShared,
  commentsForPost, isFollowing, countFollowers, countFollowing,
  getFollowers, getFollowing, areMutualFollowers,
  setReferralCode, getReferralCode, getReferralCount,
  setAvatar, createUserFile, splitStoredPath, removeStoredFile, setUserFont, fileDiskPath, getUserFileByPath,
} = require('../db');
const { canView } = require('../network');
const drive = require('../drive');
const { sanitizeProfileHTML, sanitizeCSS, parsePronouns, sanitizePronouns, PRONOUN_FIELDS_MAX, PRONOUN_LENGTH_MAX, substituteSlots, normalizeSlots } = require('../sanitize');

const router = express.Router();

const AVATAR_DIR = path.join(__dirname, '..', '..', 'uploads', 'avatars');
fs.mkdirSync(AVATAR_DIR, { recursive: true });

const ALLOWED_AVATAR_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: AVATAR_DIR,
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomBytes(12).toString('hex') + (ext === '.png' ? '.png' : '.jpg'));
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (ALLOWED_AVATAR_TYPES.includes(file.mimetype)) return cb(null, true);
    cb(null, false);
  },
});

const DEFAULT_PROFILE_HTML = `<div class="ev-banner">
  <h2>Hi, I'm on Extrovert</h2>
  <p>This is my space — I can write my own HTML and CSS here, no scripts
  allowed. Put <code>&lt;!--POSTS--&gt;</code> wherever I want my posts to show up.</p>
</div>
<div class="ev-posts-wrap">
  <!--POSTS-->
</div>`;

const DEFAULT_PROFILE_CSS = `.ev-banner {
  padding: 30px 32px;
  background: linear-gradient(135deg, var(--primary-soft), var(--secondary-soft));
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-lg);
  margin-bottom: 22px;
}
.ev-banner h2 { margin: 0 0 8px; font-family: var(--font-display); color: var(--text); }
.ev-banner p { margin: 0; color: var(--text-secondary); line-height: 1.6; }
.ev-banner code {
  background: var(--surface-2); color: var(--primary-strong);
  padding: 1px 6px; border-radius: 6px; font-size: 0.85em;
  font-family: ui-monospace, monospace;
}
.ev-posts-wrap { display: flex; flex-direction: column; gap: 14px; }`;

// The profile page is a user-authored template. Live data is rendered through
// slot elements (data-ev-slot) the server fills after sanitizing the template —
// see src/sanitize.js. The header below mirrors the previous hardcoded markup.
const POSTS_SLOT = '<div data-ev-slot="posts"></div>';

const PROFILE_EFFECTS = ['matrix', 'glitch'];

const PROFILE_HEADER_SLOTS = `<div class="profile-header">
  <div data-ev-slot="avatar" style="flex:none"></div>
  <div>
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <h1 style="margin:0" data-ev-slot="displayName"></h1>
      <span data-ev-slot="botBadge"></span>
      <span data-ev-slot="chat"></span>
    </div>
    <div class="handle"><span data-ev-slot="handle"></span><span class="pronouns" data-ev-slot="pronouns"></span></div>
    <p class="bio" data-ev-slot="bio"></p>
    <div class="profile-stats" data-ev-slot="stats"></div>
  </div>
  <span class="spacer"></span>
  <div data-ev-slot="follow"></div>
  <div data-ev-slot="report"></div>
</div>`;

// Effective template for a user. v1 is stored verbatim; legacy (v0) content is
// wrapped in the default header + .ev-custom so every profile gets one path.
function buildTemplate(custom) {
  const stored = (custom.html || '').trim();
  if (Number(custom.template_version || 0) >= 1 && stored) return custom.html;
  const content = stored || DEFAULT_PROFILE_HTML;
  const body = content.includes('<!--POSTS-->')
    ? content.replace('<!--POSTS-->', POSTS_SLOT)
    : content + '\n<div class="ev-posts-wrap">\n' + POSTS_SLOT + '\n</div>';
  return PROFILE_HEADER_SLOTS + '\n<div class="ev-custom">\n' + body + '\n</div>';
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function renderView(res, view, locals) {
  return new Promise((resolve, reject) => {
    res.app.render(view, locals, (err, html) => (err ? reject(err) : resolve(html || '')));
  });
}

// Build the trusted, server-rendered fragment for each slot. Injected into the
// (already sanitized) template, so user markup never reaches a slot body.
async function buildProfileFragments(res, ctx) {
  const { viewer, profileUser, isOwn, canSeePosts, mutual, following, pronouns } = ctx;
  const username = profileUser.username;
  const csrf = esc(res.locals.csrfToken || '');
  const f = {};

  f.avatar = profileUser.avatar
    ? `<img src="${esc(profileUser.avatar)}" alt="" style="width:72px;height:72px;border-radius:var(--radius-full);flex:none;object-fit:cover;border:1px solid var(--border-soft)">`
    : `<div class="avatar" style="width:72px;height:72px;font-size:32px">${esc((profileUser.display_name || username).slice(0, 1).toUpperCase())}</div>`;
  f.displayName = esc(profileUser.display_name);
  f.botBadge = profileUser.is_bot ? '<span class="badge" title="Automated account">bot</span>' : '';
  f.handle = '@' + esc(username);
  f.pronouns = pronouns && pronouns.length ? esc(pronouns.join(' · ')) : '';
  f.bio = esc(profileUser.bio || '');

  if (viewer && !isOwn) {
    if (mutual) {
      f.chat = `<a href="/chats/${esc(username)}" class="chat-icon" title="Send a message">${await renderView(res, 'partials/icon', { name: 'chat', size: 18 })}</a>`;
    } else {
      f.chat = `<span class="chat-icon locked" title="Follow each other to start chatting">${await renderView(res, 'partials/icon', { name: 'lock', size: 15 })}</span>`;
    }
  } else {
    f.chat = '';
  }

  const followerCount = countFollowers(profileUser.id);
  const followingCount = countFollowing(profileUser.id);
  const referralCount = getReferralCount(profileUser.id);
  let stats = `<a href="/u/${esc(username)}/followers" title="Followers"><span class="stat-dot dot-friends"></span>${followerCount} follower${followerCount === 1 ? '' : 's'}</a>`;
  stats += `<a href="/u/${esc(username)}/following" title="Following"><span class="stat-dot dot-fof"></span>${followingCount} following</a>`;
  if (referralCount > 0) {
    stats += `<span class="stat-pip" title="${referralCount} person${referralCount === 1 ? '' : 's'} referred">${await renderView(res, 'partials/icon', { name: 'starFilled', size: 13 })} ${referralCount}</span>`;
  }
  f.stats = stats;

  if (viewer && !isOwn) {
    if (following) {
      f.follow = `<form method="post" action="/unfollow/${esc(username)}"><input type="hidden" name="_csrf" value="${csrf}"><button class="btn ghost">${await renderView(res, 'partials/icon', { name: 'check', size: 15 })} Following</button></form>`;
    } else {
      f.follow = `<form method="post" action="/follow/${esc(username)}"><input type="hidden" name="_csrf" value="${csrf}"><button class="btn">${await renderView(res, 'partials/icon', { name: 'plus', size: 15 })} Follow</button></form>`;
    }
    f.report = `<div class="comment-menu-container">`
      + `<button class="comment-menu-btn" title="More actions" aria-label="More actions">${await renderView(res, 'partials/icon', { name: 'more', size: 18 })}</button>`
      + `<div class="comment-menu" style="display:none">`
      + `<button type="button" class="report-item" data-report="user" data-report-id="${profileUser.id}">${await renderView(res, 'partials/icon', { name: 'flag', size: 14 })} Report profile</button>`
      + `</div></div>`;
  } else {
    f.follow = '';
    f.report = '';
  }

  if (canSeePosts) {
    const items = hydrateProfilePosts(profileUser.id, viewer.id);
    f.posts = await renderView(res, 'partials/post-list', { items, currentUser: viewer, onProfile: true, csrfToken: res.locals.csrfToken || '' });
  } else {
    f.posts = '<div class="ev-private">Follow @' + esc(username) + ' to see their posts.</div>';
  }

  return f;
}

// Hydrate a user's posts for display on their profile (resolves reposts).
function hydrateProfilePosts(userId, viewerId) {
  const rows = postsByUser(userId);
  return rows.map(row => {
    const reposter = getUserById(row.user_id);
    let content = row;
    let author = reposter;
    if (row.type === 'repost' && row.repost_of_id) {
      const disp = getDisplayPost(row.repost_of_id);
      // Repost content is bounded by the original author's network visibility.
      if (disp && canView(viewerId, disp.post.user_id)) { content = disp.post; author = getUserById(content.user_id); }
      else { content = Object.assign({}, row, { body: '', media_path: null }); author = reposter; }
    }
    const comments = commentsForPost(content.id);
    return {
      id: row.id,
      interactId: content.id,
      type: content.type,
      body: content.body,
      mediaPath: content.media_path,
      createdAt: row.created_at,
      isRepost: row.type === 'repost',
      reposterName: row.type === 'repost' ? reposter?.display_name : null,
      reposterUsername: row.type === 'repost' ? reposter?.username : null,
      authorId: author.id,
      authorUsername: author.username,
      authorName: author.display_name,
      authorAvatar: author.avatar,
      likeCount: countLikes(content.id),
      shareCount: countShares(content.id),
      commentCount: comments.length,
      followBoost: countFollowBoost(content.id),
      liked: hasLiked(viewerId, content.id),
      shared: hasShared(viewerId, content.id),
      followingAuthor: isFollowing(viewerId, author.id),
      mutual: author.id !== viewerId && areMutualFollowers(viewerId, author.id),
      isOwn: author.id === viewerId,
      comments,
    };
  });
}

function countLikes(postId) {
  return require('../db').db.prepare(`SELECT COUNT(*) AS n FROM likes WHERE post_id = ?`).get(postId).n;
}
function countShares(postId) {
  return require('../db').db.prepare(`SELECT COUNT(*) AS n FROM shares WHERE post_id = ?`).get(postId).n;
}
function countFollowBoost(postId) {
  return require('../db').db.prepare(`SELECT COUNT(*) AS n FROM follows_from_post WHERE post_id = ?`).get(postId).n;
}

router.get('/:username', async (req, res, next) => {
  try {
    const profileUser = getUserByUsername(req.params.username);
    if (!profileUser) return res.status(404).render('404', { thing: 'user' });

    const viewer = res.locals.currentUser;
    const isOwn = !!(viewer && viewer.id === profileUser.id);
    const canSeePosts = !!(viewer && canView(viewer.id, profileUser.id));
    const following = viewer ? isFollowing(viewer.id, profileUser.id) : false;
    const mutual = !!(viewer && viewer.id !== profileUser.id && areMutualFollowers(viewer.id, profileUser.id));

    const custom = getCustomization(profileUser.id);
    const template = buildTemplate(custom);
    const font = fontInfoFor(profileUser);
    const fragments = await buildProfileFragments(res, {
      viewer, profileUser, isOwn, canSeePosts, mutual, following,
      pronouns: parsePronouns(profileUser.pronouns),
    });
    const pageHtml = substituteSlots(sanitizeProfileHTML(template), fragments);
    const rawCss = custom.css && custom.css.trim() ? custom.css : DEFAULT_PROFILE_CSS;

    // The uploaded custom font is declared for every viewer in its own <style>,
    // so it is usable by name everywhere (the editor's Font menu included) and
    // never ends up inside the user's editable stylesheet.
    const fontCss = font
      ? "@font-face { font-family: '" + font.family + "'; src: url('/u/"
        + encodeURIComponent(profileUser.username) + "/font?v=" + font.id + "'); font-display: swap; }"
      : '';

    res.render('profile', {
      pageHtml,
      css: sanitizeCSS(rawCss),
      fontCss,
      effect: custom.effect || '',
      isOwn,
      editor: isOwn ? {
        displayName: profileUser.display_name,
        bio: profileUser.bio || '',
        pronouns: parsePronouns(profileUser.pronouns),
        pronounFieldsMax: PRONOUN_FIELDS_MAX,
        pronounLengthMax: PRONOUN_LENGTH_MAX,
        customFont: font,
        templateHtml: template,
      } : null,
    });
  } catch (err) {
    next(err);
  }
});

// The old standalone editor page is gone: everything is edited on the profile
// itself, in place. Redirect old links/bookmarks into the in-page editor.
router.get('/:username/edit', (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  if (!profileUser || profileUser.id !== viewer.id) {
    return res.status(403).send('You can only edit your own profile.');
  }
  res.redirect('/u/' + profileUser.username + '?edit=1');
});

// Profile fields (name/bio/pronouns/effect) — auto-saved from the left panel.
// Only these fields, so it can never clobber the HTML/CSS.
router.post('/:username/edit/profile', (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  const wantsJson = req.xhr || (req.get('accept') || '').includes('application/json') || req.is('application/json');
  if (!profileUser || profileUser.id !== viewer.id) {
    return wantsJson
      ? res.status(403).json({ ok: false, error: 'You can only edit your own profile.' })
      : res.status(403).send('You can only edit your own profile.');
  }

  const displayName = String(req.body.displayName || '').trim().slice(0, 60) || viewer.username;
  const bio = String(req.body.bio || '').trim().slice(0, 280);
  const pronouns = sanitizePronouns(req.body.pronoun);
  let effect;
  if (req.body.effect !== undefined) {
    const rawEffect = String(req.body.effect || '').trim();
    effect = PROFILE_EFFECTS.includes(rawEffect) ? rawEffect : '';
  }

  updateUserProfile(viewer.id, { displayName, bio, pronouns });
  if (effect !== undefined) setCustomizationEffect(viewer.id, effect);
  if (wantsJson) return res.json({ ok: true, displayName, bio });
  res.redirect('/u/' + profileUser.username + '?edit=1');
});

// Reset the profile *customization* (HTML, CSS, effect) back to the defaults.
// The normal profile fields — name, bio, pronouns, avatar, custom font — are
// left untouched.
router.post('/:username/edit/reset', (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  const wantsJson = req.xhr || (req.get('accept') || '').includes('application/json') || req.is('application/json');
  if (!profileUser || profileUser.id !== viewer.id) {
    return wantsJson
      ? res.status(403).json({ ok: false, error: 'You can only edit your own profile.' })
      : res.status(403).send('You can only edit your own profile.');
  }
  setCustomization(viewer.id, '', '', '', 0);
  if (wantsJson) return res.json({ ok: true });
  res.redirect('/u/' + profileUser.username + '?edit=1');
});

// Easy Editing save: only touches HTML/CSS/effect (never displayName/bio/
// pronouns), so the visual editor can save without clobbering profile fields.
router.post('/:username/edit/visual', (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  const wantsJson = req.xhr || (req.get('accept') || '').includes('application/json') || req.is('application/json');
  if (!profileUser || profileUser.id !== viewer.id) {
    return wantsJson
      ? res.status(403).json({ ok: false, error: 'You can only edit your own profile.' })
      : res.status(403).send('You can only edit your own profile.');
  }

  const html = normalizeSlots(sanitizeProfileHTML(String(req.body.html || '')));
  const css = sanitizeCSS(String(req.body.css || ''));
  let effect;
  if (req.body.effect !== undefined) {
    const rawEffect = String(req.body.effect || '').trim();
    effect = PROFILE_EFFECTS.includes(rawEffect) ? rawEffect : '';
  }

  setCustomization(viewer.id, html, css, effect, 1);
  if (wantsJson) return res.json({ ok: true });
  res.redirect('/u/' + profileUser.username + '?edit=1');
});

// Upload/change avatar.
router.post('/:username/avatar', (req, res, next) => {
  avatarUpload.single('avatar')(req, res, (err) => {
    if (err) {
      console.error('Avatar upload multer error:', err);
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).send('File too large (max 10 MB).');
      return res.status(400).send('Upload error.');
    }
    next();
  });
}, async (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  if (!profileUser || profileUser.id !== viewer.id) return res.status(403).send('Not your profile.');
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) return res.status(403).send('CSRF validation failed');
  if (!req.file) return res.redirect('/u/' + profileUser.username + '/edit');

  const inputPath = req.file.path;
  // Avatars are stored files too, so they need room in the Drive.
  const space = drive.quotaState(viewer.id);
  if (space.used + req.file.size > space.quota) {
    try { fs.unlinkSync(inputPath); } catch (e) {}
    return res.status(413).send(
      'Not enough Drive space for a new avatar — you have ' + drive.fmt(space.remaining) + ' left. Delete something first.'
    );
  }
  const previousAvatar = viewer.avatar;
  const outputName = crypto.randomBytes(12).toString('hex') + '.jpg';
  const outputPath = path.join(AVATAR_DIR, outputName);

  try {
    await sharp(inputPath).resize(200, 200, { fit: 'cover', position: 'center' }).jpeg({ quality: 85 }).toFile(outputPath);
    fs.unlinkSync(inputPath);
    setAvatar(viewer.id, '/uploads/avatars/' + outputName);
    createUserFile({
      userId: viewer.id, kind: 'avatar', root: 'uploads', path: 'avatars/' + outputName,
      mime: 'image/jpeg', size: fs.statSync(outputPath).size,
    });
    // The old avatar is dead weight — unlink it and refund its space.
    if (previousAvatar) {
      const prev = splitStoredPath(previousAvatar);
      if (prev) removeStoredFile(prev.root, prev.path);
    }
  } catch (e) {
    console.error('Avatar processing error:', e);
    try { fs.unlinkSync(inputPath); } catch {}
    return res.status(400).send('Failed to process image');
  }

  res.redirect('/u/' + profileUser.username + '/edit');
});

// Remove avatar.
router.post('/:username/avatar/remove', (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  if (!profileUser || profileUser.id !== viewer.id) return res.status(403).send('Not your profile.');
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) return res.status(403).send('CSRF validation failed');
  const existing = viewer.avatar;
  setAvatar(viewer.id, null);
  if (existing) {
    const prev = splitStoredPath(existing);
    if (prev) removeStoredFile(prev.root, prev.path);
  }
  res.redirect('/u/' + profileUser.username + '/edit');
});

// ---------- Custom profile font ----------
// The chosen font lives in the Drive (so it counts against the quota) and is
// served at a stable URL, /u/<username>/font, for use in the profile's CSS:
//   @font-face { font-family: 'My Font'; src: url('/u/me/font'); }

function fontFamilyFromName(name, fallback) {
  const base = String(name || '').replace(/\.[a-z0-9]+$/i, '');
  const clean = base.replace(/["'\\<>{};()]/g, '').replace(/\s+/g, ' ').trim().slice(0, 40);
  return clean || fallback;
}

// What the profile editor shows for the current font, if any.
function fontInfoFor(user) {
  const split = user && user.custom_font ? splitStoredPath(user.custom_font) : null;
  if (!split) return null;
  const row = getUserFileByPath(split.root, split.path);
  return {
    url: user.custom_font,
    id: row ? row.id : 0,
    name: row && row.name ? row.name : 'Custom font',
    family: fontFamilyFromName(row && row.name, user.username),
  };
}

router.get('/:username/font', (req, res) => {
  const profileUser = getUserByUsername(req.params.username);
  const split = profileUser ? splitStoredPath(profileUser.custom_font) : null;
  const full = split ? fileDiskPath(split.root, split.path) : null;
  if (!full || !fs.existsSync(full)) return res.status(404).send('No custom font.');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Cross-Origin-Resource-Policy', 'cross-origin');
  res.set('Cache-Control', 'public, max-age=300');
  res.type(path.extname(split.path) || '.ttf');
  res.sendFile(full);
});

router.post('/:username/font', drive.quotaGuard(), drive.single('font'), async (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  if (!profileUser || profileUser.id !== viewer.id) {
    drive.discardUpload(req);
    return res.status(403).send('Not your profile.');
  }
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    drive.discardUpload(req);
    return res.status(403).send('CSRF validation failed');
  }
  if (!req.file) return res.redirect('/u/' + profileUser.username + '/edit');

  const ext = path.extname(req.file.originalname || '').toLowerCase();
  if (!drive.FONT_EXTENSIONS.has(ext)) {
    drive.discardUpload(req);
    return res.status(400).send('Fonts must be .woff2, .woff, .ttf or .otf.');
  }
  if (req.file.size > drive.MAX_FONT_BYTES) {
    drive.discardUpload(req);
    return res.status(400).send('That font is too large (max 8 MB).');
  }
  if (!drive.isFontFile(req.file.path)) {
    drive.discardUpload(req);
    return res.status(400).send('That file is not a valid font.');
  }

  // Re-serialize through the OpenType Sanitizer — the same validation browsers
  // apply to downloaded fonts — so we store sanitized output, never the raw
  // input. Without the binary we keep the checks above and warn once.
  const verdict = await drive.sanitizeFontFile(req.file.path);
  if (!verdict.ok) {
    if (verdict.reason === 'missing') {
      drive.warnOtsMissingOnce();
    } else {
      drive.discardUpload(req);
      return res.status(400).send(
        verdict.reason === 'invalid'
          ? 'That font failed validation — try exporting it again.'
          : 'Could not process that font.'
      );
    }
  } else {
    // Charge the Drive for what is actually stored.
    req.file.size = verdict.size;
  }

  const stored = drive.acceptUpload(req, res, { kind: 'font', userId: viewer.id });
  if (!stored.ok) {
    if (stored.exceeded) return drive.rejectFull(req, res, stored.state);
    return res.redirect('/u/' + profileUser.username + '/edit');
  }

  const previous = viewer.custom_font;
  setUserFont(viewer.id, stored.url);
  // One profile font at a time: drop the old file and refund its space.
  if (previous && previous !== stored.url) {
    const prev = splitStoredPath(previous);
    if (prev) removeStoredFile(prev.root, prev.path);
  }
  res.redirect('/u/' + profileUser.username + '/edit');
});

router.post('/:username/font/remove', (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  if (!profileUser || profileUser.id !== viewer.id) return res.status(403).send('Not your profile.');
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) return res.status(403).send('CSRF validation failed');
  const previous = viewer.custom_font;
  setUserFont(viewer.id, '');
  if (previous) {
    const prev = splitStoredPath(previous);
    if (prev) removeStoredFile(prev.root, prev.path);
  }
  res.redirect('/u/' + profileUser.username + '/edit');
});

// Followers list.
router.get('/:username/followers', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const target = getUserByUsername(req.params.username);
  if (!target) return res.status(404).render('404', { thing: 'user' });
  // The follow graph is network-bound like the rest of the profile.
  if (!canView(user.id, target.id)) return res.status(404).render('404', { thing: 'user' });
  const list = getFollowers(target.id).map(u => ({
    ...u, following: isFollowing(user.id, u.id),
    mutual: u.id !== user.id && areMutualFollowers(user.id, u.id),
  }));
  res.render('user-list', {
    title: 'Followers', targetUser: target, list, emptyMsg: 'No followers yet.',
  });
});

// Following list.
router.get('/:username/following', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const target = getUserByUsername(req.params.username);
  if (!target) return res.status(404).render('404', { thing: 'user' });
  if (!canView(user.id, target.id)) return res.status(404).render('404', { thing: 'user' });
  const list = getFollowing(target.id).map(u => ({
    ...u, following: isFollowing(user.id, u.id),
    mutual: u.id !== user.id && areMutualFollowers(user.id, u.id),
  }));
  res.render('user-list', {
    title: 'Following', targetUser: target, list, emptyMsg: 'Not following anyone yet.',
  });
});

// Generate referral link.
router.post('/:username/referral', (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  if (!profileUser || profileUser.id !== viewer.id) return res.status(403).send('Not your profile.');
  setReferralCode(viewer.id, req.ip);
  res.safeRedirect(req.body.next, '/u/' + viewer.username);
});

module.exports = router;
