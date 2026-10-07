'use strict';

const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
const {
  getUserByUsername, getCustomization, setCustomization, updateUserProfile,
  getDisplayPost, getUserById, postsByUser, hasLiked, hasShared,
  commentsForPost, isFollowing, countFollowers, countFollowing,
  getFollowers, getFollowing, areMutualFollowers,
  setReferralCode, getReferralCode, getReferralCount,
  setAvatar,
} = require('../db');
const { canView } = require('../network');
const { sanitizeProfileHTML, sanitizeCSS, parsePronouns, sanitizePronouns, PRONOUN_FIELDS_MAX, PRONOUN_LENGTH_MAX } = require('../sanitize');

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

// Hydrate a user's posts for display on their profile (resolves reposts).
function hydrateProfilePosts(userId, viewerId) {
  const rows = postsByUser(userId);
  return rows.map(row => {
    const reposter = getUserById(row.user_id);
    let content = row;
    let author = reposter;
    if (row.type === 'repost' && row.repost_of_id) {
      const disp = getDisplayPost(row.repost_of_id);
      if (disp) { content = disp.post; author = getUserById(content.user_id); }
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

router.get('/:username', (req, res) => {
  const profileUser = getUserByUsername(req.params.username);
  if (!profileUser) return res.status(404).render('404', { thing: 'user' });

  const viewer = res.locals.currentUser;
  const isOwn = viewer && viewer.id === profileUser.id;
  const canSeePosts = viewer && canView(viewer.id, profileUser.id);
  const following = viewer ? isFollowing(viewer.id, profileUser.id) : false;

  const custom = getCustomization(profileUser.id);
  const rawHtml = custom.html && custom.html.trim() ? custom.html : DEFAULT_PROFILE_HTML;
  const rawCss = custom.css && custom.css.trim() ? custom.css : DEFAULT_PROFILE_CSS;
  const html = sanitizeProfileHTML(rawHtml);
  const css = sanitizeCSS(rawCss);

  let postsHtml = '';
  if (canSeePosts) {
    const items = hydrateProfilePosts(profileUser.id, viewer.id);
    res.app.render('partials/post-list', { items, currentUser: viewer, onProfile: true, csrfToken: res.locals.csrfToken || '' }, (err, html2) => {
      if (err) { console.error(err); }
      postsHtml = html2 || '';
      finish();
    });
  } else {
    postsHtml = '<div class="ev-private">Follow @' + profileUser.username +
      ' to see their posts.</div>';
    finish();
  }

  function finish() {
    let finalHtml = html;
    if (finalHtml.includes('<!--POSTS-->')) {
      finalHtml = finalHtml.replace('<!--POSTS-->', postsHtml);
    } else {
      finalHtml += postsHtml;
    }
    const referralCount = getReferralCount(profileUser.id);
    res.render('profile', {
      profileUser, finalHtml, css, isOwn, following, canSeePosts,
      followerCount: countFollowers(profileUser.id),
      followingCount: countFollowing(profileUser.id),
      mutual: viewer && viewer.id !== profileUser.id && areMutualFollowers(viewer.id, profileUser.id),
      referralCount,
      effect: custom.effect || '',
      pronouns: parsePronouns(profileUser.pronouns),
    });
  }
});

router.get('/:username/edit', (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  if (!profileUser || profileUser.id !== viewer.id) {
    return res.status(403).send('You can only edit your own profile.');
  }
  const custom = getCustomization(viewer.id);
  res.render('profile-edit', {
    profileUser,
    html: custom.html || DEFAULT_PROFILE_HTML,
    css: custom.css || DEFAULT_PROFILE_CSS,
    displayName: viewer.display_name,
    bio: viewer.bio,
    effect: custom.effect || '',
    pronouns: parsePronouns(viewer.pronouns),
    pronounFieldsMax: PRONOUN_FIELDS_MAX,
    pronounLengthMax: PRONOUN_LENGTH_MAX,
  });
});

router.post('/:username/edit', (req, res) => {
  const viewer = res.locals.currentUser;
  if (!viewer) return res.redirect('/login');
  const profileUser = getUserByUsername(req.params.username);
  if (!profileUser || profileUser.id !== viewer.id) {
    return res.status(403).send('You can only edit your own profile.');
  }
  const html = String(req.body.html || '');
  const css = String(req.body.css || '');
  const displayName = String(req.body.displayName || '').trim().slice(0, 60) || viewer.username;
  const bio = String(req.body.bio || '').trim().slice(0, 280);

  const PROFILE_EFFECTS = ['matrix', 'glitch'];
  const rawEffect = String(req.body.effect || '').trim();
  const effect = PROFILE_EFFECTS.includes(rawEffect) ? rawEffect : '';
  const pronouns = sanitizePronouns(req.body.pronoun);

  setCustomization(viewer.id, html, css, effect);
  updateUserProfile(viewer.id, { displayName, bio, pronouns });
  res.redirect('/u/' + profileUser.username);
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
  const outputName = crypto.randomBytes(12).toString('hex') + '.jpg';
  const outputPath = path.join(AVATAR_DIR, outputName);

  try {
    await sharp(inputPath).resize(200, 200, { fit: 'cover', position: 'center' }).jpeg({ quality: 85 }).toFile(outputPath);
    fs.unlinkSync(inputPath);
    setAvatar(viewer.id, '/uploads/avatars/' + outputName);
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
  setAvatar(viewer.id, null);
  res.redirect('/u/' + profileUser.username + '/edit');
});

// Followers list.
router.get('/:username/followers', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const target = getUserByUsername(req.params.username);
  if (!target) return res.status(404).render('404', { thing: 'user' });
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
  const next = typeof req.body.next === 'string' && req.body.next.startsWith('/') && !req.body.next.startsWith('//') ? req.body.next : null;
  res.redirect(next || '/u/' + viewer.username);
});

module.exports = router;
