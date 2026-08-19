'use strict';

const express = require('express');
const multer = require('multer');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  db, createPost, getPostById, getDisplayPost, getUserById,
  toggleLike, addComment, commentsForPost, hasLiked, hasShared,
  sharePost, hasReposted, recordFollowFromPost, isFollowing,
  createNotification, deletePost,
  editPost, editComment, getEditHistory,
  deleteComment,
} = require('../db');
const { canView } = require('../network');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, '..', '..', 'uploads');

const ALLOWED_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp',
  '.mp4', '.webm', '.mov', '.avi', '.mkv',
]);

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      const safeExt = ALLOWED_EXTENSIONS.has(ext) ? ext : '';
      cb(null, crypto.randomBytes(12).toString('hex') + safeExt);
    },
  }),
  limits: { fileSize: 60 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      return cb(null, false);
    }
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
      cb(null, true);
    } else {
      cb(null, false);
    }
  },
});

function back(req, fallback = '/') {
  const ref = req.get('referer');
  if (ref && ref.startsWith('/') && !ref.startsWith('//')) return ref;
  return fallback;
}

// Create a post (text / photo / video).
router.post('/', upload.single('media'), (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const { requireVerifiedEmail: gate } = require('../db');
  if (gate(user)) return res.status(403).send('Your email address must be verified before you can post. Visit /settings to verify it.');
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).send('CSRF validation failed');
  }
  const type = req.body.type;
  const body = String(req.body.body || '').trim();

  let mediaPath = null;
  if ((type === 'photo' || type === 'video') && req.file) {
    mediaPath = '/uploads/' + req.file.filename;
  }

  if (type === 'text') {
    if (!body) return res.redirect(back(req, '/compose'));
    createPost({ userId: user.id, type: 'text', body });
  } else if (type === 'photo' && mediaPath) {
    createPost({ userId: user.id, type: 'photo', body, mediaPath });
  } else if (type === 'video' && mediaPath) {
    createPost({ userId: user.id, type: 'video', body, mediaPath });
  } else {
    return res.redirect(back(req, '/compose'));
  }
  res.redirect(back(req, '/'));
});

function resolveVisibleContent(req, res) {
  const user = res.locals.currentUser;
  if (!user) return null;
  const post = getPostById(Number(req.params.id));
  if (!post) return null;
  // Engagement targets the original content; repost wrappers are not directly
  // engaged with, so resolve one level.
  const content = post.type === 'repost' && post.repost_of_id
    ? getPostById(post.repost_of_id) || post
    : post;
  if (!canView(user.id, content.user_id)) return null;
  return { user, content };
}

// Like (toggle).
router.post('/:id/like', (req, res) => {
  const ctx = resolveVisibleContent(req, res);
  if (!ctx) return req.xhr ? res.json({ error: 'not found' }) : res.redirect(back(req, '/'));
  const { requireVerifiedEmail: gate } = require('../db');
  if (gate(ctx.user)) return req.xhr ? res.json({ error: 'email_unverified' }) : res.status(403).send('Your email address must be verified before you can like posts.');
  const liked = toggleLike(ctx.user.id, ctx.content.id);
  if (liked && ctx.content.user_id !== ctx.user.id) {
    createNotification({ userId: ctx.content.user_id, type: 'like', actorId: ctx.user.id, postId: ctx.content.id });
  }
  if (req.xhr) return res.json({ liked, likeCount: +db.prepare(`SELECT COUNT(*) FROM likes WHERE post_id = ?`).get(ctx.content.id)['COUNT(*)'] });
  res.redirect(back(req, '/'));
});

// Comment.
router.post('/:id/comment', (req, res) => {
  const ctx = resolveVisibleContent(req, res);
  if (!ctx) return req.xhr ? res.json({ error: 'not found' }) : res.redirect(back(req, '/'));
  const { requireVerifiedEmail: gate } = require('../db');
  if (gate(ctx.user)) return req.xhr ? res.json({ error: 'email_unverified' }) : res.status(403).send('Your email address must be verified before you can comment.');
  const body = String(req.body.body || '').trim();
  if (body) {
    const commentId = addComment(ctx.user.id, ctx.content.id, body.slice(0, 1000));
    if (ctx.content.user_id !== ctx.user.id) {
      createNotification({ userId: ctx.content.user_id, type: 'comment', actorId: ctx.user.id, postId: ctx.content.id });
    }
    if (req.xhr) {
      const c = db.prepare(`SELECT c.id, c.body, c.created_at, c.edited_at, c.user_id, u.display_name, u.username FROM comments c JOIN users u ON u.id = c.user_id WHERE c.id = ?`).get(commentId);
      return res.json({ comment: c });
    }
  }
  res.redirect(back(req, '/'));
});

// Edit a post.
router.post('/:id/edit', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return req.xhr ? res.json({ error: 'not logged in' }) : res.redirect('/login');
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).send('CSRF validation failed');
  }
  const body = String(req.body.body || '').trim();
  if (!body) return req.xhr ? res.json({ error: 'body required' }) : res.redirect(back(req, '/'));
  const ok = editPost(Number(req.params.id), user.id, body);
  if (!ok) return req.xhr ? res.json({ error: 'not found or not yours' }) : res.status(404).send('Post not found or not yours.');
  if (req.xhr) return res.json({ ok: true });
  res.redirect(back(req, '/posts/' + req.params.id));
});

// Edit a comment.
router.post('/:id/comments/:cid/edit', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return req.xhr ? res.json({ error: 'not logged in' }) : res.redirect('/login');
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).send('CSRF validation failed');
  }
  const body = String(req.body.body || '').trim().slice(0, 1000);
  if (!body) return req.xhr ? res.json({ error: 'body required' }) : res.redirect(back(req, '/'));
  const ok = editComment(Number(req.params.cid), user.id, body);
  if (!ok) return req.xhr ? res.json({ error: 'not found or not yours' }) : res.status(404).send('Comment not found or not yours.');
  if (req.xhr) return res.json({ ok: true });
  res.redirect(back(req, '/posts/' + req.params.id));
});

// Delete a comment.
router.post('/:id/comments/:cid/delete', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return req.xhr ? res.json({ error: 'not logged in' }) : res.redirect('/login');
  const token = req.body._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).send('CSRF validation failed');
  }
  const ok = deleteComment(Number(req.params.cid), user.id);
  if (!ok) return req.xhr ? res.json({ error: 'not found or not yours' }) : res.status(404).send('Comment not found or not yours.');
  if (req.xhr) return res.json({ ok: true });
  res.redirect(back(req, '/posts/' + req.params.id));
});

// View a single post (shareable link).
router.get('/:id', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const post = getPostById(Number(req.params.id));
  if (!post) return res.status(404).render('404', { thing: 'post' });
  const content = post.type === 'repost' && post.repost_of_id
    ? getPostById(post.repost_of_id) || post
    : post;
  if (!canView(user.id, content.user_id)) return res.redirect('/');
  const interactId = content.id;
  const author = getUserById(content.user_id);
  const reposter = post.type === 'repost' ? getUserById(post.user_id) : null;
  const item = {
    id: post.id, interactId,
    type: content.type, body: content.body, mediaPath: content.media_path,
    createdAt: post.created_at,
    editedAt: content.edited_at,
    isRepost: post.type === 'repost',
    reposterName: reposter?.display_name, reposterUsername: reposter?.username,
    authorId: author.id, authorUsername: author.username, authorName: author.display_name,
    likeCount: +db.prepare(`SELECT COUNT(*) FROM likes WHERE post_id = ?`).get(interactId)['COUNT(*)'],
    shareCount: +db.prepare(`SELECT COUNT(*) FROM shares WHERE post_id = ?`).get(interactId)['COUNT(*)'],
    commentCount: commentsForPost(interactId).length,
    liked: hasLiked(user.id, interactId), shared: hasShared(user.id, interactId),
    followingAuthor: isFollowing(user.id, author.id), isOwn: author.id === user.id,
    comments: commentsForPost(interactId),
  };
  res.render('post', { item });
});

// Share (engagement boost, a little more than like).
router.post('/:id/share', (req, res) => {
  const ctx = resolveVisibleContent(req, res);
  if (!ctx) return req.xhr ? res.json({ error: 'not found' }) : res.redirect(back(req, '/'));
  const { requireVerifiedEmail: gate } = require('../db');
  if (gate(ctx.user)) return req.xhr ? res.json({ error: 'email_unverified' }) : res.status(403).send('Your email address must be verified before you can share.');
  if (ctx.content.user_id !== ctx.user.id) {
    sharePost(ctx.user.id, ctx.content.id);
    createNotification({ userId: ctx.content.user_id, type: 'share', actorId: ctx.user.id, postId: ctx.content.id });
  }
  const shareCount = +db.prepare(`SELECT COUNT(*) FROM shares WHERE post_id = ?`).get(ctx.content.id)['COUNT(*)'];
  if (req.xhr) return res.json({ shared: true, shareCount });
  res.redirect('/posts/' + ctx.content.id);
});

// Repost: re-publish the original content into your own stream.
router.post('/:id/repost', (req, res) => {
  const ctx = resolveVisibleContent(req, res);
  if (!ctx) return req.xhr ? res.json({ error: 'not found' }) : res.redirect(back(req, '/'));
  const { requireVerifiedEmail: gate } = require('../db');
  if (gate(ctx.user)) return req.xhr ? res.json({ error: 'email_unverified' }) : res.status(403).send('Your email address must be verified before you can repost.');
  if (ctx.content.user_id === ctx.user.id) return req.xhr ? res.json({ ok: false, reason: 'own' }) : res.redirect(back(req, '/'));
  if (!hasReposted(ctx.user.id, ctx.content.id)) {
    createPost({ userId: ctx.user.id, type: 'repost', repostOfId: ctx.content.id });
  }
  if (req.xhr) return res.json({ ok: true });
  res.redirect(back(req, '/'));
});

// Follow the author *because of* this post -> BIG boost to that post.
router.post('/:id/follow-from', (req, res) => {
  const ctx = resolveVisibleContent(req, res);
  if (!ctx) return req.xhr ? res.json({ error: 'not found' }) : res.redirect(back(req, '/'));
  if (ctx.content.user_id !== ctx.user.id) {
    recordFollowFromPost(ctx.user.id, ctx.content.user_id, ctx.content.id);
  }
  if (req.xhr) return res.json({ ok: true });
  res.redirect(back(req, '/'));
});

// View edit history for a post or comment.
router.get('/:id/history', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const entityType = req.query.type || 'post';
  const entityId = Number(req.params.id);
  const history = getEditHistory(entityType, entityId);
  const post = getPostById(entityType === 'comment' ? Number(req.query.post_id || 0) : Number(req.params.id));
  if (post && !canView(user.id, post.user_id)) return res.redirect('/');
  res.render('edit-history', { entityType, entityId, history, post });
});

// Delete post — owner only.
router.get('/:id/delete', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const post = getPostById(Number(req.params.id));
  if (!post) return res.status(404).render('404', { thing: 'post' });
  if (post.user_id !== user.id) return res.status(403).send('You can only delete your own posts.');
  res.render('confirm-delete', { post, back: back(req, '/') });
});

router.post('/:id/delete', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return req.xhr ? res.json({ error: 'not logged in' }) : res.redirect('/login');
  const deleted = deletePost(Number(req.params.id), user.id);
  if (!deleted) return req.xhr ? res.json({ error: 'not found' }) : res.status(404).send('Post not found or not yours.');
  if (req.xhr) return res.json({ ok: true });
  res.redirect('/u/' + user.username);
});

module.exports = router;
