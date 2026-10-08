'use strict';

const express = require('express');
const { db, getMyStickers, searchUsers } = require('../db');
const { buildFeed } = require('../feed');
const { foafIds, friendIds } = require('../network');
const { buildPostScopeCss } = require('../post-scope');

const router = express.Router();

// JSON username suggestions for @mention autocomplete in the composer.
router.get('/search/suggest', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const q = String(req.query.q || '').trim();
  if (!q) return res.json({ users: [] });
  const users = searchUsers(q, { excludeId: user.id, limit: 6 });
  res.json({
    users: users.map(u => ({ username: u.username, display_name: u.display_name, avatar: u.avatar || null })),
  });
});

// Feed (home).
router.get('/', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const page = Math.max(1, Number(req.query.page) || 1);
  const { items, hasMore } = buildFeed(user.id, { page, perPage: 15 });

  const q = String(req.query.q || '').trim();
  let discoverResults = [];
  if (q) {
    discoverResults = searchUsers(q, { excludeId: user.id, limit: 20 });
  }

  const following = friendIds(user.id);
  const foaf = [...foafIds(user.id)];
  const suggestedIds = foaf.filter(id => !following.has(id)).slice(0, 12);
  const suggested = suggestedIds.length
    ? db.prepare(`SELECT id, username, display_name, avatar, bio FROM users WHERE id IN (${suggestedIds.map(() => '?').join(',')})`)
        .all(...suggestedIds)
    : [];

  const stickers = getMyStickers(user.id);

  // Posts carry their author's profile style into the feed (scoped to each post).
  const scopeCss = buildPostScopeCss(items);

  res.render('feed', { items, page, hasMore, q, discoverResults, suggested, stickers, scopeCss });
});

// Compose.
router.get('/compose', (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  res.render('compose', {});
});

// Discover: find people by username + suggested friends-of-friends to follow.
router.get('/discover', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');

  const q = String(req.query.q || '').trim();
  let results = [];
  if (q) {
    results = searchUsers(q, { excludeId: user.id, limit: 20 });
  }

  // Suggested: friends-of-friends you don't already follow (expand your network).
  const following = friendIds(user.id);
  const foaf = [...foafIds(user.id)];
  const suggestedIds = foaf.filter(id => !following.has(id)).slice(0, 12);
  const suggested = suggestedIds.length
    ? db.prepare(`SELECT id, username, display_name, avatar, bio FROM users WHERE id IN (${suggestedIds.map(() => '?').join(',')})`)
        .all(...suggestedIds)
    : [];

  res.render('discover', { q, results, suggested });
});

module.exports = router;
