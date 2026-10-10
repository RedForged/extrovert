'use strict';

const express = require('express');
const { getUserByUsername, follow, unfollow, createNotification } = require('../db');

const router = express.Router();

function back(req, fallback = '/') {
  const ref = req.get('referer');
  if (ref && ref.startsWith('/') && !ref.startsWith('//') && !/[\u0000-\u001f\\]/.test(ref)) return ref;
  return fallback;
}

router.post('/follow/:username', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const target = getUserByUsername(req.params.username);
  if (target && target.id !== user.id) {
    follow(user.id, target.id);
    createNotification({ userId: target.id, type: 'follow', actorId: user.id });
  }
  res.redirect(back(req, '/u/' + (target ? target.username : '')));
});

router.post('/unfollow/:username', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const target = getUserByUsername(req.params.username);
  if (target) unfollow(user.id, target.id);
  res.redirect(back(req, '/u/' + (target ? target.username : '')));
});

module.exports = router;
