'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { createUser, getUserByUsername, getUserByReferralCode, getUserById } = db;
const { adminExists } = db;
const { getAccountIds, getSignedInAccounts, addAccount, setActiveAccount, removeAccount } = require('../accounts');

const router = express.Router();

router.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  const ref = String(req.query.ref || '').trim();
  res.render('register', { error: null, ref });
});

router.post('/register', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const displayName = String(req.body.displayName || '').trim() || username;

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.render('register', { error: 'Username must be 3-20 letters, numbers, or underscores.' });
  }
  // Policy: at least 12 characters; at most 72 BYTES (bcrypt truncates at 72
  // bytes, so longer input would silently collide with its own prefix — a
  // byte limit prevents that while keeping full Unicode/emoji support).
  if (password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
    return res.render('register', { error: 'Password must be at least 12 characters and at most 72 bytes (multi-byte characters such as emoji count more).' });
  }
  if (getUserByUsername(username)) {
    return res.render('register', { error: 'That username is taken — try another.' });
  }

  // Handle referral.
  const ref = String(req.body.ref || req.query.ref || '').trim();
  let referredBy = null;
  const registrantIp = req.ip || req.connection.remoteAddress;
  if (ref) {
    const referrer = getUserByReferralCode(ref);
    if (referrer) {
      const refIp = db.getReferrerIp ? db.getReferrerIp(referrer.id) : null;
      // Anti-farming: reject if same IP as referrer's stored IP.
      if (refIp && registrantIp === refIp) {
        return res.render('register', { error: "You can't use a referral from your own network.", ref });
      }
      referredBy = referrer.id;
    }
  }

  const hash = bcrypt.hashSync(password, 10);
  const id = createUser({ username, passwordHash: hash, displayName, referredBy, referrerIp: registrantIp });
  // Regenerate the session so a pre-planted cookie cannot be fixed onto the
  // freshly created account.
  req.session.regenerate((err) => {
    if (err) {
      console.error('register: session regeneration failed:', err);
      return res.status(500).send('Internal server error');
    }
    req.session.userId = id;
    req.session.accountIds = [id];
    res.redirect('/');
  });
});

router.get('/login', (req, res) => {
  const addMode = String(req.query.add || '') === '1';
  // Normally an already-signed-in browser is redirected away from the login
  // page; with ?add=1 the page becomes the "add another account" flow.
  if (req.session.userId && !addMode) return res.redirect('/');
  res.render('login', {
    error: null,
    next: req.query.next || '',
    addMode,
    signedInAccounts: req.session.userId ? getSignedInAccounts(req) : [],
  });
});

router.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (password.length > 128) {
    return res.render('login', {
      error: 'Invalid username or password.',
      next: req.query.next || '',
      addMode: !!req.session.userId,
      signedInAccounts: req.session.userId ? getSignedInAccounts(req) : [],
    });
  }
  const user = getUserByUsername(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.render('login', {
      error: 'Invalid username or password.',
      next: req.query.next || '',
      addMode: !!req.session.userId,
      signedInAccounts: req.session.userId ? getSignedInAccounts(req) : [],
    });
  }
  if (user.banned) {
    return res.render('login', {
      error: 'Your account has been suspended.',
      next: req.query.next || '',
      addMode: !!req.session.userId,
      signedInAccounts: req.session.userId ? getSignedInAccounts(req) : [],
    });
  }
  // Session-fixation-safe login. When the browser is ALREADY signed in
  // (add-another-account flow), carry the existing account list across the
  // regeneration so adding an account does not sign the device out of the
  // accounts it already has. A fresh login seeds the list with just this
  // account — a planted session cookie can never inherit an attacker's list.
  const wasSignedIn = !!req.session.userId;
  const existingIds = wasSignedIn ? getAccountIds(req) : [];
  req.session.regenerate((err) => {
    if (err) {
      console.error('login: session regeneration failed:', err);
      return res.status(500).send('Internal server error');
    }
    addAccount(req, user.id);
    if (wasSignedIn && existingIds.length > 0) {
      req.session.accountIds = existingIds.includes(user.id) ? existingIds : [...existingIds, user.id];
      req.session.userId = user.id;
    }
    const loginIp = req.ip || req.connection.remoteAddress;
    try { db.db.prepare(`UPDATE users SET referrer_ip = ? WHERE id = ?`).run(loginIp, user.id); } catch {}
    if (!user.is_admin && !adminExists()) {
      return res.redirect('/become-admin');
    }
    res.safeRedirect(req.body.next, '/');
  });
});

// Logout removes the ACTIVE account from this device's list; the whole session
// is destroyed only when the last account is removed, so switching/logging out
// of one account never invalidates the others' sessions or OAuth tokens.
// ?all=1 (from the switcher menu) signs out of every account on the device.
router.post('/logout', (req, res) => {
  if (String(req.body.all || '') === '1') {
    return req.session.destroy(() => res.redirect('/login'));
  }
  const result = removeAccount(req, req.session.userId);
  if (result === 'destroyed') {
    return req.session.destroy(() => res.redirect('/login'));
  }
  res.safeRedirect(req.body.next, '/');
});

// Account switcher: lists every account signed in on this device.
router.get('/account/switch', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  res.render('account-switch', {
    signedInAccounts: getSignedInAccounts(req),
    next: res.locals.safeUrl(req.query.next, '/'),
    error: null,
  });
});

// Make another signed-in account the active one.
router.post('/account/switch', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  const accountId = Number(req.body.account_id);
  if (!Number.isInteger(accountId) || !setActiveAccount(req, accountId)) {
    return res.status(400).render('account-switch', {
      signedInAccounts: getSignedInAccounts(req),
      next: res.locals.safeUrl(req.body.next, '/'),
      error: 'That account is not signed in on this device.',
    });
  }
  res.safeRedirect(req.body.next, '/');
});

// Remove one account from this device's list.
router.post('/account/remove', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const accountId = Number(req.body.account_id);
  if (!Number.isInteger(accountId)) {
    return res.status(400).send('Invalid account id.');
  }
  const result = removeAccount(req, accountId);
  if (result === 'not-found') {
    return res.status(404).send('Account is not signed in on this device.');
  }
  if (result === 'destroyed') {
    return req.session.destroy(() => res.redirect('/login'));
  }
  res.safeRedirect(req.body.next, '/');
});

router.get('/become-admin', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const user = getUserById(req.session.userId);
  if (!user) return res.redirect('/login');
  if (user.is_admin) return res.redirect('/admin');
  if (adminExists()) return res.redirect('/');
  res.render('become-admin');
});

router.post('/become-admin', (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const user = getUserById(req.session.userId);
  if (!user) return res.redirect('/login');
  if (user.is_admin) return res.redirect('/admin');
  if (adminExists()) return res.redirect('/');
  const { promoteUser } = require('../db');
  promoteUser(user.id);
  res.redirect('/admin');
});

module.exports = router;
