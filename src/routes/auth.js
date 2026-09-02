'use strict';

const express = require('express');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { createUser, getUserByUsername, getUserByReferralCode, getUserById, isValidEmail, getEmailPolicy, isEmailVerificationRequired } = db;
const { adminExists } = db;
const { getAccountIds, getSignedInAccounts, addAccount, setActiveAccount, removeAccount } = require('../accounts');
const captcha = require('../captcha');
const emailVerify = require('../email-verify');
const twofa = require('../twofa');

const router = express.Router();

// ---------- two-factor login support ----------
const TRUSTED_DEVICE_COOKIE = 'extv_td';
const PENDING_2FA_TTL_MS = 5 * 60 * 1000;
const MAX_2FA_ATTEMPTS = 5;

function cookieSecureSetting() {
  return process.env.EXTV_COOKIE_SECURE === 'false' ? false
    : process.env.EXTV_COOKIE_SECURE === 'true' ? true
    : process.env.NODE_ENV === 'production' ? 'auto' : false;
}

// Minimal cookie reader (the app has no cookie-parser dependency).
function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return decodeURIComponent(part.slice(idx + 1).trim());
  }
  return null;
}

// True when this browser presents a valid, unexpired trusted-device token
// for exactly this account (suppresses the TOTP challenge).
function hasTrustedDevice(req, userId) {
  return !!lookupTrustedDeviceRow(req, userId);
}

// Resolves the presented trusted-device cookie to its DB row (or null).
function lookupTrustedDeviceRow(req, userId) {
  const token = readCookie(req, TRUSTED_DEVICE_COOKIE);
  if (!token) return null;
  const row = db.getTrustedDevice(twofa.hashTrustedDeviceToken(token));
  return row && row.user_id === userId ? row : null;
}

// Shared second-factor verifier: 6-digit input is a TOTP code, anything else
// is treated as a recovery code (consumed atomically, single use). Returns
// false on any failure — including decryption errors — never throws.
function verifySecondFactor(user, code) {
  const trimmed = String(code || '').trim();
  if (!trimmed) return false;
  try {
    if (/^\d{6}$/.test(trimmed.replace(/\s+/g, ''))) {
      return twofa.verifyTotp(twofa.decryptSecret(user.totp_secret), trimmed);
    }
    return db.consumeRecoveryCode(user.id, twofa.hashRecoveryCode(trimmed));
  } catch (err) {
    console.error('second-factor verify error:', err.message);
    return false;
  }
}

// The session-stored pending second factor, or null when absent/expired.
function getPending2fa(req) {
  const pending = req.session.pending2fa;
  if (!pending) return null;
  if (!pending.expiresAt || pending.expiresAt <= Date.now()) {
    delete req.session.pending2fa;
    return null;
  }
  return pending;
}

// Session-fixation-safe login completion, shared by the password path, the
// TOTP challenge path, and passkey login. When the browser is ALREADY signed
// in (add-another-account flow), the existing account list is carried across
// the regeneration so adding an account does not sign the device out of the
// accounts it already has. A fresh login seeds the list with just this
// account — a planted session cookie can never inherit an attacker's list.
function completeLogin(req, res, user, { next, wasSignedIn, existingIds }) {
  req.session.regenerate((err) => {
    if (err) {
      console.error('login: session regeneration failed:', err);
      return res.status(500).send('Internal server error');
    }
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
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
    res.safeRedirect(next, '/');
  });
}

// Passkey login completion: same regeneration + account-list rules as
// completeLogin, but hands control to a callback instead of redirecting (the
// caller responds with JSON).
function completeLoginForApi(req, res, user, done) {
  const wasSignedIn = !!req.session.userId;
  const existingIds = wasSignedIn ? getAccountIds(req) : [];
  req.session.regenerate((err) => {
    if (err) {
      console.error('passkey login: session regeneration failed:', err);
      return res.status(500).json({ error: { message: 'Internal server error' } });
    }
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    addAccount(req, user.id);
    if (wasSignedIn && existingIds.length > 0) {
      req.session.accountIds = existingIds.includes(user.id) ? existingIds : [...existingIds, user.id];
      req.session.userId = user.id;
    }
    const loginIp = req.ip || req.connection.remoteAddress;
    try { db.db.prepare(`UPDATE users SET referrer_ip = ? WHERE id = ?`).run(loginIp, user.id); } catch {}
    done();
  });
}

router.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  const ref = String(req.query.ref || '').trim();
// Generate the captcha challenge now (server-side state only — the answer is
  // never in the HTML). The <img src="/register/captcha"> the view embeds
  // regenerates it on load, which is the state the POST is verified against.
  captcha.generate(req);
  res.render('register', { error: null, ref, emailRequired: isEmailVerificationRequired(), enteredEmail: '' });
});

// Fresh captcha image for the widget (SVG). Session-bound, so the cookie jar
// that loads it must be the one that POSTs /register. no-store keeps a failed
// registration re-rendering with a genuinely fresh challenge.
router.get('/register/captcha', (req, res) => {
  const svg = captcha.generate(req);
  res.set({ 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-store, max-age=0' });
  res.send(svg);
});

router.post('/register', async (req, res) => {
  // Anti-bot gate FIRST: every attempt (successful or not) consumes the
  // single-use challenge, so a typed answer can't be replayed and cheap
  // username-enumeration attempts each cost a fresh image. The verify check is
  // a constant-time string compare — no client-side cost at all.
  const cap = captcha.verify(req, req.body);
  if (!cap.ok) {
    captcha.generate(req); // fresh challenge for the re-rendered form
    return res.render('register', {
      error: cap.error,
      ref: String(req.body.ref || req.query.ref || '').trim(),
    });
  }
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const displayName = String(req.body.displayName || '').trim() || username;
  const ref = String(req.body.ref || req.query.ref || '').trim();
  const email = String(req.body.email || '').trim();
  const emailRequired = isEmailVerificationRequired();

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    captcha.generate(req);
    return res.render('register', { error: 'Username must be 3-20 letters, numbers, or underscores.', ref, emailRequired, enteredEmail: email });
  }
  // Policy: at least 12 characters; at most 72 BYTES (bcrypt truncates at 72
  // bytes, so longer input would silently collide with its own prefix — a
  // byte limit prevents that while keeping full Unicode/emoji support).
  if (password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
    captcha.generate(req);
    return res.render('register', { error: 'Password must be at least 12 characters and at most 72 bytes (multi-byte characters such as emoji count more).', ref, emailRequired, enteredEmail: email });
  }
  if (getUserByUsername(username)) {
    captcha.generate(req);
    return res.render('register', { error: 'That username is taken — try another.', ref, emailRequired, enteredEmail: email });
  }
  // Email: optional unless the server policy makes it required. When provided
  // it must be well-formed and not already in use (addresses are treated case-
  // insensitively, so two people can't claim the same mailbox).
  if (email) {
    if (!isValidEmail(email)) {
      captcha.generate(req);
      return res.render('register', { error: 'That email address doesn\'t look valid.', ref, emailRequired, enteredEmail: email });
    }
    if (db.getUserByEmail(email)) {
      // Keep the message generic (no registration oracle): if the address is
      // taken, telling the user to log in is enough without confirming it.
      captcha.generate(req);
      return res.render('register', { error: 'That email can\'t be used. If you already have an account, try logging in.', ref, emailRequired, enteredEmail: email });
    }
  } else if (emailRequired) {
    captcha.generate(req);
    return res.render('register', { error: 'This server requires a verified email address to create an account.', ref, emailRequired, enteredEmail: email });
  }

  // Handle referral.
  let referredBy = null;
  const registrantIp = req.ip || req.connection.remoteAddress;
  if (ref) {
    const referrer = getUserByReferralCode(ref);
    if (referrer) {
      const refIp = db.getReferrerIp ? db.getReferrerIp(referrer.id) : null;
      // Anti-farming: reject if same IP as referrer's stored IP.
      if (refIp && registrantIp === refIp) {
        captcha.generate(req);
        return res.render('register', { error: "You can't use a referral from your own network.", ref, emailRequired, enteredEmail: email });
      }
      referredBy = referrer.id;
    }
  }

  const hash = bcrypt.hashSync(password, 10);
  const id = createUser({ username, passwordHash: hash, displayName, referredBy, referrerIp: registrantIp });
  if (email) {
    db.setUserEmail(id, email);
  }

  // Regenerate the session so a pre-planted cookie cannot be fixed onto the
  // freshly created account.
  req.session.regenerate(async (err) => {
    if (err) {
      console.error('register: session regeneration failed:', err);
      return res.status(500).send('Internal server error');
    }
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.userId = id;
    req.session.accountIds = [id];
    // Kick off the verification email (async — never block signup on mail,
    // and never expose whether delivery succeeded/failed to the user).
    if (email) {
      emailVerify.sendVerificationEmail({ userId: id, to: email, req }).catch((e) => {
        console.error('register: verification email failed:', e && e.message);
      });
    }
    res.redirect('/');
  });
});

router.get('/login', (req, res) => {
  // Canonical-URL login: any query string (next, add, …) is folded into the
  // session and the browser is redirected to bare /login. Password managers
  // key saved logins on the exact page URL, so serving the form under
  // /login?next=… /login?add=1 (and their variants) breaks autofill. The
  // login page URL is always exactly /login.
  const addMode = String(req.query.add || '') === '1';
  // Normally an already-signed-in browser is redirected away from the login
  // page. With ?add=1 the page becomes the "add another account" flow. The
  // add flag is also folded into the session on the canonical-URL redirect
  // below, so a signed-in browser that followed /login?add=1 -> bare /login
  // must NOT be bounced here — check the session flag too.
  if (req.session.userId && !addMode && !req.session.loginAdd) return res.redirect('/');
  if (req.query.next !== undefined || req.query.add !== undefined) {
    req.session.loginNext = req.query.next || req.session.loginNext || '';
    req.session.loginAdd = addMode;
    return res.redirect('/login');
  }
  const next = req.session.loginNext || '';
  delete req.session.loginNext;
  const wasAdd = !!req.session.loginAdd;
  delete req.session.loginAdd;
  res.render('login', {
    error: null,
    next,
    addMode: wasAdd,
    signedInAccounts: req.session.userId ? getSignedInAccounts(req) : [],
  });
});

// Email verification link landing — consumes the token and confirms.
router.get('/verify-email', async (req, res) => {
  const token = String(req.query.token || '');
  const userId = req.session.userId;
  if (!userId) {
    return res.status(400).render('login', { error: 'Please log in first, then open the verification link again. If you\'re already logged in, the link should work.', next: '' });
  }
  const result = emailVerify.verify(userId, token);
  res.render('verify-email', {
    result, // 'ok' | 'expired' | 'invalid' | 'no_token' | 'already_verified'
    tokenPresent: !!token,
  });
});

router.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const nextFromBody = req.body.next || req.session.loginNext || '';
  if (password.length > 128) {
    return res.render('login', {
      error: 'Invalid username or password.',
      next: nextFromBody,
      addMode: !!req.session.userId,
      signedInAccounts: req.session.userId ? getSignedInAccounts(req) : [],
    });
  }
  const user = getUserByUsername(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.render('login', {
      error: 'Invalid username or password.',
      next: nextFromBody,
      addMode: !!req.session.userId,
      signedInAccounts: req.session.userId ? getSignedInAccounts(req) : [],
    });
  }
  if (user.banned) {
    return res.render('login', {
      error: 'Your account has been suspended.',
      next: nextFromBody,
      addMode: !!req.session.userId,
      signedInAccounts: req.session.userId ? getSignedInAccounts(req) : [],
    });
  }
  // Two-factor accounts get a second step instead of an immediate session.
  // userId stays UNSET until the code verifies, so requireAuth-protected pages
  // remain inaccessible; the multi-account context is captured up front so
  // completion can reproduce the anti-fixation rules exactly.
  const wasSignedIn = !!req.session.userId;
  const existingIds = wasSignedIn ? getAccountIds(req) : [];
  const nextUrl = nextFromBody;
  if (user.totp_enabled && !hasTrustedDevice(req, user.id)) {
    req.session.pending2fa = {
      userId: user.id,
      next: nextUrl,
      wasSignedIn,
      existingIds,
      attempts: 0,
      expiresAt: Date.now() + PENDING_2FA_TTL_MS,
    };
    return res.redirect('/login/totp');
  }
  completeLogin(req, res, user, { next: nextUrl, wasSignedIn, existingIds });
});

// Renders the second-factor challenge. No pending state → back to /login.
router.get('/login/totp', (req, res) => {
  const pending = getPending2fa(req);
  if (!pending) return res.redirect('/login');
  res.render('totp-challenge', { error: null, remember: true });
});

// Second-factor verification. The input is either a 6-digit TOTP or a recovery
// code — both fail with the same generic message and share the attempt budget.
router.post('/login/totp', (req, res) => {
  const pending = getPending2fa(req);
  if (!pending) return res.redirect('/login');
  const user = getUserById(pending.userId);
  // The account (or its 2FA enrollment) vanished mid-challenge.
  if (!user || !user.totp_enabled || !user.totp_secret) {
    delete req.session.pending2fa;
    return res.redirect('/login');
  }
  const code = String(req.body.code || '');
  const usedRecovery = !/^\d{6}$/.test(code.replace(/\s+/g, ''));
  const ok = verifySecondFactor(user, code);
  if (!ok) {
    pending.attempts += 1;
    db.auditLog('2fa_verify_failed', pending.userId, usedRecovery ? 'recovery' : 'totp');
    if (pending.attempts >= MAX_2FA_ATTEMPTS) {
      delete req.session.pending2fa;
      return res.render('login', {
        error: 'Too many invalid codes. Please log in again.',
        next: pending.next || '',
        addMode: false,
        signedInAccounts: [],
      });
    }
    return res.render('totp-challenge', { error: 'Invalid code.', remember: !!req.body.remember });
  }
  if (req.body.remember) {
    // Rotate: the old token row (matched by the presented cookie's hash) is
    // deleted and a fresh token+cookie is issued, so a cookie's hash never
    // stays valid unchanged for the whole 30-day window.
    const oldRow = lookupTrustedDeviceRow(req, pending.userId);
    if (oldRow) db.deleteTrustedDevice(oldRow.id, pending.userId);
    const token = twofa.generateTrustedDeviceToken();
    db.addTrustedDevice(
      pending.userId,
      twofa.hashTrustedDeviceToken(token),
      Date.now() + twofa.TRUSTED_DEVICE_DAYS * 24 * 60 * 60 * 1000
    );
    res.cookie(TRUSTED_DEVICE_COOKIE, token, {
      httpOnly: true,
      secure: cookieSecureSetting(),
      sameSite: 'lax',
      maxAge: twofa.TRUSTED_DEVICE_DAYS * 24 * 60 * 60 * 1000,
      path: '/',
    });
    db.auditLog('trusted_device_added', pending.userId, `device remembered for ${twofa.TRUSTED_DEVICE_DAYS} days`);
  }
  delete req.session.pending2fa;
  db.auditLog(usedRecovery ? 'recovery_code_used' : 'totp_login_success', pending.userId, '');
  completeLogin(req, res, user, {
    next: pending.next || '',
    wasSignedIn: pending.wasSignedIn,
    existingIds: pending.existingIds || [],
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
module.exports.completeLoginForApi = completeLoginForApi;
module.exports.verifySecondFactor = verifySecondFactor;
module.exports.hasTrustedDevice = hasTrustedDevice;
