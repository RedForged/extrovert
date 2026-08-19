'use strict';

const express = require('express');
const crypto = require('node:crypto');
const db = require('../db');
const { getUserTheme, setUserTheme, getUserDeveloperMode, setUserDeveloperMode, deleteUser, isValidEmail, getUserByEmail, getEmailPolicy } = db;
const { VALID_SCOPES } = require('../api-auth');
const { removeAccount } = require('../accounts');
const emailVerify = require('../email-verify');

const router = express.Router();

function emailStatusFor(user) {
  return {
    policy: getEmailPolicy(),
    email: user.email || '',
    verified: !!user.email_verified_at,
    verifiedAt: user.email_verified_at,
  };
}

function renderSettings(res, user, { mailError = null, mailSent = false } = {}) {
  res.render('settings', {
    theme: getUserTheme(user.id),
    developerMode: getUserDeveloperMode(user.id),
    devices: db.getUserDevices(user.id),
    version: require('../../package.json').version,
    emailStatus: emailStatusFor(user),
    mailError,
    mailSent,
  });
}

router.get('/', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  renderSettings(res, user);
});

router.post('/', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const theme = req.body.theme === 'light' ? 'light' : 'dark';
  setUserTheme(user.id, theme);
  setUserDeveloperMode(user.id, req.body.developer_mode === '1');
  res.redirect('/settings');
});

// Revoke an active device
router.post('/devices/:deviceId/delete', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  db.deleteUserDevice(user.id, req.params.deviceId);
  res.redirect('/settings');
});

// Add / change email address. Changing an address always triggers a fresh
// verification (the old verification, if any, is replaced).
router.post('/email', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  if (getEmailPolicy() === 'off') return res.status(400).send('Email verification is disabled on this server.');

  const email = String(req.body.email || '').trim();
  if (!isValidEmail(email)) {
    return renderSettings(res, user, { mailError: 'That email address doesn\'t look valid.' });
  }
  const existing = getUserByEmail(email);
  if (existing && existing.id !== user.id) {
    return renderSettings(res, user, { mailError: 'That email is already registered to another account.' });
  }
  // Remove any previously stored address + verification, then set the new one.
  db.clearUserEmail(user.id);
  db.setUserEmail(user.id, email);
  db.deleteEmailVerification(user.id);
  emailVerify.sendVerificationEmail({ userId: user.id, to: email, req })
    .then(() => renderSettings(res, db.getUserById(user.id), { mailSent: true }))
    .catch((err) => {
      console.error('settings/email: send failed', err);
      renderSettings(res, db.getUserById(user.id), {
        mailError: 'Verification email could not be sent: ' + (err.message || 'unknown error') + '. Check the server\'s mail configuration.',
      });
    });
});

// Resend the verification email (with a 1-minute cooldown).
router.post('/email/resend', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  if (!user.email) {
    return renderSettings(res, user, { mailError: 'No email address on this account yet.' });
  }
  const cooldown = emailVerify.canResend(user.id);
  if (!cooldown.allowed) {
    const waitSec = Math.ceil(cooldown.waitMs / 1000);
    return renderSettings(res, user, { mailError: `Please wait ${waitSec}s before requesting another email.` });
  }
  emailVerify.sendVerificationEmail({ userId: user.id, to: user.email, req })
    .then(() => renderSettings(res, db.getUserById(user.id), { mailSent: true }))
    .catch((err) => {
      console.error('settings/email/resend: send failed', err);
      renderSettings(res, db.getUserById(user.id), {
        mailError: 'Verification email could not be sent: ' + (err.message || 'unknown error') + '. Check the server\'s mail configuration.',
      });
    });
});

// Account deletion.
router.get('/delete', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  res.render('confirm-delete-account', { csrfToken: res.locals.csrfToken });
});

router.post('/delete', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  deleteUser(user.id);
  // F1 multi-account: remove only the deleted account from this device's list.
  // Other accounts signed in on the same device stay signed in; the whole
  // session is destroyed only when the deleted account was the last one.
  const result = removeAccount(req, user.id);
  if (result === 'destroyed') {
    return req.session.destroy(() => res.redirect('/'));
  }
  res.redirect('/');
});

// Developer OAuth app management
router.get('/developers', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const apps = db.getOAuthAppsByOwner(user.id);
  const authorizedApps = db.getAuthorizedAppsForUser(user.id);
  res.render('developers', { apps, authorizedApps });
});

router.post('/developers', (req, res, next) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');

  try {
    const { name, description, website, redirect_uris, scopes } = req.body;
    if (!name || !redirect_uris) {
      return res.render('developers', {
        apps: db.getOAuthAppsByOwner(user.id),
        authorizedApps: db.getAuthorizedAppsForUser(user.id),
        error: 'Name and Redirect URIs are required.',
      });
    }

    const validScopes = scopes
      ? scopes.split(' ').filter(s => VALID_SCOPES.has(s)).join(' ')
      : 'read';

    const clientId = crypto.randomBytes(24).toString('hex');
    const clientSecret = crypto.randomBytes(32).toString('hex');
    const uris = Array.isArray(redirect_uris) ? redirect_uris.join(',') : redirect_uris;

    db.createOAuthApp({
      name,
      description: description || '',
      website: website || '',
      redirectUris: uris,
      clientId,
      clientSecret,
      scopes: validScopes,
      ownerId: user.id,
    });

    // The client secret is only ever shown once, at creation (it is stored
    // hashed), so render the page with the fresh value instead of redirecting.
    res.render('developers', {
      apps: db.getOAuthAppsByOwner(user.id),
      authorizedApps: db.getAuthorizedAppsForUser(user.id),
      freshSecret: clientSecret,
    });
  } catch (err) {
    console.error('Error registering app:', err);
    res.render('developers', {
      apps: db.getOAuthAppsByOwner(user.id),
      authorizedApps: db.getAuthorizedAppsForUser(user.id),
      error: 'Failed to register app: ' + (err.message || 'unknown error'),
    });
  }
});

router.post('/developers/:id/delete', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');

  const appId = parseInt(req.params.id, 10);
  const app = db.getOAuthAppById(appId);
  if (!app || app.owner_id !== user.id) {
    return res.status(404).send('App not found.');
  }
  db.deleteOAuthApp(appId);
  res.redirect('/settings/developers');
});

router.post('/developers/authorized/:clientId/revoke', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');

  const app = db.getOAuthAppByClientId(req.params.clientId);
  if (app) {
    db.revokeOAuthTokensForUser(user.id, app.id);
  }
  res.redirect('/settings/developers');
});

module.exports = router;
