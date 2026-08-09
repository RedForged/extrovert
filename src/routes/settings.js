'use strict';

const express = require('express');
const crypto = require('node:crypto');
const db = require('../db');
const { getUserTheme, setUserTheme, getUserDeveloperMode, setUserDeveloperMode, deleteUser } = db;
const { VALID_SCOPES } = require('../api-auth');
const { removeAccount } = require('../accounts');

const router = express.Router();

router.get('/', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const theme = getUserTheme(user.id);
  const developerMode = getUserDeveloperMode(user.id);
  const { version } = require('../../package.json');
  res.render('settings', { theme, version, developerMode });
});

router.post('/', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const theme = req.body.theme === 'light' ? 'light' : 'dark';
  setUserTheme(user.id, theme);
  setUserDeveloperMode(user.id, req.body.developer_mode === '1');
  res.redirect('/settings');
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
