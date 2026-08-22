'use strict';

const express = require('express');
const crypto = require('node:crypto');
const QRCode = require('qrcode');
const db = require('../db');
const { getUserTheme, setUserTheme, getUserDeveloperMode, setUserDeveloperMode, deleteUser, isValidEmail, getUserByEmail, getEmailPolicy } = db;
const { VALID_SCOPES } = require('../api-auth');
const { removeAccount } = require('../accounts');
const emailVerify = require('../email-verify');
const twofa = require('../twofa');

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

// ---------- Security settings (2FA / recovery codes / trusted devices / passkeys) ----------
const TRUSTED_DEVICE_COOKIE = 'extv_td';
const MAX_PASSKEYS_PER_USER = 10;

function cookieSecureSetting() {
  return process.env.EXTV_COOKIE_SECURE === 'false' ? false
    : process.env.EXTV_COOKIE_SECURE === 'true' ? true
    : process.env.NODE_ENV === 'production' ? 'auto' : false;
}

function totpKeyConfigured() {
  return !!process.env.TOTP_ENCRYPTION_KEY;
}

function renderSecurity(res, user, extra = {}) {
  res.render('security-settings', {
    user,
    totpEnabled: !!user.totp_enabled,
    totpKeyConfigured: totpKeyConfigured(),
    unusedRecoveryCodes: db.countUnusedRecoveryCodes(user.id),
    trustedDevices: db.listTrustedDevices(user.id),
    passkeys: db.getPasskeysByUser(user.id),
    ...extra,
  });
}

router.get('/security', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  renderSecurity(res, user);
});

// Step 1: generate a secret, store it ENCRYPTED, show QR + manual entry.
router.post('/security/totp/setup', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  if (!totpKeyConfigured()) {
    return renderSecurity(res, user, {
      error: 'This server has not configured TOTP_ENCRYPTION_KEY, so two-factor authentication is unavailable. The operator must set it (see docs/configuration.md).',
    });
  }
  if (user.totp_enabled) return res.redirect('/settings/security');
  const secret = twofa.generateTotpSecret();
  db.setTotpSecret(user.id, twofa.encryptSecret(secret));
  const uri = twofa.otpauthUri(secret, user.username);
  QRCode.toDataURL(uri, { margin: 1, width: 220 })
    .then((qr) => {
      res.render('totp-setup', {
        qrDataUrl: qr,
        manualSecret: twofa.base32Encode(secret),
        error: null,
      });
    })
    .catch((err) => {
      console.error('totp setup: QR generation failed:', err);
      res.render('totp-setup', {
        qrDataUrl: null,
        manualSecret: twofa.base32Encode(secret),
        error: 'Could not render the QR code — use the manual secret below.',
      });
    });
});

// Step 2: prove the authenticator works, then enable + show recovery codes once.
router.post('/security/totp/confirm', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  if (user.totp_enabled) return res.redirect('/settings/security');
  if (!user.totp_secret) {
    return res.redirect('/settings/security/totp/setup');
  }
  let ok = false;
  try {
    ok = twofa.verifyTotp(twofa.decryptSecret(user.totp_secret), String(req.body.code || ''));
  } catch (err) {
    console.error('totp confirm: decrypt failed:', err.message);
  }
  if (!ok) {
    return res.render('totp-setup', {
      qrDataUrl: null,
      manualSecret: null,
      error: 'That code didn\'t match. Scan the code again or restart setup.',
      needRestart: true,
    });
  }
  const now = Date.now();
  db.setTotpEnabled(user.id, now);
  const codes = twofa.generateRecoveryCodes();
  db.replaceRecoveryCodes(user.id, codes.map(twofa.hashRecoveryCode), now);
  db.auditLog('totp_enabled', user.id, '2FA enabled');
  // Cut off any OTHER device's pre-enrollment session (F2.7); this device's
  // session is regenerated below so it survives.
  try { require('../session-store').destroySessionsForUser(user.id, req.sessionID); } catch (err) {
    console.error('totp confirm: session purge failed:', err);
  }
  req.session.regenerate((err) => {
    if (err) {
      console.error('totp confirm: session regeneration failed:', err);
      return res.status(500).send('Internal server error');
    }
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.userId = user.id;
    req.session.accountIds = [user.id];
    res.render('totp-recovery', { codes, regenerated: false });
  });
});

// Disable 2FA: requires a current TOTP code OR an unused recovery code —
// never the password alone.
router.post('/security/totp/disable', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  if (!user.totp_enabled) return res.redirect('/settings/security');
  const code = String(req.body.code || '').trim();
  let ok = false;
  try {
    if (/^\d{6}$/.test(code.replace(/\s+/g, ''))) {
      ok = twofa.verifyTotp(twofa.decryptSecret(user.totp_secret), code);
    } else if (code) {
      ok = db.consumeRecoveryCode(user.id, twofa.hashRecoveryCode(code));
    }
  } catch (err) {
    console.error('totp disable: verify failed:', err.message);
  }
  if (!ok) {
    return renderSecurity(res, user, { error: 'Enter a valid authentication code or recovery code to disable 2FA.' });
  }
  db.setTotpSecret(user.id, null);
  db.setTotpEnabled(user.id, null);
  db.replaceRecoveryCodes(user.id, []); // clear all codes
  db.deleteAllTrustedDevices(user.id);
  res.clearCookie(TRUSTED_DEVICE_COOKIE, { path: '/' });
  db.auditLog('totp_disabled', user.id, '2FA disabled');
  try { require('../session-store').destroySessionsForUser(user.id, req.sessionID); } catch {}
  renderSecurity(res, db.getUserById(user.id), { notice: 'Two-factor authentication is now off.' });
});

// Regenerate recovery codes: requires a valid current code; old codes die.
router.post('/security/recovery/regenerate', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  if (!user.totp_enabled) return res.redirect('/settings/security');
  const code = String(req.body.code || '').trim();
  let ok = false;
  try {
    ok = /^\d{6}$/.test(code.replace(/\s+/g, ''))
      ? twofa.verifyTotp(twofa.decryptSecret(user.totp_secret), code)
      : !!code && db.consumeRecoveryCode(user.id, twofa.hashRecoveryCode(code));
  } catch (err) {
    console.error('recovery regenerate: verify failed:', err.message);
  }
  if (!ok) {
    return renderSecurity(res, user, { error: 'Enter a valid authentication code or recovery code first.' });
  }
  const codes = twofa.generateRecoveryCodes();
  db.replaceRecoveryCodes(user.id, codes.map(twofa.hashRecoveryCode));
  db.auditLog('recovery_codes_regenerated', user.id, '');
  res.render('totp-recovery', { codes, regenerated: true });
});

router.post('/security/devices/:id/revoke', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || !db.deleteTrustedDevice(id, user.id)) {
    return res.status(404).send('Trusted device not found.');
  }
  db.auditLog('trusted_device_revoked', user.id, `device #${id}`);
  res.redirect('/settings/security');
});

router.post('/security/devices/revoke-all', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  db.deleteAllTrustedDevices(user.id);
  res.clearCookie(TRUSTED_DEVICE_COOKIE, { path: '/' });
  db.auditLog('trusted_device_revoked', user.id, 'all devices');
  res.redirect('/settings/security');
});

// ---------- Passkey management (ceremonies live in routes/webauthn.js) ----------
router.post('/security/passkeys/:id/rename', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const id = Number(req.params.id);
  const name = String(req.body.device_name || '').trim().slice(0, 64);
  if (!Number.isInteger(id) || !db.getPasskeyById(id) || db.getPasskeyById(id).user_id !== user.id) {
    return res.status(404).send('Passkey not found.');
  }
  db.renamePasskey(id, user.id, name || 'Passkey');
  res.redirect('/settings/security');
});

router.post('/security/passkeys/:id/delete', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || !db.deletePasskey(id, user.id)) {
    return res.status(404).send('Passkey not found.');
  }
  db.auditLog('passkey_removed', user.id, `passkey #${id}`);
  res.redirect('/settings/security');
});

module.exports = router;
