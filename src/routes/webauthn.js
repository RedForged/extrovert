'use strict';

// WebAuthn ceremony endpoints, mounted at /passkeys in server.js.
//
// Registration ceremonies require a signed-in session (settings page).
// Authentication ceremonies are PUBLIC — that is the passwordless login path.
// All responses are JSON; client logic lives in public/passkeys.js.

const express = require('express');
const db = require('../db');
const { requireAuth } = require('../auth');
const webauthn = require('../webauthn');

const router = express.Router();

// JSON error helper — keeps every failure shape identical for the client.
function fail(res, status, message) {
  return res.status(status).json({ error: { message } });
}

// ---------- registration (enrollment from Settings → Security) ----------
router.post('/register/begin', requireAuth, async (req, res) => {
  const user = res.locals.currentUser;
  const existing = db.getPasskeysByUser(user.id);
  if (existing.length >= webauthn.MAX_PASSKEYS_PER_USER) {
    return fail(res, 400, `You can register at most ${webauthn.MAX_PASSKEYS_PER_USER} passkeys.`);
  }
  const options = await webauthn.registrationOptions(req, { user, existingPasskeys: existing });
  webauthn.setChallenge(req, 'registration', options.challenge);
  res.json(options);
});

router.post('/register/complete', requireAuth, async (req, res) => {
  const user = res.locals.currentUser;
  const expectedChallenge = webauthn.takeChallenge(req, 'registration');
  if (!expectedChallenge) return fail(res, 400, 'No active registration. Please try again.');
  if (db.countPasskeys(user.id) >= webauthn.MAX_PASSKEYS_PER_USER) {
    return fail(res, 400, `You can register at most ${webauthn.MAX_PASSKEYS_PER_USER} passkeys.`);
  }
  const { rpID, origin } = webauthn.rpInfo(req);
  let verification;
  try {
    verification = await webauthn.verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: [rpID],
      requireUserVerification: false,
    });
  } catch (err) {
    console.error('passkey register/complete verification failed:', err.message);
    return fail(res, 400, 'Passkey registration could not be verified.');
  }
  const { verified, registrationInfo } = verification;
  if (!verified || !registrationInfo) return fail(res, 400, 'Passkey registration could not be verified.');

  // v13 shape: { credential: { id, publicKey (Uint8Array), counter }, credentialDeviceType, credentialBackedUp }
  const { credential, credentialDeviceType } = registrationInfo;
  const label = String(req.body.label || '').trim().slice(0, 64) || `${credentialDeviceType} passkey`;
  const created = db.createPasskey({
    userId: user.id,
    credentialId: Buffer.from(credential.id, 'base64url').toString('base64url'), // normalized
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter || 0,
    deviceName: label,
    transports: req.body.transports || undefined,
  });
  db.auditLog('passkey_added', user.id, `${label} (${credentialDeviceType})`);
  res.json({ verified: true, device_name: created.device_name });
});

// ---------- authentication (public — this IS the login) ----------
router.post('/auth/options', async (req, res) => {
  const { rpID } = webauthn.rpInfo(req);
  // A username narrows to that account's keys; omitted = discoverable-credential
  // flow where the authenticator picks any passkey it holds for this site.
  const username = String(req.body.username || '').trim();
  let allowCredentials = [];
  if (username) {
    const user = db.getUserByUsername(username);
    if (user) {
      allowCredentials = db.getPasskeysByUser(user.id).map((p) => ({
        id: p.credential_id,
        transports: p.transports ? JSON.parse(p.transports) : undefined,
      }));
      if (allowCredentials.length === 0) {
        return fail(res, 400, 'No passkeys are registered for that account.');
      }
    }
  }
  const options = await webauthn.authenticationOptions({ rpID, allowCredentials });
  webauthn.setChallenge(req, 'authentication', options.challenge);
  res.json(options);
});

router.post('/auth/verify', async (req, res) => {
  const expectedChallenge = webauthn.takeChallenge(req, 'authentication');
  if (!expectedChallenge) return fail(res, 400, 'No active authentication. Please try again.');

  // The response's credentialId identifies the account — global lookup.
  const credentialId = req.body && req.body.id;
  if (!credentialId) return fail(res, 400, 'Invalid authentication response.');
  const stored = db.getPasskeyByCredentialId(credentialId);
  if (!stored) {
    db.auditLog('passkey_login_failed', null, 'unknown credential');
    return fail(res, 401, 'Invalid username or password.');
  }
  const user = db.getUserById(stored.user_id);
  if (!user || user.banned) {
    db.auditLog('passkey_login_failed', stored.user_id, 'banned or missing account');
    return fail(res, 403, 'Your account has been suspended.');
  }

  const { rpID, origin } = webauthn.rpInfo(req);
  let verification;
  try {
    verification = await webauthn.verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: [rpID],
      requireUserVerification: false,
      credential: {
        id: stored.credential_id,
        publicKey: Buffer.from(stored.public_key, 'base64url'),
        counter: stored.counter,
        transports: stored.transports ? JSON.parse(stored.transports) : undefined,
      },
    });
  } catch (err) {
    console.error('passkey auth/verify failed:', err.message);
    db.auditLog('passkey_login_failed', stored.user_id, 'verification failed');
    return fail(res, 401, 'Invalid username or password.');
  }
  const { verified, authenticationInfo } = verification;
  if (!verified) {
    db.auditLog('passkey_login_failed', stored.user_id, 'not verified');
    return fail(res, 401, 'Invalid username or password.');
  }

  // Cloned-authenticator guard: the signature counter must move forward
  // (both-zero is legitimate for non-counter authenticators).
  const newCount = authenticationInfo.newCounter;
  if (newCount > 0 && newCount <= stored.counter) {
    db.auditLog('passkey_login_failed', stored.user_id, 'stale counter (possible cloned authenticator)');
    return fail(res, 401, 'Invalid username or password.');
  }

  db.updatePasskeyCounter(stored.id, newCount);

  // Passkeys are full authentication by design — no TOTP step afterwards.
  // Reuse the shared completion so session regeneration + multi-account
  // handling behave exactly like the password path.
  const { completeLoginForApi } = require('./auth');
  completeLoginForApi(req, res, user, () => {
    db.auditLog('passkey_login_success', user.id, stored.credential_id.slice(0, 12));
    res.json({ verified: true, redirect: '/' });
  });
});

module.exports = router;
