// WebAuthn passkey support — thin wrapper around @simplewebauthn/server.
// Challenges live in the session (never the DB) and are single-use with a TTL.
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_PASSKEYS_PER_USER = 10;

// Relying-party identity is derived from the request host, mirroring how the
// OIDC issuer is derived (oidc.js). NOTE: credentials are bound to the rpID
// (hostname) they were created on — serving the app on a different hostname
// invalidates previously registered passkeys. The ORIGIN includes the port
// (WebAuthn compares scheme+host+port exactly), taken from the Host header.
function rpInfo(req) {
  const host = req.hostname;
  const hostHeader = req.headers.host || host; // may include :port
  const https = req.protocol === 'https' || req.get('x-forwarded-proto') === 'https';
  return { rpID: host, rpName: 'Extrovert', origin: `${https ? 'https' : 'http'}://${hostHeader}` };
}

function setChallenge(req, kind, value) {
  req.session.webauthnChallenge = { kind, value, expiresAt: Date.now() + CHALLENGE_TTL_MS };
}

// Single-use: any verify attempt consumes the stored challenge.
function takeChallenge(req, kind) {
  const stored = req.session.webauthnChallenge;
  delete req.session.webauthnChallenge;
  if (!stored || stored.kind !== kind) return null;
  if (!stored.expiresAt || stored.expiresAt <= Date.now()) return null;
  return stored.value;
}

function registrationOptions(req, { user, existingPasskeys }) {
  return generateRegistrationOptions({
    rpName: rpInfo(req).rpName,
    rpID: rpInfo(req).rpID,
    userID: Buffer.from(String(user.id)),
    userName: user.username,
    userDisplayName: user.display_name || user.username,
    attestationType: 'none',
    excludeCredentials: existingPasskeys.map((p) => ({
      id: p.credential_id,
      transports: p.transports ? JSON.parse(p.transports) : undefined,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  }).then((opts) => {
    // v13 returns challenge (and credential ids) as Uint8Array; the wire
    // format for our JSON API is base64url.
    opts.challenge = Buffer.from(opts.challenge).toString('base64url');
    (opts.excludeCredentials || []).forEach((c) => {
      if (Buffer.isBuffer(c.id)) c.id = Buffer.from(c.id).toString('base64url');
      else if (c.id instanceof Uint8Array) c.id = Buffer.from(c.id).toString('base64url');
    });
    return opts;
  });
}

function authenticationOptions({ rpID, allowCredentials }) {
  return generateAuthenticationOptions({
    rpID,
    allowCredentials,
    userVerification: 'preferred',
    timeout: 60_000,
  }).then((opts) => {
    opts.challenge = Buffer.from(opts.challenge).toString('base64url');
    (opts.allowCredentials || []).forEach((c) => {
      if (Buffer.isBuffer(c.id)) c.id = Buffer.from(c.id).toString('base64url');
      else if (c.id instanceof Uint8Array) c.id = Buffer.from(c.id).toString('base64url');
    });
    return opts;
  });
}

module.exports = {
  CHALLENGE_TTL_MS,
  MAX_PASSKEYS_PER_USER,
  rpInfo,
  setChallenge,
  takeChallenge,
  registrationOptions,
  authenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
};
