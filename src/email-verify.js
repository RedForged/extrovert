'use strict';

// Email-verification token lifecycle + message templates.
//
// Flow: a user provides an email (at registration or in settings); the app
// issues a random high-entropy token, stores its SHA-256 hash in
// email_verifications (never the raw token), and emails a verification link
// containing the raw token. Clicking the link consumes the token atomically
// and marks the address verified. Tokens expire (default 24h) and are
// single-use, so a leaked link can't be replayed.

const crypto = require('node:crypto');
const db = require('./db');
const mailer = require('./mailer');

const TOKEN_BYTES = 24;          // 192 bits of entropy
const TOKEN_TTL_MS = 1000 * 60 * 60 * 24; // 24h
const RESEND_COOLDOWN_MS = 60 * 1000;     // 1 min between resends

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Issue a fresh verification token for a user. Replaces any previous token
// (single active token per account). Returns { token, verificationUrl } so the
// caller can render the email with the RAW token — only the hash is stored.
function issueVerification(userId, email) {
  const token = crypto.randomBytes(TOKEN_BYTES).toString('base64url');
  db.saveEmailVerification({
    userId,
    tokenHash: hashToken(token),
    email: db.normalizeEmail(email),
    expiresAt: Date.now() + TOKEN_TTL_MS,
  });
  return { token, email: db.normalizeEmail(email) };
}

// Attempt to verify. `token` is the raw token from the emailed link.
// Returns one of: 'ok' | 'expired' | 'invalid' | 'no_token' | 'already_verified'.
function verify(userId, token) {
  const user = db.getUserById(userId);
  if (!user) return 'no_token';
  if (user.email_verified_at) return 'already_verified';

  const row = db.getEmailVerification(userId);
  if (!row) return 'no_token';
  if (Date.now() > row.expires_at) return 'expired';

  const tokenHash = hashToken(String(token || ''));
  const a = Buffer.from(tokenHash, 'utf8');
  const b = Buffer.from(row.token_hash, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return 'invalid';

  // Atomic single-use consume; then mark verified.
  if (!db.consumeEmailVerification(userId, row.token_hash)) return 'invalid';
  db.setUserEmailVerified(userId, row.email, Date.now());
  db.deleteEmailVerification(userId);
  return 'ok';
}

// Whether a resend is allowed (cooldown) — returns { allowed, nextEligibleAt }.
function canResend(userId) {
  const row = db.getEmailVerification(userId);
  if (!row) return { allowed: true, nextEligibleAt: null };
  const elapsed = Date.now() - row.created_at;
  const wait = RESEND_COOLDOWN_MS - elapsed;
  if (wait <= 0) return { allowed: true, nextEligibleAt: null };
  return { allowed: false, nextEligibleAt: row.created_at + RESEND_COOLDOWN_MS, waitMs: wait };
}

// The externally reachable base URL for the verification link. Only trusts
// OIDC_ISSUER when it was explicitly configured — the module's built-in
// default is the author's production URL and must never leak into
// verification links. Otherwise derives the base from the request, falling
// back to localhost:PORT for dev.
function appBaseUrl(req) {
  const explicitIssuer = process.env.OIDC_ISSUER;
  if (explicitIssuer && /^https?:\/\//.test(explicitIssuer) && !/localhost|127\.0\.0\.1|\.test\b|\.local\b/i.test(explicitIssuer)) {
    return explicitIssuer.replace(/\/$/, '');
  }
  if (req) {
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.headers['x-forwarded-host'] || req.get && req.get('host');
    if (host) return `${proto}://${host}`;
  }
  const port = process.env.PORT || 3000;
  return `http://localhost:${port}`;
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

function verificationEmail({ to, token, baseUrl, username }) {
  const url = `${baseUrl}/verify-email?token=${encodeURIComponent(token)}`;
  const expiry = '24 hours';
  return {
    subject: `Confirm your email for Extrovert`,
    text:
      `Hi${username ? ' ' + username : ''},\n\n` +
      `You're almost done! Confirm your email address to finish setting up your Extrovert account.\n\n` +
      `Click this link to verify:\n${url}\n\n` +
      `This link expires in ${expiry}. If you didn't request this, you can safely ignore this email — ` +
      `your address won't be verified and no changes are made to your account.\n\n` +
      `— Extrovert`,
    html:
      `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;color:#222">` +
      `<h2 style="margin-bottom:4px">Confirm your email</h2>` +
      `<p>Hi${username ? ' ' + escapeHtml(username) : ''},</p>` +
      `<p>Confirm your email address to finish setting up your Extrovert account.</p>` +
      `<p style="margin:22px 0"><a href="${escapeAttr(url)}" style="background:#7c5cff;color:#fff;padding:12px 22px;border-radius:8px;text-decoration:none;display:inline-block">Verify email address</a></p>` +
      `<p style="font-size:12px;color:#888">Or copy this link:<br><code>${escapeHtml(url)}</code></p>` +
      `<p style="font-size:12px;color:#888">This link expires in ${expiry}. If you didn't request this, ` +
      `you can safely ignore this email — your address won't be verified.</p>` +
      `</div>`,
  };
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function escapeAttr(s) { return escapeHtml(s).replace(/'/g, '&#39;'); }

// Send the verification email. Returns the mailer result.
async function sendVerificationEmail({ userId, to, req }) {
  const { token } = issueVerification(userId, to);
  const user = db.getUserById(userId);
  const baseUrl = appBaseUrl(req);
  const msg = verificationEmail({ to, token, baseUrl, username: user ? user.username : null });
  return mailer.sendMail({
    to,
    subject: msg.subject,
    text: msg.text,
    html: msg.html,
  });
}

module.exports = {
  TOKEN_TTL_MS,
  RESEND_COOLDOWN_MS,
  hashToken,
  issueVerification,
  verify,
  canResend,
  sendVerificationEmail,
  appBaseUrl,
  verificationEmail,
};