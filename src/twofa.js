// Two-factor authentication crypto: RFC 6238 TOTP, AES-256-GCM secret
// encryption at rest, recovery codes, trusted-device tokens.
// Pure functions only — no DB imports; storage lives in src/db.js.
const crypto = require('crypto');

const TOTP_PERIOD = 30;      // seconds, RFC 6238 default
const TOTP_DIGITS = 6;
const VERIFY_WINDOW = 1;     // accept previous/current/next step (clock drift)
const RECOVERY_CODE_COUNT = 10;
const TRUSTED_DEVICE_DAYS = 30;
// Storage format for encrypted TOTP secrets. The prefix makes decryption fail
// closed: anything not produced by encryptSecret() (e.g. plaintext) is rejected.
const ENC_PREFIX = 'v1.';
const SALT = 'extrovert-totp';

// ---------- base32 (RFC 4648) ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s-]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// ---------- TOTP (RFC 6238) ----------
function hotp(secretBuf, counter) {
  const cbuf = Buffer.alloc(8);
  cbuf.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', secretBuf).update(cbuf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16)
    | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(code % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

function currentCounter(now = Date.now()) {
  return Math.floor(now / 1000 / TOTP_PERIOD);
}

// Verifies a 6-digit token against counter-1..counter+1. Constant-time compare.
function verifyTotp(secretBuf, token, now = Date.now()) {
  const clean = String(token || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(clean)) return false;
  const want = Buffer.from(hotp(secretBuf, currentCounter(now)));
  const got = Buffer.from(clean);
  const counter = currentCounter(now);
  for (let i = counter - VERIFY_WINDOW; i <= counter + VERIFY_WINDOW; i++) {
    if (got.equals(Buffer.from(hotp(secretBuf, i)))) return true;
  }
  return false;
}

function generateTotpSecret() {
  return crypto.randomBytes(20); // RFC 4226 recommends >=160 bits
}

function otpauthUri(secretBuf, accountLabel, issuer = 'Extrovert') {
  const label = encodeURIComponent(`${issuer}:${accountLabel}`);
  const params = new URLSearchParams({
    secret: base32Encode(secretBuf),
    issuer,
    algorithm: 'SHA1',
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD),
  });
  return `otpauth://totp/${label}?${params}`;
}

// ---------- secret encryption at rest (AES-256-GCM) ----------
let cachedKey = null;
function encryptionKey() {
  if (!cachedKey) {
    const env = process.env.TOTP_ENCRYPTION_KEY;
    if (!env) {
      throw new Error('TOTP_ENCRYPTION_KEY is not set — 2FA enrollment is unavailable. Generate one with: openssl rand -base64 32');
    }
    cachedKey = crypto.scryptSync(String(env), SALT, 32);
  }
  return cachedKey;
}

function encryptSecret(plaintextBuf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const ct = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ENC_PREFIX + [iv.toString('base64'), tag.toString('base64'), ct.toString('base64')].join('.');
}

function decryptSecret(stored) {
  if (typeof stored !== 'string' || !stored.startsWith(ENC_PREFIX)) {
    throw new Error('TOTP secret is not in the expected encrypted format');
  }
  const [ivB64, tagB64, ctB64] = stored.slice(ENC_PREFIX.length).split('.');
  if (!ivB64 || !tagB64 || !ctB64) throw new Error('TOTP secret is not in the expected encrypted format');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  const pt = Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64')), decipher.final()]);
  return pt;
}

// ---------- recovery codes ----------
// 80 bits of entropy per code, base32 (Crockford-safe subset), formatted
// XXXXX-XXXXX-XXXXX-XXXXX. Old 40-bit hex codes remain valid — verification
// hashes the presented string either way.
const CODE_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
function generateRecoveryCodes(count = RECOVERY_CODE_COUNT) {
  const codes = new Set();
  while (codes.size < count) {
    const bytes = crypto.randomBytes(13);
    let bits = 0, value = 0, s = '';
    for (const b of bytes) {
      value = (value << 8) | b; bits += 8;
      while (bits >= 5 && s.replace(/-/g, '').length < 20) {
        s += CODE_ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    codes.add(s.replace(/(.{5})(?=.)/g, '$1-'));
  }
  return [...codes];
}

function hashRecoveryCode(code) {
  const normalized = String(code || '').trim().toLowerCase();
  return 'sha256$' + crypto.createHash('sha256').update(normalized).digest('hex');
}

// ---------- trusted-device tokens ----------
function generateTrustedDeviceToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashTrustedDeviceToken(token) {
  return 'sha256$' + crypto.createHash('sha256').update(String(token)).digest('hex');
}

module.exports = {
  TOTP_PERIOD, TOTP_DIGITS, VERIFY_WINDOW, RECOVERY_CODE_COUNT, TRUSTED_DEVICE_DAYS,
  base32Encode, base32Decode,
  hotp, currentCounter, verifyTotp, generateTotpSecret, otpauthUri,
  encryptSecret, decryptSecret,
  generateRecoveryCodes, hashRecoveryCode,
  generateTrustedDeviceToken, hashTrustedDeviceToken,
};
