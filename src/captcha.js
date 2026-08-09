'use strict';

// Self-hosted, self-created proof-of-work captcha for /register (anti-bot).
//
// No third-party service, no external requests, no images: the client must
// find a `number` such that sha256(challenge + salt + number) starts with
// `difficulty` hex zeroes. The server verifies with a single hash — the cost
// is paid by the client, so verification is cheap and is not a DoS vector.
//
// The challenge is random per request, bound to the session, short-lived
// (5 minutes) and SINGLE-USE: it is consumed on every registration attempt,
// successful or not, so a solved proof can never be replayed and every
// username-enumeration attempt costs a fresh solve.
//
// NOTE: this is anti-spam, not a security boundary. It stops scripted bots
// (curl, mass-signup tools) that don't do the work; a determined attacker
// willing to burn CPU can solve the PoW. Difficulty is tunable via
// EXTV_CAPTCHA_DIFFICULTY (1-5, default 4 => ~2^16 = ~65k hashes on average).

const crypto = require('node:crypto');

const DEFAULT_DIFFICULTY = 4;
const MAX_DIFFICULTY = 5; // hard ceiling: ~8.4M hashes at diff 5, a few seconds
const TTL_MS = 5 * 60 * 1000;

// The client must find a number below maxnumber, with ~8x headroom over the
// expected 2^(4*diff) hashes, so a legit solve succeeds with overwhelming
// probability (failure ~e^-8, and the widget retries with a fresh challenge).
function maxnumberFor(diff) {
  return Math.ceil(Math.pow(2, 4 * diff) * 8);
}

function difficulty() {
  const n = Number(process.env.EXTV_CAPTCHA_DIFFICULTY);
  if (Number.isInteger(n) && n >= 1 && n <= MAX_DIFFICULTY) return n;
  return DEFAULT_DIFFICULTY;
}

function hashOf(challenge, salt, number) {
  return crypto.createHash('sha256').update(challenge + salt + String(number), 'utf8').digest('hex');
}

// Pure helper: the number whose sha256(challenge + salt + number) starts with
// `diff` hex zeroes, or null if none exists below maxnumber. Exposed for tests
// and any server-side tooling.
function findNumber(challenge, salt, maxnumber, diff) {
  const target = '0'.repeat(diff);
  for (let n = 0; n <= maxnumber; n++) {
    if (hashOf(challenge, salt, n).startsWith(target)) return n;
  }
  return null;
}

// Fresh challenge bound to this session. Returns the public fields the widget
// needs; the full record (incl. expiry AND the pinned difficulty — verify()
// must not re-read the env later) lives in req.session.captcha.
function generateChallenge(req) {
  const challenge = crypto.randomBytes(32).toString('hex');
  const salt = crypto.randomBytes(16).toString('hex');
  const diff = difficulty();
  const maxnumber = maxnumberFor(diff);
  req.session.captcha = { challenge, salt, maxnumber, difficulty: diff, expiresAt: Date.now() + TTL_MS };
  return { challenge, salt, maxnumber, difficulty: diff };
}

// Verify a submitted proof. Always consumes the session challenge (single-use).
function verify(req, body) {
  const data = req.session.captcha;
  delete req.session.captcha; // single-use: consumed whether or not it verifies
  if (!data) {
    return { ok: false, error: 'Captcha verification failed — reload the page and try again.' };
  }
  if (Date.now() > data.expiresAt) {
    return { ok: false, error: 'Captcha expired — reload the page and try again.' };
  }
  const number = Number(body && body.captcha_number);
  if (!Number.isInteger(number) || number < 0 || number > data.maxnumber) {
    return { ok: false, error: 'Captcha verification failed — please try again.' };
  }
  if (!hashOf(data.challenge, data.salt, number).startsWith('0'.repeat(data.difficulty))) {
    return { ok: false, error: 'Captcha verification failed — please try again.' };
  }
  return { ok: true };
}

module.exports = { DEFAULT_DIFFICULTY, MAX_DIFFICULTY, TTL_MS, maxnumberFor, difficulty, hashOf, findNumber, generateChallenge, verify };
