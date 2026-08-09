'use strict';
// Self-hosted PoW captcha suite (register anti-bot):
//   - src/captcha.js module: challenge generation + verification semantics
//     (correct proof, wrong proof, expired, missing, single-use).
//   - public/captcha.js widget SHA-256 matches node:crypto (the client and
//     server must agree on the hash the PoW is built on).
//   - end-to-end over HTTP: register succeeds only with a freshly solved
//     proof; no captcha / wrong proof / replayed proof are all rejected.
// Run: npm run test:captcha

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-captcha-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'captcha-test-secret';
process.env.SECRET = 'captcha-test-secret';
process.env.PORT = String(35300 + Math.floor(Math.random() * 1000));

const app = require('../src/server');
const db = require('../src/db');
const captcha = require('../src/captcha');
const widget = require('../public/captcha.js');

let failures = 0;
function ok(cond, msg) { console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg); if (!cond) failures++; }

function makeJar() {
  return { cookies: {} };
}
async function req(url, jar, opts = {}) {
  const headers = {};
  const cookie = Object.values(jar.cookies).map(v => `connect.sid=${v}`).join('; ');
  if (cookie) headers['Cookie'] = cookie;
  if (opts.form) headers['Content-Type'] = 'application/x-www-form-urlencoded';
  const body = opts.form ? new URLSearchParams(opts.form).toString() : undefined;
  const r = await fetch('http://localhost:' + process.env.PORT + url, { method: opts.method || 'GET', headers, body, redirect: 'manual' });
  const scs = typeof r.headers.getSetCookie === 'function' ? r.headers.getSetCookie() : (r.headers.get('set-cookie') ? [r.headers.get('set-cookie')] : []);
  for (const sc of scs) {
    const pair = sc.split(';')[0];
    const eq = pair.indexOf('=');
    if (eq > 0) jar.cookies[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
  return r;
}
function extractCsrf(html) {
  const m = String(html).match(/name="_csrf" value="([^"]+)"/);
  return m ? m[1] : null;
}
function challengeFromHtml(html) {
  const m = String(html).match(/data-challenge="([^"]+)" data-salt="([^"]+)" data-maxnumber="(\d+)" data-difficulty="(\d+)"/);
  if (!m) return null;
  return { challenge: m[1], salt: m[2], maxnumber: Number(m[3]), difficulty: Number(m[4]) };
}
function solve(ch) {
  return captcha.findNumber(ch.challenge, ch.salt, ch.maxnumber, ch.difficulty);
}

// A number that provably FAILS the given challenge (hash prefix mismatch); the
// fallback maxnumber+1 is rejected by the range check, so this never hangs.
function wrongNumber(ch) {
  const target = '0'.repeat(ch.difficulty);
  for (let k = 1; k <= ch.maxnumber; k++) {
    if (!captcha.hashOf(ch.challenge, ch.salt, k).startsWith(target)) return k;
  }
  return ch.maxnumber + 1;
}

// Solve the embedded challenge, retrying with a fresh page/challenge if the
// rare no-proof-within-range case (~e^-8) occurs — mirrors the widget's retry.
async function solveOrRefresh(jar, html) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const ch = challengeFromHtml(html);
    const n = ch ? solve(ch) : null;
    if (n !== null) return { n, ch };
    const page = await req('/register', jar);
    html = await page.text();
  }
  throw new Error('could not solve a captcha after retries');
}

async function main() {
  const base = 'http://localhost:' + process.env.PORT;

  // ---- TEST 1: widget SHA-256 agrees with node:crypto ----
  console.log('\nTEST 1: widget sha256Hex matches node:crypto');
  const vectors = [
    '', 'abc', 'The quick brown fox jumps over the lazy dog',
    'a3f2c1b4e5d6cafebabe123456', 'f'.repeat(64) + '0'.repeat(32) + '999999',
  ];
  let allMatch = true;
  for (const v of vectors) {
    const w = widget.sha256Hex(v);
    const n = crypto.createHash('sha256').update(v, 'utf8').digest('hex');
    if (w !== n) { allMatch = false; console.log('    mismatch for', JSON.stringify(v)); }
  }
  ok(allMatch, 'widget sha256Hex === node:crypto for all vectors');

  // ---- TEST 2: src/captcha module semantics ----
  console.log('\nTEST 2: verification semantics (correct / wrong / expired / missing / single-use)');
  {
    // Correct proof.
    const sess = {};
    const ch = captcha.generateChallenge({ session: sess });
    const n = captcha.findNumber(ch.challenge, ch.salt, ch.maxnumber, ch.difficulty);
    ok(n !== null, 'a valid proof exists within maxnumber');
    const good = captcha.verify({ session: sess }, { captcha_number: String(n) });
    ok(good.ok === true, 'correct proof verifies');

    // Wrong proof: a number that provably does NOT solve this challenge.
    const sess2 = {};
    const ch2 = captcha.generateChallenge({ session: sess2 });
    const bad = captcha.verify({ session: sess2 }, { captcha_number: String(wrongNumber(ch2)) });
    ok(bad.ok === false && /[Cc]aptcha/.test(bad.error), 'wrong number rejected');

    // Missing payload.
    const sess3 = {};
    captcha.generateChallenge({ session: sess3 });
    const none = captcha.verify({ session: sess3 }, {});
    ok(none.ok === false, 'missing captcha_number rejected');

    // Expired.
    const sess4 = {};
    captcha.generateChallenge({ session: sess4 });
    sess4.captcha.expiresAt = Date.now() - 1;
    const exp = captcha.verify({ session: sess4 }, { captcha_number: String(n) });
    ok(exp.ok === false && /expired/i.test(exp.error), 'expired challenge rejected');

    // Single-use: verify consumes the challenge even on failure.
    const sess5 = {};
    captcha.generateChallenge({ session: sess5 });
    captcha.verify({ session: sess5 }, {});
    const reuse = captcha.verify({ session: sess5 }, { captcha_number: String(n) });
    ok(reuse.ok === false, 'challenge is single-use (consumed after one attempt)');

    // Negative / non-integer numbers.
    const sess6 = {};
    captcha.generateChallenge({ session: sess6 });
    ok(captcha.verify({ session: sess6 }, { captcha_number: '-5' }).ok === false, 'negative number rejected');
    const sess7 = {};
    captcha.generateChallenge({ session: sess7 });
    ok(captcha.verify({ session: sess7 }, { captcha_number: 'abc' }).ok === false, 'non-numeric rejected');
  }

  // ---- TEST 2b: difficulty is capped, search range scales, and is pinned ----
  console.log('\nTEST 2b: difficulty ceiling, scaling and pinning');
  {
    ok(captcha.MAX_DIFFICULTY === 5, 'difficulty is capped at 5 (no registration lockout)');
    ok(captcha.maxnumberFor(4) > Math.pow(2, 16), 'maxnumber at diff 4 has headroom over the expected 2^16 hashes');
    ok(captcha.maxnumberFor(5) > Math.pow(2, 20), 'maxnumber at diff 5 has headroom over the expected 2^20 hashes');
    ok(captcha.maxnumberFor(1) < captcha.maxnumberFor(5), 'maxnumber scales up with difficulty');

    const prev = process.env.EXTV_CAPTCHA_DIFFICULTY;
    process.env.EXTV_CAPTCHA_DIFFICULTY = '5';
    try {
      // A challenge is solved under its pinned difficulty even if the env
      // changes before verification (mid-flight config must not invalidate
      // already-issued proofs).
      const sess = {};
      const ch = captcha.generateChallenge({ session: sess });
      ok(ch.difficulty === 5 && ch.maxnumber === captcha.maxnumberFor(5), 'challenge carries its difficulty + scaled maxnumber');
      const n = captcha.findNumber(ch.challenge, ch.salt, ch.maxnumber, ch.difficulty);
      ok(n !== null, 'a diff-5 proof exists within the scaled range');
      ok(captcha.verify({ session: sess }, { captcha_number: String(n) }).ok === true, 'proof verifies');
      // Pinning: generate at diff 5, then lower the env — the issued challenge
      // must still verify at its pinned difficulty (mid-flight config changes
      // must not invalidate already-issued proofs).
      const sess2 = {};
      const ch2 = captcha.generateChallenge({ session: sess2 });
      process.env.EXTV_CAPTCHA_DIFFICULTY = '4';
      const n2 = captcha.findNumber(ch2.challenge, ch2.salt, ch2.maxnumber, ch2.difficulty);
      ok(captcha.verify({ session: sess2 }, { captcha_number: String(n2) }).ok === true, 'verification uses the pinned difficulty, not the live env');
    } finally {
      process.env.EXTV_CAPTCHA_DIFFICULTY = prev;
    }
  }

  // ---- TEST 3: E2E — register requires a freshly solved proof ----
  console.log('\nTEST 3: /register requires a solved captcha (E2E)');

  // 3a: no captcha -> rejected, no account.
  {
    const jar = makeJar();
    const pre = await req('/register', jar);
    const csrf = extractCsrf(await pre.text());
    const resp = await req('/register', jar, {
      method: 'POST',
      form: { username: 'nocaptcha', password: 'longenough123', _csrf: csrf },
    });
    ok(resp.status === 200, 'register without captcha is not a redirect');
    const text = await resp.text();
    ok(/[Cc]aptcha/.test(text), 'error explains the captcha requirement');
    ok(!db.getUserByUsername('nocaptcha'), 'no account created without captcha');
  }

  // 3b: wrong proof -> rejected.
  {
    const jar = makeJar();
    const pre = await req('/register', jar);
    const preHtml = await pre.text();
    const csrf = extractCsrf(preHtml);
    const ch = challengeFromHtml(preHtml);
    ok(ch, 'register page embeds a challenge for the widget');
    const resp = await req('/register', jar, {
      method: 'POST',
      form: { username: 'wrongproof', password: 'longenough123', _csrf: csrf, captcha_number: String(wrongNumber(ch)) },
    });
    ok(resp.status === 200 && /[Cc]aptcha/.test(await resp.text()), 'wrong proof rejected');
    ok(!db.getUserByUsername('wrongproof'), 'no account created with a wrong proof');
  }

  // 3c: correct proof -> account created.
  {
    const jar = makeJar();
    const pre = await req('/register', jar);
    const preHtml = await pre.text();
    const csrf = extractCsrf(preHtml);
    const { n } = await solveOrRefresh(jar, preHtml);
    const resp = await req('/register', jar, {
      method: 'POST',
      form: { username: 'gooduser', password: 'longenough123', _csrf: csrf, captcha_number: String(n) },
    });
    ok(resp.status === 302, 'register with solved captcha redirects (account created)');
    ok(db.getUserByUsername('gooduser'), 'account created');
  }

  // 3d: a solved proof cannot be replayed (single-use, session-bound).
  {
    const jar = makeJar();
    const pre = await req('/register', jar);
    const preHtml = await pre.text();
    const csrf = extractCsrf(preHtml);
    const { n } = await solveOrRefresh(jar, preHtml);
    // First attempt consumes the proof but fails on username policy.
    const first = await req('/register', jar, {
      method: 'POST',
      form: { username: 'bad name!', password: 'longenough123', _csrf: csrf, captcha_number: String(n) },
    });
    const firstHtml = await first.text();
    ok(first.status === 200 && /Username must be/.test(firstHtml), 'first attempt consumed the proof (failed on policy)');
    // Replay the SAME number against the fresh challenge — single-use means the
    // consumed proof cannot satisfy a subsequent challenge. Guard against the
    // (astronomically rare) coincidence where n solves the fresh challenge too.
    const fresh = challengeFromHtml(firstHtml);
    ok(fresh, 'failed attempt renders a fresh challenge');
    const replayN = captcha.hashOf(fresh.challenge, fresh.salt, n).startsWith('0'.repeat(fresh.difficulty))
      ? wrongNumber(fresh)
      : n;
    const replay = await req('/register', jar, {
      method: 'POST',
      form: { username: 'replayer', password: 'longenough123', _csrf: csrf, captcha_number: String(replayN) },
    });
    ok(replay.status === 200 && /[Cc]aptcha/.test(await replay.text()), 'replayed proof rejected');
    ok(!db.getUserByUsername('replayer'), 'no account created by replaying a proof');
  }

  // 3e: challenge endpoint returns fresh JSON + is session-bound.
  {
    const jar = makeJar();
    const j = await (await req('/register/captcha', jar)).json();
    ok(j.challenge && j.salt && j.maxnumber > 0 && j.difficulty >= 1, 'GET /register/captcha returns a fresh challenge');
    const jar2 = makeJar();
    const j2 = await (await req('/register/captcha', jar2)).json();
    ok(j.challenge !== j2.challenge, 'each session gets a different challenge');
  }

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL CAPTCHA TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
