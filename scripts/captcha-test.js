'use strict';
// Self-hosted image captcha suite (register anti-bot):
//   - src/captcha.js module: challenge generation + verification semantics
//     (correct case-insensitive, wrong, too-short, missing, expired,
//     single-use) and the image never leaking the answer.
//   - end-to-end over HTTP: a plain terminal (no image fetch, no OCR) cannot
//     register; with the answer read from the session store (as an operator
//     could) registration succeeds; wrong/missing/replayed answers are
//     rejected; the captcha is session-bound.
// Run: npm run test:captcha

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-captcha-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'captcha-test-secret';
process.env.SECRET = 'captcha-test-secret';
process.env.PORT = String(35300 + Math.floor(Math.random() * 1000));

const app = require('../src/server');
const db = require('../src/db');
const captcha = require('../src/captcha');
const { sidFromCookie, captchaAnswer } = require('./captcha-helper');

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
// The register page GET already generates the session's challenge; read the
// expected answer from the store (as an operator could).
async function solveCaptcha(jar) {
  const sid = sidFromCookie(jar.cookies['connect.sid']);
  const answer = await captchaAnswer(sid);
  return { answer, sid };
}

async function main() {
  // ---- TEST 1: src/captcha module semantics ----
  console.log('\nTEST 1: verification semantics (correct / wrong / short / missing / expired / single-use)');
  {
    const sess = {};
    const svg = captcha.generate({ session: sess });
    ok(typeof svg === 'string' && svg.includes('<svg'), 'generate returns an SVG image');
    ok(sess.captcha && sess.captcha.text && sess.captcha.expiresAt > Date.now(), 'expected answer + expiry stored in the session');
    ok(!svg.includes(sess.captcha.text), 'the SVG does not leak the answer as text');
    const good = captcha.verify({ session: sess }, { captcha: sess.captcha.text.toUpperCase() });
    ok(good.ok === true, 'correct answer verifies (case-insensitive)');

    const sess2 = {};
    captcha.generate({ session: sess2 });
    const bad = captcha.verify({ session: sess2 }, { captcha: 'zzzzzz' });
    ok(bad.ok === false && /[Cc]aptcha/.test(bad.error), 'wrong answer rejected');

    const sess3 = {};
    captcha.generate({ session: sess3 });
    const short = captcha.verify({ session: sess3 }, { captcha: 'ab' });
    ok(short.ok === false, 'too-short answer rejected');

    const sess4 = {};
    captcha.generate({ session: sess4 });
    const none = captcha.verify({ session: sess4 }, {});
    ok(none.ok === false, 'missing answer rejected');

    // Oversized / multibyte answers must be rejected, never crash. A naive
    // length gate on code units + Buffer.from(padEnd(16)) used to let a
    // multibyte answer reach timingSafeEqual with mismatched byte lengths,
    // whose throw would escape into the async route handler and kill the
    // process (unauthenticated DoS). Both cases below must return ok:false.
    const sess4b = {};
    captcha.generate({ session: sess4b });
    const huge = captcha.verify({ session: sess4b }, { captcha: 'a'.repeat(100) });
    ok(huge.ok === false, 'oversized answer rejected without throwing');
    const sess4c = {};
    captcha.generate({ session: sess4c });
    const wide = captcha.verify({ session: sess4c }, { captcha: 'é'.repeat(16) });
    ok(wide.ok === false, 'multibyte answer rejected without throwing');
    const sess4d = {};
    captcha.generate({ session: sess4d });
    const emoji = captcha.verify({ session: sess4d }, { captcha: '😀'.repeat(4) });
    ok(emoji.ok === false, 'emoji answer rejected without throwing');

    const sess5 = {};
    captcha.generate({ session: sess5 });
    sess5.captcha.expiresAt = Date.now() - 1;
    const exp = captcha.verify({ session: sess5 }, { captcha: sess5.captcha.text });
    ok(exp.ok === false && /expired/i.test(exp.error), 'expired challenge rejected');

    // Single-use: consumed on a failed attempt, so the correct answer no
    // longer verifies afterwards.
    const sess6 = {};
    captcha.generate({ session: sess6 });
    const answer6 = sess6.captcha.text;
    captcha.verify({ session: sess6 }, { captcha: 'zzzzzz' });
    const reuse = captcha.verify({ session: sess6 }, { captcha: answer6 });
    ok(reuse.ok === false, 'challenge is single-use (consumed after one attempt)');
  }

  // ---- TEST 2: a plain terminal cannot register -------
  console.log('\nTEST 2: terminal-style registration (no image fetch, no OCR) is blocked');
  {
    const jar = makeJar();
    const pre = await req('/register', jar);
    const html = await pre.text();
    const csrf = extractCsrf(html);
    ok(html.includes('id="captcha-img"') && html.includes('name="captcha"'), 'register page embeds the captcha image + answer field');
    // The attacker's terminal never loads the image and never types an answer
    // (no captcha field at all) — the gate must reject it.
    const resp = await req('/register', jar, {
      method: 'POST',
      form: { username: 'terminalbot', password: 'longenough123', _csrf: csrf },
    });
    ok(resp.status === 200 && /[Cc]aptcha/.test(await resp.text()), 'registration without reading the image is rejected');
    ok(!db.getUserByUsername('terminalbot'), 'no account created');
  }

  // ---- TEST 3: captcha endpoint serves a session-bound SVG, no-store ----
  console.log('\nTEST 3: captcha endpoint semantics');
  {
    const jar = makeJar();
    await req('/register', jar);
    const before = await captchaAnswer(sidFromCookie(jar.cookies['connect.sid']));
    const img = await req('/register/captcha', jar);
    ok(img.status === 200 && (img.headers.get('content-type') || '').startsWith('image/svg+xml'), 'serves image/svg+xml');
    ok((img.headers.get('cache-control') || '').includes('no-store'), 'served with Cache-Control: no-store');
    const body = await img.text();
    ok(body.includes('<svg'), 'body is an SVG image');
    const after = await captchaAnswer(sidFromCookie(jar.cookies['connect.sid']));
    ok(after && after !== before, 'loading the image regenerates the challenge (browser flow)');

    const jar2 = makeJar();
    await req('/register', jar2);
    const { answer: a1, sid: s1 } = await solveCaptcha(jar);
    const { answer: a2, sid: s2 } = await solveCaptcha(jar2);
    ok(s1 !== s2, 'each session gets its own challenge');
    ok(a1 && a1.length >= 5, 'session holds a plausible answer');
  }

  // ---- TEST 4: E2E — correct / wrong / missing / replayed answers ----
  console.log('\nTEST 4: E2E register gating');
  // 4a: correct answer -> account created.
  {
    const jar = makeJar();
    const pre = await req('/register', jar);
    const csrf = extractCsrf(await pre.text());
    const { answer } = await solveCaptcha(jar);
    const resp = await req('/register', jar, {
      method: 'POST',
      form: { username: 'gooduser', password: 'longenough123', _csrf: csrf, captcha: answer },
    });
    ok(resp.status === 302, 'register with the correct answer redirects (account created)');
    ok(db.getUserByUsername('gooduser'), 'account created');
  }

  // 4b: wrong answer -> rejected.
  {
    const jar = makeJar();
    const csrf = extractCsrf(await (await req('/register', jar)).text());
    const resp = await req('/register', jar, {
      method: 'POST',
      form: { username: 'wronguser', password: 'longenough123', _csrf: csrf, captcha: 'zzzzzz' },
    });
    ok(resp.status === 200 && /[Cc]aptcha/.test(await resp.text()), 'wrong answer rejected');
    ok(!db.getUserByUsername('wronguser'), 'no account created with a wrong answer');
  }

  // 4b2: multibyte answer over HTTP must 200, not crash the server.
  {
    const jar = makeJar();
    const csrf = extractCsrf(await (await req('/register', jar)).text());
    const resp = await req('/register', jar, {
      method: 'POST',
      form: { username: 'widebot', password: 'longenough123', _csrf: csrf, captcha: 'é'.repeat(16) },
    });
    ok(resp.status === 200, 'multibyte answer over HTTP returns 200 (server still alive)');
  }

  // 4c: replayed answer (from a consumed challenge) against a fresh challenge.
  {
    const jar = makeJar();
    const csrf = extractCsrf(await (await req('/register', jar)).text());
    const { answer } = await solveCaptcha(jar);
    // First attempt consumes the challenge but fails on username policy.
    const first = await req('/register', jar, {
      method: 'POST',
      form: { username: 'bad name!', password: 'longenough123', _csrf: csrf, captcha: answer },
    });
    ok(first.status === 200 && /Username must be/.test(await first.text()), 'first attempt consumed the challenge (failed on policy)');
    // Replay the SAME answer against the fresh challenge — must fail.
    const replay = await req('/register', jar, {
      method: 'POST',
      form: { username: 'replayer', password: 'longenough123', _csrf: csrf, captcha: answer },
    });
    ok(replay.status === 200 && /[Cc]aptcha/.test(await replay.text()), 'replayed answer rejected');
    ok(!db.getUserByUsername('replayer'), 'no account created by replaying an answer');
  }

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL CAPTCHA TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
