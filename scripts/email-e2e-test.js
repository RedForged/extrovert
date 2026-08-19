'use strict';
// End-to-end email verification test (web + API) in capture mode.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert');
const crypto = require('node:crypto');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extro-email-e2e-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'email-e2e-secret';
process.env.EXTV_MAIL_MODE = 'capture';
process.env.EXTV_EMAIL_POLICY = 'required';
process.env.EXTV_MAIL_LOG = 'error';

const db = require('../src/db');
const bcrypt = require('bcryptjs');
const app = require('../src/server');
const mailer = require('../src/mailer');
// Read the register captcha answer from the session store (server-side state,
// like an operator could; remote attackers only ever get the SVG).
const { sidFromCookie, captchaAnswer } = require('./captcha-helper');

(async () => {
  const outbox = path.join(__dirname, '..', 'data', 'outbox');
  // Clean any captured mail from previous runs so counts are deterministic.
  try { for (const f of fs.readdirSync(outbox)) fs.unlinkSync(path.join(outbox, f)); } catch {}
  const server = await new Promise((res) => { const s = app.listen(0, () => res(s)); });
  const base = 'http://localhost:' + server.address().port;
  const emlFiles = () => fs.existsSync(outbox) ? fs.readdirSync(outbox).filter(f => f.endsWith('.eml')) : [];

  const get = async (url, cookie) => {
    const r = await fetch(base + url, { headers: cookie ? { cookie } : {} });
    return { status: r.status, text: await r.text(), cookie: (r.headers.get('set-cookie') || '').split(';')[0] };
  };
  const post = async (url, body, cookie, ct = 'application/x-www-form-urlencoded') => {
    const r = await fetch(base + url, {
      method: 'POST',
      headers: { 'content-type': ct, ...(cookie ? { cookie } : {}) },
      body: ct.includes('json') ? JSON.stringify(body) : new URLSearchParams(body),
      redirect: 'manual',
    });
    return { status: r.status, text: await r.text(), cookie: (r.headers.get('set-cookie') || '').split(';')[0] };
  };
  const csrf = (html) => { const m = html.match(/name="csrf-token" content="([^"]+)"/); return m ? m[1] : ''; };

  console.log('1) register with email (policy=required) in capture mode');
  let g = await get('/register');
  let c = g.cookie;
  // sidFromCookie expects the raw cookie VALUE (after 'name=').
  const sid = sidFromCookie(c.slice(c.indexOf('=') + 1));
  const capAnswer = await captchaAnswer(sid);
  assert(!!capAnswer, 'captcha answer resolvable from session store');
  const reg = await post('/register', {
    _csrf: csrf(g.text), username: 'newbie', password: 'correct-horse-12', displayName: 'Newbie', email: 'newbie@example.org', captcha: capAnswer,
  }, c);
  assert.strictEqual(reg.status, 302, 'register redirects');
  const uid = db.getUserByUsername('newbie').id;
  const u0 = db.getUserById(uid);
  assert.strictEqual(u0.email, 'newbie@example.org', 'email stored');
  assert(!u0.email_verified_at, 'not verified yet');
  await new Promise(r => setTimeout(r, 50));
  assert.strictEqual(emlFiles().length, 1, 'one verification email captured');
  const eml = fs.readFileSync(path.join(outbox, emlFiles()[0]), 'utf8');
  assert(eml.includes('verify-email?token='), 'email contains verification link');

  console.log('2) unverified user cannot post (web)');
  // Re-login to get a clean session as newbie.
  g = await get('/login');
  c = g.cookie;
  const login = await post('/login', { _csrf: csrf(g.text), username: 'newbie', password: 'correct-horse-12' }, c);
  assert.strictEqual(login.status, 302, 'login ok');
  c = login.cookie;
  // Home page shows the verify banner.
  g = await get('/', c);
  assert(g.text.includes('verify-banner'), 'verify banner shown');
  g = await get('/compose', c);
  const postBody = await post('/posts', { _csrf: csrf(g.text), type: 'text', body: 'hello world' }, c);
  assert.strictEqual(postBody.status, 403, 'posting blocked while unverified');

  console.log('3) clicking the verification link verifies the account');
  const token = eml.match(/verify-email\?token=([A-Za-z0-9_-]+)/)[1];
  // verification link requires a logged-in session
  const v = await get('/verify-email?token=' + token, c);
  assert.strictEqual(v.status, 200, 'verify page renders');
  assert(v.text.includes('Email verified'), 'verified message shown');
  const u1 = db.getUserById(uid);
  assert(!!u1.email_verified_at, 'email_verified_at set');
  assert.strictEqual(db.getEmailVerification(uid), null, 'token row consumed/deleted');

  console.log('4) replay of the same token is rejected');
  const v2 = await get('/verify-email?token=' + token, c);
  assert(v2.text.includes('Already verified'), 'replay shows already-verified');

  console.log('5) verified user can now post');
  g = await get('/compose', c);
  const postBody2 = await post('/posts', { _csrf: csrf(g.text), type: 'text', body: 'now I can post' }, c);
  assert.strictEqual(postBody2.status, 302, 'posting allowed after verification');

  console.log('6) API: account email fields + gate');
  const aliceId = db.createUser({ username: 'alice', passwordHash: bcrypt.hashSync('pw', 10), displayName: 'Alice' });
  const appId = db.createOAuthApp({ name: 'E2E', description: '', website: '', redirectUris: 'https://ex.com/cb', clientId: 'e2e-client', clientSecret: 'e2e-secret', scopes: 'read write profile', ownerId: aliceId });
  const tokenStr = crypto.randomBytes(16).toString('hex');
  db.createOAuthToken(tokenStr, null, appId, aliceId, 'read write profile', Date.now() + 86400000);
  const authHdr = { Authorization: 'Bearer ' + tokenStr };
  let creds = await (await fetch(base + '/api/v1/accounts/verify_credentials', { headers: authHdr })).json();
  creds = creds.data || creds;
  assert.strictEqual(creds.email_verified, false, 'email_verified false for owner');
  assert.strictEqual(creds.email_required, true, 'email_required reflects policy');
  // Gate: unverified alice can't post via API.
  const gatePost = await fetch(base + '/api/v1/statuses', {
    method: 'POST', headers: { ...authHdr, 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'text', body: 'blocked' }),
  });
  assert.strictEqual(gatePost.status, 403, 'API posting blocked while unverified');
  // Set email via API.
  const setEmail = await fetch(base + '/api/v1/accounts/email', {
    method: 'PATCH', headers: { ...authHdr, 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'alice@example.org' }),
  });
  const setEmailJson = await setEmail.json();
  assert.strictEqual(setEmail.status, 200, 'email set via API');
  assert.strictEqual(setEmailJson.data && setEmailJson.data.verification_sent, true, 'verification_sent true');
  assert.strictEqual(setEmailJson.data && setEmailJson.data.email, 'alice@example.org', 'email echoed back');
  // verify via token from outbox
  await new Promise(r => setTimeout(r, 50));
  const aliceEml = fs.readdirSync(outbox).filter(f => f.endsWith('.eml')).map(f => fs.readFileSync(path.join(outbox, f), 'utf8')).find(e => e.includes('alice@example.org'));
  assert(!!aliceEml, 'alice verification email captured');
  const aliceToken = aliceEml.match(/verify-email\?token=([A-Za-z0-9_-]+)/)[1];
  // Simulate the click: consume via the module directly (the web route needs
  // a session; the module call is equivalent and simpler here).
  const ev = require('../src/email-verify');
  const res = ev.verify(aliceId, aliceToken);
  assert.strictEqual(res, 'ok', 'alice verified via module');
  creds = await (await fetch(base + '/api/v1/accounts/verify_credentials', { headers: authHdr })).json();
  creds = creds.data || creds;
  assert.strictEqual(creds.email_verified, true, 'email_verified true after verify');
  const gatePost2 = await fetch(base + '/api/v1/statuses', {
    method: 'POST', headers: { ...authHdr, 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'text', body: 'allowed now' }),
  });
  assert.strictEqual(gatePost2.status, 201, 'API posting allowed after verify');

  console.log('EMAIL E2E: ALL PASS');
  server.close();
  try { app.httpServer.close(); } catch {}
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
  process.exit(0);
})().catch((e) => { console.error('FAIL:', e); try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {} process.exit(1); });