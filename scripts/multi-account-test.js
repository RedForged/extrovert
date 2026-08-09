'use strict';
// F1 multi-account integration test (planned.md).
// Exercises the full multi-account surface:
//   - login seeds accountIds; add-another-account preserves the list
//   - switching active account (/account/switch) keeps every account signed in
//   - logout removes only the active account; last account destroys the session
//   - account_sessions rows persist per session (survive "restarts")
//   - OAuth authorize: consent POST bound to the SELECTED account, code ->
//     token -> userinfo all follow the selected account; a tampered account_id
//     (not signed in on the device) is rejected.
// Run: npm run test:multi-account

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-multi-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'multi-account-test-secret';
process.env.SECRET = 'multi-account-test-secret';
process.env.PORT = String(35200 + Math.floor(Math.random() * 1000));

const app = require('../src/server');
const db = require('../src/db');
const SessionStore = require('../src/session-store');
const store = new SessionStore();
const { listAccountSessions } = SessionStore;

let failures = 0;
function ok(cond, msg) { console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg); if (!cond) failures++; }

// Which account row on the /account/switch page carries the "Active" badge.
function activeRowOf(html) {
  const ROW = '<div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-top:1px solid var(--border-soft)">';
  for (const row of html.split(ROW)) {
    if (row.includes('Active')) return row;
  }
  return null;
}

// Minimal cookie-jar web session (mirrors oauth-flow-test.js).
function makeWebSession(username, password) {
  const jar = {};
  function sid() {
    // connect.sid=s%3A<sid>.<signature> — strip the signed-cookie envelope.
    const v = decodeURIComponent(jar.cookie.split('=')[1]);
    return v.replace(/^s:/, '').split('.')[0];
  }
  async function withCookie(url, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (jar.cookie) headers['Cookie'] = jar.cookie;
    const r = await fetch('http://localhost:' + process.env.PORT + url, { ...opts, headers, redirect: 'manual' });
    const sc = r.headers.get('set-cookie');
    if (sc) jar.cookie = sc.split(';')[0];
    return r;
  }
  return {
    jar,
    sid,
    withCookie,
    get: (url) => withCookie(url).then((r) => r.text()),
    login: async (user, pass, { add = false } = {}) => {
      const qs = add ? '?add=1' : '';
      const page = await withCookie('/login' + qs);
      const html = await page.text();
      const csrf = (html.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
      const r = await withCookie('/login' + qs, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}&_csrf=${encodeURIComponent(csrf)}`,
      });
      return r;
    },
    csrfFrom: (html) => (html.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '',
  };
}

async function main() {
  const base = 'http://localhost:' + process.env.PORT;

  const aliceId = db.createUser({ username: 'alice', passwordHash: bcrypt.hashSync('pw-alice', 10), displayName: 'Alice' });
  const bobId = db.createUser({ username: 'bob', passwordHash: bcrypt.hashSync('pw-bob', 10), displayName: 'Bob' });

  // ---- TEST 1: fresh login seeds a single-account list ----
  console.log('\nTEST 1: fresh login seeds account list');
  const s = makeWebSession();
  let r = await s.login('alice', 'pw-alice');
  ok(r.status === 302 && (r.headers.get('location') || '').startsWith('/'), 'alice login redirects');
  let html = await s.get('/account/switch');
  ok(html.includes('@alice') && !html.includes('@bob'), 'switch page lists only alice after fresh login');
  ok(listAccountSessions(s.sid()).some(x => x.user_id === aliceId && x.active === 1),
    'account_sessions row persisted for alice (active)');

  // ---- TEST 2: add another account keeps the list ----
  console.log('\nTEST 2: add-another-account preserves the existing list');
  r = await s.login('bob', 'pw-bob', { add: true });
  ok(r.status === 302, 'bob add-account login redirects');
  html = await s.get('/account/switch');
  ok(html.includes('@alice') && html.includes('@bob'), 'switch page lists both accounts after adding bob');
  // Bob must be the active account now.
  html = await s.get('/account/switch');
  const activeBob = activeRowOf(html);
  ok(activeBob && activeBob.includes('@bob'), 'active account is bob after add-login (his row is marked Active)');

  // ---- TEST 3: session model — userId = active, accountIds = list ----
  console.log('\nTEST 3: persisted session state matches the account model');
  const sid = s.sid();
  const rows = listAccountSessions(sid);
  ok(rows.length === 2, 'account_sessions has two rows for the session');
  const active = rows.filter(x => x.active === 1);
  ok(active.length === 1 && active[0].user_id === bobId, 'exactly one active account (bob)');

  // ---- TEST 4: switch active account ----
  console.log('\nTEST 4: POST /account/switch sets the active account');
  html = await s.get('/account/switch');
  const csrf = s.csrfFrom(html);
  r = await s.withCookie('/account/switch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `_csrf=${encodeURIComponent(csrf)}&account_id=${aliceId}&next=/`,
  });
  ok(r.status === 302 && (r.headers.get('location') || '') === '/', 'switch to alice redirects to next');
  ok(listAccountSessions(sid).find(x => x.user_id === aliceId).active === 1, 'alice is now the active account in account_sessions');
  html = await s.get('/account/switch');
  const activeAlice = activeRowOf(html);
  ok(activeAlice && activeAlice.includes('@alice'), 'switch page marks alice active');

  // A bogus account_id (not signed in on this device) must be rejected.
  const carolId = db.createUser({ username: 'carol', passwordHash: bcrypt.hashSync('pw-carol', 10), displayName: 'Carol' });
  r = await s.withCookie('/account/switch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `_csrf=${encodeURIComponent(csrf)}&account_id=${carolId}&next=/`,
  });
  ok(r.status === 400, 'switching to an account not signed in on the device is rejected');

  // ---- TEST 5: logout removes only the active account ----
  console.log('\nTEST 5: logout removes the active account, keeps the rest signed in');
  r = await s.withCookie('/logout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `_csrf=${encodeURIComponent(csrf)}&next=/`,
  });
  ok(r.status === 302 && (r.headers.get('location') || '').startsWith('/'), 'logout redirects');
  html = await s.get('/account/switch');
  ok(!html.includes('@alice') && html.includes('@bob'), 'alice removed from the device, bob still signed in');
  const rowsAfter = listAccountSessions(sid);
  ok(rowsAfter.length === 1 && rowsAfter[0].user_id === bobId && rowsAfter[0].active === 1, 'account_sessions now has only bob, active');

  // Removing the last account destroys the whole session.
  html = await s.get('/account/switch');
  const csrf2 = s.csrfFrom(html);
  r = await s.withCookie('/account/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `_csrf=${encodeURIComponent(csrf2)}&account_id=${bobId}`,
  });
  ok(r.status === 302 && (r.headers.get('location') || '').endsWith('/login'), 'removing the last account redirects to /login');
  r = await s.withCookie('/account/switch');
  ok(r.status === 302, 'no accounts left: /account/switch redirects to login');
  ok(listAccountSessions(sid).length === 0, 'account_sessions rows cleared with the destroyed session');

  // ---- TEST 6: OAuth — consent POST bound to the SELECTED account ----
  console.log('\nTEST 6: OAuth authorization selects which account issues the code');
  const s2 = makeWebSession();
  await s2.login('alice', 'pw-alice');
  await s2.login('bob', 'pw-bob', { add: true });
  // A normal page load materializes the session CSRF token (the OAuth GET is
  // an /api route and skips the global CSRF-token middleware).
  await s2.get('/');

  const appReg = await s2.withCookie('/api/v1/oauth/apps', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Multi app', redirect_uris: 'https://multi.example/cb', scopes: 'read openid profile' }),
  });
  const appJson = await appReg.json();
  const clientId = appJson.data.client_id;
  ok(appReg.status === 201, 'oauth app registered');

  // GET consent with two accounts signed in must embed the picker.
  html = await s2.get(`/api/v1/oauth/authorize?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent('https://multi.example/cb')}&scope=read&nonce=n-f1`);
  ok(html.includes('Authorize as:') && html.includes('name="account_id"'), 'consent page embeds the account picker when 2 accounts are signed in');

  // Approve as BOB: the issued code must be bound to bob.
  const consentCsrf = (html.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  r = await s2.withCookie('/api/v1/oauth/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: consentCsrf, client_id: clientId, redirect_uri: 'https://multi.example/cb', scope: 'read openid profile', nonce: 'n-f1', account_id: String(bobId), approve: 'yes' }),
  });
  ok(r.status === 302, 'consent approved for bob -> redirect');
  const code = new URL(r.headers.get('location')).searchParams.get('code');

  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  // issue a code with the challenge to redeem it without a secret
  r = await s2.withCookie('/api/v1/oauth/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: consentCsrf, client_id: clientId, redirect_uri: 'https://multi.example/cb', scope: 'read openid profile', nonce: 'n-f1', account_id: String(bobId), code_challenge: challenge, code_challenge_method: 'S256', approve: 'yes' }),
  });
  const pkceCode = new URL(r.headers.get('location')).searchParams.get('code');
  let tok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: clientId, code: pkceCode, redirect_uri: 'https://multi.example/cb', code_verifier: verifier }),
  });
  const tokJson = await tok.json();
  ok(tok.status === 200 && tokJson.id_token, 'code redeemed (PKCE), id_token present');
  const [, payloadB64] = tokJson.id_token.split('.');
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
  ok(payload.sub === String(bobId) && payload.nonce === 'n-f1', 'id_token sub + nonce bound to the SELECTED account (bob)');
  const ui = await fetch(base + '/api/v1/oauth/userinfo', { headers: { Authorization: 'Bearer ' + tokJson.access_token } }).then(x => x.json());
  ok(ui.sub === String(bobId) && ui.preferred_username === 'bob', 'userinfo returns the selected account (bob)');
  ok(ui.sub !== String(aliceId), 'userinfo is NOT the session-active account when another account was selected');

  // The nonce-bound code: a nonce from another flow cannot be substituted —
  // the code row carries both user_id and nonce together (same binding).

  // Tampered account_id (carol, never signed in on this device) is rejected.
  r = await s2.withCookie('/api/v1/oauth/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: consentCsrf, client_id: clientId, redirect_uri: 'https://multi.example/cb', scope: 'read', account_id: String(carolId), approve: 'yes' }),
  });
  ok(r.status === 400, 'consent with an account not signed in on the device is rejected (no code issued)');

  // Default (no account_id) still works and uses the session-active account.
  r = await s2.withCookie('/api/v1/oauth/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: consentCsrf, client_id: clientId, redirect_uri: 'https://multi.example/cb', scope: 'read', approve: 'yes' }),
  });
  const defaultCode = new URL(r.headers.get('location')).searchParams.get('code');
  const row = db.getOAuthCode(defaultCode);
  ok(row && row.user_id === bobId, 'code without account_id defaults to the active account (bob)');

  // ---- TEST 7: single-account sessions show no picker, legacy fallback ----
  console.log('\nTEST 7: single signed-in account -> no picker, legacy sessions work');
  const s3 = makeWebSession();
  await s3.login('alice', 'pw-alice');
  html = await s3.get(`/api/v1/oauth/authorize?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent('https://multi.example/cb')}&scope=read`);
  ok(!html.includes('Authorize as:'), 'no picker when only one account is signed in');
  ok(html.includes('Authorize'), 'consent still renders for a single account');

  // Legacy session (no accountIds): simulating a pre-F1 session data shape.
  const legacy = makeWebSession();
  const legacyPage = await legacy.withCookie('/login');
  const legacyCsrf = legacy.csrfFrom(await legacyPage.text());
  await legacy.withCookie('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=alice&password=pw-alice&_csrf=${encodeURIComponent(legacyCsrf)}`,
  });
  // wipe accountIds out of the stored session to emulate a legacy session
  const legSid = legacy.sid();
  const storeRow = (await new Promise((resolve) => store.get(legSid, (e, d) => resolve(d))));
  delete storeRow.accountIds;
  await new Promise((resolve) => store.set(legSid, storeRow, resolve));
  html = await legacy.get('/account/switch');
  ok(html.includes('@alice'), 'legacy session (no accountIds) still lists its active account');
  html = await legacy.get('/api/v1/oauth/authorize?client_id=' + clientId + '&response_type=code&redirect_uri=' + encodeURIComponent('https://multi.example/cb') + '&scope=read');
  ok(html.includes('Authorize') && !html.includes('Authorize as:'), 'legacy session consents without a picker');

  // ---- TEST 8: deleted accounts are cleaned out of other sessions ----
  console.log('\nTEST 8: deleted accounts are cleaned out of other sessions');
  const s4 = makeWebSession();
  await s4.login('alice', 'pw-alice');
  await s4.login('bob', 'pw-bob', { add: true });
  // alice's account is deleted from elsewhere (admin / another device).
  db.deleteUser(aliceId);
  html = await s4.get('/account/switch');
  ok(!html.includes('@alice') && html.includes('@bob'), 'deleted account dropped from the device list');
  const activeAfterDelete = activeRowOf(html);
  ok(activeAfterDelete && activeAfterDelete.includes('@bob'), 'device falls back to bob as the active account');
  ok(listAccountSessions(s4.sid()).length === 1 && listAccountSessions(s4.sid())[0].user_id === bobId,
    'account_sessions no longer holds the deleted account');

  // ---- TEST 9: self-deletion removes only the deleted account ----
  console.log('\nTEST 9: deleting your account keeps other device accounts signed in');
  const daveId = db.createUser({ username: 'dave', passwordHash: bcrypt.hashSync('pw-dave', 10), displayName: 'Dave' });
  const eveId = db.createUser({ username: 'eve', passwordHash: bcrypt.hashSync('pw-eve', 10), displayName: 'Eve' });
  const s5 = makeWebSession();
  await s5.login('dave', 'pw-dave');
  await s5.login('eve', 'pw-eve', { add: true }); // active = eve
  html = await s5.get('/settings/delete');
  const delCsrf = s5.csrfFrom(html);
  r = await s5.withCookie('/settings/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `_csrf=${encodeURIComponent(delCsrf)}`,
  });
  ok(r.status === 302, 'account deletion redirects');
  html = await s5.get('/account/switch');
  ok(!html.includes('@eve') && html.includes('@dave'), 'deleted account removed, dave still signed in');
  const activeDave = activeRowOf(html);
  ok(activeDave && activeDave.includes('@dave'), 'dave is now the active account');
  ok(listAccountSessions(s5.sid()).length === 1, 'only dave remains in account_sessions');

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL MULTI-ACCOUNT TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
