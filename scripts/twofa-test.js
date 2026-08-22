'use strict';
// F2 two-factor authentication integration test (planned.md).
// Exercises the full 2FA surface:
//   - plain login unchanged for non-enrolled accounts (regression guard)
//   - enrollment (setup → confirm → recovery codes shown once)
//   - password login lands on the challenge WITHOUT a session
//   - wrong codes burn attempts; 5 failures reset to /login (generic errors)
//   - correct TOTP completes login; sid rotates
//   - recovery code works exactly once
//   - trusted-device cookie skips the challenge
//   - disable demands a valid code and clears state
//   - OAuth consent is gated behind the second factor (F2.5), full round trip,
//     with a per-session pass so repeat authorizations don't re-prompt
//   - deleteUser cascade leaves no orphan rows
// Run: npm run test:twofa

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-twofa-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'twofa-test-secret';
process.env.PORT = String(35400 + Math.floor(Math.random() * 1000));
process.env.TOTP_ENCRYPTION_KEY = 'twofa-test-encryption-key';
// Generous limiter budgets so the suite's many verification POSTs don't 429.
process.env.EXTV_SECOND_FACTOR_RATE_LIMIT = '1000';
process.env.EXTV_OAUTH_FACTOR_RATE_LIMIT = '1000';
process.env.EXTV_AUTH_RATE_LIMIT = '10000';

const app = require('../src/server');
const db = require('../src/db');
const twofa = require('../src/twofa');
const SessionStore = require('../src/session-store');
const { destroySessionsForUser } = SessionStore;

let failures = 0;
function ok(cond, msg) { console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg); if (!cond) failures++; }

// Minimal cookie-jar web session (mirrors multi-account-test.js), extended to
// track every Set-Cookie so the trusted-device cookie survives.
function makeWebSession() {
  const jar = {};
  function sid() {
    const v = decodeURIComponent(jar.cookie.split('=')[1]);
    return v.replace(/^s:/, '').split('.')[0];
  }
  async function withCookie(url, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    // Merge all known cookies (connect.sid + extv_td) into one Cookie header.
    const parts = [];
    if (jar.cookie) parts.push(jar.cookie);
    if (jar.td && !parts.some((p) => p.startsWith('extv_td='))) parts.push(jar.td);
    if (parts.length) headers['Cookie'] = parts.join('; ');
    const r = await fetch('http://localhost:' + process.env.PORT + url, { ...opts, headers, redirect: 'manual' });
    for (const c of (r.headers.getSetCookie ? r.headers.getSetCookie() : [])) {
      if (c.startsWith('connect.sid=')) jar.cookie = c.split(';')[0];
      if (c.startsWith('extv_td=')) jar.td = jar.td && jar.td !== 'cleared' ? jar.td : c.split(';')[0];
      if (c.startsWith('extv_td=;')) jar.td = 'cleared'; // explicit clear
    }
    return r;
  }
  async function post(url, bodyObj) {
    return withCookie(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(bodyObj).toString(),
    });
  }
  async function getCsrf(pathname) {
    const html = await withCookie(pathname).then((r) => r.text());
    return (html.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  }
  return { jar, sid, withCookie, post, getCsrf };
}

// The setup/confirm pages render the manual secret in a monospace paragraph.
function secretFromSetup(html) {
  return (html.match(/font-family:monospace[^>]*>([A-Z2-7]+)</) || [])[1];
}

async function main() {
  const aliceId = db.createUser({ username: 'alice', passwordHash: bcrypt.hashSync('pw-alice', 10), displayName: 'Alice' });

  // ---- TEST 1: no-2FA account logs in exactly as before (regression guard) ----
  console.log('\nTEST 1: plain login unchanged for non-enrolled account');
  let s = makeWebSession();
  let r = await s.post('/login', { username: 'alice', password: 'pw-alice', _csrf: await s.getCsrf('/login') });
  ok(r.status === 302 && !(r.headers.get('location') || '').includes('/login/totp'), 'plain login redirects to feed (no challenge)');
  ok(!!s.jar.cookie, 'session cookie set after plain login');

  // ---- TEST 2: enrollment — setup renders QR + manual secret ----
  console.log('\nTEST 2: TOTP enrollment');
  const setupCsrf = await s.getCsrf('/settings/security');
  r = await s.post('/settings/security/totp/setup', { _csrf: setupCsrf });
  const setupHtml = await r.text();
  ok(r.status === 200, 'setup POST renders setup page');
  ok(setupHtml.includes('data:image/png;base64,'), 'QR code data URL present');
  const manualSecret = secretFromSetup(setupHtml);
  ok(/^[A-Z2-7]{32}$/.test(manualSecret || ''), 'manual base32 secret shown (32 chars)');
  ok((db.getUserById(aliceId).totp_secret || '').startsWith('v1.'), 'secret stored encrypted (v1. prefix)');
  ok(!db.getUserById(aliceId).totp_enabled, 'not enabled until confirm');

  // ---- TEST 3: wrong confirm code rejected; right one enables + shows codes ----
  console.log('\nTEST 3: confirm flow');
  r = await s.post('/settings/security/totp/confirm', { _csrf: setupCsrf, code: '000000' });
  ok(r.status === 200 && /didn.{0,8}t match/.test(await r.text()), 'wrong confirm code rejected');
  // Restart setup (the rejection told us to) and confirm with a live code.
  const setupHtml2 = await s.post('/settings/security/totp/setup', { _csrf: setupCsrf }).then((x) => x.text());
  const secret2 = twofa.base32Decode(secretFromSetup(setupHtml2));
  ok(!!secret2, 're-setup produced a fresh secret');
  const goodCode = twofa.hotp(secret2, twofa.currentCounter());
  r = await s.post('/settings/security/totp/confirm', { _csrf: setupCsrf, code: goodCode });
  const recHtml = await r.text();
  ok(recHtml.includes('recovery codes'), 'confirm succeeded — recovery codes page rendered');
  const codes = [...recHtml.matchAll(/<code style="font-size:0\.95rem;text-align:center">([a-f0-9]{10})<\/code>/g)].map((m) => m[1]);
  ok(codes.length === 10, '10 recovery codes displayed');
  ok(db.getUserById(aliceId).totp_enabled === 1, 'totp_enabled flag set in DB');
  // The live secret from here on is whatever the last setup stored.
  const liveSecret = twofa.decryptSecret(db.getUserById(aliceId).totp_secret);

  // ---- TEST 4: session purge helper (F2.7 machinery) ----
  console.log('\nTEST 4: destroySessionsForUser purges sibling sessions');
  const s3 = makeWebSession();
  await s3.post('/login', { username: 'alice', password: 'pw-alice', _csrf: await s3.getCsrf('/login') });
  const chS3 = await s3.withCookie('/login/totp').then((x) => x.text());
  const csrfS3 = (chS3.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  await s3.post('/login/totp', { _csrf: csrfS3, code: twofa.hotp(liveSecret, twofa.currentCounter()) });
  const destroyed = destroySessionsForUser(aliceId, null);
  ok(destroyed >= 2, `destroySessionsForUser wiped ${destroyed} sessions (>=2: confirm-regen + s3)`);
  ok(await s3.withCookie('/').then((x) => x.status === 302 && (x.headers.get('location') || '').startsWith('/login')), 'purged session is really signed out');

  // ---- TEST 5: password login lands on challenge without a session ----
  console.log('\nTEST 5: login challenge flow');
  const s4 = makeWebSession();
  r = await s4.post('/login', { username: 'alice', password: 'pw-alice', _csrf: await s4.getCsrf('/login') });
  ok(r.status === 302 && (r.headers.get('location') || '').includes('/login/totp'), 'password OK → redirected to challenge');
  const chHtml = await s4.withCookie('/login/totp').then((x) => x.text());
  ok(chHtml.includes('Two-factor authentication'), 'challenge page renders');
  ok(await s4.withCookie('/').then((x) => x.status === 302 && (x.headers.get('location') || '').startsWith('/login')), 'feed still protected while challenge pending');
  // Wrong codes burn attempts; the 5th resets to /login with a generic error.
  const csrfCh = (chHtml.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  let lastResp;
  for (let i = 0; i < 5; i++) lastResp = await s4.post('/login/totp', { _csrf: csrfCh, code: '000000' });
  ok((await lastResp.text()).includes('Too many invalid codes'), '5 wrong codes reset to login with generic error');
  ok(await s4.withCookie('/login/totp').then((x) => x.status === 302), 'challenge cleared after lockout');

  // ---- TEST 6: correct TOTP completes login, sid rotates ----
  console.log('\nTEST 6: successful TOTP login');
  const s5 = makeWebSession();
  await s5.post('/login', { username: 'alice', password: 'pw-alice', _csrf: await s5.getCsrf('/login') });
  const beforeSid = s5.sid();
  const ch2 = await s5.withCookie('/login/totp').then((x) => x.text());
  const csrf5 = (ch2.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  const codeNow = twofa.hotp(liveSecret, twofa.currentCounter());
  r = await s5.post('/login/totp', { _csrf: csrf5, code: codeNow });
  ok(r.status === 302 && !(r.headers.get('location') || '').includes('login'), 'valid TOTP completes login');
  ok(s5.sid() !== beforeSid, 'session id rotated on completion');
  ok(await s5.withCookie('/settings/security').then((x) => x.status === 200), 'signed in after TOTP login');

  // ---- TEST 7: recovery code works exactly once ----
  console.log('\nTEST 7: recovery code single-use');
  const recCodes = twofa.generateRecoveryCodes(2);
  db.replaceRecoveryCodes(aliceId, recCodes.map(twofa.hashRecoveryCode));
  const s6 = makeWebSession();
  await s6.post('/login', { username: 'alice', password: 'pw-alice', _csrf: await s6.getCsrf('/login') });
  const ch3 = await s6.withCookie('/login/totp').then((x) => x.text());
  const csrf6 = (ch3.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  r = await s6.post('/login/totp', { _csrf: csrf6, code: recCodes[0] });
  ok(r.status === 302 && !(r.headers.get('location') || '').includes('login'), 'recovery code completes login');
  const usedRow = db.listRecoveryCodes(aliceId).find((c) => c.code_hash === twofa.hashRecoveryCode(recCodes[0]));
  ok(usedRow && usedRow.used_at > 0, 'code marked used');
  const s7 = makeWebSession();
  await s7.post('/login', { username: 'alice', password: 'pw-alice', _csrf: await s7.getCsrf('/login') });
  const ch4 = await s7.withCookie('/login/totp').then((x) => x.text());
  const csrf7 = (ch4.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  r = await s7.post('/login/totp', { _csrf: csrf7, code: recCodes[0] });
  ok(r.status === 200 && (await r.text()).includes('Invalid code.'), 'same recovery code rejected second time');

  // ---- TEST 8: trusted-device cookie skips the challenge ----
  console.log('\nTEST 8: trusted device');
  const s8 = makeWebSession();
  await s8.post('/login', { username: 'alice', password: 'pw-alice', _csrf: await s8.getCsrf('/login') });
  const ch5 = await s8.withCookie('/login/totp').then((x) => x.text());
  const csrf8 = (ch5.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  r = await s8.post('/login/totp', { _csrf: csrf8, code: recCodes[1], remember: '1' });
  ok((r.headers.getSetCookie ? r.headers.getSetCookie() : []).some((c) => c.startsWith('extv_td=')), 'extv_td cookie issued when remember checked');
  const s9 = makeWebSession();
  s9.jar.td = s8.jar.td; // fresh browser session carrying only the td cookie
  r = await s9.post('/login', { username: 'alice', password: 'pw-alice', _csrf: await s9.getCsrf('/login') });
  ok(r.status === 302 && !(r.headers.get('location') || '').includes('login/totp'), 'trusted device skips challenge entirely');
  // Recovery codes are spent now — restore a fresh set for the OAuth test.
  db.replaceRecoveryCodes(aliceId, [twofa.hashRecoveryCode('deadbeef01'), twofa.hashRecoveryCode('deadbeef02')]);

  // ---- TEST 9: disable requires a valid code ----
  console.log('\nTEST 9: disable flow');
  const secCsrf = await s8.getCsrf('/settings/security');
  r = await s8.post('/settings/security/totp/disable', { _csrf: secCsrf, code: '999999' });
  ok((await r.text()).includes('Enter a valid authentication code or recovery code to disable'), 'disable with wrong code rejected');
  const disCode = twofa.hotp(liveSecret, twofa.currentCounter());
  r = await s8.post('/settings/security/totp/disable', { _csrf: secCsrf, code: disCode });
  ok((await r.text()).includes('Two-factor authentication is now off'), 'disable with valid code succeeds');
  ok(!db.getUserById(aliceId).totp_enabled && !db.getUserById(aliceId).totp_secret, 'DB flags cleared');
  ok(db.listTrustedDevices(aliceId).length === 0, 'trusted devices cleared on disable');
  const s10 = makeWebSession();
  r = await s10.post('/login', { username: 'alice', password: 'pw-alice', _csrf: await s10.getCsrf('/login') });
  ok(r.status === 302 && !(r.headers.get('location') || '').includes('login/totp'), 'after disable, plain login works again');

  // ---- TEST 10: OAuth consent gated behind the second factor (F2.5) ----
  console.log('\nTEST 10: OAuth second-factor gate');
  const secretX = twofa.generateTotpSecret();
  db.setTotpSecret(aliceId, twofa.encryptSecret(secretX));
  db.setTotpEnabled(aliceId, Date.now());
  db.replaceRecoveryCodes(aliceId, [twofa.hashRecoveryCode('deadbeef03')]);
  db.createOAuthApp({
    name: 'Test App', description: '', website: '',
    redirectUris: 'https://client.example/callback',
    clientId: 'cid-twofa-test', clientSecret: 'cs-twofa-test',
    scopes: 'read write', ownerId: aliceId,
  });
  const authUrl = '/api/v1/oauth/authorize?client_id=cid-twofa-test&response_type=code&redirect_uri=' +
    encodeURIComponent('https://client.example/callback') + '&scope=read&state=st123';

  const so = makeWebSession();
  await so.post('/login', { username: 'alice', password: 'pw-alice', _csrf: await so.getCsrf('/login') });
  const chO = await so.withCookie('/login/totp').then((x) => x.text());
  const csrfO = (chO.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  r = await so.post('/login/totp', { _csrf: csrfO, code: 'deadbeef03' });
  ok(r.status === 302, 'logged in via recovery code for the OAuth leg');
  // Authorize GET must show the INTERSTITIAL, not consent.
  r = await so.withCookie(authUrl);
  const intHtml = await r.text();
  ok(r.status === 200 && intHtml.includes('Two-factor verification'), 'authorize GET renders the interstitial');
  ok(intHtml.includes('cid-twofa-test'), 'authorization request relayed in hidden fields');
  const csrfInt = (intHtml.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  // Wrong code stays on the interstitial with a generic error.
  r = await so.post('/api/v1/oauth/authorize', {
    _csrf: csrfInt, client_id: 'cid-twofa-test', redirect_uri: 'https://client.example/callback',
    scope: 'read', state: 'st123', totp_code: '000000',
  });
  ok((await r.text()).includes('Invalid code.'), 'wrong code keeps interstitial with generic error');
  // Correct code bounces back to the GET → consent renders.
  const goodOtp = twofa.hotp(secretX, twofa.currentCounter());
  r = await so.post('/api/v1/oauth/authorize', {
    _csrf: csrfInt, client_id: 'cid-twofa-test', redirect_uri: 'https://client.example/callback',
    scope: 'read', state: 'st123', totp_code: goodOtp,
  });
  ok(r.status === 302 && (r.headers.get('location') || '').startsWith('/api/v1/oauth/authorize?'), 'valid code redirects back to authorize GET');
  r = await so.withCookie(r.headers.get('location'));
  const consHtml = await r.text();
  ok(consHtml.includes('Authorize') && !consHtml.includes('Two-factor verification'), 'consent page renders after factor pass');
  const csrfConsent = (consHtml.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  r = await so.post('/api/v1/oauth/authorize', {
    _csrf: csrfConsent, client_id: 'cid-twofa-test', redirect_uri: 'https://client.example/callback',
    scope: 'read', state: 'st123', approve: 'yes',
  });
  ok(r.status === 302 && (r.headers.get('location') || '').includes('code='), 'consent approval issues authorization code');
  // The factor pass is per-session: a repeat authorization must not re-prompt.
  r = await so.post('/api/v1/oauth/authorize', {
    _csrf: csrfConsent, client_id: 'cid-twofa-test', redirect_uri: 'https://client.example/callback',
    scope: 'read', state: 'st2', approve: 'yes',
  });
  ok(r.status === 302 && (r.headers.get('location') || '').includes('code='), 'repeat authorization does not re-prompt (per-session pass)');

  // ---- TEST 11: deleteUser cascade leaves no orphan rows ----
  console.log('\nTEST 11: deletion cascade');
  const bobId = db.createUser({ username: 'bob2', passwordHash: bcrypt.hashSync('pw-bob2', 10), displayName: 'Bob2' });
  db.setTotpSecret(bobId, twofa.encryptSecret(twofa.generateTotpSecret()));
  db.setTotpEnabled(bobId, Date.now());
  db.replaceRecoveryCodes(bobId, [twofa.hashRecoveryCode('aa11bb22cc')]);
  db.createPasskey({ userId: bobId, credentialId: 'test-cred-id', publicKey: 'pk', counter: 0, deviceName: 'test' });
  db.addTrustedDevice(bobId, twofa.hashTrustedDeviceToken('tok123'), Date.now() + 86400000);
  db.deleteUser(bobId);
  ok(db.listRecoveryCodes(bobId).length === 0, 'recovery codes deleted');
  ok(!db.getPasskeyByCredentialId('test-cred-id'), 'passkeys deleted');
  ok(db.listTrustedDevices(bobId).length === 0, 'trusted devices deleted');

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL TWOFA TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
