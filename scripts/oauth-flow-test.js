'use strict';
// OAuth 2.0 / OIDC flow regression test.
// Exercises the full authorize -> token -> refresh -> revoke flow plus the
// security properties: CSRF on consent, redirect_uri re-validation on POST,
// PKCE-or-secret required to redeem codes, S256-only, refresh tokens bound to
// their client, atomic code single-use, scope capping, and the stored-XSS-safe
// consent page. Run: npm run test:oauth
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-oauth-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'oauth-test-secret';
process.env.SECRET = 'oauth-test-secret';
process.env.PORT = String(35000 + Math.floor(Math.random() * 1000));

const app = require('../src/server');
const db = require('../src/db');

let failures = 0;
function ok(cond, msg) { console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg); if (!cond) failures++; }

async function main() {
  const base = 'http://localhost:' + process.env.PORT;

  const aliceId = db.createUser({ username: 'alice', passwordHash: bcrypt.hashSync('pw1', 10), displayName: 'Alice' });
  db.promoteUser(aliceId);

  async function makeWebSession(username, password) {
    const jar = {};
    async function withCookie(url, opts = {}) {
      const headers = { ...(opts.headers || {}) };
      if (jar.cookie) headers['Cookie'] = jar.cookie;
      const r = await fetch(base + url, { ...opts, headers, redirect: 'manual' });
      const sc = r.headers.get('set-cookie');
      if (sc) jar.cookie = sc.split(';')[0];
      return r;
    }
    const page = await withCookie('/login');
    const csrf = ((await page.text()).match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
    await withCookie('/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `username=${username}&password=${password}&_csrf=${encodeURIComponent(csrf)}` });
    const after = await withCookie('/chats');
    const fresh = ((await after.text()).match(/name="csrf-token" content="([^"]+)"/) || [])[1] || csrf;
    return {
      csrf: fresh,
      cookie: jar.cookie,
      req: withCookie,
      get: (url) => withCookie(url).then(r => r.text()),
    };
  }
  const alice = await makeWebSession('alice', 'pw1');

  async function registerApp(body) {
    return alice.req('/api/v1/oauth/apps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(async r => ({ status: r.status, data: await r.json() }));
  }

  console.log('\nTEST 1: registration validates redirect_uris / website (http(s) only)');
  let r = await registerApp({ name: 'Bad app', redirect_uris: 'javascript:alert(1)' });
  ok(r.status === 400, 'javascript: redirect_uri rejected');
  r = await registerApp({ name: 'Bad app', redirect_uris: 'data:text/html,<script>alert(1)</script>' });
  ok(r.status === 400, 'data: redirect_uri rejected');
  r = await registerApp({ name: 'Bad app', redirect_uris: 'https://ok.example/cb', website: 'javascript:alert(1)' });
  ok(r.status === 400, 'javascript: website rejected');
  r = await registerApp({ name: 'Bad app', redirect_uris: 'https://user:pass@ok.example/cb' });
  ok(r.status === 400, 'redirect_uri with embedded credentials rejected');
  r = await registerApp({ name: 'Good app', redirect_uris: 'https://good.example/cb', scopes: 'read' });
  ok(r.status === 201 && r.data.data.client_id, 'valid app registered');
  const confClientId = r.data.data.client_id;
  const confSecret = r.data.data.client_secret;

  console.log('\nTEST 1b: fresh login -> consent page directly (Introvert mobile flow) works');
  // Regression: a fresh browser login that lands STRAIGHT on the /api/ consent
  // page (the login POST\'s `next` target, exactly what the Introvert mobile
  // client does — it never visits a non-API page in between) must render a real
  // CSRF token and approve. Previously the /api/* CSRF-generation skip meant
  // the consent page rendered an empty _csrf after the session regeneration on
  // login, and the consent POST 403'd with 'CSRF token missing or invalid.
  // Re-open the authorization request.'
  {
    const jar = {};
    async function wc(url, opts = {}) {
      const headers = { ...(opts.headers || {}) };
      if (jar.cookie) headers['Cookie'] = jar.cookie;
      const r = await fetch(base + url, { ...opts, headers, redirect: 'manual' });
      const sc = r.headers.get('set-cookie');
      if (sc) jar.cookie = sc.split(';')[0];
      return r;
    }
    const authorizePath = '/api/v1/oauth/authorize?client_id=' + confClientId + '&response_type=code&redirect_uri=' + encodeURIComponent('https://good.example/cb') + '&scope=read&state=regress';
    // Canonical login URL: /login?next=… 302s to bare /login (next lives in the
    // session), so follow the redirect before scraping the form's CSRF token.
    const loginPage = await wc('/login?next=' + encodeURIComponent(authorizePath));
    const loginForm = await wc(loginPage.headers.get('location') || '/login');
    const loginCsrf = ((await loginForm.text()).match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
    ok(loginCsrf.length > 0, 'login page renders a CSRF token');
    const loginRes = await wc('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'alice', password: 'pw1', _csrf: loginCsrf, next: authorizePath }),
    });
    ok(loginRes.status === 302, 'login redirects (session regenerated)');
    // Follow the login redirect STRAIGHT to the consent page (no non-API visit).
    const consentHtml = await (await wc(authorizePath)).text();
    const consentCsrf = (consentHtml.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
    ok(consentCsrf.length > 0, 'consent page renders a real CSRF token after fresh login (no empty _csrf)');
    const consentRes = await wc(authorizePath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ _csrf: consentCsrf, client_id: confClientId, redirect_uri: 'https://good.example/cb', scope: 'read', state: 'regress', approve: 'yes' }),
    });
    ok(consentRes.status === 302 && consentRes.headers.get('location').includes('code='), 'consent POST approves after fresh login (no CSRF 403)');
  }

  console.log('\nTEST 2: authorize GET validates redirect_uri + caps scopes');
  let html = await alice.get(`/api/v1/oauth/authorize?client_id=${confClientId}&response_type=code&redirect_uri=${encodeURIComponent('https://evil.example/steal')}`);
  ok(!html.includes('evil.example'), 'GET rejects unregistered redirect_uri');
  html = await alice.get(`/api/v1/oauth/authorize?client_id=${confClientId}&response_type=code&redirect_uri=${encodeURIComponent('https://good.example/cb')}&scope=read%20write&state=xyz`);
  ok(html.includes('Authorize') && html.includes('good.example'), 'GET renders consent for registered redirect_uri');

  console.log('\nTEST 3: consent POST enforces CSRF + re-validates redirect_uri');
  const csrfFromPage = ((await alice.get('/api/v1/oauth/authorize?client_id=' + confClientId + '&response_type=code&redirect_uri=' + encodeURIComponent('https://good.example/cb'))).match(/name="_csrf" value="([^"]+)"/) || [])[1] || alice.csrf;
  let post = await alice.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: 'WRONG', client_id: confClientId, redirect_uri: 'https://good.example/cb', scope: 'read', approve: 'yes' }),
  });
  ok(post.status === 403, 'consent POST without valid CSRF rejected');
  post = await alice.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: csrfFromPage, client_id: confClientId, redirect_uri: 'https://evil.example/steal', scope: 'read', approve: 'yes' }),
  });
  ok(post.status === 400, 'consent POST with tampered redirect_uri rejected');

  console.log('\nTEST 3b: loopback redirect_uri renders a copy-paste code page (mobile native apps)');
  // Native apps use http://localhost:PORT/callback. Mobile browsers refuse to
  // navigate there, so the approve response for loopback URIs must be a
  // same-origin page showing the code (with a meta-refresh auto-redirect for
  // browsers that DO allow it) instead of a bare 302 that silently dies.
  let nativeApp = await alice.req('/api/v1/oauth/apps', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'Native app', redirect_uris: 'http://localhost:1420/oauth/callback', scopes: 'read' }),
  }).then(async r => ({ status: r.status, data: await r.json() }));
  ok(nativeApp.status === 201, 'native loopback app registered');
  const nativeClientId = nativeApp.data.data.client_id;
  const nativeAuthzPath = '/api/v1/oauth/authorize?client_id=' + nativeClientId + '&response_type=code&redirect_uri=' + encodeURIComponent('http://localhost:1420/oauth/callback') + '&scope=read&state=n1';
  const nativeCsrf = ((await alice.get(nativeAuthzPath)).match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  ok(nativeCsrf.length > 0, 'native consent page renders a CSRF token');
  post = await alice.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: nativeCsrf, client_id: nativeClientId, redirect_uri: 'http://localhost:1420/oauth/callback', scope: 'read', state: 'n1', approve: 'yes' }),
  });
  const nativeBody = await post.text();
  ok(post.status === 200 && nativeBody.includes('http-equiv="refresh"'), 'loopback approve renders a code page with auto-redirect');
  ok(/code=[a-f0-9]{64}/.test(nativeBody), 'code page exposes the authorization code');
  ok(nativeBody.includes('localhost:1420/oauth/callback'), 'code page points back at the app callback');
  // And the same page must be re-usable through the normal exchange path.
  const nativeCode = (nativeBody.match(/code=[a-f0-9]{64}/) || [''])[0].replace('code=', '');
  const nativeTok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: nativeClientId, client_secret: nativeApp.data.data.client_secret, code: nativeCode, redirect_uri: 'http://localhost:1420/oauth/callback' }),
  });
  ok(nativeTok.status === 200, 'code shown on the page redeems normally (single-use intact)');

  console.log('\nTEST 4: full code flow — PKCE (S256) public-style client');
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  post = await alice.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: csrfFromPage, client_id: confClientId, redirect_uri: 'https://good.example/cb', scope: 'read', state: 's1', code_challenge: challenge, code_challenge_method: 'S256', approve: 'yes' }),
  });
  ok(post.status === 302, 'consent approved -> redirect');
  const loc = post.headers.get('location') || '';
  ok(loc.startsWith('https://good.example/cb') && /code=/.test(loc) && /state=s1/.test(loc), 'redirect carries code + state');
  const code = new URL(loc).searchParams.get('code');

  // Public-style: no secret, PKCE verifier.
  let tok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: confClientId, code, redirect_uri: 'https://good.example/cb', code_verifier: verifier }),
  });
  let tokJson = await tok.json();
  ok(tok.status === 200 && tokJson.access_token && tokJson.refresh_token, 'code redeemed with PKCE (no secret)');
  ok(tokJson.token_type === 'Bearer' && tokJson.expires_in === 86400, 'token response shape correct');

  // Code reuse is blocked (atomic single-use).
  tok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: confClientId, code, redirect_uri: 'https://good.example/cb', code_verifier: verifier }),
  });
  ok(tok.status === 400, 'reused authorization code rejected');

  console.log('\nTEST 5: code without secret AND without PKCE is rejected');
  post = await alice.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: csrfFromPage, client_id: confClientId, redirect_uri: 'https://good.example/cb', scope: 'read', approve: 'yes' }),
  });
  const code2 = new URL(post.headers.get('location')).searchParams.get('code');
  tok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: confClientId, code: code2, redirect_uri: 'https://good.example/cb' }),
  });
  ok(tok.status === 400, 'secret-less + PKCE-less code exchange rejected');

  console.log('\nTEST 6: confidential client can redeem with secret (no PKCE)');
  post = await alice.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: csrfFromPage, client_id: confClientId, redirect_uri: 'https://good.example/cb', scope: 'read', approve: 'yes' }),
  });
  const code3 = new URL(post.headers.get('location')).searchParams.get('code');
  tok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: confClientId, client_secret: confSecret, code: code3, redirect_uri: 'https://good.example/cb' }),
  });
  ok(tok.status === 200 && (await tok.json()).access_token, 'confidential client redeems with secret');

  console.log('\nTEST 7: refresh tokens are bound to their client');
  const bobId = db.createUser({ username: 'bob', passwordHash: bcrypt.hashSync('pw', 10), displayName: 'Bob' });
  db.createOAuthApp({ name: 'bobapp', description: '', website: '', redirectUris: 'https://bob.example/cb', clientId: 'bob-client', clientSecret: 'bob-secret', scopes: 'read', ownerId: bobId });
  // Refresh token issued to alice's app must not be usable by bob's client.
  const victimRefresh = tokJson.refresh_token;
  const wrong = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'refresh_token', client_id: 'bob-client', client_secret: 'bob-secret', refresh_token: victimRefresh }),
  });
  ok(wrong.status === 400, "another client's refresh token rejected");
  // Own client refreshes fine (rotation invalidates the old token).
  const own = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'refresh_token', client_id: confClientId, client_secret: confSecret, refresh_token: victimRefresh }),
  });
  const ownJson = await own.json();
  ok(own.status === 200 && ownJson.access_token, 'own client refresh works');
  const replay = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'refresh_token', client_id: confClientId, client_secret: confSecret, refresh_token: victimRefresh }),
  });
  ok(replay.status === 401, 'rotated (reused) refresh token rejected as theft (401, tokens revoked)');

  console.log('\nTEST 8: scope capping (requested ⊆ registered)');
  const readOnlyApp = await registerApp({ name: 'Read only', redirect_uris: 'https://ro.example/cb', scopes: 'read' });
  const roClientId = readOnlyApp.data.data.client_id;
  const roSecret = readOnlyApp.data.data.client_secret;
  html = await alice.get(`/api/v1/oauth/authorize?client_id=${roClientId}&response_type=code&redirect_uri=${encodeURIComponent('https://ro.example/cb')}&scope=${encodeURIComponent('read write')}`);
  ok(!/write/.test(html.replace('read write', '')), 'consent page does not show unregistered scope');
  post = await alice.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: csrfFromPage, client_id: roClientId, redirect_uri: 'https://ro.example/cb', scope: 'read write', approve: 'yes' }),
  });
  const roCode = new URL(post.headers.get('location')).searchParams.get('code');
  tok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: roClientId, client_secret: roSecret, code: roCode, redirect_uri: 'https://ro.example/cb' }),
  });
  const roJson = await tok.json();
  ok(tok.status === 200 && roJson.scope === 'read', 'only registered scope granted (no escalation)');

  console.log('\nTEST 9: OIDC — id_token + userinfo + email scope');
  db.setUserEmailVerified(aliceId, 'alice@example.org', Date.now());
  const oidcApp = await registerApp({ name: 'OIDC app', redirect_uris: 'https://oidc.example/cb', scopes: 'read openid profile email' });
  const oidcClient = oidcApp.data.data.client_id;
  const oidcSecret = oidcApp.data.data.client_secret;
  const oVerifier = crypto.randomBytes(32).toString('base64url');
  const oChallenge = crypto.createHash('sha256').update(oVerifier).digest('base64url');
  post = await alice.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: csrfFromPage, client_id: oidcClient, redirect_uri: 'https://oidc.example/cb', scope: 'openid profile email read', nonce: 'n-123', code_challenge: oChallenge, code_challenge_method: 'S256', approve: 'yes' }),
  });
  const oidcCode = new URL(post.headers.get('location')).searchParams.get('code');
  tok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: oidcClient, code: oidcCode, redirect_uri: 'https://oidc.example/cb', code_verifier: oVerifier }),
  });
  const oidcJson = await tok.json();
  ok(tok.status === 200 && !!oidcJson.id_token, 'id_token issued when openid scope requested');
  const [, payloadB64] = oidcJson.id_token.split('.');
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
  ok(payload.iss && payload.sub && payload.aud === oidcClient && payload.nonce === 'n-123', 'id_token has iss/sub/aud/nonce');
  ok(payload.exp - payload.iat === 3600, 'id_token lifetime 1h');
  ok(payload.email === 'alice@example.org' && payload.email_verified === true, 'id_token has email + email_verified claims (email scope)');
  const ui = await fetch(base + '/api/v1/oauth/userinfo', { headers: { Authorization: 'Bearer ' + oidcJson.access_token } }).then(r => r.json());
  ok(ui.sub === String(aliceId) && ui.name === 'Alice' && ui.preferred_username === 'alice', 'userinfo returns sub + profile claims');
  ok(ui.email === 'alice@example.org' && ui.email_verified === true, 'userinfo has email + email_verified claims (email scope)');

  // email scope omitted -> no email claims, even though the user has one.
  const eVerifier = crypto.randomBytes(32).toString('base64url');
  const eChallenge = crypto.createHash('sha256').update(eVerifier).digest('base64url');
  post = await alice.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: csrfFromPage, client_id: oidcClient, redirect_uri: 'https://oidc.example/cb', scope: 'openid read', nonce: 'n-2', code_challenge: eChallenge, code_challenge_method: 'S256', approve: 'yes' }),
  });
  const eCode = new URL(post.headers.get('location')).searchParams.get('code');
  const eTok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: oidcClient, code: eCode, redirect_uri: 'https://oidc.example/cb', code_verifier: eVerifier }),
  });
  const eJson = await eTok.json();
  const ePayload = JSON.parse(Buffer.from(eJson.id_token.split('.')[1], 'base64url').toString());
  ok(!('email' in ePayload), 'id_token omits email claim without email scope');
  const eUi = await fetch(base + '/api/v1/oauth/userinfo', { headers: { Authorization: 'Bearer ' + eJson.access_token } }).then(r => r.json());
  ok(!('email' in eUi), 'userinfo omits email claim without email scope');

  // User without any email + email scope -> claims omitted entirely.
  const carolId = db.createUser({ username: 'carol', passwordHash: bcrypt.hashSync('pw', 10), displayName: 'Carol' });
  const carol = await makeWebSession('carol', 'pw');
  const carolPage = await carol.get(`/api/v1/oauth/authorize?client_id=${oidcClient}&response_type=code&redirect_uri=${encodeURIComponent('https://oidc.example/cb')}&scope=${encodeURIComponent('openid email')}&nonce=n-3&code_challenge=${encodeURIComponent(eChallenge)}&code_challenge_method=S256`);
  const carolCsrf = (carolPage.match(/name="_csrf" value="([^"]+)"/) || [])[1] || carol.csrf;
  post = await carol.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: carolCsrf, client_id: oidcClient, redirect_uri: 'https://oidc.example/cb', scope: 'openid email', nonce: 'n-3', code_challenge: eChallenge, code_challenge_method: 'S256', approve: 'yes' }),
  });
  const cCode = new URL(post.headers.get('location')).searchParams.get('code');
  const cTok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: oidcClient, code: cCode, redirect_uri: 'https://oidc.example/cb', code_verifier: eVerifier }),
  });
  const cJson = await cTok.json();
  const cPayload = JSON.parse(Buffer.from(cJson.id_token.split('.')[1], 'base64url').toString());
  ok(!('email' in cPayload) && cPayload.email_verified === false, 'no-email account: id_token omits email but email_verified is a boolean false');
  const cUi = await fetch(base + '/api/v1/oauth/userinfo', { headers: { Authorization: 'Bearer ' + cJson.access_token } }).then(r => r.json());
  ok(!('email' in cUi) && cUi.email_verified === false, 'no-email account: userinfo omits email but email_verified is a boolean false');

  // Unverified email + email scope -> email present, email_verified boolean false.
  const daveId = db.createUser({ username: 'dave', passwordHash: bcrypt.hashSync('pw', 10), displayName: 'Dave' });
  db.setUserEmail(daveId, 'dave@example.org');
  const dave = await makeWebSession('dave', 'pw');
  const davePage = await dave.get(`/api/v1/oauth/authorize?client_id=${oidcClient}&response_type=code&redirect_uri=${encodeURIComponent('https://oidc.example/cb')}&scope=${encodeURIComponent('openid email')}&nonce=n-4&code_challenge=${encodeURIComponent(eChallenge)}&code_challenge_method=S256`);
  const daveCsrf = (davePage.match(/name="_csrf" value="([^"]+)"/) || [])[1] || dave.csrf;
  post = await dave.req('/api/v1/oauth/authorize', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: daveCsrf, client_id: oidcClient, redirect_uri: 'https://oidc.example/cb', scope: 'openid email', nonce: 'n-4', code_challenge: eChallenge, code_challenge_method: 'S256', approve: 'yes' }),
  });
  const dCode = new URL(post.headers.get('location')).searchParams.get('code');
  const dTok = await fetch(base + '/api/v1/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: oidcClient, code: dCode, redirect_uri: 'https://oidc.example/cb', code_verifier: eVerifier }),
  });
  const dJson = await dTok.json();
  const dPayload = JSON.parse(Buffer.from(dJson.id_token.split('.')[1], 'base64url').toString());
  ok(dPayload.email === 'dave@example.org' && dPayload.email_verified === false, 'unverified email: id_token has email + email_verified boolean false');
  const dUi = await fetch(base + '/api/v1/oauth/userinfo', { headers: { Authorization: 'Bearer ' + dJson.access_token } }).then(r => r.json());
  ok(dUi.email === 'dave@example.org' && dUi.email_verified === false, 'unverified email: userinfo has email + email_verified boolean false');

  console.log('\nTEST 10: token revocation');
  const rev = await fetch(base + '/api/v1/oauth/revoke', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: oidcJson.access_token }),
  });
  ok(rev.status === 200, 'revoke returns 200');
  const afterRevoke = await fetch(base + '/api/v1/oauth/userinfo', { headers: { Authorization: 'Bearer ' + oidcJson.access_token } });
  ok(afterRevoke.status === 401, 'revoked token no longer works');

  console.log('\nTEST 11: consent page escapes app names (no stored XSS)');
  const evil = await registerApp({ name: '<img src=x onerror=alert(1)>', redirect_uris: 'https://evil2.example/cb' });
  const evilClient = evil.data.data.client_id;
  html = await alice.get(`/api/v1/oauth/authorize?client_id=${evilClient}&response_type=code&redirect_uri=${encodeURIComponent('https://evil2.example/cb')}`);
  ok(html.includes('&lt;img') && !html.includes('<img src=x onerror'), 'consent page escapes app name');

  console.log('\nTEST 12: cold login -> direct OAuth authorize redirect -> consent POST with CSRF');
  const mobileUserId = db.createUser({ username: 'mobileuser', passwordHash: bcrypt.hashSync('pw2', 10), displayName: 'Mobile User' });
  const mobileJar = {};
  async function mobileReq(url, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (mobileJar.cookie) headers['Cookie'] = mobileJar.cookie;
    const res = await fetch(base + url, { ...opts, headers, redirect: 'manual' });
    const sc = res.headers.get('set-cookie');
    if (sc) mobileJar.cookie = sc.split(';')[0];
    return res;
  }
  const oauthTarget = `/api/v1/oauth/authorize?client_id=${confClientId}&response_type=code&redirect_uri=${encodeURIComponent('https://good.example/cb')}&scope=read`;
  const initGet = await mobileReq(oauthTarget);
  ok(initGet.status === 302, 'unauthenticated OAuth authorize redirects to login');
  const loginUrl = initGet.headers.get('location');
  // Canonical login URL: /login?next=… 302s to bare /login (next lives in the
  // session), so follow the redirect before scraping the form's CSRF token.
  const loginPage = await mobileReq(loginUrl);
  const loginForm = await mobileReq(loginPage.headers.get('location') || '/login');
  const loginCsrf = ((await loginForm.text()).match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  const loginPost = await mobileReq('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=mobileuser&password=pw2&_csrf=${encodeURIComponent(loginCsrf)}&next=${encodeURIComponent(oauthTarget)}`,
  });
  ok(loginPost.status === 302 && loginPost.headers.get('location') === oauthTarget, 'login redirects back to OAuth authorize');
  const consentPage = await mobileReq(loginPost.headers.get('location'));
  const consentHtml = await consentPage.text();
  const consentCsrf = (consentHtml.match(/name="_csrf" value="([^"]+)"/) || [])[1];
  ok(!!consentCsrf && consentCsrf.length === 64, 'consent page contains a valid non-empty CSRF token');
  const consentPost = await mobileReq('/api/v1/oauth/authorize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: consentCsrf, client_id: confClientId, redirect_uri: 'https://good.example/cb', scope: 'read', approve: 'yes' }),
  });
  ok(consentPost.status === 302, 'consent POST succeeds and redirects to redirect_uri');
  const finalCode = new URL(consentPost.headers.get('location')).searchParams.get('code');
  ok(!!finalCode, 'consent redirect contains authorization code');

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch(err => { console.error(err); process.exit(1); });
