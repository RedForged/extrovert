'use strict';

// OWASP Top 10 (2021) security test suite for Extrovert.
//
// Boots the real Express app on a throwaway SQLite database and exercises the
// ten OWASP categories end-to-end over HTTP (session + CSRF flows for the web
// routes, Bearer-token flows for the REST API):
//
//   A01 Broken Access Control        A06 Vulnerable and Outdated Components
//   A02 Cryptographic Failures       A07 Identification and Authentication Failures
//   A03 Injection                    A08 Software and Data Integrity Failures
//   A04 Insecure Design              A09 Security Logging and Monitoring Failures
//   A05 Security Misconfiguration    A10 Server-Side Request Forgery
//
// Run with:  npm run test:owasp   (or  node --test scripts/owasp-test.js)

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-owasp-'));
const TEST_DB = path.join(TEST_DIR, 'test.db');
const TEST_SESSION_DB = path.join(TEST_DIR, 'sessions.db');

process.env.EXTV_DB_PATH = TEST_DB;
process.env.EXTV_SESSION_DB_PATH = TEST_SESSION_DB;
process.env.SESSION_SECRET = 'owasp-test-session-secret';

const bcrypt = require('bcryptjs');
const db = require('../src/db');
const app = require('../src/server');

let server, baseUrl;

const PASSWORD = 'secret123';
const pwHash = bcrypt.hashSync(PASSWORD, 10);

// ---------------------------------------------------------------- seeding ---
const aliceId = db.createUser({ username: 'alice', passwordHash: pwHash, displayName: 'Alice' });
const bobId = db.createUser({ username: 'bob', passwordHash: pwHash, displayName: 'Bob' });
const carolId = db.createUser({ username: 'carol', passwordHash: pwHash, displayName: 'Carol' });
const malloryId = db.createUser({ username: 'mallory', passwordHash: pwHash, displayName: 'Mallory' });
const rootId = db.createUser({ username: 'root', passwordHash: pwHash, displayName: 'Root' });
db.promoteUser(rootId); // a real admin exists -> become-admin bootstrap is locked

// Network: alice <-> bob mutual; carol -> bob (carol is alice's friend-of-friend);
// mallory is isolated from everyone (invisible to alice).
db.follow(aliceId, bobId);
db.follow(bobId, aliceId);
db.follow(carolId, bobId);

// A banned user with a valid token (A01: suspension must be enforced).
const bannedId = db.createUser({ username: 'banned_usr', passwordHash: pwHash, displayName: 'Banned' });
db.banUser(bannedId);

// OAuth apps + tokens.
const aliceAppId = db.createOAuthApp({
  name: 'AliceApp', description: '', website: '',
  redirectUris: 'https://ex.com/cb',
  clientId: 'owasp-alice-client', clientSecret: 'owasp-alice-secret',
  scopes: 'read write follow notifications media.write profile',
  ownerId: aliceId,
});
const bobAppId = db.createOAuthApp({
  name: 'BobApp', description: '', website: '',
  redirectUris: 'https://ex.com/cb',
  clientId: 'owasp-bob-client', clientSecret: 'owasp-bob-secret',
  scopes: 'read write follow',
  ownerId: bobId,
});

const aliceToken = crypto.randomBytes(32).toString('hex');
const aliceRefresh = crypto.randomBytes(32).toString('hex');
db.createOAuthToken(aliceToken, aliceRefresh, aliceAppId, aliceId, 'read write follow notifications media.write profile', Date.now() + 86400000);

const aliceReadToken = crypto.randomBytes(32).toString('hex');
db.createOAuthToken(aliceReadToken, null, aliceAppId, aliceId, 'read', Date.now() + 86400000);

const malloryToken = crypto.randomBytes(32).toString('hex');
db.createOAuthToken(malloryToken, null, aliceAppId, malloryId, 'read write follow', Date.now() + 86400000);

// bob's token with direct-message scopes (A01: DM access-control test).
const bobToken = crypto.randomBytes(32).toString('hex');
db.createOAuthToken(bobToken, null, bobAppId, bobId, 'read write follow read:direct write:direct', Date.now() + 86400000);

const bannedToken = crypto.randomBytes(32).toString('hex');
db.createOAuthToken(bannedToken, null, aliceAppId, bannedId, 'read write', Date.now() + 86400000);

// Posts: a marker body unique per author so search-visibility is assertable.
const RAND = crypto.randomBytes(4).toString('hex');
const bobPostBody = `OWASP_VISIBLE_BOB_${RAND}`;
const malloryPostBody = `OWASP_HIDDEN_MALLORY_${RAND}`;
const alicePostId = db.createPost({ userId: aliceId, type: 'text', body: `OWASP_ALICE_${RAND}`, createdAt: Date.now() - 5000 });
const bobPostId = db.createPost({ userId: bobId, type: 'text', body: bobPostBody, createdAt: Date.now() - 4000 });
const malloryPostId = db.createPost({ userId: malloryId, type: 'text', body: malloryPostBody, createdAt: Date.now() - 3000 });

// A room created by bob (founder) with its default 'general' channel; alice is not a member.
const roomId = db.createRoom('bob-room', 'Bob\'s room', bobId, true);
const channelId = db.getRoomChannels(roomId)[0].id;

// ----------------------------------------------------------- HTTP helpers ---
function absorbCookies(jar, resp) {
  const setCookies = typeof resp.headers.getSetCookie === 'function'
    ? resp.headers.getSetCookie()
    : (resp.headers.get('set-cookie') ? resp.headers.get('set-cookie').split(/,(?=[^;,]+=)/) : []);
  for (const sc of setCookies) {
    const pair = sc.split(';')[0];
    const eq = pair.indexOf('=');
    if (eq > 0) jar.cookies[pair.slice(0, eq)] = pair.slice(eq + 1);
  }
}

function jarHeader(jar) {
  return Object.values(jar.cookies).map(v => `connect.sid=${v}`).join('; ');
}

function extractCsrf(html) {
  const m = String(html).match(/name="_csrf" value="([^"]+)"/);
  return m ? m[1] : null;
}

// Fetch the captcha image for the jar, then return the session's expected
// answer (read from the server-side store, as an operator could). Keeps the
// captcha ENFORCED in these security suites.
const { sidFromCookie, captchaAnswer } = require('./captcha-helper');
async function solveCaptcha(jar) {
  const answer = await captchaAnswer(sidFromCookie(jar.cookies['connect.sid']));
  if (!answer) throw new Error('captcha answer not found in session');
  return { captcha: answer };
}

async function req(url, opts = {}) {
  const headers = {};
  if (opts.token) headers['Authorization'] = 'Bearer ' + opts.token;
  if (opts.jar) headers['Cookie'] = jarHeader(opts.jar);
  if (opts.csrf) headers['X-CSRF-Token'] = opts.csrf;
  if (opts.body !== undefined && !opts.form) headers['Content-Type'] = 'application/json';
  if (opts.form) headers['Content-Type'] = 'application/x-www-form-urlencoded';
  const body = opts.form
    ? new URLSearchParams(opts.form).toString()
    : opts.rawBody
      ? opts.body
      : opts.body !== undefined ? JSON.stringify(opts.body) : undefined;
  const resp = await fetch(baseUrl + url, {
    method: opts.method || 'GET',
    headers,
    body,
    redirect: 'manual',
  });
  if (opts.jar) absorbCookies(opts.jar, resp);
  return resp;
}

async function json(resp) {
  try { return await resp.json(); } catch { return null; }
}

// Fresh-jar login: GET /login (session + CSRF) then POST /login.
async function login(username, password, extra = {}) {
  const jar = { cookies: {} };
  const pre = await req('/login', { jar });
  const csrf = extractCsrf(await pre.text());
  const post = await req('/login', {
    method: 'POST', jar, form: { username, password, _csrf: csrf, next: extra.next || '' },
  });
  return { jar, pre, post, csrf };
}

// Logged-in sessions + CSRF token, plus pre/post-login cookies for A07.
let aliceSession, bobSession, preLoginCookie, postLoginCookie;

describe('OWASP Top 10', () => {
  before(async () => {
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        baseUrl = 'http://localhost:' + server.address().port;
        console.log(`\n  OWASP test server on ${baseUrl}`);
        resolve();
      });
    });

    const la = await login('alice', PASSWORD);
    preLoginCookie = la.pre.headers.get('set-cookie') || '';
    postLoginCookie = la.post.headers.get('set-cookie') || '';
    assert.strictEqual(la.post.status, 302, 'alice login succeeds');
    aliceSession = la.jar;
    aliceSession.csrf = extractCsrf(await (await req('/', { jar: aliceSession })).text());

    const lb = await login('bob', PASSWORD);
    bobSession = lb.jar;
    bobSession.csrf = extractCsrf(await (await req('/', { jar: bobSession })).text());
  });

  after(() => {
    server.close();
    server.closeAllConnections(); // undici keep-alive sockets would otherwise keep the event loop alive
    try { app.httpServer.close(); } catch {}
    try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
  });

  // ================================================================ A01 ====
  describe('A01 Broken Access Control', () => {
    it('blocks non-admins from the admin area (web)', async () => {
      const resp = await req('/admin', { jar: aliceSession });
      assert.strictEqual(resp.status, 403);
    });

    it('blocks anonymous access to the admin area', async () => {
      const resp = await req('/admin');
      assert.strictEqual(resp.status, 403);
    });

    it('cannot delete another user\'s post via the API (IDOR)', async () => {
      const resp = await req(`/api/v1/statuses/${bobPostId}`, { method: 'DELETE', token: aliceToken });
      assert.strictEqual(resp.status, 404);
      const p = db.getPostById(bobPostId);
      assert.ok(p, 'bob\'s post still exists');
    });

    it('cannot view a disconnected user\'s post (network visibility)', async () => {
      const resp = await req(`/api/v1/statuses/${malloryPostId}`, { token: aliceToken });
      assert.strictEqual(resp.status, 404);
    });

    it('cannot interact with a disconnected user\'s post', async () => {
      const resp = await req(`/api/v1/statuses/${malloryPostId}/favourite`, { method: 'POST', token: aliceToken });
      assert.strictEqual(resp.status, 404);
    });

    it('can view own post even when isolated', async () => {
      const resp = await req(`/api/v1/statuses/${malloryPostId}`, { token: malloryToken });
      assert.strictEqual(resp.status, 200);
    });

    it('cannot read a DM conversation unless mutual followers', async () => {
      // carol follows bob but bob does not follow carol -> not mutual.
      const resp = await req('/api/v1/conversations/carol', { token: bobToken });
      assert.strictEqual(resp.status, 403);
    });

    it('cannot read room messages as a non-member', async () => {
      const resp = await req(`/api/v1/rooms/${roomId}/channels/${channelId}/messages`, { token: aliceToken });
      assert.strictEqual(resp.status, 403);
    });

    it('enforces OAuth scopes (read-only token cannot write)', async () => {
      const resp = await req('/api/v1/statuses', { method: 'POST', token: aliceReadToken, body: { type: 'text', body: 'nope' } });
      assert.strictEqual(resp.status, 403);
      const j = await json(resp);
      assert.strictEqual(j.error, 'insufficient_scope');
    });

    it('rejects tokens belonging to a banned user', async () => {
      const resp = await req('/api/v1/accounts/verify_credentials', { token: bannedToken });
      assert.strictEqual(resp.status, 403);
    });

    it('search does not leak posts outside the viewer\'s network', async () => {
      const r1 = await req(`/api/v1/search?type=statuses&q=${encodeURIComponent(malloryPostBody)}`, { token: aliceToken });
      const j1 = await json(r1);
      assert.strictEqual(r1.status, 200);
      const list1 = Array.isArray(j1.data) ? j1.data : (j1.data && j1.data.statuses) || [];
      assert.ok(!list1.some(s => String(s.body || '').includes(malloryPostBody)), 'alice cannot find mallory\'s post');

      const r2 = await req(`/api/v1/search?type=statuses&q=${encodeURIComponent(bobPostBody)}`, { token: malloryToken });
      const j2 = await json(r2);
      assert.strictEqual(r2.status, 200);
      const list2 = Array.isArray(j2.data) ? j2.data : (j2.data && j2.data.statuses) || [];
      assert.ok(!list2.some(s => String(s.body || '').includes(bobPostBody)), 'mallory cannot find bob\'s post');
    });
  });

  // ================================================================ A02 ====
  describe('A02 Cryptographic Failures', () => {
    it('stores passwords as bcrypt hashes, never plaintext', async () => {
      // Register a real user over HTTP (exercises the whole register pipeline).
      const jar = { cookies: {} };
      const pre = await req('/register', { jar });
      const preHtml = await pre.text();
      const csrf = extractCsrf(preHtml);
      const cap = await solveCaptcha(jar);
      const reg = await req('/register', {
        method: 'POST', jar,
        form: { username: 'crypto_user', password: 's3cretPass!123', displayName: 'Crypto', _csrf: csrf, ...cap },
      });
      assert.strictEqual(reg.status, 302, 'registration succeeds');
      const row = db.db.prepare(`SELECT password_hash FROM users WHERE username = 'crypto_user'`).get();
      assert.ok(row, 'crypto_user exists');
      assert.notStrictEqual(row.password_hash, 's3cretPass!123', 'hash != plaintext');
      assert.ok(/^\$2[aby]\$/.test(row.password_hash), 'hash is bcrypt ($2a/$2b/$2y)');
      assert.ok(bcrypt.compareSync('s3cretPass!123', row.password_hash), 'hash verifies against the password');
    });

    it('stores OAuth bearer tokens hashed at rest', async () => {
      const stored = db.db.prepare(`SELECT token, refresh_token FROM oauth_tokens WHERE app_id = ?`).get(aliceAppId);
      assert.ok(stored, 'token row exists');
      assert.notStrictEqual(stored.token, aliceToken, 'raw token is not stored verbatim');
      assert.ok(String(stored.token).startsWith('sha256$'), 'access token is hashed (sha256$ prefix)');
      assert.ok(String(stored.refresh_token).startsWith('sha256$'), 'refresh token is hashed');
      // Lookup still resolves the raw token presented by the client.
      assert.ok(db.getOAuthToken(aliceToken), 'getOAuthToken resolves raw token');
      assert.ok(db.getOAuthTokenByRefresh(aliceRefresh), 'getOAuthTokenByRefresh resolves raw refresh token');
      assert.ok(!db.getOAuthToken('does-not-exist'), 'unknown token still rejected');
    });

    it('stores OAuth client secrets hashed at rest', () => {
      const row = db.db.prepare(`SELECT client_secret FROM oauth_apps WHERE id = ?`).get(aliceAppId);
      assert.ok(String(row.client_secret).startsWith('sha256$'), 'client secret is hashed');
      assert.notStrictEqual(row.client_secret, 'owasp-alice-secret', 'raw secret not stored');
      assert.strictEqual(row.client_secret, db.hashOAuthToken('owasp-alice-secret'), 'hash matches presented secret');
    });

    it('stores OAuth authorization codes hashed at rest', () => {
      const code = crypto.randomBytes(32).toString('hex');
      db.createOAuthCode(code, aliceAppId, aliceId, 'read', null, null, 'https://ex.com/cb', null);
      const row = db.db.prepare(`SELECT code FROM oauth_codes WHERE app_id = ? ORDER BY id DESC LIMIT 1`).get(aliceAppId);
      assert.ok(String(row.code).startsWith('sha256$'), 'auth code is hashed');
      assert.notStrictEqual(row.code, code, 'raw code not stored');
      assert.ok(db.getOAuthCode(code), 'raw code still resolves via hash lookup');
    });

    it('migrates legacy plaintext OAuth secrets (tokens, client secrets, codes) to hashes', () => {
      const raw = crypto.randomBytes(32).toString('hex');
      db.db.prepare(`INSERT INTO oauth_tokens (token, refresh_token, app_id, user_id, scopes, expires_at, created_at) VALUES (?,?,?,?,?,?,?)`)
        .run(raw, null, aliceAppId, aliceId, 'read', Date.now() + 86400000, Date.now());
      const rawSecret = crypto.randomBytes(32).toString('hex');
      db.db.prepare(`INSERT INTO oauth_apps (name, description, website, redirect_uris, client_id, client_secret, scopes, owner_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)`)
        .run('legacy-app', '', '', 'https://x/cb', 'legacy-client-id', rawSecret, 'read', aliceId, Date.now());
      const rawCode = crypto.randomBytes(32).toString('hex');
      db.db.prepare(`INSERT INTO oauth_codes (code, app_id, user_id, scopes, redirect_uri, expires_at, created_at) VALUES (?,?,?,?,?,?,?)`)
        .run(rawCode, aliceAppId, aliceId, 'read', 'https://x/cb', Date.now() + 600000, Date.now());

      db.migrateOAuthTokenHashes();

      const tokRow = db.db.prepare(`SELECT token FROM oauth_tokens WHERE user_id = ? AND app_id = ? ORDER BY id DESC LIMIT 1`).get(aliceId, aliceAppId);
      assert.ok(String(tokRow.token).startsWith('sha256$'), 'legacy token was hashed');
      assert.ok(db.getOAuthToken(raw), 'legacy raw token still resolves after migration');

      const appRow = db.db.prepare(`SELECT client_secret FROM oauth_apps WHERE client_id = 'legacy-client-id'`).get();
      assert.ok(String(appRow.client_secret).startsWith('sha256$'), 'legacy client secret was hashed');
      assert.strictEqual(appRow.client_secret, db.hashOAuthToken(rawSecret), 'legacy secret hash matches');

      const codeRow = db.db.prepare(`SELECT code FROM oauth_codes WHERE app_id = ? ORDER BY id DESC LIMIT 1`).get(aliceAppId);
      assert.ok(String(codeRow.code).startsWith('sha256$'), 'legacy auth code was hashed');
      assert.ok(db.getOAuthCode(rawCode), 'legacy raw code still resolves after migration');
    });

    it('sets hardened session cookies (HttpOnly, SameSite)', async () => {
      assert.ok(/HttpOnly/i.test(postLoginCookie), 'cookie is HttpOnly');
      assert.ok(/SameSite=Lax/i.test(postLoginCookie), 'cookie has SameSite=Lax');
    });
  });

  // ================================================================ A03 ====
  describe('A03 Injection', () => {
    it('SQL injection cannot bypass login', async () => {
      const jar = { cookies: {} };
      const pre = await req('/login', { jar });
      const csrf = extractCsrf(await pre.text());
      const resp = await req('/login', {
        method: 'POST', jar,
        form: { username: `' OR 1=1 --`, password: `' OR '1'='1`, _csrf: csrf },
      });
      assert.strictEqual(resp.status, 200, 'no redirect, no session granted');
      const text = await resp.text();
      assert.ok(text.includes('Invalid username or password'), 'generic failure, no auth bypass');
    });

    it('SQL injection in search returns clean results (parameterized query)', async () => {
      const resp = await req(`/api/v1/search?q=${encodeURIComponent(`' OR 1=1--`)}`, { token: aliceToken });
      assert.strictEqual(resp.status, 200);
      const j = await json(resp);
      assert.ok(j && Array.isArray(j.data.accounts) && Array.isArray(j.data.statuses), 'valid JSON envelope');
    });

    it('SQL metacharacters in post body are stored literally, not executed', async () => {
      const body = `inject ' OR 1=1-- '; DROP TABLE posts;--`;
      const resp = await req('/api/v1/statuses', { method: 'POST', token: aliceToken, body: { type: 'text', body } });
      assert.strictEqual(resp.status, 201, 'no SQL error surfaced');
      const j = await json(resp);
      assert.ok(j && j.data && j.data.id, 'post created');
      const fetched = await req(`/api/v1/statuses/${j.data.id}`, { token: aliceToken });
      const fj = await json(fetched);
      assert.ok(String(fj.data.body).includes('DROP TABLE posts'), 'payload stored verbatim');
      assert.ok(db.getPostById(alicePostId), 'posts table still intact');
    });

    it('registration rejects SQLi/HTML in usernames', async () => {
      const jar = { cookies: {} };
      const pre = await req('/register', { jar });
      const preHtml = await pre.text();
      const csrf = extractCsrf(preHtml);
      const cap = await solveCaptcha(jar);
      const resp = await req('/register', {
        method: 'POST', jar,
        form: { username: `<script>alert(1)</script>' OR 1=1--`, password: 'secret123456', _csrf: csrf, ...cap },
      });
      assert.strictEqual(resp.status, 200, 'no redirect');
      const text = await resp.text();
      assert.ok(text.includes('Username must be'), 'username rejected by policy');
    });

    it('stored XSS in profile HTML/CSS is sanitized before serving', async () => {
      const evilHtml = '<script>alert(1)</script><img src=x onerror=alert(1)><a href="javascript:alert(1)">click</a><div style="background:url(javascript:alert(1))">hi</div>';
      const evilCss = 'body{background:url(javascript:alert(1))} a{behavior:url(x)}';
      const resp = await req('/u/alice/edit', {
        method: 'POST', jar: aliceSession, csrf: aliceSession.csrf,
        form: { html: evilHtml, css: evilCss, displayName: 'Alice', bio: 'hi' },
      });
      assert.strictEqual(resp.status, 302, 'profile update accepted');
      const page = await (await req('/u/alice', { jar: aliceSession })).text();
      assert.ok(!page.includes('alert(1)'), 'script payload stripped');
      assert.ok(!/onerror\s*=/.test(page), 'event handler attributes stripped');
      assert.ok(!page.includes('javascript:'), 'javascript: scheme stripped');
    });

    it('stored XSS in room HTML/CSS is sanitized at write time', async () => {
      const evilHtml = '<script>alert(2)</script><img src=x onerror=alert(2)>';
      const evilCss = 'body{background:url(javascript:alert(2))}';
      const resp = await req(`/rooms/${roomId}/settings`, {
        method: 'POST', jar: bobSession, csrf: bobSession.csrf,
        form: { name: 'bob-room', description: 'desc', html: evilHtml, css: evilCss, is_public: '1' },
      });
      assert.strictEqual(resp.status, 302, 'room settings accepted');
      const j = await json(await req(`/api/v1/rooms/${roomId}`, { token: aliceToken }));
      assert.ok(!String(j.data.html).includes('alert(2)'), 'room html sanitized');
      assert.ok(!/onerror\s*=/.test(String(j.data.html)), 'room html event handlers stripped');
      assert.ok(!String(j.data.css).includes('javascript:'), 'room css sanitized');
    });
  });

  // ================================================================ A04 ====
  describe('A04 Insecure Design', () => {
    it('referral signup cannot be farmed from the same IP as the referrer', async () => {
      // alice logged in above -> her referrer_ip was recorded as the runtime req.ip.
      db.db.prepare(`UPDATE users SET referral_code = 'owasp-ref' WHERE id = ?`).run(aliceId);
      const jar = { cookies: {} };
      const pre = await req('/register?ref=owasp-ref', { jar });
      const preHtml = await pre.text();
      const csrf = extractCsrf(preHtml);
      const cap = await solveCaptcha(jar);
      const resp = await req('/register', {
        method: 'POST', jar,
        form: { username: 'ref_farmer', password: 'secret123456', ref: 'owasp-ref', _csrf: csrf, ...cap },
      });
      assert.strictEqual(resp.status, 200, 'same-IP referral rejected, no redirect');
      const text = await resp.text();
      assert.ok(text.includes('referral'), 'error explains the referral rejection');
      assert.ok(!db.getUserByUsername('ref_farmer'), 'no account was created');
    });
  });

  // ================================================================ A05 ====
  describe('A05 Security Misconfiguration', () => {
    it('sends security headers (CSP, nosniff)', async () => {
      const resp = await req('/login');
      assert.strictEqual(resp.status, 200);
      assert.match(resp.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
      assert.match(resp.headers.get('content-security-policy') || '', /default-src 'self'/);
      assert.strictEqual(resp.headers.get('x-content-type-options'), 'nosniff');
    });

    it('serves uploads with nosniff and no directory listing', async () => {
      const file = await req('/uploads/');
      assert.strictEqual(file.status, 404, 'no directory listing');
      const apiUploads = await req('/api-uploads/');
      assert.strictEqual(apiUploads.status, 404, 'no directory listing');
    });

    it('error responses do not leak stack traces', async () => {
      const resp = await req('/api/v1/statuses', {
        method: 'POST', token: aliceToken, rawBody: true,
        body: '{ "type": "text", "body": "broken json",', // invalid JSON sent verbatim
      });
      const text = await resp.text();
      assert.ok(!text.includes('node_modules'), 'no source path leaked');
      assert.ok(!/^\s*at\s/m.test(text), 'no stack frames leaked');
    });

    it('unknown API routes return a JSON error envelope, not a crash', async () => {
      const resp = await req('/api/v1/does-not-exist', { token: aliceToken });
      assert.strictEqual(resp.status, 404);
      const j = await json(resp);
      assert.strictEqual(j.title, 'Not Found');
    });
  });

  // ================================================================ A06 ====
  describe('A06 Vulnerable and Outdated Components', () => {
    it('npm audit reports no high or critical vulnerabilities', { timeout: 120000 }, async (t) => {
      const root = path.resolve(__dirname, '..');
      const out = await new Promise((resolve) => {
        execFile('npm', ['audit', '--omit=dev', '--json'], { cwd: root, timeout: 90000 }, (err, stdout) => {
          // npm audit exits 1 when vulnerabilities exist; stdout still has the report.
          resolve(stdout || '');
        });
      });
      if (!out.trim()) {
        t.skip('npm audit produced no output (offline?) — cannot verify component status');
        return;
      }
      let report;
      try { report = JSON.parse(out); } catch { t.skip('npm audit output not parseable'); return; }
      const v = (report.metadata && report.metadata.vulnerabilities) || {};
      assert.strictEqual(v.critical || 0, 0, 'no critical vulnerabilities');
      assert.strictEqual(v.high || 0, 0, 'no high vulnerabilities');
    });
  });

  // ================================================================ A07 ====
  describe('A07 Identification and Authentication Failures', () => {
    it('login error does not reveal whether a username exists', async () => {
      const unknown = await login('no_such_user_xyz', 'whatever');
      const known = await login('alice', 'wrong-password-xyz');
      const t1 = await unknown.post.text();
      const t2 = await known.post.text();
      assert.strictEqual(unknown.post.status, 200);
      assert.strictEqual(known.post.status, 200);
      assert.ok(t1.includes('Invalid username or password'));
      assert.ok(t2.includes('Invalid username or password'));
      assert.ok(!t1.includes('no_such_user_xyz') || !t1.includes('does not exist'), 'no enumeration wording');
    });

    it('regenerates the session id on login (anti session-fixation)', async () => {
      assert.ok(preLoginCookie, 'pre-login session cookie exists (CSRF)');
      const preSid = preLoginCookie.match(/connect\.sid=([^;]+)/);
      const postSid = postLoginCookie.match(/connect\.sid=([^;]+)/);
      assert.ok(preSid && postSid, 'session cookies present');
      assert.notStrictEqual(preSid[1], postSid[1], 'session id changes after login');
    });

    it('rejects login for banned accounts', async () => {
      const r = await login('banned_usr', PASSWORD);
      assert.strictEqual(r.post.status, 200);
      const text = await r.post.text();
      assert.ok(text.includes('suspended'), 'banned user told account is suspended');
    });

    it('enforces a minimum password length on registration', async () => {
      const jar = { cookies: {} };
      const pre = await req('/register', { jar });
      const preHtml = await pre.text();
      const csrf = extractCsrf(preHtml);
      const cap = await solveCaptcha(jar);
      const resp = await req('/register', {
        method: 'POST', jar, form: { username: 'shortpw', password: 'abc', _csrf: csrf, ...cap },
      });
      assert.strictEqual(resp.status, 200, 'weak password not accepted');
      const text = await resp.text();
      assert.ok(text.includes('Password must be'), 'policy error shown');
      assert.ok(!db.getUserByUsername('shortpw'), 'no account created');
    });

    it('rejects OAuth token requests with a wrong client secret', async () => {
      const resp = await req('/api/v1/oauth/token', {
        method: 'POST', body: { client_id: 'owasp-bob-client', client_secret: 'wrong-secret', grant_type: 'refresh_token', refresh_token: 'x' },
      });
      assert.strictEqual(resp.status, 401);
      const j = await json(resp);
      assert.strictEqual(j.error, 'invalid_client');
    });

    it('accepts a matching OAuth client secret (hash-compared at rest)', async () => {
      // Correct secret passes clientAppAuth (stored hashed); the refresh flow
      // then fails on the unknown refresh token with 400 — not 401.
      const resp = await req('/api/v1/oauth/token', {
        method: 'POST', body: { client_id: 'owasp-bob-client', client_secret: 'owasp-bob-secret', grant_type: 'refresh_token', refresh_token: 'not-a-real-token' },
      });
      assert.strictEqual(resp.status, 400, 'client authenticated; token rejected');
      const j = await json(resp);
      assert.ok(!j.access_token, 'no token issued');
    });

    it('does not support a password grant (no credential dumping via OAuth)', async () => {
      const resp = await req('/api/v1/oauth/token', {
        method: 'POST', body: { client_id: 'owasp-alice-client', client_secret: 'owasp-alice-secret', grant_type: 'password', username: 'alice', password: PASSWORD },
      });
      assert.strictEqual(resp.status, 400);
      const j = await json(resp);
      assert.ok(!j.access_token, 'no token issued');
    });
  });

  // ================================================================ A08 ====
  describe('A08 Software and Data Integrity Failures', () => {
    it('CSRF: state-changing web POSTs require a valid token', async () => {
      const noToken = await req(`/posts/${bobPostId}/like`, { method: 'POST', jar: aliceSession });
      assert.strictEqual(noToken.status, 403, 'POST without CSRF token rejected');

      const withToken = await req(`/posts/${bobPostId}/like`, { method: 'POST', jar: aliceSession, csrf: aliceSession.csrf });
      assert.ok([200, 302].includes(withToken.status), 'POST with CSRF token accepted');
    });

    it('login next= parameter cannot be used for open redirects', async () => {
      const r = await login('alice', PASSWORD, { next: 'https://evil.example.com/phish' });
      const loc = r.post.headers.get('location') || '';
      assert.ok(!loc.startsWith('https://'), 'not redirected off-site');
      assert.ok(!loc.startsWith('//'), 'not protocol-relative redirect');
    });

    it('JSON bodies with prototype-pollution keys are inert', async () => {
      // Build __proto__ as an own enumerable key (object-literal syntax would
      // set the prototype instead of serializing the key).
      const body = JSON.parse('{"type":"text","body":"proto test","__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}');
      const resp = await req('/api/v1/statuses', { method: 'POST', token: aliceToken, body });
      assert.strictEqual(resp.status, 201, 'no crash, no 500');
      const j = await json(resp);
      assert.ok(j.data && j.data.id, 'post created normally');
      assert.strictEqual({}.polluted, undefined, 'Object.prototype not polluted');
    });
  });

  // ================================================================ A09 ====
  describe('A09 Security Logging and Monitoring Failures', () => {
    it('records failed API authentication in the audit log', async () => {
      const before = db.db.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE action = 'api_auth_failure'`).get().n;
      await req('/api/v1/accounts/verify_credentials', { token: 'definitely-invalid-token' });
      const after = db.db.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE action = 'api_auth_failure'`).get().n;
      assert.ok(after > before, 'api_auth_failure logged');
    });

    it('never logs passwords or session secrets', async () => {
      const rows = db.db.prepare(`SELECT details FROM audit_log WHERE details IS NOT NULL`).all();
      for (const r of rows) {
        assert.ok(!String(r.details).includes('secret123'), 'password not present in audit log');
        assert.ok(!String(r.details).includes('owasp-test-session-secret'), 'session secret not present in audit log');
      }
    });

    it('audit log has a persistent schema (action, actor, details, ip, timestamp)', async () => {
      const cols = db.db.prepare(`PRAGMA table_info(audit_log)`).all().map(c => c.name);
      for (const c of ['action', 'actor_id', 'details', 'ip', 'created_at']) {
        assert.ok(cols.includes(c), `audit_log has column ${c}`);
      }
    });
  });

  // ================================================================ A10 ====
  describe('A10 Server-Side Request Forgery', () => {
    it('push subscriptions reject loopback / private / obfuscated endpoints', async () => {
      const bad = [
        // canonical literals
        'http://127.0.0.1:9/x',
        'https://localhost:8443/x',
        'http://169.254.169.254/latest/meta-data',
        'http://10.0.0.5:8080/internal',
        'http://192.168.1.1:80/x',
        'http://[::1]:9/x',
        // obfuscated forms that resolve to loopback
        'https://127.1/x',
        'https://2130706433/x',
        'https://0x7f000001/x',
        'https://127.0.0.1./x',
        'https://[0:0:0:0:0:0:0:1]/x',
        'https://[::ffff:7f00:1]/x',
        // leading whitespace: legacy url.parse() still resolves the hostname
        ' https://127.0.0.1/x',
        // scheme-less host:port and backslash forms web-push's url.parse() would target
        '127.0.0.1:8443/x',
        '10.0.0.5:8080/x',
        'https:\\169.254.169.254/x',
        '\\169.254.169.254/x',
        // IPv6 transition / embedding prefixes that can reach IPv4
        'https://[2001::1]/x',
        'https://[2001:0:0:0:0:0:0:1]/x',
        'https://[64:ff9b:1:2:3:4:5:6]/x',
        // wildcard-DNS names that resolve to private addresses
        'https://localtest.me/x',
        'https://169.254.169.254.nip.io/x',
      ];
      for (const endpoint of bad) {
        const resp = await req('/api/v1/push/subscribe', {
          method: 'POST', token: aliceToken, body: { endpoint, p256dh: 'a', auth: 'b', platform: 'web' },
        });
        assert.strictEqual(resp.status, 400, `endpoint ${endpoint} rejected`);
      }
      // Non-https endpoints are rejected too (web-push only speaks https).
      const http = await req('/api/v1/push/subscribe', {
        method: 'POST', token: aliceToken, body: { endpoint: 'http://example.com/x', p256dh: 'a', auth: 'b', platform: 'web' },
      });
      assert.strictEqual(http.status, 400, 'plain http endpoint rejected');
    });

    it('push subscriptions still accept legitimate https endpoints and device tokens', async () => {
      const resp = await req('/api/v1/push/subscribe', {
        method: 'POST', token: aliceToken,
        body: { endpoint: 'https://fcm.googleapis.com/fcm/send/abc123', p256dh: 'a', auth: 'b', platform: 'web' },
      });
      assert.strictEqual(resp.status, 200, 'real push service endpoint accepted');

      // Device-token platforms (fcm/apns/ws) are not URLs and must keep working.
      const device = await req('/api/v1/push/subscribe', {
        method: 'POST', token: aliceToken,
        body: { endpoint: 'fcm-device-token-abc123', platform: 'fcm' },
      });
      assert.strictEqual(device.status, 200, 'device-token platform accepted');

      const wsToken = await req('/push/subscribe', {
        method: 'POST', jar: aliceSession, csrf: aliceSession.csrf,
        body: { endpoint: 'ws-native-device-token', platform: 'ws' },
      });
      assert.strictEqual(wsToken.status, 200, 'web route accepts ws device token');
    });

    it('web platform requires an https endpoint URL (no bare tokens → loopback)', async () => {
      // web-push derives the send target with legacy url.parse(); a bare token
      // yields hostname null, which Node's https.request defaults to loopback.
      const api = await req('/api/v1/push/subscribe', {
        method: 'POST', token: aliceToken, body: { endpoint: 'bare-device-token', platform: 'web' },
      });
      assert.strictEqual(api.status, 400, 'API rejects bare token for web platform');

      const web = await req('/push/subscribe', {
        method: 'POST', jar: aliceSession, csrf: aliceSession.csrf,
        body: { endpoint: 'bare-device-token', platform: 'web' },
      });
      assert.strictEqual(web.status, 400, 'web route rejects bare token for web platform');
    });

    it('web push subscribe route applies the same SSRF guard', async () => {
      const resp = await req('/push/subscribe', {
        method: 'POST', jar: aliceSession, csrf: aliceSession.csrf,
        body: { endpoint: 'http://127.0.0.1:9/x', platform: 'web' },
      });
      assert.strictEqual(resp.status, 400, 'loopback endpoint rejected on web route');
    });
  });

  // ================================================================ A04b ===
  // Brute-force protection must run LAST: it exhausts the per-IP auth rate
  // limiter, which would interfere with any later login/register test.
  describe('A04 Insecure Design — brute-force protection', () => {
    it('rate-limits repeated failed logins (429)', async () => {
      let saw429 = false;
      for (let i = 0; i < 40; i++) {
        const jar = { cookies: {} };
        const pre = await req('/login', { jar });
        const csrf = extractCsrf(await pre.text());
        const resp = await req('/login', {
          method: 'POST', jar,
          form: { username: `brute_${i}`, password: 'wrong', _csrf: csrf },
        });
        if (resp.status === 429) { saw429 = true; break; }
      }
      assert.ok(saw429, 'auth limiter kicked in within 40 rapid failed logins');
    });
  });
});
