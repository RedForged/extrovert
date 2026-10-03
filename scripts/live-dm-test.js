// Live DM delivery over the WebSocket — end-to-end test.
// Logs in a recipient via the real web flow, opens a WS with the session cookie,
// sends a DM as another user over the API, and asserts the WS receives 'new_dm'.
// Run: node scripts/live-dm-test.js
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-livedm-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'extrovert.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 'sessions.db');
process.env.SESSION_SECRET = 'live-dm-test-secret';
process.env.SECRET = 'live-dm-test-secret';
process.env.PORT = String(32000 + Math.floor(Math.random() * 1000));

const app = require('../src/server');
const db = require('../src/db');

let failures = 0;
function ok(cond, msg) { console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg); if (!cond) failures++; }

async function main() {
  const base = 'http://localhost:' + process.env.PORT;
  const wsBase = 'ws://localhost:' + process.env.PORT;

  // Users: alice (sender) + bob (recipient), mutual followers.
  const aliceId = db.createUser({ username: 'alice', passwordHash: bcrypt.hashSync('pw1', 10), displayName: 'Alice' });
  const bobId = db.createUser({ username: 'bob', passwordHash: bcrypt.hashSync('pw2', 10), displayName: 'Bob' });
  db.follow(aliceId, bobId);
  db.follow(bobId, aliceId);
  db.setOlmIdentity(aliceId, 'alice-curve25519', 'alice-ed25519', null);

  // OAuth token for alice (sender).
  db.createOAuthApp({ name: 't', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'c', clientSecret: 's', scopes: 'read write follow read:direct write:direct', ownerId: aliceId });
  const atok = crypto.randomBytes(32).toString('hex');
  db.createOAuthToken(atok, null, db.getOAuthAppByClientId('c').id, aliceId, 'read write follow read:direct write:direct', Date.now() + 86400000);

  // Log in as bob via the web flow to get a session cookie.
  const jar = {};
  async function withCookie(url, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (jar.cookie) headers['Cookie'] = jar.cookie;
    const r = await fetch(base + url, { ...opts, headers, redirect: 'manual' });
    const sc = r.headers.get('set-cookie');
    if (sc) {
      const sid = sc.split(';')[0];
      jar.cookie = (jar.cookie ? jar.cookie + '; ' : '') + sid;
    }
    return r;
  }

  const loginPage = await withCookie('/login');
  const html = await loginPage.text();
  const csrfMatch = html.match(/name="_csrf" value="([^"]+)"/);
  ok(!!csrfMatch, 'login page provides a CSRF token');
  const csrf = csrfMatch ? csrfMatch[1] : '';

  const loginRes = await withCookie('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=bob&password=pw2&_csrf=${encodeURIComponent(csrf)}`,
  });
  ok(loginRes.status === 302 || loginRes.status === 200, 'bob logs in via web flow');

  // Open a WebSocket with bob's session cookie. Like the real browser client
  // (public/webrtc.js), the first message is a ping that registers this
  // connection for live DM delivery.
  const ws = new WebSocket(wsBase + '/ws', { headers: { Cookie: jar.cookie } });
  await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
  ws.send(JSON.stringify({ type: 'ping' }));

  const received = new Promise((resolve) => {
    ws.on('message', (raw) => {
      let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }
      if (msg.type === 'new_dm') resolve(msg);
    });
  });

  // Wait for the connection to register.
  await new Promise(r => setTimeout(r, 300));

  const dmClientTxId = 'dm-client-tx-' + Date.now();
  // Alice sends a DM to bob via the API.
  const sendRes = await fetch(base + '/api/v1/conversations/bob/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + atok },
    body: JSON.stringify({
      proto: 'olm',
      body: '{"t":0,"b":"ciphertext-blob"}',
      sender_ciphertext: '{"t":0,"b":"self-copy"}',
      client_id: dmClientTxId,
    }),
  });
  ok(sendRes.status === 201, 'alice sends a DM over the API');
  const sendJson = await sendRes.json();
  ok(sendJson.data.client_id === dmClientTxId, 'DM response echoes client_id');

  const msg = await Promise.race([
    received,
    new Promise((_, rej) => setTimeout(() => rej(new Error('timeout waiting for new_dm')), 3000)),
  ]).catch(err => err);

  ok(msg && msg.type === 'new_dm', 'bob\'s WebSocket receives new_dm live');
  ok(msg && msg.client_id === dmClientTxId, 'pushed message carries client_id');
  if (msg && msg.message) {
    ok(String(msg.message.from_id) === String(aliceId), 'pushed message carries sender id');
    ok(msg.message.proto === 'olm', 'pushed message carries proto');
    ok(msg.sender_curve === 'alice-curve25519', 'pushed message carries sender curve key');
  }

  // The sender must NOT be the delivery target of their own message (no loop): open a WS as alice.
  const aliceLogin = await (async () => {
    const r1 = await fetch(base + '/login');
    const h1 = await r1.text();
    const c1 = r1.headers.get('set-cookie').split(';')[0];
    const t = h1.match(/name="_csrf" value="([^"]+)"/)[1];
    const r2 = await fetch(base + '/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: c1 }, body: `username=alice&password=pw1&_csrf=${encodeURIComponent(t)}`, redirect: 'manual' });
    const c2 = r2.headers.get('set-cookie') ? r2.headers.get('set-cookie').split(';')[0] : c1;
    return { cookie: c2 };
  })();
  const wsAlice = new WebSocket(wsBase + '/ws', { headers: { Cookie: aliceLogin.cookie } });
  await new Promise((resolve, reject) => { wsAlice.once('open', resolve); wsAlice.once('error', reject); });
  wsAlice.send(JSON.stringify({ type: 'ping' }));
  await new Promise(r => setTimeout(r, 300));

  let aliceGotDm = false;
  wsAlice.on('message', (raw) => { let m; try { m = JSON.parse(raw.toString()); } catch { return; } if (m.type === 'new_dm') aliceGotDm = true; });
  await fetch(base + '/api/v1/conversations/alice/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + atok },
    body: JSON.stringify({ proto: 'olm', body: '{"t":0,"b":"x"}', sender_ciphertext: '{"t":0,"b":"y"}' }),
  });
  await new Promise(r => setTimeout(r, 500));
  ok(!aliceGotDm, 'sender does not receive their own DM back (no delivery loop)');

  ws.close();
  wsAlice.close();
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL LIVE DM CHECKS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch(err => { console.error(err); process.exit(1); });
