'use strict';
// Render smoke: boot the server on a temp DB, register users, GET every page
// type and fail on any 500 / EJS error. Run: node scripts/render-smoke.js
const fs = require('fs');
const path = require('path');
const os = require('os');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-render-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'render-test-secret';
process.env.SECRET = 'render-test-secret';
process.env.PORT = String(34000 + Math.floor(Math.random() * 1000));

const app = require('../src/server');
const db = require('../src/db');

let failures = 0;
const seen = new Set();
function ok(cond, label) {
  if (seen.has(label)) return;
  seen.add(label);
  console.log((cond ? '  [OK]   ' : '  [FAIL] ') + label);
  if (!cond) failures++;
}

async function main() {
  const base = 'http://localhost:' + process.env.PORT;
  const aliceId = db.createUser({ username: 'alice', passwordHash: bcrypt.hashSync('pw1', 10), displayName: 'Alice' });
  const bobId = db.createUser({ username: 'bob', passwordHash: bcrypt.hashSync('pw2', 10), displayName: 'Bob' });
  db.follow(aliceId, bobId); db.follow(bobId, aliceId);
  db.createPost({ userId: aliceId, type: 'text', body: 'hello world', createdAt: Date.now() });
  db.promoteUser(aliceId);
  db.createSecurityReport({ reporterName: 'whitehat', reporterContact: 'wh@example.com', summary: 'smoke-test finding', details: 'render smoke detail body' });

  async function session(username, password) {
    const jar = {};
    async function req(url, opts = {}) {
      const headers = { ...(opts.headers || {}) };
      if (jar.cookie) headers['Cookie'] = jar.cookie;
      const r = await fetch(base + url, { ...opts, headers, redirect: 'manual' });
      const sc = r.headers.get('set-cookie');
      if (sc) jar.cookie = sc.split(';')[0];
      return r;
    }
    const page = await req('/login');
    const csrf = ((await page.text()).match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
    await req('/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `username=${username}&password=${password}&_csrf=${encodeURIComponent(csrf)}` });
    const after = await req('/chats');
    const fresh = ((await after.text()).match(/name="csrf-token" content="([^"]+)"/) || [])[1] || csrf;
    return {
      jar, csrf: fresh,
      get: (url) => req(url).then(r => ({ status: r.status, text: r.text() })),
    };
  }

  const alice = await session('alice', 'pw1');
  const bob = await session('bob', 'pw2');

  // Enable bob's olm identity so the chat thread renders fully.
  db.setOlmIdentity(bobId, 'b-curve', 'b-ed', null);
  db.setOlmIdentity(aliceId, 'a-curve', 'a-ed', null);

  const roomId = db.createRoom('Test Room', 'desc', aliceId, 1);

  const pages = [
    ['/', 'feed'],
    ['/compose', 'compose'],
    ['/discover', 'discover'],
    ['/chats', 'chats list'],
    ['/chats/bob', 'chat thread'],
    ['/inbox', 'inbox'],
    ['/settings', 'settings'],
    ['/u/alice', 'own profile'],
    ['/u/alice/edit', 'profile edit'],
    ['/u/alice/followers', 'followers list'],
    ['/u/alice/following', 'following list'],
    ['/rooms', 'rooms list'],
    ['/rooms/create', 'room create'],
    ['/rooms/' + roomId, 'room detail'],
    ['/rooms/' + roomId + '/settings', 'room settings'],
    ['/rooms/' + roomId + '/members', 'room members'],
    ['/rooms/' + roomId + '/roles', 'room roles'],
    ['/rooms/' + roomId + '/channels', 'room channels'],
    ['/docs', 'docs'],
    ['/developers/docs', 'developers docs'],
    ['/stickers', 'stickers'],
    ['/security', 'security'],
    ['/admin', 'admin dashboard'],
    ['/admin/reports', 'admin reports'],
    ['/admin/security-reports', 'admin security reports'],
    ['/admin/announcement', 'admin announcement'],
    ['/this-does-not-exist', '404 page'],
  ];

  console.log('\nRender smoke (alice):');
  for (const [url, label] of pages) {
    try {
      const r = await alice.get(url);
      const text = await r.text;
      ok(r.status !== 500, label + ' (' + url + ') status=' + r.status);
      if (r.status === 500) { failures++; console.log('    ' + (text || '').slice(0, 300)); }
    } catch (e) { ok(false, label + ' threw: ' + e.message); }
  }

  console.log('\nRender smoke (bob, sees alice):');
  for (const [url, label] of [['/chats/alice', 'bob chat thread'], ['/', 'bob feed']]) {
    const r = await bob.get(url);
    ok(r.status !== 500, label + ' status=' + r.status);
  }

  const inbox = await alice.get('/admin/security-reports');
  const inboxText = await inbox.text;
  ok(inbox.status === 200 && inboxText.includes('smoke-test finding'),
    'admin security inbox renders report contents');

  console.log('\nAnon pages:');
  const anon = await fetch(base + '/login');
  ok(anon.status === 200, 'login page renders');
  const anonReg = await fetch(base + '/register');
  ok(anonReg.status === 200, 'register page renders');

  console.log(failures ? '\nRENDER SMOKE FAILED' : '\nRENDER SMOKE PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch(err => { console.error(err); process.exit(1); });
