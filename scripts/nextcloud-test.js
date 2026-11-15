'use strict';
// Drive -> user's own Nextcloud (WebDAV) end-to-end check against a fake
// Nextcloud: connect, upload, proxied read, pause/resume, delete, quota bypass.
// Run: node scripts/nextcloud-test.js
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-nc-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'nextcloud-test-secret';
process.env.PORT = String(35000 + Math.floor(Math.random() * 1000));
process.env.EXTV_DRIVE_QUOTA_BYTES = '1024'; // tiny: remote uploads must bypass it

const REMOTE = new Map(); // WebDAV path -> Buffer
let mkcolCount = 0;
let lastAuth = null;

const dav = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    lastAuth = req.headers.authorization || null;
    const body = Buffer.concat(chunks);
    const p = req.url;
    if (req.method === 'PROPFIND') {
      res.statusCode = 207;
      return res.end('<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"/>');
    }
    if (req.method === 'MKCOL') {
      if (REMOTE.has(p + '/')) { res.statusCode = 405; return res.end(); }
      REMOTE.set(p + '/', Buffer.alloc(0));
      mkcolCount++;
      res.statusCode = 201;
      return res.end();
    }
    if (req.method === 'PUT') {
      REMOTE.set(p, body);
      res.statusCode = 201;
      return res.end();
    }
    if (req.method === 'GET') {
      const data = REMOTE.get(p);
      if (!data) { res.statusCode = 404; return res.end(); }
      res.statusCode = 200;
      res.setHeader('Content-Length', String(data.length));
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Content-Type', 'application/octet-stream');
      return res.end(data);
    }
    if (req.method === 'DELETE') {
      if (!REMOTE.delete(p)) { res.statusCode = 404; return res.end(); }
      res.statusCode = 204;
      return res.end();
    }
    res.statusCode = 405;
    res.end();
  });
});

let failures = 0;
function ok(cond, msg) {
  console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg);
  if (!cond) failures++;
}

async function main() {
  await new Promise((r) => dav.listen(0, '127.0.0.1', r));
  const davPort = dav.address().port;

  const app = require('../src/server');
  const db = require('../src/db');
  const drive = require('../src/drive');

  const aliceId = db.createUser({ username: 'alice', passwordHash: bcrypt.hashSync('pw1', 10), displayName: 'Alice' });
  const base = 'http://localhost:' + process.env.PORT;

  let cookie = '';
  async function req(url, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (cookie) headers.Cookie = cookie;
    const r = await fetch(base + url, { ...opts, headers, redirect: 'manual' });
    const sc = r.headers.get('set-cookie');
    if (sc) cookie = sc.split(';')[0];
    return r;
  }

  const login = await req('/login');
  const loginCsrf = ((await login.text()).match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  await req('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=alice&password=pw1&_csrf=${encodeURIComponent(loginCsrf)}`,
  });

  const page = await req('/settings/drive');
  const csrf = ((await page.text()).match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  ok(!!csrf, 'got CSRF token');

  // Connect through the real settings route (probe + MKCOL).
  const connectForm = new URLSearchParams({
    _csrf: csrf,
    base_url: `http://127.0.0.1:${davPort}/`,
    username: 'alice',
    app_password: 'app-pass-123',
  });
  const connect = await req('/settings/drive', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: connectForm.toString(),
  });
  const connectText = await connect.text();
  ok(connect.status === 200 && connectText.includes('Connected'), 'settings connects to Nextcloud');
  ok(connectText.includes('no longer applies'), 'page says the size limit no longer applies');
  const row = db.getUserNextcloud(aliceId);
  ok(!!row && row.base_url === `http://127.0.0.1:${davPort}`, 'connection stored');
  ok(lastAuth && lastAuth.startsWith('Basic '), 'WebDAV used Basic auth');
  ok(mkcolCount === 1, 'Extrovert folder created');

  // Pausing keeps the connection but sends new uploads back to local storage.
  const pause = await req('/settings/drive/pause', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `_csrf=${encodeURIComponent(csrf)}`,
  });
  ok(pause.status === 302 || pause.status === 200, 'pause route responds');
  ok(db.getActiveNextcloud(aliceId) === null, 'paused backend is inactive');
  const smallForm = new FormData();
  smallForm.append('_csrf', csrf);
  smallForm.append('file', new Blob([Buffer.alloc(64, 0x42)], { type: 'text/plain' }), 'local.txt');
  const pausedUp = await req('/drive/upload', { method: 'POST', body: smallForm, headers: { Accept: 'application/json' } });
  const pausedJson = await pausedUp.json();
  ok(pausedUp.status === 200 && pausedJson.backend === 'local', 'paused upload stays local');
  db.removeStoredFile('drive', pausedJson.url.slice('/drive/f/'.length));

  const resume = await req('/settings/drive/resume', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `_csrf=${encodeURIComponent(csrf)}`,
  });
  ok(resume.status === 302 || resume.status === 200, 'resume route responds');
  ok(!!db.getActiveNextcloud(aliceId), 'resumed backend is active');

  // Upload something larger than the 1 KB local quota.
  const payload = Buffer.alloc(4096, 0x41);
  const form = new FormData();
  form.append('_csrf', csrf);
  form.append('file', new Blob([payload], { type: 'text/plain' }), 'hello.txt');
  const before = fs.readdirSync(drive.DRIVE_DIR);
  const up = await req('/drive/upload', { method: 'POST', body: form, headers: { Accept: 'application/json' } });
  const upJson = await up.json();
  ok(up.status === 200, 'upload accepted (' + up.status + ')');
  ok(upJson.backend === 'nextcloud', 'upload reports nextcloud backend');
  ok(typeof upJson.url === 'string' && upJson.url.startsWith('/drive/f/'), 'capability URL returned');

  const name = upJson.url.slice('/drive/f/'.length);
  const remotePath = '/remote.php/dav/files/alice/Extrovert/' + name;
  ok(REMOTE.has(remotePath), 'file written to fake Nextcloud');
  ok(REMOTE.get(remotePath).equals(payload), 'remote bytes match the upload');
  ok(fs.readdirSync(drive.DRIVE_DIR).length === before.length, 'no staged copy left on local disk');

  const meta = db.getUserFileByPath('drive', name);
  ok(meta && meta.backend === 'nextcloud' && meta.remote_path === 'Extrovert/' + name, 'accounting row marked nextcloud');
  ok(meta && meta.name === 'hello.txt' && meta.mime === 'text/plain', 'original name/mime kept');

  // Proxy read keeps the same capability URL.
  const proxied = await fetch(base + upJson.url);
  const proxiedBody = Buffer.from(await proxied.arrayBuffer());
  ok(proxied.status === 200, 'proxied read returns 200');
  ok(proxied.headers.get('x-content-type-options') === 'nosniff', 'proxied read is nosniff');
  ok(proxiedBody.equals(payload), 'proxied bytes match');

  const drivePage = await (await req('/drive')).text();
  ok(drivePage.includes('no size limit'), 'drive page hides the quota');
  ok(drivePage.includes('Nextcloud'), 'drive page marks the remote file');

  // Delete goes through to Nextcloud.
  const del = await req('/drive/' + meta.id + '/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `_csrf=${encodeURIComponent(csrf)}`,
  });
  ok(del.status === 302 || del.status === 200, 'delete route responds');
  await new Promise((r) => setTimeout(r, 150));
  ok(!REMOTE.has(remotePath), 'remote file deleted');

  // Sanity: without a backend, the tiny quota still refuses a 4 KB upload.
  db.deleteUserNextcloud(aliceId);
  const form2 = new FormData();
  form2.append('_csrf', csrf);
  form2.append('file', new Blob([payload], { type: 'text/plain' }), 'big.txt');
  const local = await req('/drive/upload', { method: 'POST', body: form2, headers: { Accept: 'application/json' } });
  ok(local.status === 413, 'local upload still enforces the quota (' + local.status + ')');

  console.log(failures ? '\nNEXTCLOUD TEST FAILED' : '\nNEXTCLOUD TEST PASSED');
  dav.close();
  process.exit(failures ? 1 : 0);
}

main().catch((err) => { console.error(err); dav.close(); process.exit(1); });
