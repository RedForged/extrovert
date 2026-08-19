'use strict';
// Smoke-test the /admin/mail panel: boot the app on a temp DB, promote a
// user to admin, GET /admin/mail, POST settings, verify persistence + render.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extro-mail-admin-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'admin-mail-test-secret';
process.env.EXTV_MAIL_MODE = 'capture';

const db = require('../src/db');
const bcrypt = require('bcryptjs');
const app = require('../src/server');

(async () => {
  const server = await new Promise((res) => { const s = app.listen(0, () => res(s)); });
  const base = 'http://localhost:' + server.address().port;

  // Existing user -> make admin directly in DB.
  const uid = db.createUser({ username: 'root', passwordHash: bcrypt.hashSync('x', 10), displayName: 'Root' });
  db.promoteUser(uid);
  const admin = db.getUserById(uid);
  assert(admin.is_admin === 1, 'user is admin');

  // Login via cookie jar (fetch manually).
  const csrf = async (url) => {
    const r = await fetch(base + url);
    const html = await r.text();
    const m = html.match(/name="csrf-token" content="([^"]+)"/);
    return m ? m[1] : null;
  };

  // Create a session: GET /login to get a csrf + cookie.
  const get1 = await fetch(base + '/login');
  const cookies = get1.headers.get('set-cookie') || '';
  const csrf1 = (await get1.text()).match(/name="csrf-token" content="([^"]+)"/)[1];
  const login = await fetch(base + '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookies.split(';')[0] },
    body: new URLSearchParams({ _csrf: csrf1, username: 'root', password: 'x' }),
    redirect: 'manual',
  });
  const sessCookie = (login.headers.get('set-cookie') || cookies).split(';')[0];

  // GET /admin/mail (should render with defaults).
  const g = await fetch(base + '/admin/mail', { headers: { cookie: sessCookie } });
  const html = await g.text();
  assert.strictEqual(g.status, 200, 'admin/mail GET 200');
  assert(html.includes('Admin · Mail'), 'panel heading');

  // POST settings via the session csrf.
  const csrf2 = (await (await fetch(base + '/admin/mail', { headers: { cookie: sessCookie } })).text()).match(/name="csrf-token" content="([^"]+)"/)[1];
  const post = await fetch(base + '/admin/mail', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: sessCookie },
    body: new URLSearchParams({
      _csrf: csrf2,
      policy: 'optional',
      from: 'hello@example.org',
      from_name: 'Extrovert Test',
      mode: 'capture',
      dkim_enabled: '1',
      dkim_domain: 'example.org',
      dkim_selector: 'extrovert',
      starttls: 'opportunistic',
    }),
    redirect: 'manual',
  });
  assert.strictEqual(post.status, 200, 'admin/mail POST 200');
  const postHtml = await post.text();
  assert(postHtml.includes('Saved'), 'saved flash shown');

  // Verify persistence + live config.
  const mailer = require('../src/mailer');
  const cfg = mailer.reloadConfig();
  assert.strictEqual(cfg.from, 'hello@example.org', 'from persisted + effective');
  assert.strictEqual(cfg.dkim.domain, 'example.org', 'dkim domain persisted');
  assert.strictEqual(db.getEmailPolicy(), 'optional', 'policy persisted');

  console.log('ADMIN MAIL SMOKE: ALL PASS');
  server.close();
  try { app.httpServer.close(); } catch {}
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
  process.exit(0);
})().catch((e) => { console.error('FAIL:', e); try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {} process.exit(1); });