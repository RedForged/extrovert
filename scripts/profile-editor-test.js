'use strict';
// Easy Editing integration test: boots the server on a temp DB and exercises
// the whole-page profile template + the /edit/visual save endpoint.
// Run: node scripts/profile-editor-test.js
const fs = require('fs');
const path = require('path');
const os = require('os');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-editor-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'editor-test-secret';
process.env.SECRET = 'editor-test-secret';
process.env.PORT = String(35000 + Math.floor(Math.random() * 1000));

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
  db.createPost({ userId: aliceId, type: 'text', body: 'hello from alice', createdAt: Date.now() });
  // Legacy (template_version 0) profile content for bob.
  db.setCustomization(bobId, '<div id="legacy">LEGACY-CONTENT</div>', '.legacy { color: red; }');

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
    const after = await req('/u/' + username);
    const fresh = ((await after.text()).match(/name="csrf-token" content="([^"]+)"/) || [])[1] || csrf;
    return {
      cookie: jar.cookie, csrf: fresh,
      get: (url) => req(url).then(async r => ({ status: r.status, text: await r.text() })),
      post: (url, opts) => req(url, { method: 'POST', ...opts }),
    };
  }

  const alice = await session('alice', 'pw1');
  const bob = await session('bob', 'pw2');

  console.log('\nOwner profile render (alice):');
  const own = await alice.get('/u/alice');
  ok(own.status === 200, 'own profile 200');
  ok(own.text.includes('data-ev-slot="posts"'), 'posts slot present in template');
  ok(own.text.includes('hello from alice'), 'post list injected into the page');
  ok(own.text.includes('data-ev-slot="displayName"') && own.text.includes('>Alice<'), 'displayName slot filled');
  ok(own.text.includes('data-ev-slot="handle"') && own.text.includes('@alice'), 'handle slot filled');
  ok(own.text.includes('data-ev-slot="stats"'), 'stats slot present');
  ok(own.text.includes('id="ev-user-css"'), 'user CSS style element has an id for the editor');
  ok(own.text.includes('/static/profile-editor.js'), 'editor script loaded for the owner');
  ok(own.text.includes('id="ev-edit-toggle"'), 'Edit styles toggle rendered for the owner');
  ok(own.text.includes('id="ev-fields"'), 'left-panel profile fields rendered for the owner');
  ok(own.text.includes('id="ev-html-box"'), 'collapsible HTML box rendered for the owner');
  ok(own.text.includes('id="ev-reset"'), 'reset button rendered for the owner');

  console.log('\nNon-owner render (bob views alice):');
  const other = await bob.get('/u/alice');
  ok(other.status === 200, 'profile 200 for non-owner');
  ok(!other.text.includes('/static/profile-editor.js'), 'editor script NOT loaded for non-owner');
  ok(!other.text.includes('id="ev-edit-toggle"'), 'no Edit styles toggle for non-owner');
  ok(!other.text.includes('id="ev-fields"'), 'no profile fields block for non-owner');
  ok(other.text.includes('data-ev-slot="follow"') && /action="\/unfollow\/alice"/.test(other.text),
    'viewer-relative follow slot filled (Following form)');

  console.log('\nLegacy (v0) profile render (bob):');
  const legacy = await bob.get('/u/bob');
  ok(legacy.status === 200, 'legacy profile 200');
  ok(legacy.text.includes('LEGACY-CONTENT'), 'legacy authored content still rendered');
  ok(legacy.text.includes('data-ev-slot="posts"'), 'legacy content gets the default header + posts slot');

  console.log('\nSave endpoint authorization:');
  const anonPost = await fetch(base + '/u/alice/edit/visual', {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ html: '<p>x</p>', css: '' }),
  });
  ok(anonPost.status === 403, 'anon visual save rejected (CSRF enforced before auth)');

  const bobPost = await bob.post('/u/alice/edit/visual', {
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': bob.csrf },
    body: JSON.stringify({ html: '<p>x</p>', css: '' }),
  });
  ok(bobPost.status === 403, 'non-owner visual save is 403');

  const noCsrf = await alice.post('/u/alice/edit/visual', {
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
    body: JSON.stringify({ html: '<p>x</p>', css: '' }),
  });
  ok(noCsrf.status === 403, 'missing CSRF on visual save is 403');

  console.log('\nVisual save (alice) sanitizes and adopts v1:');
  const dirty = '<div data-ev-slot="posts"></div><p onclick="x()">Hi<script>alert(1)</script></p>';
  const save = await alice.post('/u/alice/edit/visual', {
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': alice.csrf },
    body: JSON.stringify({ html: dirty, css: 'body { color: red; }' }),
  });
  const saveJson = await save.json().catch(() => ({}));
  ok(save.status === 200 && saveJson.ok === true, 'owner visual save returns {ok:true}');

  const stored = db.getCustomization(aliceId);
  ok(stored.template_version === 1, 'template_version set to 1 on save');
  ok(!/script/i.test(stored.html), '<script> stripped from stored html');
  ok(!/onclick/i.test(stored.html), 'onclick stripped from stored html');
  ok(/data-ev-slot="posts"/.test(stored.html), 'posts slot preserved through save round-trip');
  ok(/color: red/.test(stored.css), 'css stored');

  const afterSave = await alice.get('/u/alice');
  ok(afterSave.text.includes('hello from alice'), 'posts still injected after save');
  ok(!/<script>alert\(1\)<\/script>/.test(afterSave.text), 'injected script never reaches the page');

  console.log('\nEdit redirects into the in-page editor:');
  const editRedirect = await alice.get('/u/alice/edit');
  ok(editRedirect.status === 302, '/u/alice/edit redirects (302)');

  console.log('\nCustom font is declared and offered in the editor:');
  db.createUserFile({ userId: aliceId, kind: 'font', root: 'uploads', path: 'drive/test-font.ttf', mime: 'font/ttf', size: 1234, name: 'My Test Font.ttf' });
  db.setUserFont(aliceId, '/uploads/drive/test-font.ttf');
  const withFont = await alice.get('/u/alice');
  ok(/@font-face[^}]*font-family: 'My Test Font'/.test(withFont.text), 'owner page injects the @font-face');
  ok(withFont.text.includes('id="ev-font-face"'), 'custom font lives in its own style element');
  const editableCss = (withFont.text.match(/<style id="ev-user-css">([\s\S]*?)<\/style>/) || [])[1] || '';
  ok(!/@font-face/.test(editableCss), 'the editable stylesheet stays free of the injected @font-face');
  ok(withFont.text.includes('/u/alice/font?v='), '@font-face points at the stable font URL');
  ok(withFont.text.includes('data-font-family="My Test Font"'), 'font family exposed to the editor');
  const visitorView = await bob.get('/u/alice');
  ok(/@font-face[^}]*font-family: 'My Test Font'/.test(visitorView.text), 'visitors get the custom font too');

  console.log('\nProfile fields save (auto-save endpoint):');
  const fieldsSave = await alice.post('/u/alice/edit/profile', {
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': alice.csrf },
    body: JSON.stringify({ displayName: 'Alice Prime', bio: 'new bio', effect: 'glitch', pronoun: ['they/them'] }),
  });
  ok(fieldsSave.status === 200, 'owner profile-field save returns 200');
  const aliceRow = db.getUserByUsername('alice');
  ok(aliceRow.bio === 'new bio' && aliceRow.display_name === 'Alice Prime', 'name + bio updated');
  ok(db.getCustomization(aliceId).effect === 'glitch', 'effect updated');
  ok(/data-ev-slot="posts"/.test(db.getCustomization(aliceId).html), 'profile-field save did not clobber the HTML');

  const fieldsDenied = await bob.post('/u/alice/edit/profile', {
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': bob.csrf },
    body: JSON.stringify({ displayName: 'Nope' }),
  });
  ok(fieldsDenied.status === 403, 'non-owner profile-field save is 403');

  console.log('\nOff-profile: posts carry their author\'s style');
  db.setCustomization(aliceId, '<div data-ev-slot="posts"></div>', '.post-body { color: red; } body { font-family: serif; }', '', 1);
  const feed = await bob.get('/');
  ok(feed.text.includes('<style id="ev-post-scope">'), 'feed injects scoped post CSS');
  ok(feed.text.includes('data-ev-author="alice"'), "feed wraps alice's post in a scope");
  ok(/\.ev-scope\[data-ev-author="alice"\] \.post-body/.test(feed.text), "author's rule is scoped to their posts");
  ok(/\.ev-scope\[data-ev-author="alice"\]\{/.test(feed.text), 'body rule remapped onto the post wrapper');
  ok(/@font-face\s*\{[^}]*font-family: 'ev-alice'/.test(feed.text), 'custom font injected with a per-author family');
  const prof = await alice.get('/u/alice');
  ok(!prof.text.includes('ev-post-scope'), 'the profile page itself is not scoped-injected');

  console.log('\nReset customizations:');
  db.setCustomization(aliceId, '<div data-ev-slot="posts"></div>', '.post { color: red; }', 'glitch', 1);
  const reset = await alice.post('/u/alice/edit/reset', {
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': alice.csrf },
    body: '{}',
  });
  ok(reset.status === 200, 'owner reset returns 200');
  const afterReset = db.getCustomization(aliceId);
  ok(afterReset.html === '' && afterReset.css === '' && afterReset.effect === '' && afterReset.template_version === 0,
    'customization (html/css/effect/version) cleared');
  const aliceAfterReset = db.getUserByUsername('alice');
  ok(aliceAfterReset.display_name === 'Alice Prime' && aliceAfterReset.bio === 'new bio',
    'reset keeps the normal profile fields');
  const resetDenied = await bob.post('/u/alice/edit/reset', {
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': bob.csrf },
    body: '{}',
  });
  ok(resetDenied.status === 403, 'non-owner reset is 403');

  console.log(failures ? '\nPROFILE EDITOR TEST FAILED' : '\nPROFILE EDITOR TEST PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch(err => { console.error(err); process.exit(1); });
