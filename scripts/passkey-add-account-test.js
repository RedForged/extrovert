'use strict';
// Focused end-to-end: signing in with a PASSKEY while already signed in ADDS
// the account to the device list (the "Add another account" passkey flow),
// rather than replacing it. Reuses the proven WebAuthn builders from
// scripts/passkeys-test.js. Run: node scripts/passkey-add-account-test.js
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-pkadd-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'pkadd-secret';
process.env.PORT = String(35700 + Math.floor(Math.random() * 1000));
process.env.TOTP_ENCRYPTION_KEY = 'pkadd-key';
process.env.EXTV_SECOND_FACTOR_RATE_LIMIT = '10000';
process.env.EXTV_AUTH_RATE_LIMIT = '10000';

const app = require('../src/server');
const db = require('../src/db');

let failures = 0;
function ok(cond, msg) { console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg); if (!cond) failures++; }

// --- minimal CBOR + WebAuthn builders (mirror passkeys-test.js) ---
function cborEncode(value) { const parts = []; encode(value, parts); return Buffer.concat(parts); }
function head(major, val) {
  if (val < 24) return Buffer.from([(major << 5) | val]);
  if (val < 0x100) return Buffer.from([(major << 5) | 24, val]);
  if (val < 0x10000) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(val, 1); return b; }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(val, 1); return b;
}
function encode(value, parts) {
  if (Buffer.isBuffer(value)) { parts.push(head(2, value.length)); parts.push(value); }
  else if (typeof value === 'number') { if (value >= 0) parts.push(head(0, value)); else parts.push(head(1, -value - 1)); }
  else if (typeof value === 'string') { const b = Buffer.from(value, 'utf8'); parts.push(head(3, b.length)); parts.push(b); }
  else if (Array.isArray(value)) { parts.push(head(4, value.length)); for (const v of value) encode(v, parts); }
  else if (typeof value === 'object' && value !== null) { const keys = Object.keys(value); parts.push(head(5, keys.length)); for (const k of keys) { encode(Number(k) !== undefined && !isNaN(Number(k)) ? Number(k) : k, parts); encode(value[k], parts); } }
}
const RP_ID = 'localhost';
const b64u = (buf) => Buffer.from(buf).toString('base64url');
function es256CoseKey(jwk) { return cborEncode({ 1: 2, 3: -7, '-1': 1, '-2': Buffer.from(jwk.x, 'base64url'), '-3': Buffer.from(jwk.y, 'base64url') }); }
function buildAuthData({ flags, counter, attested }) {
  const rpIdHash = crypto.createHash('sha256').update(RP_ID).digest();
  const buf = Buffer.alloc(37); rpIdHash.copy(buf, 0); buf[32] = flags; buf.writeUInt32BE(counter || 0, 33);
  if (!attested) return buf;
  const credId = Buffer.from(attested.credId, 'base64url');
  const len = Buffer.alloc(2); len.writeUInt16BE(credId.length);
  return Buffer.concat([buf, Buffer.alloc(16), len, credId, attested.coseKey]);
}
function clientData(type, challenge) { return Buffer.from(JSON.stringify({ type, challenge, origin: 'http://localhost:' + process.env.PORT, crossOrigin: false })); }
function makeCredential() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  return { credId: crypto.randomBytes(32).toString('base64url'), coseKey: es256CoseKey(jwk), privateKey, counter: 0 };
}
function buildAttestation(cred, challenge) {
  const authData = buildAuthData({ flags: 0x45, counter: 0, attested: cred });
  const attObj = cborEncode({ fmt: 'none', attStmt: {}, authData });
  return { id: cred.credId, rawId: cred.credId, type: 'public-key', response: { clientDataJSON: b64u(clientData('webauthn.create', challenge)), attestationObject: b64u(attObj) } };
}
function signAssertion(cred, challenge) {
  const c = ++cred.counter;
  const authData = buildAuthData({ flags: 0x05, counter: c });
  const cdj = clientData('webauthn.get', challenge);
  const toSign = Buffer.concat([authData, crypto.createHash('sha256').update(cdj).digest()]);
  const sig = crypto.sign('sha256', toSign, cred.privateKey);
  return { id: cred.credId, rawId: cred.credId, type: 'public-key', response: { clientDataJSON: b64u(cdj), authenticatorData: b64u(authData), signature: b64u(sig), userHandle: null } };
}
function makeWebSession() {
  const jar = {};
  async function withCookie(url, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (jar.cookie) headers['Cookie'] = jar.cookie;
    const r = await fetch('http://localhost:' + process.env.PORT + url, { ...opts, headers, redirect: 'manual' });
    for (const c of (r.headers.getSetCookie ? r.headers.getSetCookie() : [])) if (c.startsWith('connect.sid=')) jar.cookie = c.split(';')[0];
    return r;
  }
  async function postJson(url, body) {
    const html = await withCookie('/settings/security').then((x) => x.text());
    let token = (html.match(/name="csrf-token" content="([^"]+)"/) || [])[1];
    if (!token) token = await withCookie('/login').then((x) => x.text()).then((h) => (h.match(/name="_csrf" value="([^"]+)"/) || [])[1]);
    return withCookie(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token }, body: JSON.stringify(body || {}) });
  }
  async function getCsrf(p) { return withCookie(p).then((x) => x.text()).then((h) => (h.match(/name="_csrf" value="([^"]+)"/) || [])[1] || ''); }
  async function postForm(url, b) { return withCookie(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(b).toString() }); }
  async function login(u, p) { return postForm('/login', { username: u, password: p, _csrf: await getCsrf('/login') }); }
  async function follow(url, max = 5) { let cur = url; for (let i = 0; i < max; i++) { const r = await withCookie(cur); if (r.status >= 300 && r.status < 400 && r.headers.get('location')) { cur = new URL(r.headers.get('location'), 'http://localhost:' + process.env.PORT).pathname; continue; } return r; } return withCookie(cur); }
  return { jar, withCookie, postJson, getCsrf, postForm, login, follow };
}

async function registerPasskey(session, username, password) {
  // login, register a credential, return { session, cred }
  await session.login(username, password);
  const regOpts = await (await session.postJson('/passkeys/register/begin', {})).json();
  const cred = makeCredential();
  const r = await session.postJson('/passkeys/register/complete', buildAttestation(cred, regOpts.challenge));
  if (r.status !== 200) throw new Error('register/complete failed: ' + r.status);
  return cred;
}

async function main() {
  const alice = db.createUser({ username: 'alice', passwordHash: bcrypt.hashSync('pw', 10), displayName: 'Alice' });
  const bob = db.createUser({ username: 'bob', passwordHash: bcrypt.hashSync('pw', 10), displayName: 'Bob' });

  // Session A: alice signs in with password, then registers a passkey.
  console.log('\nTEST: passkey add-account while signed in');
  const sa = makeWebSession();
  const aliceCred = await registerPasskey(sa, 'alice', 'pw');
  ok(true, 'alice registered a passkey');

  // Confirms sa is signed in as alice only.
  let html = await sa.withCookie('/account/switch').then((x) => x.text());
  ok(html.includes('@alice') && !html.includes('@bob'), 'before add: only alice signed in');

  // Now "Add another account" as bob via PASSKEY (same session sa).
  // Bob needs a passkey registered too -> use a fresh session for bob's registration.
  const sb = makeWebSession();
  const bobCred = await registerPasskey(sb, 'bob', 'pw');
  ok(true, 'bob registered a passkey');

  // Bob authenticates into session sa (browser navigating to /login?add=1, passkey).
  const authOpts = await (await sa.postJson('/passkeys/auth/options', {})).json();
  const assertion = signAssertion(bobCred, authOpts.challenge);
  const vr = await sa.postJson('/passkeys/auth/verify', assertion);
  ok(vr.status === 200, 'passkey /auth/verify accepted bob');

  html = await sa.withCookie('/account/switch').then((x) => x.text());
  ok(html.includes('@alice') && html.includes('@bob'), 'after passkey add: both alice and bob signed in');
  ok(html.includes('@bob') && /\bActive\b/.test(html), 'bob is marked active after add-account passkey');

  console.log('\n' + (failures === 0 ? 'ALL PASSKEY ADD-ACCOUNT TESTS PASSED' : failures + ' FAILURE(S)'));
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
