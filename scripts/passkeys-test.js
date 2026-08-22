'use strict';
// F3 passkeys (WebAuthn) integration test.
// Hand-builds ES256 credentials/assertions with node:crypto (no browser):
//   - registration ceremony completes and stores the credential
//   - passkey login issues a FULL session without any TOTP step
//   - challenge reuse (replay) is rejected
//   - stale signature counters are rejected (cloned-authenticator guard)
//   - unknown credentials are rejected
//   - cap of 10 passkeys per account
// Run: npm run test:passkeys

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-passkeys-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'e.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 's.db');
process.env.SESSION_SECRET = 'passkeys-test-secret';
process.env.PORT = String(35600 + Math.floor(Math.random() * 1000));
process.env.TOTP_ENCRYPTION_KEY = 'passkeys-test-key';
process.env.EXTV_SECOND_FACTOR_RATE_LIMIT = '10000';
process.env.EXTV_AUTH_RATE_LIMIT = '10000';

const app = require('../src/server');
const db = require('../src/db');

let failures = 0;
function ok(cond, msg) { console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg); if (!cond) failures++; }

// ---------- minimal CBOR encoder (subset sufficient for COSE/WebAuthn) ----------
function cborEncode(value) {
  const parts = [];
  encode(value, parts);
  return Buffer.concat(parts);
}
function head(major, val) {
  if (val < 24) return Buffer.from([(major << 5) | val]);
  if (val < 0x100) return Buffer.from([(major << 5) | 24, val]);
  if (val < 0x10000) {
    const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(val, 1); return b;
  }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(val, 1); return b;
}
function encode(value, parts) {
  if (Buffer.isBuffer(value)) {
    parts.push(head(2, value.length)); parts.push(value);
  } else if (typeof value === 'number') {
    if (value >= 0) parts.push(head(0, value));
    else parts.push(head(1, -value - 1));
  } else if (typeof value === 'string') {
    const b = Buffer.from(value, 'utf8');
    parts.push(head(3, b.length)); parts.push(b);
  } else if (Array.isArray(value)) {
    parts.push(head(4, value.length));
    for (const v of value) encode(v, parts);
  } else if (typeof value === 'object' && value !== null) {
    const keys = Object.keys(value);
    parts.push(head(5, keys.length));
    for (const k of keys) { encode(Number(k) !== undefined && !isNaN(Number(k)) ? Number(k) : k, parts); encode(value[k], parts); }
  }
}

// ---------- WebAuthn artifact builders ----------
const RP_ID = 'localhost';
function b64u(buf) { return Buffer.from(buf).toString('base64url'); }

function es256CoseKey(publicKeyJwk) {
  // COSE EC2: {1: kty=EC2(2), 3: alg=ES256(-7), -1: crv=P-256(1), -2: x, -3: y}
  return cborEncode({
    1: 2,
    3: -7,
    '-1': 1,
    '-2': Buffer.from(publicKeyJwk.x, 'base64url'),
    '-3': Buffer.from(publicKeyJwk.y, 'base64url'),
  });
}

function buildAuthData({ flags, counter, attested }) {
  const rpIdHash = crypto.createHash('sha256').update(RP_ID).digest();
  const buf = Buffer.alloc(37);
  rpIdHash.copy(buf, 0);
  buf[32] = flags;
  buf.writeUInt32BE(counter || 0, 33);
  if (!attested) return buf;
  // attestedCredentialData: aaguid(16 zeros) + credIdLen + credId + coseKey
  const credId = Buffer.from(attested.credId, 'base64url');
  const len = Buffer.alloc(2); len.writeUInt16BE(credId.length);
  return Buffer.concat([buf, Buffer.alloc(16), len, credId, attested.coseKey]);
}

function clientData(type, challenge) {
  return Buffer.from(JSON.stringify({
    type,
    challenge,
    origin: 'http://localhost:' + process.env.PORT,
    crossOrigin: false,
  }));
}

// A fresh virtual authenticator credential.
function makeCredential() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  return {
    credId: crypto.randomBytes(32).toString('base64url'),
    coseKey: es256CoseKey(jwk),
    privateKey,
    counter: 0,
  };
}

// Registration response (attestation fmt 'none') — same shape a browser sends.
function buildAttestation(cred, challenge) {
  const authData = buildAuthData({ flags: 0x45, counter: 0, attested: cred }); // UP|UV|AT
  const attObj = cborEncode({ fmt: 'none', attStmt: {}, authData });
  return {
    id: cred.credId,
    rawId: cred.credId,
    type: 'public-key',
    response: {
      clientDataJSON: b64u(clientData('webauthn.create', challenge)),
      attestationObject: b64u(attObj),
    },
  };
}

// Authentication assertion signed with the credential's private key.
function signAssertion(cred, challenge, { counter, stale } = {}) {
  const c = counter !== undefined ? counter : ++cred.counter;
  const authData = buildAuthData({ flags: 0x05, counter: c }); // UP|UV
  const cdj = clientData('webauthn.get', challenge);
  const signed = crypto.createHash('sha256').update(cdj).digest();
  const toSign = Buffer.concat([authData, signed]);
  const sig = crypto.sign('sha256', toSign, cred.privateKey);
  void stale;
  return {
    id: cred.credId,
    rawId: cred.credId,
    type: 'public-key',
    response: {
      clientDataJSON: b64u(cdj),
      authenticatorData: b64u(authData),
      signature: b64u(sig),
      userHandle: null,
    },
  };
}

// ---------- HTTP helpers (cookie-jar web session) ----------
function makeWebSession() {
  const jar = {};
  async function withCookie(url, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (jar.cookie) headers['Cookie'] = jar.cookie;
    const r = await fetch('http://localhost:' + process.env.PORT + url, { ...opts, headers, redirect: 'manual' });
    for (const c of (r.headers.getSetCookie ? r.headers.getSetCookie() : [])) {
      if (c.startsWith('connect.sid=')) jar.cookie = c.split(';')[0];
      if (c.startsWith('extv_td=')) jar.td = jar.td && jar.td !== 'cleared' ? jar.td : c.split(';')[0];
      if (c.startsWith('extv_td=;')) jar.td = 'cleared';
    }
    return r;
  }
  async function postJson(url, body, { authedCsrf } = {}) {
    const headers = { 'Content-Type': 'application/json' };
    let token = authedCsrf;
    if (!token) {
      // Authenticated pages carry the meta tag; /login works pre-auth.
      const grab = async (path) => {
        const html = await withCookie(path).then((x) => x.text());
        return (html.match(/name="csrf-token" content="([^"]+)"/) || [])[1]
          || (html.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
      };
      token = await grab('/settings/security');
      if (!token) token = await grab('/login');
    }
    headers['X-CSRF-Token'] = token;
    return withCookie(url, { method: 'POST', headers, body: JSON.stringify(body || {}) });
  }
  async function getCsrf(pathname) {
    const html = await withCookie(pathname).then((x) => x.text());
    return (html.match(/name="_csrf" value="([^"]+)"/) || [])[1] || '';
  }
  async function postForm(url, bodyObj) {
    return withCookie(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(bodyObj).toString(),
    });
  }
  async function login(username, password) {
    const r = await postForm('/login', { username, password, _csrf: await getCsrf('/login') });
    return r;
  }
  return { jar, withCookie, postJson, getCsrf, postForm, login };
}

async function main() {
  const uid = db.createUser({ username: 'pkey', passwordHash: bcrypt.hashSync('pw-pkey', 10), displayName: 'Passkey User' });

  // ---- TEST 1: unauthenticated ceremonies are rejected ----
  console.log('\nTEST 1: registration requires an authenticated session');
  const s = makeWebSession();
  let r = await s.postJson('/passkeys/register/begin', {});
  ok(r.status === 302, 'register/begin redirects anonymous users to login');

  // ---- TEST 2: full registration ceremony ----
  console.log('\nTEST 2: registration ceremony');
  await s.login('pkey', 'pw-pkey');
  r = await s.postJson('/passkeys/register/begin', {});
  ok(r.status === 200, 'register/begin returns options');
  const regOpts = await r.json();
  ok(typeof regOpts.challenge === 'string' && regOpts.challenge.length >= 32, 'options carry a challenge');
  const cred = makeCredential();
  r = await s.postJson('/passkeys/register/complete', buildAttestation(cred, regOpts.challenge));
  ok(r.status === 200, 'register/complete verifies the attestation');
  const stored = db.getPasskeyByCredentialId(cred.credId);
  ok(!!stored && stored.user_id === uid, 'credential stored for the right account');
  ok(stored.counter === 0, 'counter initialized to 0');

  // Challenge single-use:
  r = await s.postJson('/passkeys/register/complete', buildAttestation(cred, regOpts.challenge));
  ok(r.status === 400, 'registration challenge cannot be reused');

  // ---- TEST 3: passkey login issues a full session (NO TOTP step) ----
  console.log('\nTEST 3: passwordless login');
  const s2 = makeWebSession();
  r = await s2.postJson('/passkeys/auth/options', {});
  ok(r.status === 200, 'auth/options works anonymously (discoverable flow)');
  const authOpts = await r.json();
  const assertion = signAssertion(cred, authOpts.challenge);
  r = await s2.postJson('/passkeys/auth/verify', assertion);
  ok(r.status === 200, 'auth/verify accepts a valid assertion');
  ok(await s2.withCookie('/settings/security').then((x) => x.status === 200), 'passkey login yields a real session');
  const row = db.getPasskeyByCredentialId(cred.credId);
  ok(row.counter === 1 && row.last_used_at > 0, 'counter advanced and last_used_at touched');

  // Challenge reuse (replay) is rejected:
  r = await s2.postJson('/passkeys/auth/verify', assertion);
  ok(r.status === 400, 'same assertion cannot be replayed (single-use challenge)');

  // ---- TEST 4: stale counter rejected (cloned-authenticator guard) ----
  console.log('\nTEST 4: cloned-authenticator guard');
  db.updatePasskeyCounter(row.id, 100); // simulate the authenticator being ahead
  const s3 = makeWebSession();
  const opts3 = await (await s3.postJson('/passkeys/auth/options', {})).json();
  r = await s3.postJson('/passkeys/auth/verify', signAssertion(cred, opts3.challenge, { counter: 50 }));
  ok(r.status === 401, 'assertion whose counter went BACKWARDS is rejected');
  ok(!db.getPasskeyByCredentialId(cred.credId).last_used_at ||
      db.getPasskeyByCredentialId(cred.credId).counter === 100, 'stale assertion did not update state');

  // ---- TEST 5: unknown credential rejected with generic message ----
  console.log('\nTEST 5: unknown credential');
  const stranger = makeCredential();
  const s4 = makeWebSession();
  const opts4 = await (await s4.postJson('/passkeys/auth/options', {})).json();
  r = await s4.postJson('/passkeys/auth/verify', signAssertion(stranger, opts4.challenge));
  const errBody = await r.json().catch(() => null);
  ok(r.status === 401, 'unknown credential gets 401');
  ok(errBody && errBody.error && errBody.error.message === 'Invalid username or password.', 'error text is generic (no oracle)');

  // ---- TEST 6: tampered signature rejected ----
  console.log('\nTEST 6: tampered signature');
  const s5 = makeWebSession();
  const opts5 = await (await s5.postJson('/passkeys/auth/options', {})).json();
  const bad = signAssertion(cred, opts5.challenge);
  bad.signature = Buffer.from('ff' + crypto.randomBytes(15).toString('hex'), 'hex').toString('base64url');
  r = await s5.postJson('/passkeys/auth/verify', bad);
  ok(r.status === 401, 'corrupted signature rejected');

  // ---- TEST 7: passkey-only account needs NO TOTP even when TOTP also enabled ----
  console.log('\nTEST 7: passkey login bypasses TOTP by design');
  // Resync the stored counter (TEST 4 deliberately desynced it to simulate a
  // cloned authenticator) so this credential can authenticate again.
  db.updatePasskeyCounter(row.id, cred.counter);
  const secret = (() => {
    const twofa = require('../src/twofa');
    const sec = twofa.generateTotpSecret();
    db.setTotpSecret(uid, twofa.encryptSecret(sec));
    db.setTotpEnabled(uid, Date.now());
    return sec;
  })();
  const s6 = makeWebSession();
  const opts6 = await (await s6.postJson('/passkeys/auth/options', {})).json();
  r = await s6.postJson('/passkeys/auth/verify', signAssertion(cred, opts6.challenge));
  ok(r.status === 200, 'passkey login succeeds even with TOTP enrolled');
  ok(await s6.withCookie('/').then((x) => x.status === 200), 'full session without ever entering a code');
  // Clean up the enrollment so later tests aren't affected.
  db.setTotpSecret(uid, null);
  db.setTotpEnabled(uid, null);

  // ---- TEST 8: rename/delete via settings routes ----
  console.log('\nTEST 8: management endpoints');
  const csrfSec = await s.getCsrf('/settings/security');
  r = await s.postForm(`/settings/security/passkeys/${row.id}/rename`, { _csrf: csrfSec, device_name: 'Test Key' });
  ok(r.status === 302, 'rename redirects back');
  ok(db.getPasskeyByCredentialId(cred.credId).device_name === 'Test Key', 'device_name updated');
  // Cap: fill up to 10 then expect rejection at begin.
  for (let i = db.countPasskeys(uid); i < 10; i++) {
    const c = makeCredential();
    const o = await (await s.postJson('/passkeys/register/begin', {})).json();
    await s.postJson('/passkeys/register/complete', buildAttestation(c, o.challenge));
  }
  ok(db.countPasskeys(uid) === 10, '10 passkeys registered');
  r = await s.postJson('/passkeys/register/begin', {});
  ok(r.status === 400, '11th passkey refused at begin');
  r = await s.postForm(`/settings/security/passkeys/${row.id}/delete`, { _csrf: csrfSec });
  ok(r.status === 302 && !db.getPasskeyByCredentialId(cred.credId), 'delete removes the credential');

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL PASSKEY TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
