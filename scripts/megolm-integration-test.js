// Room Megolm E2EE integration test over the real HTTP API.
// Exercises: room group session publish -> pending key fetch -> encrypted send ->
// plaintext send rejection -> message fetch returns ciphertext fields.
// Run: node scripts/megolm-integration-test.js
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// Point the app at a throwaway data dir so we don't touch the dev DB.
const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-megolm-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'extrovert.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 'sessions.db');
process.env.SESSION_SECRET = 'megolm-integration-test-secret';
process.env.SECRET = 'megolm-integration-test-secret';

const app = require('../src/server');
const db = require('../src/db');
const Olm = require('@matrix-org/olm');

let failures = 0;
function ok(cond, msg) { console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg); if (!cond) failures++; }

function identityKeys(account) {
  const k = JSON.parse(account.identity_keys());
  return { curve25519: k.curve25519, ed25519: k.ed25519 };
}
function oneTimeKeys(account) {
  const k = JSON.parse(account.one_time_keys());
  return Object.keys(k.curve25519).map(id => ({ id, key: k.curve25519[id] }));
}

async function main() {
  await Olm.init({ wasmBinary: fs.readFileSync(require.resolve('@matrix-org/olm/olm.wasm')) });

  const server = await new Promise(resolve => {
    const s = app.listen(0, () => resolve(s));
  });
  const base = 'http://localhost:' + server.address().port;

  // Users + OAuth tokens
  const aliceId = db.createUser({ username: 'alice', passwordHash: 'x', displayName: 'Alice' });
  const bobId = db.createUser({ username: 'bob', passwordHash: 'x', displayName: 'Bob' });
  db.createOAuthApp({ name: 't', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'c1', clientSecret: 's1', scopes: 'read write follow read:direct write:direct', ownerId: aliceId });
  db.createOAuthApp({ name: 't2', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'c2', clientSecret: 's2', scopes: 'read write follow read:direct write:direct', ownerId: bobId });
  const atok = crypto.randomBytes(32).toString('hex');
  const btok = crypto.randomBytes(32).toString('hex');
  db.createOAuthToken(atok, null, db.getOAuthAppByClientId('c1').id, aliceId, 'read write follow read:direct write:direct', Date.now() + 86400000);
  db.createOAuthToken(btok, null, db.getOAuthAppByClientId('c2').id, bobId, 'read write follow read:direct write:direct', Date.now() + 86400000);

  async function api(url, opts = {}) {
    const headers = { Authorization: 'Bearer ' + opts.token };
    if (opts.body) headers['Content-Type'] = 'application/json';
    const r = await fetch(base + url, { method: opts.method || 'GET', headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
    return { status: r.status, json: await r.json().catch(() => null) };
  }

  // Set up Olm accounts for both users, publish identities + prekeys.
  const aliceAcc = new Olm.Account(); aliceAcc.create(); aliceAcc.generate_one_time_keys(10); aliceAcc.generate_fallback_key();
  const bobAcc = new Olm.Account(); bobAcc.create(); bobAcc.generate_one_time_keys(10); bobAcc.generate_fallback_key();
  const aliceIdKeys = identityKeys(aliceAcc), bobIdKeys = identityKeys(bobAcc);

  await api('/api/v1/conversations/prekeys', { token: atok, method: 'POST', body: {
    identity_key: aliceIdKeys.curve25519, ed25519_key: aliceIdKeys.ed25519, fallback_key: JSON.parse(aliceAcc.fallback_key()).curve25519[Object.keys(JSON.parse(aliceAcc.fallback_key()).curve25519)[0]],
    one_time_keys: oneTimeKeys(aliceAcc).map(k => ({ id: k.id, public_key: k.key })),
  }});
  await api('/api/v1/conversations/prekeys', { token: btok, method: 'POST', body: {
    identity_key: bobIdKeys.curve25519, ed25519_key: bobIdKeys.ed25519, fallback_key: JSON.parse(bobAcc.fallback_key()).curve25519[Object.keys(JSON.parse(bobAcc.fallback_key()).curve25519)[0]],
    one_time_keys: oneTimeKeys(bobAcc).map(k => ({ id: k.id, public_key: k.key })),
  }});

  // Create a room, alice founder, add bob as member.
  const roomId = db.createRoom('Secret Room', '', aliceId, 0);
  db.addRoomMember(roomId, bobId, db.joinDefaultRole(roomId).id);

  // ---- Alice publishes her Megolm outbound session, wrapping the key to Bob ----
  const outbound = new Olm.OutboundGroupSession();
  outbound.create();
  const megolmKey = outbound.session_key();

  // Alice fetches Bob's bundle (room-scoped, no mutual-follower needed — they're not mutual).
  const bundle = await api(`/api/v1/rooms/${roomId}/bundle/bob`, { token: atok });
  ok(bundle.status === 200 && bundle.json.data && bundle.json.data.identity_key, 'room-scoped bundle fetch works without mutual follow');

  // Alice creates a 1:1 session to Bob and wraps the Megolm key.
  const a2b = new Olm.Session();
  a2b.create_outbound(aliceAcc, bundle.json.data.identity_key, bundle.json.data.one_time_key ? bundle.json.data.one_time_key.public_key : bundle.json.data.fallback_key);
  const wrapped = a2b.encrypt(megolmKey);

  const pub = await api(`/api/v1/rooms/${roomId}/session`, { token: atok, method: 'POST', body: {
    keys: [{ recipient_id: bobId, encrypted_key: JSON.stringify({ t: wrapped.type, b: wrapped.body }) }],
    member_ids: [aliceId, bobId],
  }});
  ok(pub.status === 200 && pub.json.data && pub.json.data.session_id, 'group session publish returns session_id');
  const sessionId = pub.json.data.session_id;

  // Rotation: a fresh publish with rotate=true must issue a NEW session id.
  const rot = await api(`/api/v1/rooms/${roomId}/session`, { token: atok, method: 'POST', body: {
    keys: [], member_ids: [aliceId, bobId], rotate: true,
  }});
  ok(rot.status === 200 && rot.json.data.session_id && String(rot.json.data.session_id) !== String(sessionId), 'rotation issues a new session id');

  // Re-publish the real session key under the rotated id, then send with it.
  const pub2 = await api(`/api/v1/rooms/${roomId}/session`, { token: atok, method: 'POST', body: {
    keys: [{ recipient_id: bobId, encrypted_key: JSON.stringify({ t: wrapped.type, b: wrapped.body }) }],
    member_ids: [aliceId, bobId],
  }});
  const sessionId2 = pub2.json.data.session_id;
  ok(String(sessionId2) === String(rot.json.data.session_id), 're-publish without rotate keeps the rotated session id');
  ok(String(sessionId2) !== String(sessionId), 'rotated id differs from the original');

  // ---- Bob fetches pending keys ----
  // Rotation now RETAINS the previous session's undelivered keys (P1-9), so Bob
  // sees the key from BOTH the original and the rotated session.
  const pending = await api(`/api/v1/rooms/${roomId}/session/keys`, { token: btok });
  ok(pending.status === 200 && pending.json.data.keys.length === 2, 'Bob sees 2 pending session keys (old session retained on rotate)');

  // Bob decrypts the wrapped key with an inbound session from the prekey message.
  const b2a = new Olm.Session();
  b2a.create_inbound(bobAcc, wrapped.body);
  bobAcc.remove_one_time_keys(b2a);
  const key = b2a.decrypt(wrapped.type, wrapped.body);
  ok(key === megolmKey, 'Bob recovers the exact Megolm key via 1:1 Olm');
  const inbound = new Olm.InboundGroupSession();
  inbound.create(key);

  // Bob marks delivered.
  await api(`/api/v1/rooms/${roomId}/session/keys/delivered`, { token: btok, method: 'POST', body: { key_ids: pending.json.data.keys.map(k => k.key_id) } });
  const pending2 = await api(`/api/v1/rooms/${roomId}/session/keys`, { token: btok });
  ok(pending2.json.data.keys.length === 0, 'delivered keys no longer pending');

  // ---- Alice sends an encrypted room message ----
  const ct = outbound.encrypt('top secret room message');
  const msgRes = await api(`/api/v1/rooms/${roomId}/channels/${db.getRoomChannels(roomId)[0].id}/messages`, { token: atok, method: 'POST', body: {
    proto: 'megolm', ciphertext: ct, group_session_id: String(sessionId2),
  }});
  ok(msgRes.status === 201, 'encrypted room message accepted');

  // ---- Plaintext room message is rejected ----
  const plainRes = await api(`/api/v1/rooms/${roomId}/channels/${db.getRoomChannels(roomId)[0].id}/messages`, { token: atok, method: 'POST', body: {
    body: 'this is plaintext and must be rejected',
  }});
  ok(plainRes.status === 400, 'plaintext room message rejected (400)');

  // ---- Bob can read the message ciphertext + decrypt it ----
  const msgs = await api(`/api/v1/rooms/${roomId}/channels/${db.getRoomChannels(roomId)[0].id}/messages`, { token: btok });
  const m = msgs.json.data.messages.find(x => x.id === String(msgRes.json.data.id));
  ok(m && m.proto === 'megolm' && m.ciphertext, 'message stored with proto + ciphertext');
  const plain = m ? inbound.decrypt(m.ciphertext).plaintext : null;
  ok(plain === 'top secret room message', 'Bob decrypts the room message end-to-end');

  server.close();
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL MEGOLM INTEGRATION CHECKS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch(err => { console.error(err); process.exit(1); });
