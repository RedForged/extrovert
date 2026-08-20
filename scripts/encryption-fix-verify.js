'use strict';
// Focused verification of the encryption-audit fixes against a live server.
// Covers: P0-1 (non-destructive bundle + claim + no pool drain on repeated
// sends), P0-3/P0-4 (rekey heal ack clears the flag), P1-7 (newest-first DM
// history + cursor), P2-13 (random per-account KEK salt), P2-14 (oversize
// ciphertext rejected), P1-8/P1-9/P1-10 (room key fanned out to every device
// incl. the sender's other device, and rotation keeps undelivered keys).
//
// Run: node scripts/encryption-fix-verify.js

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extv-fix-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'ext.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 'sessions.db');
process.env.SESSION_SECRET = 'fix-verify-secret';
process.env.SECRET = 'fix-verify-secret';
process.env.PORT = String(36000 + Math.floor(Math.random() * 500));

const app = require('../src/server');
const db = require('../src/db');

const PICKLE_KEY = 'extrovert-olm-pickle-v1';
let failures = 0;
function ok(cond, msg) {
  console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg);
  if (!cond) failures++;
}

// ---- One Olm device ----
class Device {
  constructor(username, userId, password) {
    this.username = username;
    this.userId = userId;
    this.password = password;
    this.deviceId = 'dev_' + crypto.randomBytes(6).toString('hex');
    this.cookie = '';
    this.csrf = '';
    this.account = null;
    this.myIdKeys = null;
    this.sessions = {}; // fullKey -> Olm.Session (in-memory)
    this.baselines = {}; // fullKey -> pickle
  }
  async login(base) {
    this.base = base;
    const page = await this.fetch('/login');
    const csrf = (await page.text()).match(/name="_csrf" value="([^"]+)"/)[1];
    await this.fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(this.username)}&password=${encodeURIComponent(this.password)}&_csrf=${encodeURIComponent(csrf)}`,
    });
    const chats = await this.fetch('/chats');
    this.csrf = (await chats.text()).match(/name="csrf-token" content="([^"]+)"/)[1];
  }
  async fetch(url, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (this.cookie) headers['Cookie'] = this.cookie;
    const r = await fetch(this.base + url, { ...opts, headers, redirect: 'manual' });
    const sc = r.headers.get('set-cookie');
    if (sc) this.cookie = sc.split(';')[0];
    return r;
  }
  async csrfFetch(url, opts = {}) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (opts.body && !opts.headers['Content-Type']) opts.headers['Content-Type'] = 'application/json';
    opts.headers['X-CSRF-Token'] = this.csrf;
    opts.headers['X-Requested-With'] = 'XMLHttpRequest';
    return this.fetch(url, opts);
  }
  async initCrypto() {
    this.account = new Olm.Account();
    this.account.create();
    this.account.generate_fallback_key();
    this.account.generate_one_time_keys(5);
    const k = JSON.parse(this.account.identity_keys());
    this.myIdKeys = { curve25519: k.curve25519, ed25519: k.ed25519 };
    await this.publish();
  }
  async publish() {
    const keys = JSON.parse(this.account.one_time_keys());
    const otks = Object.keys(keys.curve25519).map(id => ({ id, public_key: keys.curve25519[id] }));
    const fb = JSON.parse(this.account.fallback_key());
    const fbK = Object.keys(fb.curve25519 || {})[0];
    await this.csrfFetch('/chats/devices/register', {
      method: 'POST',
      body: JSON.stringify({
        device_id: this.deviceId,
        identity_key: this.myIdKeys.curve25519,
        ed25519_key: this.myIdKeys.ed25519,
        fallback_key: fb.curve25519[fbK],
        device_name: 'TestDevice',
        one_time_keys: otks,
      }),
    });
    this.account.mark_keys_as_published();
  }
  bundleFor(username) {
    return this.csrfFetch('/chats/' + encodeURIComponent(username) + '/bundle').then(r => r.json());
  }
  claimFor(username, deviceIds, senderDeviceIds) {
    const body = {};
    if (deviceIds) body.device_ids = deviceIds;
    if (senderDeviceIds) body.sender_device_ids = senderDeviceIds;
    return this.csrfFetch('/chats/' + encodeURIComponent(username) + '/claim', { method: 'POST', body: JSON.stringify(body) }).then(r => r.json());
  }
  roomBundleFor(roomId, username) {
    return this.csrfFetch('/rooms/' + encodeURIComponent(roomId) + '/bundle/' + encodeURIComponent(username)).then(r => r.json());
  }
  roomClaim(roomId, username, deviceIds) {
    return this.csrfFetch('/rooms/' + encodeURIComponent(roomId) + '/claim/' + encodeURIComponent(username), {
      method: 'POST', body: JSON.stringify({ device_ids: deviceIds }),
    }).then(r => r.json());
  }
  // Fixed-client outbound establishment for a single (peer, device).
  async establishOutbound(peerUsername, peerDeviceId, peerIdentityKey, peerFallbackKey) {
    const fullKey = String(this.userId) + ':' + peerDeviceId;
    if (this.sessions[fullKey]) return this.sessions[fullKey];
    const claimed = await this.claimFor(peerUsername, [peerDeviceId], null);
    const cd = (claimed.devices || []).find(d => d.device_id === peerDeviceId) || null;
    const idKey = cd ? cd.identity_key : peerIdentityKey;
    const otk = cd && cd.one_time_key ? cd.one_time_key.public_key : (cd ? cd.fallback_key : peerFallbackKey);
    const s = new Olm.Session();
    s.create_outbound(this.account, idKey, otk);
    this.baselines[fullKey] = s.pickle(PICKLE_KEY);
    this.sessions[fullKey] = s;
    return s;
  }
  // Room-scoped variant (uses /rooms/:id/claim — no mutual-follow req, so it
  // works for the sender's OWN other devices too).
  async establishRoomOutbound(roomId, username, dev) {
    const fullKey = String(this.userId) + ':' + dev.device_id;
    if (this.sessions[fullKey]) return this.sessions[fullKey];
    const claimed = await this.roomClaim(roomId, username, [dev.device_id]);
    const cd = (claimed.devices || []).find(d => d.device_id === dev.device_id) || dev;
    const idKey = cd.identity_key || dev.identity_key;
    const otk = cd && cd.one_time_key ? cd.one_time_key.public_key : (cd.fallback_key || dev.fallback_key);
    const s = new Olm.Session();
    s.create_outbound(this.account, idKey, otk);
    this.baselines[fullKey] = s.pickle(PICKLE_KEY);
    this.sessions[fullKey] = s;
    return s;
  }
  // Multi-device encrypt mirroring encryptOlm: per-device ciphertexts + self.
  async encryptDm(peer, plaintext) {
    const bundle = await this.bundleFor(peer.username);
    const recipients = bundle.devices || [];
    const senders = bundle.sender_devices || [];
    const cts = {};
    for (const dev of recipients) {
      const s = await this.establishOutbound(peer.username, dev.device_id, dev.identity_key, dev.fallback_key);
      const enc = s.encrypt(plaintext);
      cts[dev.device_id] = { t: enc.type, b: enc.body };
    }
    for (const dev of senders) {
      if (dev.device_id === this.deviceId) continue;
      const s = await this.establishOutbound(this.username, dev.device_id, dev.identity_key, dev.fallback_key);
      const enc = s.encrypt(plaintext);
      cts[dev.device_id] = { t: enc.type, b: enc.body };
    }
    const primary = recipients[0] ? recipients[0].device_id : 'default';
    const pc = cts[primary] || { t: 1, b: '' };
    return JSON.stringify({ v: 2, sender_device_id: this.deviceId, devices: cts, t: pc.t, b: pc.b });
  }
  // Fixed-client decrypt ladder (simplified: live -> baselines -> fresh PreKey).
  async decryptDm(envelopeStr, senderUserId, senderCurve) {
    const e = JSON.parse(envelopeStr);
    const myDevId = this.deviceId;
    let cipher = e;
    let senderDevId = 'default';
    if (e && e.v === 2 && e.devices) {
      senderDevId = e.sender_device_id || 'default';
      cipher = e.devices[myDevId] || (e.t !== undefined && e.b ? { t: e.t, b: e.b } : e.devices[Object.keys(e.devices)[0]]);
    }
    const fullKey = String(senderUserId) + ':' + senderDevId;
    // live
    let live = this.sessions[fullKey];
    if (live) {
      const pickle = live.pickle(PICKLE_KEY);
      try { return live.decrypt(cipher.t, cipher.b); } catch (_) { live = new Olm.Session(); live.unpickle(PICKLE_KEY, pickle); this.sessions[fullKey] = live; }
    }
    // baselines (list)
    const basePickle = this.baselines[fullKey];
    if (basePickle) {
      const b = new Olm.Session(); b.unpickle(PICKLE_KEY, basePickle);
      try { const p = b.decrypt(cipher.t, cipher.b); this.sessions[fullKey] = b; return p; } catch (_) {}
    }
    // fresh PreKey
    if (cipher.t === 0 || cipher.t === 2) {
      const ns = new Olm.Session();
      ns.create_inbound(this.account, cipher.b);
      this.account.remove_one_time_keys(ns);
      this.baselines[fullKey] = ns.pickle(PICKLE_KEY);
      const p = ns.decrypt(cipher.t, cipher.b);
      this.sessions[fullKey] = ns;
      return p;
    }
    throw new Error('No session for sender');
  }
  async sendDm(peer, plaintext) {
    const recipientCipher = await this.encryptDm(peer, plaintext);
    const usp = new URLSearchParams();
    usp.set('proto', 'olm');
    usp.set('body', recipientCipher);
    usp.set('sender_ciphertext', JSON.stringify({ t: 1, b: '' }));
    const r = await this.csrfFetch('/chats/' + encodeURIComponent(peer.username) + '/send', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: usp.toString(),
    });
    return r;
  }
}

async function main() {
  const OlmMod = require('@matrix-org/olm');
  const wasmPath = path.join(path.dirname(require.resolve('@matrix-org/olm/package.json')), 'olm.wasm');
  await OlmMod.init({ wasmBinary: fs.readFileSync(wasmPath) });
  global.Olm = OlmMod;

  const base = 'http://localhost:' + process.env.PORT;
  await new Promise(r => setTimeout(r, 300));

  function mkUser(username) {
    const id = db.createUser({ username, passwordHash: bcrypt.hashSync('pw', 10), displayName: username });
    return id;
  }
  function mkDevice(username, userId) {
    const d = new Device(username, userId, 'pw');
    return d;
  }

  // ===== DM churn (P0-1) =====
  console.log('\n=== P0-1: non-destructive bundle + claim + no pool drain ===');
  const aliceId = mkUser('alice');
  const bobId = mkUser('bob');
  db.follow(aliceId, bobId); db.follow(bobId, aliceId);
  const alice = mkDevice('alice', aliceId); await alice.login(base); await alice.initCrypto();
  const bob = mkDevice('bob', bobId); await bob.login(base); await bob.initCrypto();

  // Bundle is non-destructive: two reads return the SAME unclaimed OTK id.
  const b1 = await alice.bundleFor('bob');
  const b2 = await alice.bundleFor('bob');
  const otkId1 = b1.devices[0].one_time_key ? b1.devices[0].one_time_key.id : null;
  const otkId2 = b2.devices[0].one_time_key ? b2.devices[0].one_time_key.id : null;
  ok(otkId1 !== null, 'bundle returns an unclaimed OTK preview');
  ok(otkId1 === otkId2, 'two bundle reads return the same OTK id (non-destructive)');

  const availStart = db.countAvailableDevicePrekeys(bobId, bob.deviceId);
  // Claim consumes exactly one per call.
  const c1 = await alice.claimFor('bob', [bob.deviceId], null);
  const c2 = await alice.claimFor('bob', [bob.deviceId], null);
  const cid1 = c1.devices[0].one_time_key ? c1.devices[0].one_time_key.id : null;
  const cid2 = c2.devices[0].one_time_key ? c2.devices[0].one_time_key.id : null;
  ok(cid1 !== null && cid2 !== null, 'claim returns a one-time key each call');
  ok(cid1 !== cid2, 'two claims return different OTK ids (each consumes one)');
  const availAfterClaims = db.countAvailableDevicePrekeys(bobId, bob.deviceId);
  ok(availAfterClaims === availStart - 2, 'claim consumed exactly 2 prekeys (got ' + availAfterClaims + ', expected ' + (availStart - 2) + ')');

  // Repeated sends drain the pool by exactly ONE (session reused, no churn).
  // c1's OTK was consumed by the first PreKey; c2 is still in bob's account
  // (unconsumed) but claimed server-side. The first send establishes; the
  // next four reuse the session and claim nothing.
  const availBeforeSends = db.countAvailableDevicePrekeys(bobId, bob.deviceId);
  for (let i = 0; i < 5; i++) await alice.sendDm(bob, 'msg ' + i);
  const availAfterSends = db.countAvailableDevicePrekeys(bobId, bob.deviceId);
  // Establishing the session for bob's device claims once; the rest reuse.
  ok(availAfterSends === availBeforeSends - 1, '5 sends drained the pool by exactly 1 (got ' + (availBeforeSends - availAfterSends) + ')');

  // Bob decrypts all five (live session advances; no rotation).
  const msgs = db.getMessages(aliceId, bobId).filter(m => m.from_id === aliceId);
  let allOk = true;
  for (let i = 0; i < msgs.length; i++) {
    const p = await bob.decryptDm(msgs[i].body, aliceId, alice.myIdKeys.curve25519);
    if (p !== 'msg ' + i) allOk = false;
  }
  ok(allOk, 'bob decrypts all 5 messages through the reused session');

  // ===== Rekey heal (P0-3/P0-4) =====
  console.log('\n=== P0-3/P0-4: rekey heal request + ack clears the flag ===');
  const r = await bob.csrfFetch('/chats/rekey/request', { method: 'POST', body: JSON.stringify({ other_id: aliceId }) });
  ok(r.status === 200, 'bob registers a rekey request to alice');
  const needed = await alice.csrfFetch('/chats/rekey/needed?requester_id=' + bobId).then(x => x.json());
  ok(needed && needed.needed === true, 'alice sees the pending rekey request');
  const ack = await alice.csrfFetch('/chats/rekey/ack', { method: 'POST', body: JSON.stringify({ requester_id: bobId }) });
  ok(ack.status === 200, 'alice acks the rekey');
  const needed2 = await alice.csrfFetch('/chats/rekey/needed?requester_id=' + bobId).then(x => x.json());
  ok(needed2 && needed2.needed === false, 'after ack, no pending rekey remains');

  // ===== Newest-first DM history + cursor (P1-7) =====
  console.log('\n=== P1-7: newest-first DM history + cursor pagination ===');
  // Insert 101 stub messages directly so the conversation exceeds the page.
  for (let i = 0; i < 101; i++) db.sendMessage(aliceId, bobId, 'stub-' + i, null, null, 'olm', null, 0);
  const newest = db.getMessages(aliceId, bobId); // newest-first, 100
  ok(newest.length === 100, 'getMessages returns a 100-message page (got ' + newest.length + ')');
  ok(newest[0].body === 'stub-1' && newest[99].body === 'stub-100', 'page is newest-first (stub-1..stub-100), NOT oldest');
  const chatPage = await alice.fetch('/chats/bob');
  const html = await chatPage.text();
  ok(/Load older messages/.test(html), 'chat page shows "Load older messages" (page is full)');
  ok(html.indexOf('stub-100') !== -1, 'newest message (stub-100) is in the page');
  ok(html.indexOf('stub-0') === -1, 'oldest message (stub-0) is NOT in the first page');
  const firstMsgId = Number((html.match(/data-msg-id="(\d+)"/) || [])[1] || 0);
  const olderPage = await alice.fetch('/chats/bob?before=' + firstMsgId);
  const olderHtml = await olderPage.text();
  ok(olderHtml.indexOf('stub-0') !== -1, 'older page (cursor) contains the oldest message');

  // ===== Oversize ciphertext rejected (P2-14) =====
  console.log('\n=== P2-14: oversize ciphertext rejected (not truncated) ===');
  const huge = 'A'.repeat(70000);
  const oversize = await alice.csrfFetch('/chats/bob/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'proto=olm&body=' + encodeURIComponent(huge) + '&sender_ciphertext=' + encodeURIComponent(huge),
  }).then(r => r.json());
  ok(oversize && oversize.error, 'oversize send rejected with an error (not stored/truncated)');

  // ===== Random KEK salt (P2-13) =====
  console.log('\n=== P2-13: random per-account KEK salt ===');
  const saltRes = await fetch(base + '/chats/kek-salt?username=bob');
  const salt0 = await saltRes.json();
  ok(salt0 && salt0.salt === null && salt0.legacy === false, 'no backup yet: salt null, not legacy');
  // Upload a salted backup.
  await bob.csrfFetch('/chats/prekeys', { method: 'POST', body: JSON.stringify({ backup: 'BK-ENC', backup_identity: bob.myIdKeys.curve25519, kek_salt: 'rAndOmSaLt' }) });
  const salt1 = await fetch(base + '/chats/kek-salt?username=bob').then(r => r.json());
  ok(salt1.salt === 'rAndOmSaLt', 'salt stored alongside the backup and readable pre-login');
  // A legacy (unsalted) upload must NOT clobber a salted backup.
  await bob.csrfFetch('/chats/prekeys', { method: 'POST', body: JSON.stringify({ backup: 'BK-LEGACY', backup_identity: bob.myIdKeys.curve25519 }) });
  const bk = await bob.csrfFetch('/chats/prekeys/backup').then(r => r.json());
  ok(bk.backup === 'BK-ENC' && bk.salt === 'rAndOmSaLt', 'legacy (unsalted) upload did not clobber the salted backup');

  // ===== Room multi-device fan-out (P1-8 / P1-9 / P1-10) =====
  console.log('\n=== P1-8/P1-9/P1-10: room key to every device + rotation retention ===');
  const roomId = db.createRoom('Room', '', aliceId, 1);
  const chanId = db.db.prepare(`SELECT id FROM room_channels WHERE room_id = ?`).get(roomId).id;
  const memberRole = db.db.prepare(`SELECT id FROM room_roles WHERE room_id = ? AND is_founder = 0 LIMIT 1`).get(roomId).id;
  db.addRoomMember(roomId, bobId, memberRole);

  // Give alice a SECOND device and bob a SECOND device.
  const alice2 = mkDevice('alice', aliceId); await alice2.login(base); await alice2.initCrypto();
  const bob2 = mkDevice('bob', bobId); await bob2.login(base); await bob2.initCrypto();

  // alice (device 1) creates a Megolm session and shares to every member
  // device (bob's two) + her own other device (alice2).
  const out = new Olm.OutboundGroupSession(); out.create();
  const sessionKey = out.session_key();
  const keys = [];
  // bob's devices
  for (const bobDev of [bob, bob2]) {
    const bb = await alice.roomBundleFor(roomId, 'bob');
    const dev = bb.devices.find(d => d.device_id === bobDev.deviceId);
    const s = await alice.establishRoomOutbound(roomId, 'bob', dev);
    const enc = s.encrypt(sessionKey);
    keys.push({ recipient_id: bobId, encrypted_key: JSON.stringify({ v: 2, sender_device_id: alice.deviceId, devices: { [dev.device_id]: { t: enc.type, b: enc.body } }, t: enc.type, b: enc.body }) });
  }
  // alice's own other device (alice2) — the room claim endpoint allows self.
  {
    const ab = await alice.roomBundleFor(roomId, 'alice');
    const dev = ab.devices.find(d => d.device_id === alice2.deviceId);
    const s = await alice.establishRoomOutbound(roomId, 'alice', dev);
    const enc = s.encrypt(sessionKey);
    keys.push({ recipient_id: aliceId, encrypted_key: JSON.stringify({ v: 2, sender_device_id: alice.deviceId, devices: { [dev.device_id]: { t: enc.type, b: enc.body } }, t: enc.type, b: enc.body }) });
  }
  const shareRes = await alice.csrfFetch('/rooms/' + roomId + '/session', {
    method: 'POST', body: JSON.stringify({ keys, member_ids: [aliceId, bobId], rotate: true, sender_device_id: alice.deviceId }),
  }).then(r => r.json());
  ok(shareRes && shareRes.session_id, 'room session published (session_id returned)');

  // bob's SECOND device (bob2) fetches + imports its key and decrypts a room msg.
  const pending = await bob2.csrfFetch('/rooms/' + roomId + '/session/keys').then(r => r.json());
  let bob2GotKey = false;
  for (const k of (pending.keys || [])) {
    const env = JSON.parse(k.encrypted_key);
    if (env && env.v === 2 && env.devices && env.devices[bob2.deviceId]) {
      const fullKey = String(k.sender_id) + ':' + env.sender_device_id;
      // establish inbound by claiming alice's device OTK? No — the share used an
      // already-claimed OTK; bob2 create_inbound from the PreKey message.
      const ns = new Olm.Session();
      ns.create_inbound(bob2.account, env.devices[bob2.deviceId].b);
      bob2.account.remove_one_time_keys(ns);
      const sessionKeyPlain = ns.decrypt(env.devices[bob2.deviceId].t, env.devices[bob2.deviceId].b);
      const ig = new Olm.InboundGroupSession(); ig.create(sessionKeyPlain);
      // Save + mark delivered
      bob2._roomInbound = ig;
      await bob2.csrfFetch('/rooms/' + roomId + '/session/keys/delivered', { method: 'POST', body: JSON.stringify({ key_ids: [k.key_id] }) });
      bob2GotKey = true;
    }
  }
  ok(bob2GotKey, "bob's second device received + decrypted its room key (per-device fan-out)");

  // alice's second device (alice2) also got the key (P1-10).
  const pendingA = await alice2.csrfFetch('/rooms/' + roomId + '/session/keys').then(r => r.json());
  let alice2GotKey = false;
  for (const k of (pendingA.keys || [])) {
    if (String(k.sender_id) !== String(aliceId)) continue;
    const env = JSON.parse(k.encrypted_key);
    if (env && env.v === 2 && env.devices && env.devices[alice2.deviceId]) {
      const ns = new Olm.Session();
      ns.create_inbound(alice2.account, env.devices[alice2.deviceId].b);
      alice2.account.remove_one_time_keys(ns);
      const sessionKeyPlain = ns.decrypt(env.devices[alice2.deviceId].t, env.devices[alice2.deviceId].b);
      alice2._roomInbound = new Olm.InboundGroupSession(); alice2._roomInbound.create(sessionKeyPlain);
      await alice2.csrfFetch('/rooms/' + roomId + '/session/keys/delivered', { method: 'POST', body: JSON.stringify({ key_ids: [k.key_id] }) });
      alice2GotKey = true;
    }
  }
  ok(alice2GotKey, "alice's second device received its own room key (sender self-fan-out)");

  // alice sends a room message; bob2 and alice2 decrypt it.
  const ct = out.encrypt('hello room');
  const sendRoom = await alice.csrfFetch('/rooms/' + roomId + '/channels/' + chanId + '/send', {
    method: 'POST', body: JSON.stringify({ proto: 'megolm', ciphertext: ct, group_session_id: String(shareRes.session_id) }),
  }).then(r => r.json());
  ok(sendRoom && sendRoom.id, 'room message sent');
  let bob2Plain = null;
  if (bob2._roomInbound) { try { bob2Plain = bob2._roomInbound.decrypt(ct).plaintext; } catch (_) {} }
  ok(bob2Plain === 'hello room', "bob's second device decrypts the room message -> " + JSON.stringify(bob2Plain));
  let alice2Plain = null;
  if (alice2._roomInbound) { try { alice2Plain = alice2._roomInbound.decrypt(ct).plaintext; } catch (_) {} }
  ok(alice2Plain === 'hello room', "alice's second device decrypts her own room message -> " + JSON.stringify(alice2Plain));

  // P1-9: rotation keeps the previous session's undelivered keys.
  // Mark bob's device-1 key as NOT delivered, then rotate: the old session row
  // and its undelivered key must survive.
  const oldSessionId = shareRes.session_id;
  // Re-share under a NEW session (rotate=true) without delivering bob's key.
  const out2 = new Olm.OutboundGroupSession(); out2.create();
  const keys2 = [];
  {
    const bb = await alice.roomBundleFor(roomId, 'bob');
    const dev = bb.devices.find(d => d.device_id === bob.deviceId);
    const s = await alice.establishRoomOutbound(roomId, 'bob', dev);
    const enc = s.encrypt(out2.session_key());
    keys2.push({ recipient_id: bobId, encrypted_key: JSON.stringify({ v: 2, sender_device_id: alice.deviceId, devices: { [dev.device_id]: { t: enc.type, b: enc.body } }, t: enc.type, b: enc.body }) });
  }
  await alice.csrfFetch('/rooms/' + roomId + '/session', {
    method: 'POST', body: JSON.stringify({ keys: keys2, member_ids: [aliceId, bobId], rotate: true, sender_device_id: alice.deviceId }),
  });
  const oldRow = db.db.prepare(`SELECT id FROM room_group_sessions WHERE id = ?`).get(Number(oldSessionId));
  ok(!!oldRow, 'old room session row survived rotation (history kept)');
  const oldKeys = db.db.prepare(`SELECT COUNT(*) AS n FROM room_group_session_keys WHERE session_id = ?`).get(Number(oldSessionId)).n;
  ok(oldKeys > 0, 'old session keys were NOT deleted on rotate (undelivered keys retained)');

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL FIX-VERIFY TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch(err => { console.error(err); process.exit(1); });
