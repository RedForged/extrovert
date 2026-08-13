'use strict';

/**
 * full-devserver-e2e-test.js
 * In-depth integration test running against a real Extrovert server instance.
 * Tests message sending, receiving, and encrypted rooms across multiple devices and new logins.
 */

const http = require('node:http');
const assert = require('node:assert');
const crypto = require('node:crypto');
const Olm = require('@matrix-org/olm');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-fulle2e-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'extrovert.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 'sessions.db');
process.env.SESSION_SECRET = 'fulle2e-test-secret';
process.env.SECRET = 'fulle2e-test-secret';

const app = require('../src/server');
const db = require('../src/db');

// Node.js PBKDF2 helper matching WebCrypto
function deriveKekNode(password, username) {
  const salt = Buffer.from(username.toLowerCase());
  return crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256');
}

function encryptWithKekNode(plaintext, kek) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, enc, tag]).toString('base64');
}

function decryptWithKekNode(b64, kek) {
  const buf = Buffer.from(b64, 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const enc = buf.subarray(12, buf.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

class SimulatedBrowserDevice {
  constructor(baseUrl, deviceName) {
    this.baseUrl = baseUrl;
    this.deviceName = deviceName;
    this.deviceId = 'dev_' + crypto.randomBytes(8).toString('hex');
    this.cookie = null;
    this.csrfToken = null;
    this.account = null;
    this.idKeys = null;
    this.fallbackKey = null;
    this.sessions = {}; // peerKey -> Olm.Session
    this.groupOutbound = {}; // roomId -> Olm.OutboundGroupSession
    this.groupInbound = {}; // roomId:senderId:sessionId -> Olm.InboundGroupSession
    this.secureStore = {}; // convKey -> array of messages
    this.user = null;
  }

  async fetch(path, opts = {}) {
    opts.headers = opts.headers || {};
    if (this.cookie) opts.headers['Cookie'] = this.cookie;
    if (this.csrfToken && (opts.method === 'POST' || opts.method === 'DELETE')) {
      opts.headers['X-CSRF-Token'] = this.csrfToken;
      opts.headers['Content-Type'] = opts.headers['Content-Type'] || 'application/json';
    }

    const res = await fetch(this.baseUrl + path, opts);

    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      const match = setCookie.match(/connect\.sid=([^;]+)/);
      if (match) this.cookie = 'connect.sid=' + match[1];
    }
    return res;
  }

  async getCsrf() {
    const res = await this.fetch('/login');
    const text = await res.text();
    const match = text.match(/name="_csrf" value="([^"]+)"/);
    if (match) this.csrfToken = match[1];
    return this.csrfToken;
  }

  async registerAndLogin(username, password, displayName) {
    await this.getCsrf();
    const params = new URLSearchParams({
      _csrf: this.csrfToken,
      username,
      password,
      display_name: displayName
    });
    const res = await this.fetch('/register', {
      method: 'POST',
      body: params.toString(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      redirect: 'manual'
    });
    this.user = { username, password, displayName };
    await this.getCsrf(); // Refresh CSRF for authenticated session
    return res;
  }

  async login(username, password) {
    await this.getCsrf();
    const params = new URLSearchParams({
      _csrf: this.csrfToken,
      username,
      password
    });
    const res = await this.fetch('/login', {
      method: 'POST',
      body: params.toString(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      redirect: 'manual'
    });
    this.user = { username, password };
    const chats = await this.fetch('/chats');
    const text = await chats.text();
    const meta = text.match(/name="csrf-token" content="([^"]+)"/);
    if (meta) this.csrfToken = meta[1];
    return res;
  }

  async initE2EE() {
    this.account = new Olm.Account();
    this.account.create();
    this.account.generate_fallback_key();
    this.account.generate_one_time_keys(10);
    this.idKeys = JSON.parse(this.account.identity_keys());
    const otks = JSON.parse(this.account.one_time_keys()).curve25519;
    this.fallbackKey = Object.values(JSON.parse(this.account.fallback_key()).curve25519)[0];

    const cleanOtks = Object.keys(otks).map(k => ({ id: k, public_key: otks[k] }));

    const res = await this.fetch('/chats/devices/register', {
      method: 'POST',
      body: JSON.stringify({
        device_id: this.deviceId,
        identity_key: this.idKeys.curve25519,
        ed25519_key: this.idKeys.ed25519,
        fallback_key: this.fallbackKey,
        device_name: this.deviceName,
        one_time_keys: cleanOtks
      })
    });
    const data = await res.json();
    this.account.mark_keys_as_published();
    await this.restoreHistoryFromServer();
    return data;
  }

  async sendDm(recipientUsername, plaintext) {
    const bundleRes = await this.fetch('/chats/' + encodeURIComponent(recipientUsername) + '/bundle');
    const bundle = await bundleRes.json();
    const recipientDevices = bundle.devices || [];
    const senderDevices = bundle.sender_devices || [];

    const deviceCiphertexts = {};

    // 1. Encrypt for each recipient device
    for (const dev of recipientDevices) {
      const sessKey = recipientUsername + ':' + dev.device_id;
      let sess = this.sessions[sessKey];
      if (!sess) {
        sess = new Olm.Session();
        const otk = dev.one_time_key ? dev.one_time_key.public_key : dev.fallback_key;
        sess.create_outbound(this.account, dev.identity_key, otk);
        this.sessions[sessKey] = sess;
      }
      const enc = sess.encrypt(plaintext);
      deviceCiphertexts[dev.device_id] = { t: enc.type, b: enc.body };
    }

    // 2. Encrypt for sender's other devices
    for (const dev of senderDevices) {
      if (dev.device_id === this.deviceId) continue;
      const sessKey = this.user.username + ':' + dev.device_id;
      let sess = this.sessions[sessKey];
      if (!sess) {
        sess = new Olm.Session();
        const otk = dev.one_time_key ? dev.one_time_key.public_key : dev.fallback_key;
        sess.create_outbound(this.account, dev.identity_key, otk);
        this.sessions[sessKey] = sess;
      }
      const enc = sess.encrypt(plaintext);
      deviceCiphertexts[dev.device_id] = { t: enc.type, b: enc.body };
    }

    const envelope = {
      v: 2,
      sender_device_id: this.deviceId,
      devices: deviceCiphertexts
    };

    const sendRes = await this.fetch('/chats/' + encodeURIComponent(recipientUsername) + '/send', {
      method: 'POST',
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        body: JSON.stringify(envelope),
        proto: 'olm',
        sender_ciphertext: JSON.stringify(envelope)
      })
    });

    // Save to local secure store and sync history
    const convKey = 'conv:' + recipientUsername;
    this.secureStore[convKey] = this.secureStore[convKey] || [];
    this.secureStore[convKey].push({ plaintext, fromMe: true, time: Date.now() });

    await this.syncHistoryToServer();
    return sendRes.status === 200 ? sendRes.json().catch(() => ({})) : {};
  }

  async decryptDmEnvelope(envRaw, fromUsername) {
    const env = JSON.parse(envRaw);
    let cipher = null;
    let senderDevId = 'default';
    if (env && env.v === 2 && env.devices) {
      senderDevId = env.sender_device_id || 'default';
      cipher = env.devices[this.deviceId] || Object.values(env.devices)[0];
    } else {
      cipher = env;
    }

    const sessKey = fromUsername + ':' + senderDevId;
    let sess = this.sessions[sessKey];
    if (!sess) {
      sess = new Olm.Session();
      sess.create_inbound(this.account, cipher.b);
      this.account.remove_one_time_keys(sess);
      this.sessions[sessKey] = sess;
    }

    const decrypted = sess.decrypt(cipher.t, cipher.b);

    const convKey = 'conv:' + fromUsername;
    this.secureStore[convKey] = this.secureStore[convKey] || [];
    this.secureStore[convKey].push({ plaintext: decrypted, fromMe: false, time: Date.now() });
    await this.syncHistoryToServer();
    return decrypted;
  }

  async syncHistoryToServer() {
    if (!this.user || !this.user.password) return;
    const existing = await this.restoreHistoryFromServer() || {};
    for (const k of Object.keys(existing)) {
      if (!this.secureStore[k]) this.secureStore[k] = existing[k];
    }
    for (const k of Object.keys(this.secureStore)) {
      const currentList = this.secureStore[k] || [];
      const remoteList = existing[k] || [];
      const map = new Map();
      for (const m of remoteList) map.set(m.plaintext, m);
      for (const m of currentList) map.set(m.plaintext, m);
      this.secureStore[k] = Array.from(map.values());
    }
    const kek = deriveKekNode(this.user.password, this.user.username);
    const encData = encryptWithKekNode(JSON.stringify(this.secureStore), kek);
    await this.fetch('/chats/history/backup', {
      method: 'POST',
      body: JSON.stringify({ backup_data: encData })
    });
  }

  async restoreHistoryFromServer() {
    const res = await this.fetch('/chats/history/backup');
    const data = await res.json();
    if (!data || !data.backup_data) return null;
    const kek = deriveKekNode(this.user.password, this.user.username);
    const decryptedJson = decryptWithKekNode(data.backup_data, kek);
    this.secureStore = JSON.parse(decryptedJson);
    return this.secureStore;
  }
}

async function runTest() {
  console.log('\n======================================================');
  console.log('🚀 Extrovert Real Dev-Server End-to-End Test Suite 🚀');
  console.log('======================================================\n');

  await Olm.init();

  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;
  console.log(`✓ Real Extrovert test server listening on port ${port}\n`);

  try {
    const rand = crypto.randomBytes(4).toString('hex');
    const aliceUser = 'alice_e2e_' + rand;
    const bobUser = 'bob_e2e_' + rand;
    const pass = 'SuperSecret123!';
    const bcrypt = require('bcryptjs');

    // ----------------------------------------------------
    // PHASE 1: User Registration & Multi-Device Setup
    // ----------------------------------------------------
    console.log('--- PHASE 1: Multi-Device Registration ---');

    const aliceId = db.createUser({ username: aliceUser, passwordHash: bcrypt.hashSync(pass, 10), displayName: 'Alice Real' });
    const bobId = db.createUser({ username: bobUser, passwordHash: bcrypt.hashSync(pass, 10), displayName: 'Bob Real' });
    db.follow(aliceId, bobId);
    db.follow(bobId, aliceId);
    console.log('✓ Created users and mutual followers.');

    const aliceRow = db.getUserById(aliceId);
    const bobRow = db.getUserById(bobId);

    // Alice Device 1 (Desktop)
    const aliceDev1 = new SimulatedBrowserDevice(baseUrl, 'Alice Desktop');
    await aliceDev1.login(aliceUser, pass);
    await aliceDev1.initE2EE();
    console.log('✓ Alice Device 1 registered.');

    // Bob Device 1 (Mobile)
    const bobDev1 = new SimulatedBrowserDevice(baseUrl, 'Bob Mobile');
    await bobDev1.login(bobUser, pass);
    await bobDev1.initE2EE();
    console.log('✓ Bob Device 1 registered.');

    // Alice Device 2 (Laptop - secondary device)
    const aliceDev2 = new SimulatedBrowserDevice(baseUrl, 'Alice Laptop');
    await aliceDev2.login(aliceUser, pass);
    await aliceDev2.initE2EE();
    console.log('✓ Alice Device 2 logged in and registered.');

    // Bob Device 2 (Tablet - secondary device)
    const bobDev2 = new SimulatedBrowserDevice(baseUrl, 'Bob Tablet');
    await bobDev2.login(bobUser, pass);
    await bobDev2.initE2EE();
    console.log('✓ Bob Device 2 logged in and registered.');

    // Verify devices list on server
    const aliceDevices = await (await aliceDev1.fetch('/chats/devices')).json();
    assert.strictEqual(aliceDevices.devices.length, 2, 'Alice should have 2 registered devices on server');
    console.log('✓ Server reports 2 active devices for Alice.');

    const bobDevices = await (await bobDev1.fetch('/chats/devices')).json();
    assert.strictEqual(bobDevices.devices.length, 2, 'Bob should have 2 registered devices on server');
    console.log('✓ Server reports 2 active devices for Bob.');

    // ----------------------------------------------------
    // PHASE 2: Direct Messaging Fan-Out
    // ----------------------------------------------------
    console.log('\n--- PHASE 2: Multi-Device Direct Messaging ---');

    const msg1Text = 'Hello Bob, message #1 from Alice Desktop!';
    await aliceDev1.sendDm(bobUser, msg1Text);
    console.log('✓ Alice Dev 1 sent fan-out DM to Bob.');

    // Fetch latest message from DB
    const lastMsg = db.db.prepare(`SELECT * FROM messages WHERE from_id = ? ORDER BY id DESC LIMIT 1`).get(aliceRow.id);
    assert.ok(lastMsg, 'Message must be in DB');

    // Bob Dev 1 decrypts
    const bob1Plain = await bobDev1.decryptDmEnvelope(lastMsg.body, aliceUser);
    assert.strictEqual(bob1Plain, msg1Text, 'Bob Dev 1 must decrypt message');
    console.log('✓ Bob Dev 1 received and decrypted message.');

    // Bob Dev 2 decrypts
    const bob2Plain = await bobDev2.decryptDmEnvelope(lastMsg.body, aliceUser);
    assert.strictEqual(bob2Plain, msg1Text, 'Bob Dev 2 must decrypt message');
    console.log('✓ Bob Dev 2 received and decrypted message.');

    // Alice Dev 2 (Sender's other device) decrypts
    const alice2Plain = await aliceDev2.decryptDmEnvelope(lastMsg.body, aliceUser);
    assert.strictEqual(alice2Plain, msg1Text, 'Alice Dev 2 must decrypt sender copy');
    console.log('✓ Alice Dev 2 (sender copy) received and decrypted message.');

    // Bob replies from Dev 2
    const replyText = 'Hi Alice, this is Bob replying from my Tablet!';
    await bobDev2.sendDm(aliceUser, replyText);
    console.log('✓ Bob Dev 2 sent reply to Alice.');

    const replyMsg = db.db.prepare(`SELECT * FROM messages WHERE from_id = ? ORDER BY id DESC LIMIT 1`).get(bobRow.id);
    assert.ok(replyMsg, 'Reply message must be in DB');

    // Alice Dev 1 and Dev 2 both decrypt Bob's reply
    const alice1Reply = await aliceDev1.decryptDmEnvelope(replyMsg.body, bobUser);
    assert.strictEqual(alice1Reply, replyText, 'Alice Dev 1 must decrypt Bob reply');
    console.log('✓ Alice Dev 1 received and decrypted reply.');

    const alice2Reply = await aliceDev2.decryptDmEnvelope(replyMsg.body, bobUser);
    assert.strictEqual(alice2Reply, replyText, 'Alice Dev 2 must decrypt Bob reply');
    console.log('✓ Alice Dev 2 received and decrypted reply.');

    // ----------------------------------------------------
    // PHASE 3: Encrypted Rooms (Megolm) Flow
    // ----------------------------------------------------
    console.log('\n--- PHASE 3: Encrypted Rooms (Megolm) ---');

    // Alice creates a room
    const roomId = db.createRoom('Secret Club ' + rand, 'E2EE room', aliceRow.id, 1);
    const roles = db.getRoomRoles(roomId);
    const memberRole = roles.find(r => !r.is_founder);
    db.addRoomMember(roomId, bobRow.id, memberRole.id);
    console.log(`✓ Room created (id: ${roomId}) with Alice and Bob as members.`);

    // Alice Dev 1 creates Outbound Group Session
    const roomOutbound = new Olm.OutboundGroupSession();
    roomOutbound.create();
    const roomSessionId = roomOutbound.session_id();
    const roomSessionKey = roomOutbound.session_key();

    // Alice shares group key with Bob Dev 1 via room bundle
    const roomBundleRes = await aliceDev1.fetch(`/rooms/${roomId}/bundle/${bobUser}`);
    const roomBundle = await roomBundleRes.json();
    assert.ok(roomBundle.devices && roomBundle.devices.length > 0, 'Room bundle must return recipient devices');

    // Target Bob Dev 1 specifically
    const devBob1 = roomBundle.devices.find(d => d.device_id === bobDev1.deviceId) || roomBundle.devices[0];
    const bob1Otk = devBob1.one_time_key ? devBob1.one_time_key.public_key : devBob1.fallback_key;

    // Alice wraps session key using 1:1 Olm
    const aliceToBobRoomSess = new Olm.Session();
    aliceToBobRoomSess.create_outbound(aliceDev1.account, devBob1.identity_key, bob1Otk);
    const keyEnc = aliceToBobRoomSess.encrypt(roomSessionKey);

    // Save session on server
    await aliceDev1.fetch(`/rooms/${roomId}/session`, {
      method: 'POST',
      body: JSON.stringify({
        keys: [{ recipient_id: bobRow.id, encrypted_key: JSON.stringify({ t: keyEnc.type, b: keyEnc.body }) }],
        member_ids: [aliceRow.id, bobRow.id],
        rotate: true
      })
    });
    console.log('✓ Alice published Megolm room session and shared wrapped key with Bob Dev 1.');

    // Alice encrypts a room message
    const roomPlaintext = 'Welcome to the secret room!';
    const roomCt = roomOutbound.encrypt(roomPlaintext);
    const channels = db.getRoomChannels(roomId);
    db.sendRoomMessage(channels[0].id, aliceRow.id, '[Encrypted message]', 'megolm', roomCt, roomSessionId);
    console.log('✓ Alice posted encrypted room message.');

    // Bob Dev 1 fetches pending room keys and decrypts
    const keysRes = await bobDev1.fetch(`/rooms/${roomId}/session/keys`);
    const keysData = await keysRes.json();
    assert.ok(keysData.keys && keysData.keys.length > 0, 'Bob must have pending room session keys');

    const pendingKey = keysData.keys[0];
    const wrappedEnv = JSON.parse(pendingKey.encrypted_key);
    const bobRoomInboundSess = new Olm.Session();
    bobRoomInboundSess.create_inbound(bobDev1.account, wrappedEnv.b);
    bobDev1.account.remove_one_time_keys(bobRoomInboundSess);
    const unwrappedSessionKey = bobRoomInboundSess.decrypt(wrappedEnv.t, wrappedEnv.b);

    // Bob creates InboundGroupSession and decrypts room message
    const bobGroupInbound = new Olm.InboundGroupSession();
    bobGroupInbound.create(unwrappedSessionKey);
    const decryptedRoomMsg = bobGroupInbound.decrypt(roomCt);
    assert.strictEqual(decryptedRoomMsg.plaintext, roomPlaintext, 'Bob must successfully decrypt room message');
    console.log('✓ Bob decrypted room message using Megolm.');

    // ----------------------------------------------------
    // PHASE 4: Fresh Login on Device 3 & Password History Restore
    // ----------------------------------------------------
    console.log('\n--- PHASE 4: Password History Restore on Fresh Device ---');

    // Alice logs in on Device 3 (Fresh browser / phone)
    const aliceDev3 = new SimulatedBrowserDevice(baseUrl, 'Alice Phone 2');
    await aliceDev3.login(aliceUser, pass);
    await aliceDev3.initE2EE();
    console.log('✓ Alice Device 3 registered.');

    // Alice Dev 3 restores message history from server using password KEK
    const restored = await aliceDev3.restoreHistoryFromServer();
    assert.ok(restored && restored['conv:' + bobUser], 'Restored history must contain conversation with Bob');
    assert.strictEqual(restored['conv:' + bobUser][0].plaintext, msg1Text, 'Restored message must match original');
    console.log('✓ Alice Device 3 restored chat history using login password without recovery keys.');

    // Alice Dev 3 sends message to Bob
    const msg3Text = 'Message from Alice Device 3!';
    await aliceDev3.sendDm(bobUser, msg3Text);
    console.log('✓ Alice Device 3 sent DM to Bob.');

    const msg3Db = db.db.prepare(`SELECT * FROM messages WHERE from_id = ? ORDER BY id DESC LIMIT 1`).get(aliceRow.id);
    const bob1Msg3 = await bobDev1.decryptDmEnvelope(msg3Db.body, aliceUser);
    assert.strictEqual(bob1Msg3, msg3Text, 'Bob Dev 1 must decrypt message from Alice Dev 3');
    console.log('✓ Bob Dev 1 received and decrypted message from Alice Dev 3.');

    // Alice Dev 1 also receives Alice Dev 3 sender copy
    const alice1Msg3 = await aliceDev1.decryptDmEnvelope(msg3Db.body, aliceUser);
    assert.strictEqual(alice1Msg3, msg3Text, 'Alice Dev 1 must decrypt sender copy from Alice Dev 3');
    console.log('✓ Alice Dev 1 seamlessly received sender copy from Alice Dev 3.');

    console.log('\n======================================================');
    console.log('🎉 ALL REAL DEV-SERVER E2E TESTS PASSED SUCCESSFULLY! 🎉');
    console.log('======================================================\n');
    process.exit(0);
  } finally {
    server.close();
  }
}

runTest().catch(err => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
