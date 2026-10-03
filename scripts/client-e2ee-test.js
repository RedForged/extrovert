'use strict';

/**
 * client-e2ee-test.js
 *
 * Exhaustive integration test suite for E2EE Client DX enhancements:
 * - Bootstrap E2EE prekey status & OTK warnings (GET /api/v1/client/bootstrap)
 * - Batch Room Prekey Bundles (GET /api/v1/rooms/:id/bundles)
 * - Filtering bundles by missing_for_session
 * - Unified Room Session Sync (POST /api/v1/rooms/:id/session/sync)
 * - Realtime push of room session keys over WebSocket gateway (room_session_key)
 * - Zero-latency inlined session keys on message_create broadcast
 * - Proactive OTK depletion warnings on WebSocket connect
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const WebSocket = require('ws');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-e2ee-client-test-'));
const TEST_DB = path.join(TEST_DIR, 'test.db');
const TEST_SESSION_DB = path.join(TEST_DIR, 'sessions.db');

process.env.EXTV_DB_PATH = TEST_DB;
process.env.EXTV_SESSION_DB_PATH = TEST_SESSION_DB;
process.env.SESSION_SECRET = 'client-e2ee-secret';
process.env.PORT = '0';
process.env.HOST = '127.0.0.1';

const db = require('../src/db');
const app = require('../src/server');

let baseUrl;
let wsUrl;

let aliceId, bobId, charlieId;
let aliceToken, bobToken, charlieToken;
let roomId, channelId;

before(async () => {
  await new Promise((resolve) => {
    const checkPort = () => {
      const addr = app.httpServer.address();
      if (addr && addr.port) {
        baseUrl = `http://127.0.0.1:${addr.port}/api/v1`;
        wsUrl = `ws://127.0.0.1:${addr.port}/ws`;
        resolve();
      } else {
        setTimeout(checkPort, 10);
      }
    };
    checkPort();
  });

  // Seed users
  aliceId = db.createUser({ username: 'alice_e2ee', passwordHash: 'hash', displayName: 'Alice E2EE' });
  bobId = db.createUser({ username: 'bob_e2ee', passwordHash: 'hash', displayName: 'Bob E2EE' });
  charlieId = db.createUser({ username: 'charlie_e2ee', passwordHash: 'hash', displayName: 'Charlie E2EE' });

  // Mutual follow alice <-> bob, alice <-> charlie
  db.follow(aliceId, bobId);
  db.follow(bobId, aliceId);
  db.follow(aliceId, charlieId);
  db.follow(charlieId, aliceId);

  // PATs for auth
  aliceToken = 'ext_pat_alice_e2ee_token';
  bobToken = 'ext_pat_bob_e2ee_token';
  charlieToken = 'ext_pat_charlie_e2ee_token';

  db.createPersonalAccessToken(aliceId, 'Alice Dev', aliceToken, 'read write follow notifications media.write read:direct write:direct profile', null);
  db.createPersonalAccessToken(bobId, 'Bob Dev', bobToken, 'read write follow notifications media.write read:direct write:direct profile', null);
  db.createPersonalAccessToken(charlieId, 'Charlie Dev', charlieToken, 'read write follow notifications media.write read:direct write:direct profile', null);

  // Seed E2EE identity & prekeys for Bob and Charlie
  db.registerUserDevice(bobId, 'bob_dev_1', 'bob_curve_identity', 'bob_ed25519_identity', null, 'Bob Device');
  db.addDevicePrekeys(bobId, 'bob_dev_1', [
    { id: '1', public_key: 'bob_otk_1' },
    { id: '2', public_key: 'bob_otk_2' },
  ]);

  db.registerUserDevice(charlieId, 'charlie_dev_1', 'charlie_curve_identity', 'charlie_ed25519_identity', null, 'Charlie Device');
  db.addDevicePrekeys(charlieId, 'charlie_dev_1', [
    { id: '1', public_key: 'charlie_otk_1' },
  ]);

  // Create room with general channel
  roomId = db.createRoom('E2EE Test Room', 'Testing E2EE enhancements', aliceId, true);
  db.addRoomMember(roomId, bobId);
  db.addRoomMember(roomId, charlieId);

  const channels = db.getRoomChannels(roomId);
  channelId = channels[0].id;
});

after(() => {
  try { app.httpServer.close(); } catch {}
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
});

describe('E2EE Server Enhancements for Client Developers', () => {

  it('reports E2EE status and OTK count in /client/bootstrap', async () => {
    const res = await fetch(`${baseUrl}/client/bootstrap`, {
      headers: { Authorization: `Bearer ${bobToken}` },
    });
    assert.strictEqual(res.status, 200);
    const json = await res.json();
    assert.ok(json.data.e2ee, 'Should include e2ee object');
    assert.strictEqual(typeof json.data.e2ee.otk_count, 'number');
    assert.strictEqual(typeof json.data.e2ee.otk_low, 'boolean');
  });

  it('fetches batch prekey bundles for room members via GET /rooms/:id/bundles in 1 call', async () => {
    const res = await fetch(`${baseUrl}/rooms/${roomId}/bundles`, {
      headers: { Authorization: `Bearer ${aliceToken}` },
    });
    assert.strictEqual(res.status, 200);
    const json = await res.json();
    assert.strictEqual(json.data.room_id, String(roomId));
    assert.strictEqual(json.data.returned_bundles, 2, 'Should return bundles for both Bob and Charlie');

    const usernames = json.data.bundles.map(b => b.username);
    assert.ok(usernames.includes('bob_e2ee'));
    assert.ok(usernames.includes('charlie_e2ee'));

    const bobBundle = json.data.bundles.find(b => b.username === 'bob_e2ee');
    assert.strictEqual(bobBundle.identity_key, 'bob_curve_identity');
    assert.ok(bobBundle.one_time_key);
  });

  it('performs unified session sync (POST /rooms/:id/session/sync) and reports missing members', async () => {
    // 1. Initial sync before any keys are distributed
    const syncRes1 = await fetch(`${baseUrl}/rooms/${roomId}/session/sync`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${aliceToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sender_device_id: 'alice_device_1',
      }),
    });
    assert.strictEqual(syncRes1.status, 200);
    const syncJson1 = await syncRes1.json();
    assert.ok(syncJson1.data.active_session_id, 'Should generate active session id');
    const sessionId = syncJson1.data.active_session_id;

    // Both Bob and Charlie still need keys
    assert.strictEqual(syncJson1.data.missing_members.length, 2);

    // 2. Alice sends key for Bob ONLY via sync
    const syncRes2 = await fetch(`${baseUrl}/rooms/${roomId}/session/sync`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${aliceToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sender_device_id: 'alice_device_1',
        keys: [
          { recipient_id: bobId, encrypted_key: 'encrypted_megolm_key_for_bob' },
        ],
      }),
    });
    assert.strictEqual(syncRes2.status, 200);
    const syncJson2 = await syncRes2.json();
    assert.strictEqual(syncJson2.data.recipients_count, 1);
    assert.strictEqual(syncJson2.data.missing_members.length, 1);
    assert.strictEqual(syncJson2.data.missing_members[0].username, 'charlie_e2ee');

    // 3. Batch bundles filtered by missing_for_session only returns Charlie!
    const bundlesRes = await fetch(`${baseUrl}/rooms/${roomId}/bundles?missing_for_session=${sessionId}`, {
      headers: { Authorization: `Bearer ${aliceToken}` },
    });
    assert.strictEqual(bundlesRes.status, 200);
    const bundlesJson = await bundlesRes.json();
    assert.strictEqual(bundlesJson.data.returned_bundles, 1);
    assert.strictEqual(bundlesJson.data.bundles[0].username, 'charlie_e2ee');
  });

  it('pushes room_session_key over WebSocket in realtime when a key is saved', async () => {
    // Connect Bob to WebSocket
    const bobWs = new WebSocket(`${wsUrl}?token=${bobToken}&auto_subscribe=1`);
    const subPromise = new Promise((resolve) => {
      bobWs.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg.type === 'subscribed' && msg.auto_subscribed) resolve(msg);
        } catch {}
      });
    });
    await new Promise((resolve, reject) => {
      bobWs.on('open', resolve);
      bobWs.on('error', reject);
    });
    await subPromise;

    const keyReceivedPromise = new Promise((resolve) => {
      bobWs.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg.event === 'room_session_key') {
            resolve(msg);
          }
        } catch {}
      });
    });

    // Alice publishes a fresh session and distributes key to Bob
    await fetch(`${baseUrl}/rooms/${roomId}/session`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${aliceToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        rotate: true,
        sender_device_id: 'alice_device_1',
        keys: [
          { recipient_id: bobId, encrypted_key: 'realtime_pushed_key_for_bob' },
        ],
      }),
    });

    const pushedEvent = await keyReceivedPromise;
    assert.strictEqual(pushedEvent.type, 'gateway_event');
    assert.strictEqual(pushedEvent.event, 'room_session_key');
    assert.strictEqual(pushedEvent.data.encrypted_key, 'realtime_pushed_key_for_bob');
    assert.strictEqual(pushedEvent.data.sender_username, 'alice_e2ee');

    bobWs.close();
  });

  it('inlines session_key directly inside message_create broadcast for zero-latency decrypt', async () => {
    // Alice creates another session with a key for Bob
    const sessionRes = await fetch(`${baseUrl}/rooms/${roomId}/session`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${aliceToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        rotate: true,
        sender_device_id: 'alice_device_1',
        keys: [
          { recipient_id: bobId, encrypted_key: 'inlined_session_key_for_bob' },
        ],
      }),
    });
    const sessionJson = await sessionRes.json();
    const gsid = sessionJson.data.session_id;

    // Connect Bob
    const bobWs = new WebSocket(`${wsUrl}?token=${bobToken}&auto_subscribe=1`);
    const subPromise = new Promise((resolve) => {
      bobWs.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg.type === 'subscribed' && msg.auto_subscribed) resolve(msg);
        } catch {}
      });
    });
    await new Promise((resolve, reject) => {
      bobWs.on('open', resolve);
      bobWs.on('error', reject);
    });
    await subPromise;

    // Wait for message_create
    const msgReceivedPromise = new Promise((resolve) => {
      bobWs.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg.event === 'message_create' && String(msg.data.group_session_id) === String(gsid)) {
            resolve(msg);
          }
        } catch {}
      });
    });

    // Alice sends a Megolm room message
    await fetch(`${baseUrl}/rooms/${roomId}/channels/${channelId}/messages`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${aliceToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        proto: 'megolm',
        ciphertext: 'ciphertext_sample_payload',
        group_session_id: String(gsid),
      }),
    });

    const receivedMsg = await msgReceivedPromise;
    assert.strictEqual(String(receivedMsg.data.group_session_id), String(gsid));
    assert.ok(receivedMsg.data.session_key, 'Message frame MUST inline the recipient session_key');
    assert.strictEqual(receivedMsg.data.session_key.encrypted_key, 'inlined_session_key_for_bob');

    bobWs.close();
  });

  it('broadcasts otk_low event over WebSocket when prekeys are low', async () => {
    // Alice has 0 prekeys
    const aliceWs = new WebSocket(`${wsUrl}?token=${aliceToken}&auto_subscribe=1`);
    const otkLowPromise = new Promise((resolve) => {
      aliceWs.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg.event === 'otk_low') {
            resolve(msg);
          }
        } catch {}
      });
    });
    await new Promise((resolve) => aliceWs.on('open', resolve));

    const event = await otkLowPromise;
    assert.strictEqual(event.type, 'gateway_event');
    assert.strictEqual(event.event, 'otk_low');
    assert.strictEqual(event.data.count, 0);

    aliceWs.close();
  });

  it('filters pending session keys by room ID in GET /rooms/:id/session/keys', async () => {
    // Create room2 and add Bob to it
    const room2Id = db.createRoom('Room 2 Keys Isolation', 'Testing room key isolation', aliceId, 1);
    db.addRoomMember(room2Id, bobId);

    // Publish session keys in room 2 for Bob
    const s2Res = await fetch(`${baseUrl}/rooms/${room2Id}/session`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${aliceToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        rotate: true,
        sender_device_id: 'alice_device_r2',
        keys: [
          { recipient_id: bobId, encrypted_key: 'room_2_key_for_bob' },
        ],
      }),
    });
    assert.strictEqual(s2Res.status, 200);

    // Fetch keys for room 1: should ONLY contain room 1 keys
    const r1KeysRes = await fetch(`${baseUrl}/rooms/${roomId}/session/keys`, {
      headers: { Authorization: `Bearer ${bobToken}` },
    });
    assert.strictEqual(r1KeysRes.status, 200);
    const r1KeysJson = await r1KeysRes.json();
    assert.ok(r1KeysJson.data.keys.length > 0);
    for (const k of r1KeysJson.data.keys) {
      assert.strictEqual(k.room_id, roomId, 'Key in room 1 query must belong to room 1');
    }

    // Fetch keys for room 2: should ONLY contain room 2 keys
    const r2KeysRes = await fetch(`${baseUrl}/rooms/${room2Id}/session/keys`, {
      headers: { Authorization: `Bearer ${bobToken}` },
    });
    assert.strictEqual(r2KeysRes.status, 200);
    const r2KeysJson = await r2KeysRes.json();
    assert.ok(r2KeysJson.data.keys.length > 0);
    for (const k of r2KeysJson.data.keys) {
      assert.strictEqual(k.room_id, room2Id, 'Key in room 2 query must belong to room 2');
    }
  });
});
