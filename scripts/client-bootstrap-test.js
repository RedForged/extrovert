'use strict';

/**
 * client-bootstrap-test.js
 *
 * Integration test suite for:
 * 1. Device Pairing (POST /api/v1/auth/pair/init & claim)
 * 2. Unified Client Bootstrap (GET /api/v1/client/bootstrap)
 * 3. Gateway Auto-Subscription (?token=...&auto_subscribe=1)
 * 4. Client ID / Nonce Echo on Status, Comment, and Room Message
 * 5. Dynamic room auto-subscription on join/leave
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const WebSocket = require('ws');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-bootstrap-test-'));
const TEST_DB = path.join(TEST_DIR, 'test.db');
const TEST_SESSION_DB = path.join(TEST_DIR, 'sessions.db');

process.env.EXTV_DB_PATH = TEST_DB;
process.env.EXTV_SESSION_DB_PATH = TEST_SESSION_DB;
process.env.SESSION_SECRET = 'bootstrap-test-secret';
process.env.PORT = '0'; // Ephemeral port
process.env.HOST = '127.0.0.1';

const db = require('../src/db');
const app = require('../src/server');

let baseUrl;
let wsUrl;
let aliceToken;
let bobToken;
let server;

// Seed test users
const aliceId = db.createUser({ username: 'alice_boot', passwordHash: 'hash', displayName: 'Alice Boot' });
const bobId = db.createUser({ username: 'bob_boot', passwordHash: 'hash', displayName: 'Bob Boot' });

// Create PATs for testing
aliceToken = 'ext_pat_' + require('node:crypto').randomBytes(32).toString('hex');
bobToken = 'ext_pat_' + require('node:crypto').randomBytes(32).toString('hex');
db.createPersonalAccessToken(aliceId, 'Alice Test Token', aliceToken, 'read write profile', null);
db.createPersonalAccessToken(bobId, 'Bob Test Token', bobToken, 'read write profile', null);

// Setup room and channel for Alice & Bob
const roomId = db.createRoom('Tech Talk', 'Technology discussion', aliceId, 1);
const roomChannels = db.getRoomChannels(roomId);
const defaultChan = roomChannels.find(c => c.name === 'general') || roomChannels[0];

// Create post for Alice
const postId = db.createPost({
  userId: aliceId,
  type: 'text',
  body: 'Welcome to Extrovert client testing!',
});

before(async () => {
  return new Promise((resolve) => {
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
});

after(() => {
  try { app.httpServer.close(); } catch {}
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
});

describe('Client Ergonomics & Unified Bootstrap Test Suite', () => {
  let pairingCode;
  let pairedPat;

  describe('Device Pairing Flow (Zero-Typing Login)', () => {
    it('initializes a short-lived pairing code (POST /api/v1/auth/pair/init)', async () => {
      const res = await fetch(`${baseUrl}/auth/pair/init`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${aliceToken}`,
          'Content-Type': 'application/json',
        },
      });

      assert.strictEqual(res.status, 201);
      const json = await res.json();
      assert.ok(json.data.code);
      assert.ok(json.data.code.startsWith('EXT-'));
      assert.strictEqual(json.data.expires_in, 300);
      assert.ok(json.data.pairing_url.includes(json.data.code));
      pairingCode = json.data.code;
    });

    it('claims the pairing code on a new client (POST /api/v1/auth/pair/claim)', async () => {
      const res = await fetch(`${baseUrl}/auth/pair/claim`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: pairingCode,
          client_name: 'Extrovert Native Linux',
        }),
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(json.token);
      assert.ok(json.token.startsWith('ext_pat_'));
      assert.strictEqual(json.token_type, 'Bearer');
      assert.strictEqual(json.data.user.username, 'alice_boot');
      assert.ok(json.data.scopes.includes('read:direct'));
      assert.ok(json.data.scopes.includes('write:direct'));
      assert.ok(json.data.scopes.includes('notifications'));
      assert.ok(json.data.scopes.includes('media.write'));
      assert.ok(json.data.scopes.includes('follow'));
      pairedPat = json.token;
    });

    it('rejects claiming an already claimed pairing code (single-use)', async () => {
      const res = await fetch(`${baseUrl}/auth/pair/claim`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: pairingCode }),
      });

      assert.strictEqual(res.status, 404);
    });

    it('validates authentication with the newly claimed paired PAT', async () => {
      const res = await fetch(`${baseUrl}/accounts/verify_credentials`, {
        headers: { 'Authorization': `Bearer ${pairedPat}` },
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.username, 'alice_boot');
    });

    it('allows initiator to specify custom scopes on pairing init', async () => {
      const initRes = await fetch(`${baseUrl}/auth/pair/init`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${aliceToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ scopes: 'read profile read:direct' }),
      });
      assert.strictEqual(initRes.status, 201);
      const initJson = await initRes.json();
      const customCode = initJson.data.code;

      const claimRes = await fetch(`${baseUrl}/auth/pair/claim`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: customCode, client_name: 'Scoped Device' }),
      });
      assert.strictEqual(claimRes.status, 200);
      const claimJson = await claimRes.json();
      assert.deepStrictEqual(claimJson.data.scopes, ['read', 'profile', 'read:direct']);
    });
  });

  describe('Unified Client Bootstrap (GET /api/v1/client/bootstrap)', () => {
    it('returns complete startup state in a single network round-trip', async () => {
      const res = await fetch(`${baseUrl}/client/bootstrap`, {
        headers: { 'Authorization': `Bearer ${pairedPat}` },
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      const data = json.data;

      // 1. Current user
      assert.ok(data.user);
      assert.strictEqual(data.user.username, 'alice_boot');

      // 2. Gateway initial sequence number
      assert.strictEqual(typeof data.initial_seq, 'number');

      // 3. Unread notifications
      assert.strictEqual(typeof data.unread_notifications, 'number');

      // 4. Joined rooms with channels and founder role
      assert.ok(Array.isArray(data.rooms));
      assert.strictEqual(data.rooms.length, 1);
      const room = data.rooms[0];
      assert.strictEqual(room.name, 'Tech Talk');
      assert.ok(room.role);
      assert.strictEqual(room.role.is_founder, true);
      assert.ok(Array.isArray(room.channels));
      assert.ok(room.channels.length > 0);
      assert.ok(Array.isArray(room.latest_messages));

      // 5. Home timeline
      assert.ok(Array.isArray(data.timeline));
      assert.ok(data.timeline.length > 0);
      assert.strictEqual(data.timeline[0].body, 'Welcome to Extrovert client testing!');

      // 6. ICE servers
      assert.ok(Array.isArray(data.ice_servers));
      assert.ok(data.ice_servers.length > 0);

      // 7. Server info
      assert.ok(data.server);
      assert.strictEqual(data.server.e2ee_supported, true);
      assert.strictEqual(data.server.realtime_gateway_url, '/ws');
    });
  });

  describe('Optimistic UI & Client ID Echo', () => {
    it('echoes client_id on status creation and broadcasts it over WebSocket', async () => {
      const ws = new WebSocket(`${wsUrl}?token=${bobToken}&auto_subscribe=1`);
      const subscribedPromise = new Promise((resolve) => {
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'subscribed' && msg.auto_subscribed) resolve();
          } catch {}
        });
      });
      await new Promise((resolve) => ws.on('open', resolve));
      await subscribedPromise;

      const clientTxId = 'opt-tx-' + Date.now();
      const broadcastPromise = new Promise((resolve) => {
        ws.on('message', (raw) => {
          const msg = JSON.parse(raw.toString());
          if (msg.type === 'gateway_event' && msg.event === 'post_create' && msg.data.client_id === clientTxId) {
            resolve(msg.data);
          }
        });
      });

      const res = await fetch(`${baseUrl}/statuses`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${aliceToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          body: 'Testing optimistic post UI echo',
          client_id: clientTxId,
        }),
      });

      assert.strictEqual(res.status, 201);
      const json = await res.json();
      assert.strictEqual(json.data.client_id, clientTxId);

      const eventData = await broadcastPromise;
      assert.strictEqual(eventData.client_id, clientTxId);
      assert.strictEqual(eventData.body, 'Testing optimistic post UI echo');

      ws.close();
    });

    it('echoes client_id on comment creation and broadcasts it', async () => {
      const ws = new WebSocket(`${wsUrl}?token=${bobToken}&auto_subscribe=1`);
      const subscribedPromise = new Promise((resolve) => {
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'subscribed' && msg.auto_subscribed) resolve();
          } catch {}
        });
      });
      await new Promise((resolve) => ws.on('open', resolve));
      await subscribedPromise;

      const commentTxId = 'comment-tx-' + Date.now();
      const broadcastPromise = new Promise((resolve) => {
        ws.on('message', (raw) => {
          const msg = JSON.parse(raw.toString());
          if (msg.type === 'gateway_event' && msg.event === 'comment_create' && msg.data.client_id === commentTxId) {
            resolve(msg.data);
          }
        });
      });

      const res = await fetch(`${baseUrl}/statuses/${postId}/comments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${aliceToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          body: 'Great test comment!',
          client_id: commentTxId,
        }),
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.client_id, commentTxId);

      const eventData = await broadcastPromise;
      assert.strictEqual(eventData.client_id, commentTxId);
      assert.strictEqual(eventData.body, 'Great test comment!');

      ws.close();
    });
  });

  describe('WebSocket Auto-Subscription & Dynamic Room Lifecycle', () => {
    it('automatically subscribes Bob to timeline, notifications, and joined rooms', async () => {
      // First, Bob joins the room
      await fetch(`${baseUrl}/rooms/${roomId}/join`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${bobToken}` },
      });

      const ws = new WebSocket(`${wsUrl}?token=${bobToken}&auto_subscribe=1`);
      const subPromise = new Promise((resolve) => {
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'subscribed' && msg.auto_subscribed) resolve(msg);
          } catch {}
        });
      });
      await new Promise((resolve) => ws.on('open', resolve));
      const subFrame = await subPromise;

      assert.strictEqual(subFrame.auto_subscribed, true);
      assert.ok(subFrame.channels.includes('timeline:home'));
      assert.ok(subFrame.channels.includes('notifications'));
      assert.ok(subFrame.channels.includes('presence'));
      assert.ok(subFrame.channels.includes(`room:${roomId}`));

      ws.close();
    });

    it('echoes client_id on room sticker message and broadcasts to room topic', async () => {
      const ws = new WebSocket(`${wsUrl}?token=${aliceToken}&auto_subscribe=1`);
      const subPromise = new Promise((resolve) => {
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'subscribed' && msg.auto_subscribed) resolve(msg);
          } catch {}
        });
      });
      await new Promise((resolve) => ws.on('open', resolve));
      await subPromise;

      const roomTxId = 'room-tx-' + Date.now();
      const broadcastPromise = new Promise((resolve) => {
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'gateway_event' && msg.event === 'message_create' && msg.data.client_id === roomTxId) {
              resolve(msg.data);
            }
          } catch {}
        });
      });

      const res = await fetch(`${baseUrl}/rooms/${roomId}/channels/${defaultChan.id}/messages`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${aliceToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          body: '/uploads/stickers/thumbsup.png',
          client_id: roomTxId,
        }),
      });

      assert.strictEqual(res.status, 201);
      const json = await res.json();
      assert.strictEqual(json.data.client_id, roomTxId);

      const eventData = await broadcastPromise;
      assert.strictEqual(eventData.client_id, roomTxId);
      assert.strictEqual(eventData.body, '/uploads/stickers/thumbsup.png');

      ws.close();
    });

    it('supports reconnecting and resuming with auto_subscribe: true in one frame', async () => {
      const ws = new WebSocket(wsUrl);
      await new Promise((resolve) => ws.on('open', resolve));

      const subPromise = new Promise((resolve) => {
        ws.on('message', (raw) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg.type === 'resumed') resolve(msg);
          } catch {}
        });
      });

      ws.send(JSON.stringify({
        action: 'resume',
        token: aliceToken,
        seq: 0,
        auto_subscribe: true,
      }));

      const resumeFrame = await subPromise;
      assert.strictEqual(resumeFrame.type, 'resumed');
      assert.ok(resumeFrame.last_seq >= 1);

      ws.close();
    });
  });
});
