'use strict';

/**
 * client-parity-test.js
 *
 * Exhaustive integration test suite for Client DX:
 * - Dynamic Client Registration (POST /api/v1/apps)
 * - Personal Access Tokens (PATs) & auth middleware
 * - Session Management (GET & DELETE /api/v1/accounts/sessions)
 * - Post Editing & Revision History (PATCH & GET /api/v1/statuses/:id/history)
 * - Follow Attribution (POST /api/v1/statuses/:id/follow_from)
 * - Comment Edit & Delete (PATCH & DELETE /api/v1/statuses/:id/comments/:cid)
 * - DM Message Edit & Delete (PATCH & DELETE /api/v1/messages/:id)
 * - Full Room Management (create, patch, channels, roles, assign, leave, delete)
 * - Stickers REST API (GET, POST, DELETE /api/v1/stickers)
 * - FoF Discover (GET /api/v1/discover)
 * - WebRTC ICE Servers (GET /api/v1/calls/ice_servers)
 * - Realtime WebSocket Gateway (subscribe, broadcast, seq buffer, resume)
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const WebSocket = require('ws');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-client-test-'));
const TEST_DB = path.join(TEST_DIR, 'test.db');
const TEST_SESSION_DB = path.join(TEST_DIR, 'sessions.db');

process.env.EXTV_DB_PATH = TEST_DB;
process.env.EXTV_SESSION_DB_PATH = TEST_SESSION_DB;
process.env.SESSION_SECRET = 'client-test-secret';
process.env.PORT = '0'; // Ephemeral port
process.env.HOST = '127.0.0.1';

const db = require('../src/db');
const app = require('../src/server');

let baseUrl;
let wsUrl;

// Seed test users
const aliceId = db.createUser({ username: 'alice', passwordHash: 'hash', displayName: 'Alice' });
const bobId = db.createUser({ username: 'bob', passwordHash: 'hash', displayName: 'Bob' });
const charlieId = db.createUser({ username: 'charlie', passwordHash: 'hash', displayName: 'Charlie' });

// Social graph: Alice <-> Bob (mutual), Bob <-> Charlie (mutual) => Charlie is FoF to Alice
db.follow(aliceId, bobId);
db.follow(bobId, aliceId);
db.follow(bobId, charlieId);
db.follow(charlieId, bobId);

// Create OAuth tokens for initial setup
const appId = db.createOAuthApp({
  name: 'ClientTest', description: '', website: '',
  redirectUris: 'https://ex.com/cb',
  clientId: 'client-test-id', clientSecret: 'client-test-secret',
  scopes: 'read write follow notifications media.write read:direct write:direct profile',
  ownerId: aliceId,
});

const aliceOAuthToken = crypto.randomBytes(32).toString('hex');
db.createOAuthToken(aliceOAuthToken, null, appId, aliceId, 'read write follow notifications media.write read:direct write:direct profile', Date.now() + 86400000);
// An existing sticker file must have a user_files row owned by the uploader
// (the "add by path" endpoint only adopts files you own).
db.createUserFile({ userId: aliceId, kind: 'sticker', root: 'uploads', path: 'stickers/my_sticker.png', size: 10 });

const bobOAuthToken = crypto.randomBytes(32).toString('hex');
db.createOAuthToken(bobOAuthToken, null, appId, bobId, 'read write follow notifications media.write read:direct write:direct profile', Date.now() + 86400000);

function fetchJson(url, opts = {}) {
  const headers = {};
  if (opts.token) headers['Authorization'] = 'Bearer ' + opts.token;
  if (opts.body && !opts.formData) headers['Content-Type'] = 'application/json';

  const body = opts.body ? (opts.formData ? opts.body : JSON.stringify(opts.body)) : undefined;
  return fetch(`${baseUrl}${url}`, {
    method: opts.method || 'GET',
    headers,
    body,
    redirect: 'manual',
  });
}

describe('Extrovert Client Developer Experience & Parity Suite', () => {
  before(async () => {
    return new Promise((resolve) => {
      // app.httpServer is already listening on PORT 0
      const port = app.httpServer.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      wsUrl = `ws://127.0.0.1:${port}/ws`;
      console.log(`\n  Client test server running on ${baseUrl} (WS: ${wsUrl})\n`);
      resolve();
    });
  });

  after(() => {
    try { app.httpServer.close(); } catch {}
    try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}
  });

  // ----------------------------------------------------
  // 1. Dynamic Client Registration
  // ----------------------------------------------------
  describe('Dynamic Client Registration (POST /api/v1/apps)', () => {
    it('allows unauthenticated registration of third-party/native apps', async () => {
      const res = await fetchJson('/api/v1/apps', {
        method: 'POST',
        body: {
          client_name: 'Extrovert Desktop Client',
          redirect_uris: 'extrovert://oauth-callback',
          scopes: 'read write follow notifications',
          website: 'https://github.com/redforged/extrovert',
        },
      });

      assert.strictEqual(res.status, 201);
      const json = await res.json();
      assert.strictEqual(json.name, 'Extrovert Desktop Client');
      assert.ok(json.client_id, 'client_id should be returned');
      assert.ok(json.client_secret, 'client_secret should be returned');
      assert.strictEqual(json.redirect_uri, 'extrovert://oauth-callback');
    });

    it('rejects registration without client_name', async () => {
      const res = await fetchJson('/api/v1/apps', {
        method: 'POST',
        body: { redirect_uris: 'urn:ietf:wg:oauth:2.0:oob' },
      });
      assert.strictEqual(res.status, 400);
    });
  });

  // ----------------------------------------------------
  // 2. Personal Access Tokens (PATs)
  // ----------------------------------------------------
  describe('Personal Access Tokens (PATs)', () => {
    let createdPat = null;
    let patId = null;

    it('creates a personal access token for the authenticated user', async () => {
      const res = await fetchJson('/api/v1/accounts/tokens', {
        method: 'POST',
        token: aliceOAuthToken,
        body: {
          name: 'My Rust Laptop CLI',
          scopes: 'read write follow',
          expires_in_days: 30,
        },
      });

      assert.strictEqual(res.status, 201);
      const json = await res.json();
      assert.ok(json.data.token.startsWith('ext_pat_'), 'PAT must start with ext_pat_');
      assert.strictEqual(json.data.name, 'My Rust Laptop CLI');
      createdPat = json.data.token;
      patId = json.data.id;
    });

    it('allows authenticating to protected endpoints using the PAT bearer header', async () => {
      const res = await fetchJson('/api/v1/accounts/verify_credentials', {
        token: createdPat,
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.username, 'alice');
    });

    it('lists personal access tokens with redacted token secrets', async () => {
      const res = await fetchJson('/api/v1/accounts/tokens', {
        token: aliceOAuthToken,
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.data));
      const found = json.data.find(t => t.id === patId);
      assert.ok(found, 'Created PAT should be listed');
      assert.strictEqual(found.token, undefined, 'Full token secret must not be exposed on list');
      assert.ok(found.token_prefix, 'Token prefix should be visible for identification');
    });

    it('revokes a personal access token', async () => {
      const delRes = await fetchJson(`/api/v1/accounts/tokens/${patId}`, {
        method: 'DELETE',
        token: aliceOAuthToken,
      });
      assert.strictEqual(delRes.status, 200);

      // Verifying with revoked PAT must now fail
      const testRes = await fetchJson('/api/v1/accounts/verify_credentials', {
        token: createdPat,
      });
      assert.strictEqual(testRes.status, 401);
    });
  });

  // ----------------------------------------------------
  // 3. Post Editing & Edit History
  // ----------------------------------------------------
  describe('Post Editing & Edit History', () => {
    let postId = null;

    it('creates a post and edits it via PATCH /api/v1/statuses/:id', async () => {
      // 1. Create post
      const createRes = await fetchJson('/api/v1/statuses', {
        method: 'POST',
        token: aliceOAuthToken,
        body: { status: '# Original Title\n\nOriginal text content' },
      });
      assert.ok(createRes.status === 200 || createRes.status === 201, 'Post creation should return 200 or 201');
      const created = await createRes.json();
      postId = created.data.id;

      // 2. Edit post
      const editRes = await fetchJson(`/api/v1/statuses/${postId}`, {
        method: 'PATCH',
        token: aliceOAuthToken,
        body: { status: '# Updated Title\n\nUpdated markdown text with **bold**' },
      });
      assert.strictEqual(editRes.status, 200);
      const updated = await editRes.json();
      assert.strictEqual(updated.data.content, '# Updated Title\n\nUpdated markdown text with **bold**');
      assert.ok(updated.data.edited_at, 'edited_at timestamp should be set');
      assert.ok(updated.data.content_html.includes('<strong>bold</strong>'), 'Markdown should be rendered');
    });

    it('retrieves the revision edit history via GET /api/v1/statuses/:id/history', async () => {
      const res = await fetchJson(`/api/v1/statuses/${postId}/history`, {
        token: aliceOAuthToken,
      });

      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.data));
      assert.strictEqual(json.data.length, 1, 'Should have 1 recorded edit revision');
      assert.strictEqual(json.data[0].body, '# Original Title\n\nOriginal text content');
    });

    it('forbids editing a post by a different user', async () => {
      const res = await fetchJson(`/api/v1/statuses/${postId}`, {
        method: 'PATCH',
        token: bobOAuthToken,
        body: { status: 'Hacked by Bob' },
      });
      assert.strictEqual(res.status, 403);
    });

    it('records follow attribution via POST /api/v1/statuses/:id/follow_from', async () => {
      const res = await fetchJson(`/api/v1/statuses/${postId}/follow_from`, {
        method: 'POST',
        token: bobOAuthToken,
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.ok, true);
    });
  });

  // ----------------------------------------------------
  // 4. Comments Edit & Delete
  // ----------------------------------------------------
  describe('Comment Edit & Delete', () => {
    let postId = null;
    let commentId = null;

    before(async () => {
      const res = await fetchJson('/api/v1/statuses', {
        method: 'POST',
        token: aliceOAuthToken,
        body: { status: 'Post for comment test' },
      });
      const json = await res.json();
      postId = json.data.id;
    });

    it('adds, edits, and deletes a comment', async () => {
      // 1. Add comment
      const addRes = await fetchJson(`/api/v1/statuses/${postId}/comment`, {
        method: 'POST',
        token: bobOAuthToken,
        body: { body: 'Initial comment from Bob' },
      });
      assert.strictEqual(addRes.status, 200);
      const commentJson = await addRes.json();
      commentId = commentJson.data.id;

      // 2. Edit comment
      const editRes = await fetchJson(`/api/v1/statuses/${postId}/comments/${commentId}`, {
        method: 'PATCH',
        token: bobOAuthToken,
        body: { body: 'Edited comment from Bob' },
      });
      assert.strictEqual(editRes.status, 200);
      const edited = await editRes.json();
      assert.strictEqual(edited.data.body, 'Edited comment from Bob');

      // 3. Delete comment
      const delRes = await fetchJson(`/api/v1/statuses/${postId}/comments/${commentId}`, {
        method: 'DELETE',
        token: bobOAuthToken,
      });
      assert.strictEqual(delRes.status, 200);
      const deleted = await delRes.json();
      assert.strictEqual(deleted.data.ok, true);
    });
  });

  // ----------------------------------------------------
  // 5. Room Full Management REST API
  // ----------------------------------------------------
  describe('DM Message Edit & Delete (MLS)', () => {
    let msgId = null;

    it('sends an MLS DM message', async () => {
      const res = await fetchJson('/api/v1/conversations/bob/messages', {
        method: 'POST',
        token: aliceOAuthToken,
        body: { proto: 'mls', body: 'bWxzX2NpcGhlcnRleHRfMQ==' },
      });
      assert.strictEqual(res.status, 201);
      const d = await res.json();
      msgId = String((d.data && d.data.id) || d.id);
      assert.ok(msgId && msgId !== 'undefined', 'send must return the message id');
    });

    it('edits an MLS message without sender_ciphertext', async () => {
      const res = await fetchJson('/api/v1/messages/' + msgId, {
        method: 'PATCH',
        token: aliceOAuthToken,
        body: { proto: 'mls', body: 'bWxzX2NpcGhlcnRleHRfMg==' },
      });
      assert.strictEqual(res.status, 200);
    });

    it("rejects editing someone else's message", async () => {
      const res = await fetchJson('/api/v1/messages/' + msgId, {
        method: 'PATCH',
        token: bobOAuthToken,
        body: { proto: 'mls', body: 'aGF4' },
      });
      assert.strictEqual(res.status, 404);
    });

    it('rejects legacy plaintext edits', async () => {
      const res = await fetchJson('/api/v1/messages/' + msgId, {
        method: 'PATCH',
        token: aliceOAuthToken,
        body: { proto: 'rsa', body: 'plaintext' },
      });
      assert.strictEqual(res.status, 400);
    });

    it('deletes the message', async () => {
      const res = await fetchJson('/api/v1/messages/' + msgId, {
        method: 'DELETE',
        token: aliceOAuthToken,
      });
      assert.strictEqual(res.status, 200);
      const gone = await fetchJson('/api/v1/messages/' + msgId, {
        method: 'DELETE',
        token: aliceOAuthToken,
      });
      assert.strictEqual(gone.status, 404, 'double delete must not succeed');
    });
  });

  describe('Room Full Management REST API', () => {
    let roomId = null;
    let channelId = null;
    let roleId = null;

    it('creates a room (POST /api/v1/rooms)', async () => {
      const res = await fetchJson('/api/v1/rooms', {
        method: 'POST',
        token: aliceOAuthToken,
        body: {
          name: 'Native Guild',
          description: 'A test room for native clients',
          is_public: true,
        },
      });
      assert.strictEqual(res.status, 201);
      const json = await res.json();
      roomId = json.data.id;
      assert.strictEqual(json.data.name, 'Native Guild');
    });

    it('updates room styling and description (PATCH /api/v1/rooms/:id)', async () => {
      const res = await fetchJson(`/api/v1/rooms/${roomId}`, {
        method: 'PATCH',
        token: aliceOAuthToken,
        body: {
          description: 'Updated description',
          custom_css: 'body { background: #000; }',
        },
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.description, 'Updated description');
      assert.strictEqual(json.data.css, 'body { background: #000; }');
    });

    it('creates a channel in the room (POST /api/v1/rooms/:id/channels)', async () => {
      const res = await fetchJson(`/api/v1/rooms/${roomId}/channels`, {
        method: 'POST',
        token: aliceOAuthToken,
        body: { name: 'rust-dev', type: 'text' },
      });
      assert.strictEqual(res.status, 201);
      const json = await res.json();
      channelId = json.data.id;
      assert.strictEqual(json.data.name, 'rust-dev');
    });

    it('creates a role in the room (POST /api/v1/rooms/:id/roles)', async () => {
      const res = await fetchJson(`/api/v1/rooms/${roomId}/roles`, {
        method: 'POST',
        token: aliceOAuthToken,
        body: {
          name: 'Core Developer',
          color: '#3498db',
          permissions: 31,
        },
      });
      assert.strictEqual(res.status, 201);
      const json = await res.json();
      roleId = json.data.id;
      assert.strictEqual(json.data.name, 'Core Developer');
    });

    it('allows Bob to join the public room (POST /api/v1/rooms/:id/join)', async () => {
      const res = await fetchJson(`/api/v1/rooms/${roomId}/join`, {
        method: 'POST',
        token: bobOAuthToken,
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.status, 'joined');
    });

    it('assigns role to Bob (POST /api/v1/rooms/:id/members/:uid/roles)', async () => {
      const res = await fetchJson(`/api/v1/rooms/${roomId}/members/${bobId}/roles`, {
        method: 'POST',
        token: aliceOAuthToken,
        body: { role_id: roleId },
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.ok, true);
    });

    it('allows Bob to leave the room (POST /api/v1/rooms/:id/leave)', async () => {
      const res = await fetchJson(`/api/v1/rooms/${roomId}/leave`, {
        method: 'POST',
        token: bobOAuthToken,
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.ok, true);
    });

    it('deletes the room (DELETE /api/v1/rooms/:id)', async () => {
      const res = await fetchJson(`/api/v1/rooms/${roomId}`, {
        method: 'DELETE',
        token: aliceOAuthToken,
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.ok, true);
    });
  });

  // ----------------------------------------------------
  // 6. Stickers REST API
  // ----------------------------------------------------
  describe('Stickers REST API', () => {
    let stickerId = null;

    it('lists stickers (GET /api/v1/stickers)', async () => {
      const res = await fetchJson('/api/v1/stickers', {
        token: aliceOAuthToken,
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.data));
    });

    it('adds an existing sticker path (POST /api/v1/stickers)', async () => {
      const res = await fetchJson('/api/v1/stickers', {
        method: 'POST',
        token: aliceOAuthToken,
        body: { path: '/uploads/stickers/my_sticker.png' },
      });
      assert.strictEqual(res.status, 201);
      const json = await res.json();
      stickerId = json.data.id;
      assert.strictEqual(json.data.file_path, '/uploads/stickers/my_sticker.png');
    });

    it('deletes a sticker (DELETE /api/v1/stickers/:id)', async () => {
      const res = await fetchJson(`/api/v1/stickers/${stickerId}`, {
        method: 'DELETE',
        token: aliceOAuthToken,
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.strictEqual(json.data.ok, true);
    });
  });

  // ----------------------------------------------------
  // 7. FoF Discover & WebRTC ICE Servers
  // ----------------------------------------------------
  describe('FoF Discover & ICE Servers', () => {
    it('returns FoF user recommendations (GET /api/v1/discover)', async () => {
      // Alice follows Bob, Bob follows Charlie. Charlie is FoF of Alice.
      const res = await fetchJson('/api/v1/discover', {
        token: aliceOAuthToken,
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.data));
      const foundCharlie = json.data.find(u => u.username === 'charlie');
      assert.ok(foundCharlie, 'Charlie should be suggested to Alice as FoF');
    });

    it('returns ICE servers configuration (GET /api/v1/calls/ice_servers)', async () => {
      const res = await fetchJson('/api/v1/calls/ice_servers', {
        token: aliceOAuthToken,
      });
      assert.strictEqual(res.status, 200);
      const json = await res.json();
      assert.ok(Array.isArray(json.data.ice_servers));
      assert.ok(json.data.ice_servers.length > 0);
      assert.ok(json.data.ice_servers[0].urls);
    });
  });

  // ----------------------------------------------------
  // 8. WebSocket Gateway Pub/Sub & Sequence Replay
  // ----------------------------------------------------
  describe('WebSocket Realtime Gateway', () => {
    it('subscribes to topics, receives broadcast events with seq numbers, and supports resume', async () => {
      const ws = new WebSocket(wsUrl);

      await new Promise((resolve, reject) => {
        ws.on('open', resolve);
        ws.on('error', reject);
      });

      // 1. Subscribe to timeline:home
      ws.send(JSON.stringify({
        action: 'subscribe',
        topic: 'timeline:home',
        token: aliceOAuthToken,
      }));

      // Wait for subscribed confirmation
      const subscribed = await new Promise((resolve) => {
        ws.on('message', (raw) => {
          const msg = JSON.parse(raw);
          if (msg.type === 'subscribed') resolve(msg);
        });
      });
      assert.strictEqual(subscribed.topic, 'timeline:home');

      // 2. Trigger an event by publishing a post
      const receivedEventPromise = new Promise((resolve) => {
        ws.on('message', (raw) => {
          const msg = JSON.parse(raw);
          if (msg.type === 'gateway_event' && msg.event === 'post_create') {
            resolve(msg);
          }
        });
      });

      await fetchJson('/api/v1/statuses', {
        method: 'POST',
        token: aliceOAuthToken,
        body: { status: 'Gateway Realtime Broadcast Test Post' },
      });

      const eventMsg = await receivedEventPromise;
      assert.strictEqual(eventMsg.topic, 'timeline:home');
      assert.strictEqual(eventMsg.event, 'post_create');
      assert.ok(typeof eventMsg.seq === 'number', 'Event must contain sequence number');
      const receivedSeq = eventMsg.seq;

      // 3. Test typing indicator
      const typingPromise = new Promise((resolve) => {
        ws.on('message', (raw) => {
          const msg = JSON.parse(raw);
          if (msg.type === 'typing') resolve(msg);
        });
      });

      ws.send(JSON.stringify({
        action: 'typing',
        channel: 'room:test',
        typing: true,
      }));

      const typingMsg = await typingPromise;
      assert.strictEqual(typingMsg.type, 'typing');
      assert.strictEqual(typingMsg.channel, 'room:test');
      assert.strictEqual(typingMsg.typing, true);

      // Close first connection
      ws.close();

      // 4. Test reconnect with resume opcode
      const ws2 = new WebSocket(wsUrl);
      await new Promise((resolve, reject) => {
        ws2.on('open', resolve);
        ws2.on('error', reject);
      });

      // Subscribe again
      ws2.send(JSON.stringify({
        action: 'subscribe',
        topic: 'timeline:home',
        token: aliceOAuthToken,
      }));

      await new Promise((resolve) => {
        const handler = (raw) => {
          const msg = JSON.parse(raw);
          if (msg.type === 'subscribed') {
            ws2.off('message', handler);
            resolve();
          }
        };
        ws2.on('message', handler);
      });

      // Resume from receivedSeq - 1
      const resumedPromise = new Promise((resolve) => {
        ws2.on('message', (raw) => {
          const msg = JSON.parse(raw);
          if (msg.type === 'resumed') resolve(msg);
        });
      });

      ws2.send(JSON.stringify({
        action: 'resume',
        seq: receivedSeq - 1,
      }));

      const resumedMsg = await resumedPromise;
      assert.strictEqual(resumedMsg.type, 'resumed');
      assert.ok(resumedMsg.replayed >= 1, 'Should replay missed events');

      ws2.close();
    });
  });
});
