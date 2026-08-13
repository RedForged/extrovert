// End-to-end and unit tests for message deletion (DMs and Rooms).
// Run: node scripts/delete-message-test.js
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const bcrypt = require('bcryptjs');
const WebSocket = require('ws');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-delmsg-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'extrovert.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 'sessions.db');
process.env.SESSION_SECRET = 'del-msg-test-secret';
process.env.SECRET = 'del-msg-test-secret';
process.env.PORT = String(32000 + Math.floor(Math.random() * 1000));

const app = require('../src/server');
const db = require('../src/db');

let failures = 0;
function ok(cond, msg) {
  console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg);
  if (!cond) failures++;
}

async function main() {
  const base = 'http://localhost:' + process.env.PORT;
  const wsBase = 'ws://localhost:' + process.env.PORT;

  // Setup users: alice, bob (mutuals), carol (not mutual)
  const aliceId = db.createUser({ username: 'alice', passwordHash: bcrypt.hashSync('pw1', 10), displayName: 'Alice' });
  const bobId = db.createUser({ username: 'bob', passwordHash: bcrypt.hashSync('pw2', 10), displayName: 'Bob' });
  const carolId = db.createUser({ username: 'carol', passwordHash: bcrypt.hashSync('pw3', 10), displayName: 'Carol' });

  db.follow(aliceId, bobId);
  db.follow(bobId, aliceId);
  db.setOlmIdentity(aliceId, 'alice-curve', 'alice-ed', null);
  db.setOlmIdentity(bobId, 'bob-curve', 'bob-ed', null);

  // Setup OAuth apps & tokens for alice and bob
  db.createOAuthApp({ name: 't', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'c1', clientSecret: 's1', scopes: 'read write follow read:direct write:direct', ownerId: aliceId });
  const aliceToken = crypto.randomBytes(32).toString('hex');
  db.createOAuthToken(aliceToken, null, db.getOAuthAppByClientId('c1').id, aliceId, 'read write follow read:direct write:direct', Date.now() + 86400000);

  const bobToken = crypto.randomBytes(32).toString('hex');
  db.createOAuthToken(bobToken, null, db.getOAuthAppByClientId('c1').id, bobId, 'read write follow read:direct write:direct', Date.now() + 86400000);

  const carolToken = crypto.randomBytes(32).toString('hex');
  db.createOAuthToken(carolToken, null, db.getOAuthAppByClientId('c1').id, carolId, 'read write follow read:direct write:direct', Date.now() + 86400000);

  // Helper for web session cookies
  async function loginWeb(username, password) {
    const jar = {};
    async function req(url, opts = {}) {
      const headers = { ...(opts.headers || {}) };
      if (jar.cookie) headers['Cookie'] = jar.cookie;
      const r = await fetch(base + url, { ...opts, headers, redirect: 'manual' });
      const sc = r.headers.get('set-cookie');
      if (sc) {
        const sid = sc.split(';')[0];
        jar.cookie = sid;
      }
      return r;
    }

    const loginPage = await req('/login');
    const html = await loginPage.text();
    const csrf = html.match(/name="_csrf" value="([^"]+)"/)[1];
    await req('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&_csrf=${encodeURIComponent(csrf)}`,
    });
    const postLogin = await req('/chats');
    const postHtml = await postLogin.text();
    const fresh = postHtml.match(/name="csrf-token" content="([^"]+)"/);
    const sessionCsrf = fresh ? fresh[1] : csrf;
    return { jar, csrf: sessionCsrf, req };
  }

  const aliceWeb = await loginWeb('alice', 'pw1');
  const bobWeb = await loginWeb('bob', 'pw2');

  console.log('\nTEST 1: Direct Message Deletion via Web Flow');

  // Bob connects to WS to receive live events
  const wsBob = new WebSocket(wsBase + '/ws', { headers: { Cookie: bobWeb.jar.cookie } });
  await new Promise((resolve, reject) => { wsBob.once('open', resolve); wsBob.once('error', reject); });
  wsBob.send(JSON.stringify({ type: 'ping' }));
  await new Promise(r => setTimeout(r, 200));

  let bobReceivedDelete = null;
  wsBob.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (msg.type === 'delete_dm') bobReceivedDelete = msg;
  });

  // Alice sends a message to Bob
  const msgId1 = db.sendMessage(aliceId, bobId, '{"b":"secret"}', null, null, 'olm', '{"b":"self"}', 0);
  ok(!!db.db.prepare('SELECT id FROM messages WHERE id = ?').get(msgId1), 'Alice sent message exists in DB');

  // Alice edits the message (to generate edit_history)
  db.editMessage(msgId1, aliceId, '{"b":"edited"}', null, null, 'olm', '{"b":"edited-self"}');
  const historyBefore = db.getEditHistory('message', msgId1);
  ok(historyBefore.length === 1, 'Edit history recorded before deletion');

  // Bob tries to delete Alice's message -> should fail (404/not yours)
  const bobDelRes = await bobWeb.req('/chats/alice/delete/' + msgId1, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
    body: `_csrf=${encodeURIComponent(bobWeb.csrf)}`,
  });
  const bobDelData = await bobDelRes.json();
  ok(bobDelRes.status === 404 || !!bobDelData.error, 'Bob cannot delete Alice message');

  // Alice deletes her message
  const aliceDelRes = await aliceWeb.req('/chats/bob/delete/' + msgId1, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
    body: `_csrf=${encodeURIComponent(aliceWeb.csrf)}`,
  });
  const aliceDelData = await aliceDelRes.json();
  ok(aliceDelData.ok && aliceDelData.deleted === msgId1, 'Alice deleted message via web endpoint');

  // Verify message row is gone from DB
  const rowAfter = db.db.prepare('SELECT id FROM messages WHERE id = ?').get(msgId1);
  ok(!rowAfter, 'Message removed from database');

  // Verify edit_history is cleaned up
  const historyAfter = db.getEditHistory('message', msgId1);
  ok(historyAfter.length === 0, 'Associated edit history cleaned up');

  // Wait for WebSocket event
  await new Promise(r => setTimeout(r, 300));
  ok(bobReceivedDelete && bobReceivedDelete.message_id === msgId1, 'Bob received live delete_dm WebSocket event');

  console.log('\nTEST 2: Direct Message Deletion via REST API');

  // Alice sends another message via API
  const sendRes = await fetch(base + '/api/v1/conversations/bob/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + aliceToken },
    body: JSON.stringify({ proto: 'olm', body: '{"b":"api-secret"}', sender_ciphertext: '{"b":"api-self"}' }),
  });
  const sendData = await sendRes.json();
  const msgId2 = parseInt(sendData.data.id, 10);
  ok(sendRes.status === 201 && !!msgId2, 'Alice sent DM via API');

  bobReceivedDelete = null;

  // Bob tries to delete Alice's message via API -> 404
  const bobApiDel = await fetch(base + '/api/v1/messages/' + msgId2, {
    method: 'DELETE',
    headers: { Authorization: 'Bearer ' + bobToken },
  });
  ok(bobApiDel.status === 404, 'Bob cannot delete Alice message via API (404)');

  // Alice deletes via API
  const aliceApiDel = await fetch(base + '/api/v1/messages/' + msgId2, {
    method: 'DELETE',
    headers: { Authorization: 'Bearer ' + aliceToken },
  });
  const aliceApiDelData = await aliceApiDel.json();
  ok(aliceApiDel.status === 200 && aliceApiDelData.data.ok, 'Alice deleted DM via REST API');

  // Check DB
  ok(!db.db.prepare('SELECT id FROM messages WHERE id = ?').get(msgId2), 'API-deleted message removed from DB');

  // Check WebSocket event
  await new Promise(r => setTimeout(r, 300));
  ok(bobReceivedDelete && bobReceivedDelete.message_id === msgId2, 'Bob received live delete_dm event from API deletion');

  console.log('\nTEST 3: Room Message Deletion via REST API');

  // Alice creates a room and channel
  const roomId = db.createRoom('Tech Chat', 'Discuss tech', aliceId, 1);
  const channels = db.getRoomChannels(roomId);
  const chanId = channels[0].id;
  db.addRoomMember(roomId, bobId, db.getRoomRoles(roomId).find(r => r.is_founder === 0).id);
  db.addRoomMember(roomId, carolId, db.getRoomRoles(roomId).find(r => r.is_founder === 0).id);

  // Bob posts a message to the room channel
  const roomMsgId1 = db.sendRoomMessage(chanId, bobId, '/uploads/stickers/cat.png', 'plain', null, null);
  ok(!!db.db.prepare('SELECT id FROM room_messages WHERE id = ?').get(roomMsgId1), 'Bob posted room message');

  // Carol (regular member) tries to delete Bob's room message -> 403
  const carolRoomDel = await fetch(base + `/api/v1/rooms/${roomId}/channels/${chanId}/messages/${roomMsgId1}`, {
    method: 'DELETE',
    headers: { Authorization: 'Bearer ' + carolToken },
  });
  ok(carolRoomDel.status === 403, 'Carol cannot delete Bob room message (403)');

  // Bob deletes his own room message -> 200
  const bobRoomDel = await fetch(base + `/api/v1/rooms/${roomId}/channels/${chanId}/messages/${roomMsgId1}`, {
    method: 'DELETE',
    headers: { Authorization: 'Bearer ' + bobToken },
  });
  const bobRoomDelData = await bobRoomDel.json();
  ok(bobRoomDel.status === 200 && bobRoomDelData.data.ok, 'Bob deleted his own room message via API');
  ok(!db.db.prepare('SELECT id FROM room_messages WHERE id = ?').get(roomMsgId1), 'Room message removed from DB');

  // Bob posts another room message
  const roomMsgId2 = db.sendRoomMessage(chanId, bobId, '/uploads/stickers/dog.png', 'plain', null, null);
  // Alice (founder/admin) deletes Bob's room message -> 200
  const aliceRoomDel = await fetch(base + `/api/v1/rooms/${roomId}/channels/${chanId}/messages/${roomMsgId2}`, {
    method: 'DELETE',
    headers: { Authorization: 'Bearer ' + aliceToken },
  });
  const aliceRoomDelData = await aliceRoomDel.json();
  ok(aliceRoomDel.status === 200 && aliceRoomDelData.data.ok, 'Alice (founder) deleted Bob room message as moderator');
  ok(!db.db.prepare('SELECT id FROM room_messages WHERE id = ?').get(roomMsgId2), 'Room message deleted by founder removed from DB');

  wsBob.close();
  try { fs.rmSync(TEST_DIR, { recursive: true, force: true }); } catch {}

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL MESSAGE DELETION CHECKS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
