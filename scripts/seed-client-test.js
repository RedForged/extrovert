#!/usr/bin/env node
'use strict';

/**
 * seed-client-test.js
 *
 * Populates the database with deterministic test fixtures for native and third-party
 * client development (e.g. extrovert_native in Rust + Tauri).
 *
 * Run with: npm run seed:client
 */

const bcrypt = require('bcryptjs');
const db = require('../src/db');

async function seed() {
  console.log('--- Extrovert Client Development Testbed Seeder ---');

  const passwordHash = bcrypt.hashSync('password123', 8);

  // 1. Create or get test users
  function getOrCreateUser(username, displayName, email) {
    let user = db.getUserByUsername(username);
    if (!user) {
      const id = db.createUser({
        username,
        passwordHash,
        displayName,
        email,
      });
      user = db.getUserById(id);
      console.log(`[+] Created user: @${username} (id: ${id})`);
    } else {
      console.log(`[*] Existing user: @${username} (id: ${user.id})`);
    }
    // Verify email if policy requires
    db.db.prepare('UPDATE users SET email_verified_at = ? WHERE id = ?').run(Date.now(), user.id);
    return user;
  }

  const alice = getOrCreateUser('alice', 'Alice Developer', 'alice@test.local');
  const bob = getOrCreateUser('bob', 'Bob Tester', 'bob@test.local');
  const charlie = getOrCreateUser('charlie', 'Charlie Reviewer', 'charlie@test.local');

  // 2. Establish Social Graph (Mutual Follows & FoF)
  // Alice <-> Bob (mutual)
  // Bob <-> Charlie (mutual)
  // Therefore, Charlie is FoF to Alice!
  function ensureFollow(followerId, targetId) {
    if (!db.isFollowing(followerId, targetId)) {
      db.follow(followerId, targetId);
    }
  }

  ensureFollow(alice.id, bob.id);
  ensureFollow(bob.id, alice.id);
  ensureFollow(bob.id, charlie.id);
  ensureFollow(charlie.id, bob.id);
  console.log('[+] Established social graph (Alice <-> Bob <-> Charlie)');

  // 3. Create Personal Access Tokens (PATs)
  const fullScopes = 'read write follow notifications media.write read:direct write:direct profile';
  
  const alicePat = 'ext_pat_alice_full_access_token_12345';
  const bobPat = 'ext_pat_bob_full_access_token_67890';

  // Remove existing test tokens if present to ensure clean idempotency
  db.db.prepare(`DELETE FROM personal_access_tokens WHERE name IN ('client-dev-alice', 'client-dev-bob')`).run();

  const aliceToken = db.createPersonalAccessToken(alice.id, 'client-dev-alice', alicePat, fullScopes, null);
  const bobToken = db.createPersonalAccessToken(bob.id, 'client-dev-bob', bobPat, fullScopes, null);
  console.log('[+] Created deterministic PATs for @alice and @bob');

  // 4. Create Rooms & Channels
  let townSquare = db.db.prepare(`SELECT * FROM rooms WHERE name = 'Town Square'`).get();
  if (!townSquare) {
    const roomId = db.createRoom('Town Square', 'The community hub for Extrovert native testing', alice.id, 1);
    townSquare = db.getRoom(roomId);
    console.log(`[+] Created Public Room: Town Square (id: ${townSquare.id})`);
  } else {
    console.log(`[*] Existing Room: Town Square (id: ${townSquare.id})`);
  }

  // Ensure members
  if (!db.isRoomMember(townSquare.id, alice.id)) db.addRoomMember(townSquare.id, alice.id);
  if (!db.isRoomMember(townSquare.id, bob.id)) db.addRoomMember(townSquare.id, bob.id);
  if (!db.isRoomMember(townSquare.id, charlie.id)) db.addRoomMember(townSquare.id, charlie.id);

  // Ensure channels
  const channels = db.getRoomChannels(townSquare.id);
  let generalChan = channels.find(c => c.name === 'general');
  let devChan = channels.find(c => c.name === 'dev-talk');

  if (!generalChan) {
    const cid = db.createRoomChannel(townSquare.id, 'general', 'text');
    generalChan = db.getRoomChannel(cid);
    console.log(`[+] Created channel: #general (id: ${cid})`);
  }
  if (!devChan) {
    const cid = db.createRoomChannel(townSquare.id, 'dev-talk', 'text');
    devChan = db.getRoomChannel(cid);
    console.log(`[+] Created channel: #dev-talk (id: ${cid})`);
  }

  // 5. Seed sample posts
  const post1 = db.createPost({
    userId: alice.id,
    type: 'text',
    body: '# Welcome to Extrovert!\n\nThis is a sample post formatted in **Markdown** to test native client rendering.\n\n- Zero corporate bloat\n- YAGNI clean design\n- Realtime Gateway ready',
  });
  const post2 = db.createPost({
    userId: bob.id,
    type: 'text',
    body: 'Testing client reactions and comments. *It works!*',
  });
  console.log('[+] Created sample posts');

  console.log('\n======================================================');
  console.log('          CLIENT TEST FIXTURES READY TO USE           ');
  console.log('======================================================');
  console.log(`Alice PAT Token:  ${alicePat}`);
  console.log(`Bob PAT Token:    ${bobPat}`);
  console.log(`Town Square Room: ID ${townSquare.id}`);
  console.log(`General Channel:  ID ${generalChan.id}`);
  console.log('------------------------------------------------------');
  console.log('Example cURL:');
  console.log(`  curl -H "Authorization: Bearer ${alicePat}" http://localhost:3000/api/v1/accounts/verify_credentials`);
  console.log('------------------------------------------------------');
  console.log('Example WebSocket Gateway Connect:');
  console.log('  ws://localhost:3000/ws');
  console.log(`  -> {"action":"subscribe","topic":"room:${townSquare.id}","token":"${alicePat}"}`);
  console.log('======================================================\n');
}

if (require.main === module) {
  seed().catch(err => {
    console.error('Seed failed:', err);
    process.exit(1);
  });
}

module.exports = { seed };
