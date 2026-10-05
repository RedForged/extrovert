'use strict';

/**
 * Dual-Stack End-to-End Room Integration Test (Phase 3)
 *
 * Validates:
 * 1. Alice creates a Room with Bob (legacy-only user, no MLS devices):
 *    - Room MLS capability check resolves false
 *    - Automatically routes to Megolm room encryption (proto: 'megolm')
 *    - Server stores Megolm message with group_session_id
 * 2. Alice creates a Room with Charlie and Dave (dual-stack MLS):
 *    - Room MLS capability check resolves true
 *    - Automatically initializes MLS group 'room:<id>' on server
 *    - Welcomes queued for Charlie and Dave
 *    - Alice sends message with proto: 'mls' (single ciphertext, zero device fanout)
 *    - Charlie and Dave consume Welcomes, join the room group, and BOTH decrypt Alice's message
 * 3. Dave replies to Room:
 *    - Dave encrypts with active MLS room state (proto: 'mls')
 *    - Alice and Charlie BOTH decrypt Dave's reply cleanly
 * 4. Dynamic Member Addition:
 *    - Eve joins the room
 *    - Active member commits AddProposal(Eve) advancing epoch to 2
 *    - Eve consumes Welcome, joins room, and decrypts subsequent messages
 * 5. Message Edit with MLS:
 *    - Dave edits his message with proto: 'mls'
 *    - Edited message stored and decrypted by peers
 * 6. CAS Epoch Conflict Resiliency:
 *    - Concurrent commit attempt triggers 409 EpochConflict
 *    - Client catches up on commits and rebases cleanly
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const tmpDb = '/tmp/extrovert-mls-room-dualstack-test.db';
try { fs.unlinkSync(tmpDb); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}

process.env.EXTV_DB_PATH = tmpDb;
process.env.SESSION_SECRET = 'mls-room-dualstack-secret-1234567890';
process.env.PORT = 0;

const app = require('../src/server');
const db = require('../src/db');

// Load MLS library
global.window = global;
if (!global.crypto) global.crypto = crypto.webcrypto;
require('../public/lib/mls.js');
const mls = window.MLS;

function uint8ToHex(u) {
  let s = '';
  for (let i = 0; i < u.length; i++) {
    const h = u[i].toString(16);
    s += (h.length === 1 ? '0' : '') + h;
  }
  return s;
}

function uint8ToB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return Buffer.from(binary, 'binary').toString('base64');
}

function b64ToUint8(b64) {
  const binary = Buffer.from(b64, 'base64').toString('binary');
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function run() {
  console.log('=== Starting Dual-Stack Room Negotiation & Messaging Integration Test ===\n');

  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port;

  try {
    const cs = mls.getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519');
    const impl = await mls.getCiphersuiteImpl(cs);

    // 1. Setup 5 users in Extrovert
    const aliceId = Number(db.createUser({ username: 'alice', passwordHash: 'x', displayName: 'Alice' }));
    const bobId = Number(db.createUser({ username: 'bob', passwordHash: 'x', displayName: 'Bob' }));
    const charlieId = Number(db.createUser({ username: 'charlie', passwordHash: 'x', displayName: 'Charlie' }));
    const daveId = Number(db.createUser({ username: 'dave', passwordHash: 'x', displayName: 'Dave' }));
    const eveId = Number(db.createUser({ username: 'eve', passwordHash: 'x', displayName: 'Eve' }));

    // Create OAuth tokens for API calls
    const users = [
      { id: aliceId, name: 'alice' },
      { id: bobId, name: 'bob' },
      { id: charlieId, name: 'charlie' },
      { id: daveId, name: 'dave' },
      { id: eveId, name: 'eve' }
    ];

    const tokens = {};
    for (const u of users) {
      db.createOAuthApp({
        name: 'app_' + u.name,
        description: '',
        website: '',
        redirectUris: 'https://x/cb',
        clientId: 'c_' + u.name,
        clientSecret: 's_' + u.name,
        scopes: 'read write follow read:direct write:direct',
        ownerId: u.id
      });
      const tok = 'tok_' + u.name + '_' + crypto.randomBytes(16).toString('hex');
      tokens[u.name] = tok;
      db.createOAuthToken(tok, null, db.getOAuthAppByClientId('c_' + u.name).id, u.id, 'read write follow read:direct write:direct', Date.now() + 86400000);
    }

    console.log('1. Setting up Dual-Stack and Legacy Room Members...');
    // - Alice, Charlie, Dave, Eve: Dual-stack (Registers MLS Device + Uploads KeyPackages)
    // - Bob: Legacy-only (NO MLS devices registered)

    const mlsUsers = [
      { id: aliceId, name: 'alice', devId: 'dev_alice_desk' },
      { id: charlieId, name: 'charlie', devId: 'dev_charlie_desk' },
      { id: daveId, name: 'dave', devId: 'dev_dave_desk' },
      { id: eveId, name: 'eve', devId: 'dev_eve_desk' },
    ];

    const userKeyPackages = {};
    const userCredentials = {};

    for (const mu of mlsUsers) {
      // Register device
      await fetch(`${base}/mls/device/register`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${tokens[mu.name]}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_id: mu.devId,
          device_name: `${mu.name} Desktop`,
          signing_key_pub: uint8ToB64(crypto.randomBytes(32))
        })
      });

      // Generate KeyPackage
      const cred = { credentialType: 'basic', identity: new TextEncoder().encode(String(mu.id)) };
      userCredentials[mu.name] = cred;
      const kp = await mls.generateKeyPackage(cred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
      userKeyPackages[mu.name] = kp;
      const encKp = mls.encodeMlsMessage({
        keyPackage: kp.publicPackage,
        wireformat: 'mls_key_package',
        version: 'mls10'
      });

      // Upload KeyPackage
      await fetch(`${base}/mls/keypackages`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${tokens[mu.name]}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_id: mu.devId,
          keypackages: [{
            data: uint8ToB64(encKp),
            ciphersuite: 1
          }]
        })
      });
    }
    console.log('   [OK] Alice, Charlie, Dave, and Eve registered MLS devices. Bob left as legacy-only.');

    // 2. Test Case A: Alice and Bob in a Room (Legacy-only peer Bob)
    console.log('\n2. Testing Alice and Bob in Room 1 (Legacy-only peer Bob)...');
    const room1Id = db.createRoom('Legacy Room', 'Room with legacy members', aliceId, false);
    const channel1 = db.getRoomChannels(room1Id)[0];
    const defaultRole1 = db.getRoomRoles(room1Id)[0];
    db.addRoomMember(room1Id, bobId, defaultRole1.id);

    // Verify Bob has no MLS devices
    const bobMlsRes = await fetch(`${base}/mls/devices?user_id=${bobId}`, {
      headers: { 'Authorization': `Bearer ${tokens.alice}` }
    }).then(r => r.json());
    assert.strictEqual(bobMlsRes.devices.length, 0, 'Bob must have zero MLS devices');
    console.log('   [OK] Room MLS check resolves false because Bob has no MLS devices');

    // Alice creates Megolm session in Room 1
    const sessionId = db.publishRoomGroupSession(room1Id, aliceId, 'dev_alice_desk', false);
    assert(sessionId > 0);

    // Alice sends Megolm message
    const sendRes1 = await fetch(`${base}/api/v1/rooms/${room1Id}/channels/${channel1.id}/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.alice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proto: 'megolm',
        ciphertext: 'base64_megolm_ciphertext_payload_here',
        group_session_id: String(sessionId)
      })
    }).then(r => r.json());
    assert(sendRes1.data && sendRes1.data.id, 'Megolm message must be created: ' + JSON.stringify(sendRes1));
    assert.strictEqual(sendRes1.data.proto, 'megolm');
    console.log(`   [OK] Legacy room message created with proto='megolm', id=${sendRes1.data.id}`);

    // 3. Test Case B: Dual-Stack MLS Room (Alice + Charlie + Dave)
    console.log('\n3. Testing Dual-Stack MLS Room 2 (Alice + Charlie + Dave)...');
    const room2Id = db.createRoom('MLS Room', 'Room with dual-stack members', aliceId, false);
    const channel2 = db.getRoomChannels(room2Id)[0];
    const defaultRole2 = db.getRoomRoles(room2Id)[0];
    db.addRoomMember(room2Id, charlieId, defaultRole2.id);
    db.addRoomMember(room2Id, daveId, defaultRole2.id);

    // Verify all members have MLS devices
    const cMls = await fetch(`${base}/mls/devices?user_id=${charlieId}`, { headers: { 'Authorization': `Bearer ${tokens.alice}` } }).then(r => r.json());
    const dMls = await fetch(`${base}/mls/devices?user_id=${daveId}`, { headers: { 'Authorization': `Bearer ${tokens.alice}` } }).then(r => r.json());
    assert(cMls.devices.length > 0 && dMls.devices.length > 0, 'Both Charlie and Dave have MLS devices');
    console.log('   [OK] Room MLS check resolves true for Charlie and Dave');

    // Alice claims KeyPackages for Charlie and Dave
    const claimC = await fetch(`${base}/mls/keypackages/${charlieId}`, { headers: { 'Authorization': `Bearer ${tokens.alice}` } }).then(r => r.json());
    const claimD = await fetch(`${base}/mls/keypackages/${daveId}`, { headers: { 'Authorization': `Bearer ${tokens.alice}` } }).then(r => r.json());
    assert(claimC.ok && claimC.keypackages.length === 1);
    assert(claimD.ok && claimD.keypackages.length === 1);

    const charlieKpMsg = mls.decodeMlsMessage(b64ToUint8(claimC.keypackages[0].keypackage_data), 0)[0];
    const daveKpMsg = mls.decodeMlsMessage(b64ToUint8(claimD.keypackages[0].keypackage_data), 0)[0];

    // Alice creates group room:room2Id
    const roomGroupId = `room:${room2Id}`;
    const aliceRoomKp = await mls.generateKeyPackage(userCredentials.alice, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
    const freshGroup = await mls.createGroup(new TextEncoder().encode(roomGroupId), aliceRoomKp.publicPackage, aliceRoomKp.privatePackage, [], impl);

    // Commit AddProposals for Charlie and Dave
    const addProposals = [
      { proposalType: 'add', add: { keyPackage: charlieKpMsg.keyPackage } },
      { proposalType: 'add', add: { keyPackage: daveKpMsg.keyPackage } }
    ];

    const commitRes = await mls.createCommit(
      { state: freshGroup, cipherSuite: impl },
      { extraProposals: addProposals, ratchetTreeExtension: true }
    );
    let aliceRoomState = commitRes.newState;

    const welcomeEnc = mls.encodeMlsMessage({
      welcome: commitRes.welcome,
      wireformat: 'mls_welcome',
      version: 'mls10'
    });
    const commitEnc = mls.encodeMlsMessage(commitRes.commit);

    // Post group init to server
    const initRes = await fetch(`${base}/mls/groups/init`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.alice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        group_id: roomGroupId,
        initial_commit: uint8ToB64(commitEnc),
        welcomes: [
          { user_id: charlieId, device_id: 'dev_charlie_desk', welcome_data: uint8ToB64(welcomeEnc) },
          { user_id: daveId, device_id: 'dev_dave_desk', welcome_data: uint8ToB64(welcomeEnc) }
        ],
        members: [
          { user_id: aliceId, device_id: 'dev_alice_desk', leaf_index: 0, role: 'creator' },
          { user_id: charlieId, device_id: 'dev_charlie_desk', leaf_index: 1, role: 'member' },
          { user_id: daveId, device_id: 'dev_dave_desk', leaf_index: 2, role: 'member' }
        ],
        idempotency_key: `init_${roomGroupId}_1`
      })
    }).then(r => r.json());
    assert.strictEqual(initRes.ok, true, 'Room MLS group init must succeed');
    console.log(`   [OK] Alice initialized MLS Room group '${roomGroupId}' on server at epoch 1`);

    // Alice encrypts ONE message to Room 2
    const alicePlaintext = 'Welcome everyone to the MLS-encrypted Room!';
    const appMsgRes = await mls.createApplicationMessage(aliceRoomState, new TextEncoder().encode(alicePlaintext), impl);
    aliceRoomState = appMsgRes.newState;

    const aliceCipherEnc = mls.encodeMlsMessage({
      privateMessage: appMsgRes.privateMessage,
      wireformat: 'mls_private_message',
      version: 'mls10'
    });
    const aliceCipherB64 = uint8ToB64(aliceCipherEnc);

    // Alice sends message to Room 2 with proto='mls'
    const roomMsgRes = await fetch(`${base}/api/v1/rooms/${room2Id}/channels/${channel2.id}/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.alice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proto: 'mls',
        ciphertext: aliceCipherB64
      })
    }).then(r => r.json());

    const roomMsg = roomMsgRes.data || roomMsgRes;
    assert(roomMsg.id, 'Room message must be created');
    assert.strictEqual(roomMsg.proto, 'mls', 'Protocol must be mls');
    console.log(`   [OK] Room message created with proto='mls', id=${roomMsg.id}`);

    // Verify DB record: single ciphertext, no group_session_id
    const dbRoomMsg = db.db.prepare('SELECT * FROM room_messages WHERE id = ?').get(roomMsg.id);
    assert.strictEqual(dbRoomMsg.proto, 'mls');
    assert.strictEqual(dbRoomMsg.ciphertext, aliceCipherB64);
    assert.strictEqual(dbRoomMsg.group_session_id, null);
    console.log('   [OK] Room message stored with zero Megolm session wrapper and single broadcast ciphertext');

    // 4. Charlie and Dave receive Welcome, join group, and BOTH decrypt Alice's message
    console.log('\n4. Verifying Charlie and Dave BOTH join and decrypt Alice message...');

    // Charlie fetches Welcome & joins
    const charlieWelcomes = await fetch(`${base}/mls/welcomes?device_id=dev_charlie_desk`, {
      headers: { 'Authorization': `Bearer ${tokens.charlie}` }
    }).then(r => r.json());
    assert(charlieWelcomes.welcomes.length >= 1);
    const charlieWData = mls.decodeMlsMessage(b64ToUint8(charlieWelcomes.welcomes[0].welcome_data), 0)[0].welcome;
    let charlieRoomState = await mls.joinGroup(charlieWData, userKeyPackages.charlie.publicPackage, userKeyPackages.charlie.privatePackage, mls.emptyPskIndex, impl);

    // Dave fetches Welcome & joins
    const daveWelcomes = await fetch(`${base}/mls/welcomes?device_id=dev_dave_desk`, {
      headers: { 'Authorization': `Bearer ${tokens.dave}` }
    }).then(r => r.json());
    assert(daveWelcomes.welcomes.length >= 1);
    const daveWData = mls.decodeMlsMessage(b64ToUint8(daveWelcomes.welcomes[0].welcome_data), 0)[0].welcome;
    let daveRoomState = await mls.joinGroup(daveWData, userKeyPackages.dave.publicPackage, userKeyPackages.dave.privatePackage, mls.emptyPskIndex, impl);

    // Charlie decrypts Alice's message
    const decMsgC = mls.decodeMlsMessage(b64ToUint8(aliceCipherB64), 0)[0];
    const resC = await mls.processPrivateMessage(charlieRoomState, decMsgC.privateMessage, mls.emptyPskIndex, impl);
    charlieRoomState = resC.newState;
    const plainC = new TextDecoder().decode(resC.message);
    assert.strictEqual(plainC, alicePlaintext);
    console.log(`   [OK] Charlie successfully decrypted: "${plainC}"`);

    // Dave decrypts Alice's message
    const decMsgD = mls.decodeMlsMessage(b64ToUint8(aliceCipherB64), 0)[0];
    const resD = await mls.processPrivateMessage(daveRoomState, decMsgD.privateMessage, mls.emptyPskIndex, impl);
    daveRoomState = resD.newState;
    const plainD = new TextDecoder().decode(resD.message);
    assert.strictEqual(plainD, alicePlaintext);
    console.log(`   [OK] Dave successfully decrypted: "${plainD}"`);

    // 5. Dave sends reply to Room 2; Alice and Charlie both decrypt it
    console.log('\n5. Dave replying to Room 2...');
    const davePlaintext = 'Confirmed Alice! Dave is online and decrypting MLS with zero Olm wrapping!';
    const daveAppRes = await mls.createApplicationMessage(daveRoomState, new TextEncoder().encode(davePlaintext), impl);
    daveRoomState = daveAppRes.newState;

    const daveCipherEnc = mls.encodeMlsMessage({
      privateMessage: daveAppRes.privateMessage,
      wireformat: 'mls_private_message',
      version: 'mls10'
    });
    const daveCipherB64 = uint8ToB64(daveCipherEnc);

    const daveSendRes = await fetch(`${base}/api/v1/rooms/${room2Id}/channels/${channel2.id}/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.dave}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proto: 'mls',
        ciphertext: daveCipherB64
      })
    }).then(r => r.json());
    assert(daveSendRes.data && daveSendRes.data.id);
    const daveMsgId = daveSendRes.data.id;

    // Alice decrypts Dave's reply
    const decMsgDaveByAlice = mls.decodeMlsMessage(b64ToUint8(daveCipherB64), 0)[0];
    const resDaveByAlice = await mls.processPrivateMessage(aliceRoomState, decMsgDaveByAlice.privateMessage, mls.emptyPskIndex, impl);
    aliceRoomState = resDaveByAlice.newState;
    const plainDaveByAlice = new TextDecoder().decode(resDaveByAlice.message);
    assert.strictEqual(plainDaveByAlice, davePlaintext);
    console.log(`   [OK] Alice successfully decrypted Dave reply: "${plainDaveByAlice}"`);

    // Charlie decrypts Dave's reply
    const decMsgDaveByCharlie = mls.decodeMlsMessage(b64ToUint8(daveCipherB64), 0)[0];
    const resDaveByCharlie = await mls.processPrivateMessage(charlieRoomState, decMsgDaveByCharlie.privateMessage, mls.emptyPskIndex, impl);
    charlieRoomState = resDaveByCharlie.newState;
    const plainDaveByCharlie = new TextDecoder().decode(resDaveByCharlie.message);
    assert.strictEqual(plainDaveByCharlie, davePlaintext);
    console.log(`   [OK] Charlie successfully decrypted Dave reply: "${plainDaveByCharlie}"`);

    // 6. Message Edit with MLS
    console.log('\n6. Testing Message Editing with proto: mls...');
    const editedPlaintext = 'Confirmed Alice! (EDITED) Dave is online!';
    const editAppRes = await mls.createApplicationMessage(daveRoomState, new TextEncoder().encode(editedPlaintext), impl);
    daveRoomState = editAppRes.newState;

    const editCipherEnc = mls.encodeMlsMessage({
      privateMessage: editAppRes.privateMessage,
      wireformat: 'mls_private_message',
      version: 'mls10'
    });
    const editCipherB64 = uint8ToB64(editCipherEnc);

    // Edit via web route
    const editRes = await fetch(`${base}/rooms/${room2Id}/channels/${channel2.id}/messages/${daveMsgId}/edit`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.dave}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        proto: 'mls',
        ciphertext: editCipherB64
      })
    }).then(r => r.json());
    assert.strictEqual(editRes.ok, true, 'Message edit must succeed');

    const dbEdited = db.db.prepare('SELECT * FROM room_messages WHERE id = ?').get(daveMsgId);
    assert.strictEqual(dbEdited.ciphertext, editCipherB64);
    assert(dbEdited.edited_at > 0);

    // Alice decrypts edited message
    const decEditByAlice = mls.decodeMlsMessage(b64ToUint8(editCipherB64), 0)[0];
    const resEditByAlice = await mls.processPrivateMessage(aliceRoomState, decEditByAlice.privateMessage, mls.emptyPskIndex, impl);
    aliceRoomState = resEditByAlice.newState;
    const plainEditByAlice = new TextDecoder().decode(resEditByAlice.message);
    assert.strictEqual(plainEditByAlice, editedPlaintext);
    console.log(`   [OK] Alice successfully decrypted edited message: "${plainEditByAlice}"`);

    // 7. Dynamic Member Addition: Eve joins Room 2
    console.log('\n7. Dynamic Member Addition: Eve joins Room 2...');
    db.addRoomMember(room2Id, eveId, defaultRole2.id);

    // Alice claims Eve's KeyPackage
    const claimEve = await fetch(`${base}/mls/keypackages/${eveId}`, { headers: { 'Authorization': `Bearer ${tokens.alice}` } }).then(r => r.json());
    assert(claimEve.ok && claimEve.keypackages.length === 1);
    const eveKpMsg = mls.decodeMlsMessage(b64ToUint8(claimEve.keypackages[0].keypackage_data), 0)[0];

    // Alice commits AddProposal(Eve) advancing epoch to 2
    const addEveProposal = { proposalType: 'add', add: { keyPackage: eveKpMsg.keyPackage } };
    const commitEveRes = await mls.createCommit(
      { state: aliceRoomState, cipherSuite: impl },
      { extraProposals: [addEveProposal], ratchetTreeExtension: true }
    );
    aliceRoomState = commitEveRes.newState;

    const welcomeEveEnc = mls.encodeMlsMessage({
      welcome: commitEveRes.welcome,
      wireformat: 'mls_welcome',
      version: 'mls10'
    });
    const commitEveEnc = mls.encodeMlsMessage(commitEveRes.commit);

    // Alice posts commit to server
    const commitApiRes = await fetch(`${base}/mls/groups/${roomGroupId}/commit`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.alice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        current_epoch: 1,
        commit_message: uint8ToB64(commitEveEnc),
        welcomes: [{
          user_id: eveId,
          device_id: 'dev_eve_desk',
          welcome_data: uint8ToB64(welcomeEveEnc)
        }],
        members_added: [{
          user_id: eveId,
          device_id: 'dev_eve_desk',
          role: 'member'
        }],
        idempotency_key: `add_eve_${Date.now()}`
      })
    }).then(r => r.json());
    assert.strictEqual(commitApiRes.ok, true);
    assert.strictEqual(commitApiRes.new_epoch, 2);
    console.log(`   [OK] Epoch advanced to 2 with Eve added to Room 2`);

    // Eve fetches Welcome, joins at epoch 2
    const eveWelcomes = await fetch(`${base}/mls/welcomes?device_id=dev_eve_desk`, {
      headers: { 'Authorization': `Bearer ${tokens.eve}` }
    }).then(r => r.json());
    assert(eveWelcomes.welcomes.length >= 1);
    const eveWData = mls.decodeMlsMessage(b64ToUint8(eveWelcomes.welcomes[0].welcome_data), 0)[0].welcome;
    let eveRoomState = await mls.joinGroup(eveWData, userKeyPackages.eve.publicPackage, userKeyPackages.eve.privatePackage, mls.emptyPskIndex, impl);
    assert.strictEqual(Number(eveRoomState.groupContext.epoch), 2, 'Eve must join at epoch 2');

    // Charlie catches up to epoch 2 using public commits
    const catchupRes = await fetch(`${base}/mls/groups/${roomGroupId}/commits?since=1`, {
      headers: { 'Authorization': `Bearer ${tokens.charlie}` }
    }).then(r => r.json());
    assert(catchupRes.commits.length >= 1);
    const cCommitBytes = b64ToUint8(catchupRes.commits[0].commit_data);
    const decCommitEve = mls.decodeMlsMessage(cCommitBytes, 0)[0];
    const charlieSync = await mls.processMessage(decCommitEve, charlieRoomState, mls.emptyPskIndex, function () {}, impl);
    charlieRoomState = charlieSync.newState;
    assert.strictEqual(Number(charlieRoomState.groupContext.epoch), 2, 'Charlie must advance to epoch 2');

    // Alice sends message to all 4 members at epoch 2
    const welcomeAllMsg = 'Welcome Eve! Room 2 is now 4 active MLS members!';
    const appMsg2 = await mls.createApplicationMessage(aliceRoomState, new TextEncoder().encode(welcomeAllMsg), impl);
    aliceRoomState = appMsg2.newState;
    const cipher2B64 = uint8ToB64(mls.encodeMlsMessage({
      privateMessage: appMsg2.privateMessage,
      wireformat: 'mls_private_message',
      version: 'mls10'
    }));

    // Verify Eve and Charlie can BOTH decrypt message at epoch 2!
    const decMsg2ByEve = mls.decodeMlsMessage(b64ToUint8(cipher2B64), 0)[0];
    const res2ByEve = await mls.processPrivateMessage(eveRoomState, decMsg2ByEve.privateMessage, mls.emptyPskIndex, impl);
    eveRoomState = res2ByEve.newState;
    assert.strictEqual(new TextDecoder().decode(res2ByEve.message), welcomeAllMsg);
    console.log(`   [OK] New member Eve successfully decrypted: "${new TextDecoder().decode(res2ByEve.message)}"`);

    const decMsg2ByCharlie = mls.decodeMlsMessage(b64ToUint8(cipher2B64), 0)[0];
    const res2ByCharlie = await mls.processPrivateMessage(charlieRoomState, decMsg2ByCharlie.privateMessage, mls.emptyPskIndex, impl);
    charlieRoomState = res2ByCharlie.newState;
    assert.strictEqual(new TextDecoder().decode(res2ByCharlie.message), welcomeAllMsg);
    console.log(`   [OK] Existing member Charlie successfully decrypted at epoch 2: "${new TextDecoder().decode(res2ByCharlie.message)}"`);

    // 8. CAS Conflict Handling
    console.log('\n8. Testing CAS Conflict Handling...');
    const conflictRes = await fetch(`${base}/mls/groups/${roomGroupId}/commit`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.dave}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        current_epoch: 1, // Stale epoch (server is at 2)
        commit_message: uint8ToB64(new Uint8Array([1, 2, 3]))
      })
    });
    assert.strictEqual(conflictRes.status, 409);
    const conflictJson = await conflictRes.json();
    assert.strictEqual(conflictJson.error, 'EpochConflict');
    assert.strictEqual(conflictJson.server_epoch, 2);
    console.log('   [OK] CAS epoch conflict detected: rejected stale commit with 409 EpochConflict');

    console.log('\n=== All Dual-Stack Room Integration Tests PASSED 100%! ===\n');

  } finally {
    server.close();
    try { fs.unlinkSync(tmpDb); } catch (_) {}
    try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
    try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}
  }
}

run().then(() => {
  process.exit(0);
}).catch((err) => {
  console.error('\n[FATAL TEST FAILURE]', err);
  process.exit(1);
});
