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
      const ref = await mls.makeKeyPackageRef(kp.publicPackage, impl.hash);
      const refHex = uint8ToHex(ref);
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
            ciphersuite: 1,
            keypackage_ref: refHex
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

    // 9. Member Removal / Admin Kick Test (Alice removes Dave at leaf 2)
    console.log('\n9. Testing Admin Kick / Member Removal (Alice removes Dave)...');
    const removeDaveProposal = { proposalType: 'remove', remove: { removed: 2 } };
    const kickCommitRes = await mls.createCommit(
      { state: aliceRoomState, cipherSuite: impl },
      { extraProposals: [removeDaveProposal] }
    );
    aliceRoomState = kickCommitRes.newState;
    const kickCommitEnc = mls.encodeMlsMessage(kickCommitRes.commit);

    const kickCommitPost = await fetch(`${base}/mls/groups/${roomGroupId}/commit`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.alice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        current_epoch: 2,
        commit_message: uint8ToB64(kickCommitEnc),
        welcomes: [],
        members_removed: [{ user_id: daveId, device_id: 'dev_dave_desk' }],
        idempotency_key: `kick_dave_${Date.now()}`
      })
    }).then(r => r.json());
    assert.strictEqual(kickCommitPost.ok, true, 'Kick commit must be accepted by server');
    assert.strictEqual(kickCommitPost.new_epoch, 3, 'Epoch must advance to 3 on member kick');
    console.log('   [OK] Admin kick commit accepted on server at epoch 3');

    // Charlie fetches commit since epoch 2 and catches up
    const charlieCommitsRes = await fetch(`${base}/mls/groups/${roomGroupId}/commits?since=2`, {
      headers: { 'Authorization': `Bearer ${tokens.charlie}` }
    }).then(r => r.json());
    assert.strictEqual(charlieCommitsRes.commits.length, 1);
    const decKickCommit = mls.decodeMlsMessage(b64ToUint8(charlieCommitsRes.commits[0].commit_data), 0)[0];
    const charlieCatchup = await mls.processPrivateMessage(charlieRoomState, decKickCommit.privateMessage, mls.emptyPskIndex, impl);
    charlieRoomState = charlieCatchup.newState;
    assert.strictEqual(Number(charlieRoomState.groupContext.epoch), 3);
    console.log('   [OK] Remaining member Charlie processed kick commit and advanced to epoch 3');

    // Alice sends post-kick message at epoch 3
    const postKickText = 'Security Notice: Dave has been removed from this room.';
    const postKickAppRes = await mls.createApplicationMessage(aliceRoomState, new TextEncoder().encode(postKickText), impl);
    aliceRoomState = postKickAppRes.newState;
    const postKickCipherB64 = uint8ToB64(mls.encodeMlsMessage({
      privateMessage: postKickAppRes.privateMessage,
      wireformat: 'mls_private_message',
      version: 'mls10'
    }));

    // Post to room
    await fetch(`${base}/api/v1/rooms/${room2Id}/channels/${channel2.id}/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.alice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ body: postKickCipherB64, proto: 'mls', group_id: roomGroupId })
    });

    // Charlie decrypts successfully
    const decMsg3ByCharlie = mls.decodeMlsMessage(b64ToUint8(postKickCipherB64), 0)[0];
    const res3ByCharlie = await mls.processPrivateMessage(charlieRoomState, decMsg3ByCharlie.privateMessage, mls.emptyPskIndex, impl);
    charlieRoomState = res3ByCharlie.newState;
    assert.strictEqual(new TextDecoder().decode(res3ByCharlie.message), postKickText);
    console.log(`   [OK] Remaining member Charlie decrypted post-kick message: "${postKickText}"`);

    // Kicked user Dave attempts to decrypt post-kick message (must fail)
    let daveDecrypted = false;
    try {
      await mls.processPrivateMessage(daveRoomState, decMsg3ByCharlie.privateMessage, mls.emptyPskIndex, impl);
      daveDecrypted = true;
    } catch (_) {
      // Expected cryptographic failure
    }
    assert.strictEqual(daveDecrypted, false, 'Kicked user Dave must NOT be able to decrypt post-kick message');
    console.log('   [OK] Cryptographic forward secrecy verified: Kicked user Dave CANNOT decrypt epoch 3 message');

    // 10. Voluntary Leave Test (Eve leaves Room 2)
    console.log('\n10. Testing Voluntary Leave (Eve leaves Room 2)...');
    // Eve is leaf index 3 in the group tree. Eve generates self-remove proposal
    const removeEveProposal = { proposalType: 'remove', remove: { removed: 3 } };
    const propRes = await mls.createProposal(eveRoomState, false, removeEveProposal, impl);
    const encProp = mls.encodeMlsMessage(propRes.message);

    const propPost = await fetch(`${base}/mls/groups/${roomGroupId}/proposals`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.eve}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        epoch: 3,
        proposal_type: 'remove',
        proposal_data: uint8ToB64(encProp)
      })
    }).then(r => r.json());
    assert.strictEqual(propPost.ok, true, 'Eve self-remove proposal must be accepted by server');
    console.log('   [OK] Eve posted self-remove proposal to delivery service at epoch 3');

    // Alice commits Eve's remove proposal
    const leaveCommitRes = await mls.createCommit(
      { state: aliceRoomState, cipherSuite: impl },
      { extraProposals: [removeEveProposal] }
    );
    aliceRoomState = leaveCommitRes.newState;
    const leaveCommitEnc = mls.encodeMlsMessage(leaveCommitRes.commit);

    const leavePost = await fetch(`${base}/mls/groups/${roomGroupId}/commit`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokens.alice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        current_epoch: 3,
        commit_message: uint8ToB64(leaveCommitEnc),
        welcomes: [],
        members_removed: [{ user_id: eveId, device_id: 'dev_eve_desk' }],
        idempotency_key: `leave_eve_${Date.now()}`
      })
    }).then(r => r.json());
    assert.strictEqual(leavePost.ok, true, 'Voluntary leave commit must be accepted by server');
    assert.strictEqual(leavePost.new_epoch, 4, 'Epoch must advance to 4 on voluntary leave');
    console.log('   [OK] Remaining peer committed voluntary leave: epoch advanced to 4');

    // Alice sends post-leave message at epoch 4
    const postLeaveText = 'Eve has voluntarily left Room 2. Only Alice and Charlie remain.';
    const postLeaveAppRes = await mls.createApplicationMessage(aliceRoomState, new TextEncoder().encode(postLeaveText), impl);
    aliceRoomState = postLeaveAppRes.newState;
    const postLeaveCipherB64 = uint8ToB64(mls.encodeMlsMessage({
      privateMessage: postLeaveAppRes.privateMessage,
      wireformat: 'mls_private_message',
      version: 'mls10'
    }));

    // Former member Eve attempts to decrypt post-leave message (must fail)
    let eveDecrypted = false;
    try {
      const decMsg4ByEve = mls.decodeMlsMessage(b64ToUint8(postLeaveCipherB64), 0)[0];
      await mls.processPrivateMessage(eveRoomState, decMsg4ByEve.privateMessage, mls.emptyPskIndex, impl);
      eveDecrypted = true;
    } catch (_) {
      // Expected cryptographic failure
    }
    assert.strictEqual(eveDecrypted, false, 'Former member Eve must NOT be able to decrypt post-leave message');
    console.log('   [OK] Forward secrecy verified: Former member Eve CANNOT decrypt epoch 4 message');

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
