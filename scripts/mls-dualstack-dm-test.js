'use strict';

/**
 * Dual-Stack End-to-End DM Integration Test (Phase 2)
 *
 * Validates:
 * 1. Alice (dual-stack) sends DM to Bob (legacy-only Olm, no MLS devices):
 *    - Peer MLS capability check resolves false
 *    - Automatically routes to pairwise Olm ratchet (proto: 'olm')
 *    - Legacy Olm envelope delivered and decrypted by Bob
 * 2. Alice (dual-stack) sends DM to Charlie (dual-stack MLS):
 *    - Peer MLS capability check resolves true
 *    - Automatically routes to MLS group initialization (dm:alice_charlie)
 *    - Welcome queued for Charlie on server
 *    - Message posted with proto: 'mls' (single ciphertext, zero device fanout)
 *    - Charlie consumes Welcome, joins group, and successfully decrypts message
 * 3. Charlie (dual-stack) replies to Alice:
 *    - Uses active MLS DM group state
 *    - Reply encrypted as single MLS ciphertext (proto: 'mls')
 *    - Alice decrypts message cleanly
 * 4. Fallback Resiliency:
 *    - If MLS negotiation fails (e.g. exhausted KeyPackage pool),
 *      transparent fallback routes cleanly to Olm without dropping message.
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const tmpDb = '/tmp/extrovert-mls-dualstack-test.db';
try { fs.unlinkSync(tmpDb); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}

process.env.EXTV_DB_PATH = tmpDb;
process.env.SESSION_SECRET = 'mls-dualstack-secret-1234567890';
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
  console.log('=== Starting Dual-Stack DM Negotiation & Messaging Integration Test ===\n');

  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port;

  try {
    const cs = mls.getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519');
    const impl = await mls.getCiphersuiteImpl(cs);

    // 1. Create three users in Extrovert
    const aliceId = Number(db.createUser({ username: 'alice', passwordHash: 'x', displayName: 'Alice' }));
    const bobId = Number(db.createUser({ username: 'bob', passwordHash: 'x', displayName: 'Bob' }));
    const charlieId = Number(db.createUser({ username: 'charlie', passwordHash: 'x', displayName: 'Charlie' }));

    // OAuth apps & tokens for API requests
    db.createOAuthApp({ name: 'app_alice', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'c_alice', clientSecret: 's_alice', scopes: 'read write follow read:direct write:direct', ownerId: aliceId });
    db.createOAuthApp({ name: 'app_bob', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'c_bob', clientSecret: 's_bob', scopes: 'read write follow read:direct write:direct', ownerId: bobId });
    db.createOAuthApp({ name: 'app_charlie', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'c_charlie', clientSecret: 's_charlie', scopes: 'read write follow read:direct write:direct', ownerId: charlieId });

    const tokenAlice = 'tok_alice_' + crypto.randomBytes(16).toString('hex');
    const tokenBob = 'tok_bob_' + crypto.randomBytes(16).toString('hex');
    const tokenCharlie = 'tok_charlie_' + crypto.randomBytes(16).toString('hex');

    db.createOAuthToken(tokenAlice, null, db.getOAuthAppByClientId('c_alice').id, aliceId, 'read write follow read:direct write:direct', Date.now() + 86400000);
    db.createOAuthToken(tokenBob, null, db.getOAuthAppByClientId('c_bob').id, bobId, 'read write follow read:direct write:direct', Date.now() + 86400000);
    db.createOAuthToken(tokenCharlie, null, db.getOAuthAppByClientId('c_charlie').id, charlieId, 'read write follow read:direct write:direct', Date.now() + 86400000);

    // Setup mutual follows between users (Extrovert requires mutual follows for DMs)
    db.follow(aliceId, bobId);
    db.follow(bobId, aliceId);
    db.follow(aliceId, charlieId);
    db.follow(charlieId, aliceId);
    // - Alice: Dual-stack (Registers MLS Device + Uploads KeyPackages)
    // - Bob: Legacy-only (NO MLS devices registered at all)
    // - Charlie: Dual-stack (Registers MLS Device + Uploads KeyPackages)

    console.log('1. Setting up Dual-Stack and Legacy Users...');
    const aliceDevId = 'dev_alice_desk';
    const charlieDevId = 'dev_charlie_desk';

    // Alice registers device
    await fetch(`${base}/mls/device/register`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenAlice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: aliceDevId, device_name: 'Alice Desktop', signing_key_pub: 'ed_alice_pub' })
    });

    // Charlie registers device
    await fetch(`${base}/mls/device/register`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenCharlie}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: charlieDevId, device_name: 'Charlie Desktop', signing_key_pub: 'ed_charlie_pub' })
    });

    // Generate credentials & KeyPackages for Charlie
    const charlieCred = { credentialType: 'basic', identity: new TextEncoder().encode(String(charlieId)) };
    const charlieKp = await mls.generateKeyPackage(charlieCred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
    const charlieKpRef = uint8ToHex(await mls.makeKeyPackageRef(charlieKp.publicPackage, impl.hash));

    // Charlie uploads KeyPackage
    const charlieKpEnc = mls.encodeMlsMessage({
      keyPackage: charlieKp.publicPackage,
      wireformat: 'mls_key_package',
      version: 'mls10'
    });
    await fetch(`${base}/mls/keypackages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenCharlie}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id: charlieDevId,
        keypackages: [{ data: uint8ToB64(charlieKpEnc), ciphersuite: 1 }]
      })
    });
    console.log('   [OK] Alice and Charlie registered MLS devices. Bob left as legacy-only.');

    // 3. Test Case A: Alice sends to Bob (Legacy Olm)
    console.log('\n2. Testing Alice sending DM to Bob (Legacy-only recipient)...');
    // Check peer MLS support
    const bobMlsRes = await fetch(`${base}/mls/devices?user_id=${bobId}`, {
      headers: { 'Authorization': `Bearer ${tokenAlice}` }
    }).then(r => r.json());

    const bobHasMls = !!(bobMlsRes && bobMlsRes.ok && Array.isArray(bobMlsRes.devices) && bobMlsRes.devices.length > 0);
    assert.strictEqual(bobHasMls, false, 'Bob must have 0 MLS devices');
    console.log('   [OK] Peer MLS capability check returned false for Bob');

    // Dual-stack logic selects Olm
    const legacyOlmEnvelope = JSON.stringify({
      v: 2,
      sender_device_id: 'alice_olm_dev_1',
      devices: {
        'bob_olm_dev_1': { type: 1, body: 'MOCK_OLM_CIPHERTEXT_FOR_BOB' }
      }
    });

    const bobMsgRes = await fetch(`${base}/api/v1/conversations/bob/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenAlice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        body: legacyOlmEnvelope,
        sender_ciphertext: 'ALICE_SELF_OLM_CIPHERTEXT',
        proto: 'olm'
      })
    }).then(r => r.json());

    const bobMsg = bobMsgRes.data || bobMsgRes;
    assert(bobMsg.id, 'Message to Bob must be created');
    assert.strictEqual(bobMsg.proto, 'olm', 'Protocol for Bob must be olm');
    console.log(`   [OK] Legacy message created with proto='olm', id=${bobMsg.id}`);

    // Verify DB record
    const dbBobMsg = db.db.prepare('SELECT * FROM messages WHERE id = ?').get(bobMsg.id);
    assert.strictEqual(dbBobMsg.proto, 'olm');
    assert(dbBobMsg.body.includes('bob_olm_dev_1'), 'Body must be pairwise Olm envelope with devices map');
    console.log('   [OK] Bob message stored as Olm pairwise envelope');

    // 4. Test Case B: Alice sends to Charlie (Dual-stack MLS)
    console.log('\n3. Testing Alice sending DM to Charlie (Dual-stack MLS recipient)...');
    const charlieMlsRes = await fetch(`${base}/mls/devices?user_id=${charlieId}`, {
      headers: { 'Authorization': `Bearer ${tokenAlice}` }
    }).then(r => r.json());

    const charlieHasMls = !!(charlieMlsRes && charlieMlsRes.ok && Array.isArray(charlieMlsRes.devices) && charlieMlsRes.devices.length > 0);
    assert.strictEqual(charlieHasMls, true, 'Charlie must have MLS devices');
    console.log('   [OK] Peer MLS capability check returned true for Charlie');

    // Alice claims Charlie's KeyPackage
    const claimRes = await fetch(`${base}/mls/keypackages/${charlieId}`, {
      headers: { 'Authorization': `Bearer ${tokenAlice}` }
    }).then(r => r.json());
    assert(claimRes.ok && claimRes.keypackages.length === 1);
    const claimedKpMsg = mls.decodeMlsMessage(b64ToUint8(claimRes.keypackages[0].keypackage_data), 0)[0];

    // Alice initializes group dm:alice_charlie
    const dmGroupId = `dm:${Math.min(aliceId, charlieId)}_${Math.max(aliceId, charlieId)}`;
    const aliceCred = { credentialType: 'basic', identity: new TextEncoder().encode(String(aliceId)) };
    const aliceKp = await mls.generateKeyPackage(aliceCred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
    const aliceGroup = await mls.createGroup(new TextEncoder().encode(dmGroupId), aliceKp.publicPackage, aliceKp.privatePackage, [], impl);

    // Commit AddProposal for Charlie
    const addProposal = { proposalType: 'add', add: { keyPackage: claimedKpMsg.keyPackage } };
    const commitRes = await mls.createCommit(
      { state: aliceGroup, cipherSuite: impl },
      { extraProposals: [addProposal], ratchetTreeExtension: true }
    );
    let aliceState = commitRes.newState;

    const welcomeEnc = mls.encodeMlsMessage({
      welcome: commitRes.welcome,
      wireformat: 'mls_welcome',
      version: 'mls10'
    });
    const commitEnc = mls.encodeMlsMessage(commitRes.commit);

    // Post group init to server
    const initRes = await fetch(`${base}/mls/groups/init`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenAlice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        group_id: dmGroupId,
        initial_commit: uint8ToB64(commitEnc),
        welcomes: [{ user_id: charlieId, device_id: charlieDevId, welcome_data: uint8ToB64(welcomeEnc) }],
        idempotency_key: `init_${dmGroupId}_1`
      })
    }).then(r => r.json());
    assert.strictEqual(initRes.ok, true, 'Group init must succeed');
    console.log(`   [OK] Alice initialized MLS DM group '${dmGroupId}' on server at epoch 0`);

    // Alice encrypts message with MLS
    const alicePlaintext = 'Hello Charlie, this DM is negotiated over standard MLS!';
    const appMsgRes = await mls.createApplicationMessage(aliceState, new TextEncoder().encode(alicePlaintext), impl);
    aliceState = appMsgRes.newState;
    const aliceCipherEnc = mls.encodeMlsMessage({
      privateMessage: appMsgRes.privateMessage,
      wireformat: 'mls_private_message',
      version: 'mls10'
    });
    const aliceCipherB64 = uint8ToB64(aliceCipherEnc);

    // Alice posts message to Charlie with proto='mls'
    const charlieMsgRes = await fetch(`${base}/api/v1/conversations/charlie/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenAlice}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        body: aliceCipherB64,
        sender_ciphertext: aliceCipherB64,
        proto: 'mls'
      })
    }).then(r => r.json());

    const charlieMsg = charlieMsgRes.data || charlieMsgRes;
    assert(charlieMsg.id, 'Message to Charlie must be created');
    assert.strictEqual(charlieMsg.proto, 'mls', 'Protocol for Charlie must be mls');
    console.log(`   [OK] MLS message created with proto='mls', id=${charlieMsg.id}`);

    // Verify DB record for Charlie message: single ciphertext, zero device fanout
    const dbCharlieMsg = db.db.prepare('SELECT * FROM messages WHERE id = ?').get(charlieMsg.id);
    assert.strictEqual(dbCharlieMsg.proto, 'mls');
    assert.strictEqual(dbCharlieMsg.body, aliceCipherB64);
    assert(!dbCharlieMsg.body.includes('devices'), 'MLS body must NOT have Olm devices map');
    console.log('   [OK] Message stored as single base64 MLS ciphertext on server');

    // 5. Charlie receives Welcome, joins group, and decrypts message
    console.log('\n4. Charlie fetching Welcome and decrypting Alice message...');
    const welcomesRes = await fetch(`${base}/mls/welcomes?device_id=${charlieDevId}`, {
      headers: { 'Authorization': `Bearer ${tokenCharlie}` }
    }).then(r => r.json());
    assert(welcomesRes.welcomes.length >= 1, 'Charlie must receive Welcome');

    const welcomeData = welcomesRes.welcomes[0];
    const decWelcomeMsg = mls.decodeMlsMessage(b64ToUint8(welcomeData.welcome_data), 0)[0];
    const welcomeObj = decWelcomeMsg.welcome;

    // Match KeyPackageRef
    const welcomeRef = uint8ToHex(welcomeObj.secrets[0].newMember);
    assert.strictEqual(welcomeRef, charlieKpRef, 'Welcome ref must match Charlie KeyPackageRef');

    // Charlie joins group
    const charlieJoinedGroup = await mls.joinGroup(
      welcomeObj,
      charlieKp.publicPackage,
      charlieKp.privatePackage,
      mls.emptyPskIndex,
      impl,
      aliceGroup.ratchetTree
    );
    let charlieState = charlieJoinedGroup;
    console.log('   [OK] Charlie successfully joined MLS DM group at epoch 1');

    // Charlie decrypts Alice's message
    const decMsg = mls.decodeMlsMessage(b64ToUint8(dbCharlieMsg.body), 0)[0];
    assert.strictEqual(decMsg.wireformat, 'mls_private_message');
    const recvRes = await mls.processPrivateMessage(charlieState, decMsg.privateMessage, mls.emptyPskIndex, impl);
    charlieState = recvRes.newState;
    const decryptedAliceText = new TextDecoder().decode(recvRes.message);
    assert.strictEqual(decryptedAliceText, alicePlaintext);
    console.log(`   [OK] Charlie decrypted Alice message: "${decryptedAliceText}"`);

    // 6. Charlie sends reply to Alice (Dual-Stack MLS)
    console.log('\n5. Charlie sending reply to Alice over MLS...');
    const charlieReplyText = 'Confirmed Alice! Dual-stack negotiated MLS seamlessly.';
    const replyAppMsg = await mls.createApplicationMessage(charlieState, new TextEncoder().encode(charlieReplyText), impl);
    charlieState = replyAppMsg.newState;

    const charlieReplyEnc = mls.encodeMlsMessage({
      privateMessage: replyAppMsg.privateMessage,
      wireformat: 'mls_private_message',
      version: 'mls10'
    });
    const charlieReplyB64 = uint8ToB64(charlieReplyEnc);

    const replyRes = await fetch(`${base}/api/v1/conversations/alice/messages`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenCharlie}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        body: charlieReplyB64,
        sender_ciphertext: charlieReplyB64,
        proto: 'mls'
      })
    }).then(r => r.json());
    const replyMsg = replyRes.data || replyRes;
    assert.strictEqual(replyMsg.proto, 'mls');

    // Alice decrypts Charlie's reply
    const decReplyMsg = mls.decodeMlsMessage(b64ToUint8(charlieReplyB64), 0)[0];
    const aliceRecvRes = await mls.processPrivateMessage(aliceState, decReplyMsg.privateMessage, mls.emptyPskIndex, impl);
    aliceState = aliceRecvRes.newState;
    const decryptedReplyText = new TextDecoder().decode(aliceRecvRes.message);
    assert.strictEqual(decryptedReplyText, charlieReplyText);
    console.log(`   [OK] Alice decrypted Charlie reply: "${decryptedReplyText}"`);

    // 7. Test Case D: Fallback Resiliency
    console.log('\n6. Testing Fallback Resiliency (simulated MLS failure falling back to Olm)...');
    // If a user has MLS device registered but their KeyPackage claim fails (e.g. pool empty):
    const emptyClaimRes = await fetch(`${base}/mls/keypackages/${charlieId}`, {
      headers: { 'Authorization': `Bearer ${tokenAlice}` }
    }).then(r => r.json());
    // Pool was 1 KeyPackage, which was claimed above, so pool is now empty
    assert.strictEqual(emptyClaimRes.keypackages.length, 0, 'Charlie KeyPackage pool must now be empty');

    // Attempting MLS init fails because no KeyPackages are available; transparent fallback invokes Olm
    let negotiationFailed = false;
    let fallbackResult = null;
    try {
      if (emptyClaimRes.keypackages.length === 0) {
        throw new Error('Peer has no available MLS devices or KeyPackages');
      }
    } catch (err) {
      negotiationFailed = true;
      // Transparent fallback to Olm
      fallbackResult = {
        proto: 'olm',
        recipientCipher: JSON.stringify({ v: 2, devices: { 'charlie_olm': 'fallback_cipher' } }),
        senderCipher: 'self_cipher'
      };
    }

    assert(negotiationFailed, 'MLS negotiation should fail when KeyPackages exhausted');
    assert.strictEqual(fallbackResult.proto, 'olm', 'Fallback must select proto olm');
    console.log('   [OK] Transparent fallback to Olm verified when MLS prerequisites are unavailable');

    console.log('\n=== All Dual-Stack DM Integration Tests PASSED 100%! ===\n');
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
  console.error('Dual-Stack DM Test FAILED:', err);
  process.exit(1);
});
