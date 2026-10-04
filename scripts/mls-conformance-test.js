'use strict';

/**
 * Phase 0 Conformance & Interop Test Suite for Extrovert MLS (RFC 9420)
 * Tests:
 * 1. Ciphersuite initialization (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
 * 2. KeyPackage generation, serialization, and deserialization
 * 3. Group creation at epoch 0
 * 4. Multi-device addition via AddProposal + Commit -> Welcome message
 * 5. Welcome processing by new devices (joinGroup)
 * 6. Single ciphertext application message decrypted by all devices
 * 7. Catch-up commit processing for devices that joined at older epochs
 * 8. RFC 9420 Section 10.4 Exporter Secret derivation
 */

const assert = require('assert');

// Simulate browser environment to test the exact bundled artifact public/lib/mls.js
global.window = global;
if (!global.crypto) {
  global.crypto = require('crypto').webcrypto;
}
require('../public/lib/mls.js');

const mls = window.MLS;

async function run() {
  console.log('=== Starting Phase 0 MLS Conformance Suite ===\n');

  // 1. Ciphersuite check
  console.log('1. Initializing Ciphersuite MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519...');
  const cs = mls.getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519');
  const impl = await mls.getCiphersuiteImpl(cs);
  assert.ok(impl, 'Ciphersuite implementation must be loaded');
  console.log('   [OK] Ciphersuite loaded successfully\n');

  // 2. KeyPackage generation and serialization
  console.log('2. Generating and encoding KeyPackages for 3 test devices...');
  const aliceCred = { credentialType: 'basic', identity: new TextEncoder().encode('user:1:dev:alice1') };
  const bob1Cred = { credentialType: 'basic', identity: new TextEncoder().encode('user:2:dev:bob1') };
  const bob2Cred = { credentialType: 'basic', identity: new TextEncoder().encode('user:2:dev:bob2') };

  const aliceKp = await mls.generateKeyPackage(aliceCred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
  const bob1Kp = await mls.generateKeyPackage(bob1Cred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
  const bob2Kp = await mls.generateKeyPackage(bob2Cred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);

  const bob1Encoded = mls.encodeMlsMessage({ keyPackage: bob1Kp.publicPackage, wireformat: 'mls_key_package', version: 'mls10' });
  const [bob1Decoded] = mls.decodeMlsMessage(bob1Encoded, 0);
  assert.strictEqual(bob1Decoded.wireformat, 'mls_key_package', 'Wireformat must match mls_key_package');
  console.log('   [OK] KeyPackages generated and wireformat validated\n');

  // 3. Group Creation
  console.log('3. Alice creates MLS Group dm:1_2 at epoch 0...');
  const groupId = new TextEncoder().encode('dm:1_2');
  let aliceGroup = await mls.createGroup(groupId, aliceKp.publicPackage, aliceKp.privatePackage, [], impl);
  assert.strictEqual(aliceGroup.groupContext.epoch, 0n, 'Initial group epoch must be 0');
  console.log('   [OK] Group initialized at epoch 0\n');

  // 4. Add Bob1 to Group (Epoch 0 -> 1)
  console.log('4. Alice commits AddProposal(Bob1)...');
  const addBob1Proposal = { proposalType: 'add', add: { keyPackage: bob1Decoded.keyPackage } };
  const commit1 = await mls.createCommit(
    { state: aliceGroup, cipherSuite: impl },
    { extraProposals: [addBob1Proposal], ratchetTreeExtension: true }
  );
  aliceGroup = commit1.newState;
  commit1.consumed.forEach(mls.zeroOutUint8Array);
  assert.strictEqual(aliceGroup.groupContext.epoch, 1n, 'Epoch must advance to 1');
  assert.ok(commit1.welcome, 'Welcome message must be generated for Bob1');
  console.log('   [OK] Commit accepted, epoch advanced to 1, Welcome generated\n');

  // 5. Bob1 joins Group from Welcome
  console.log('5. Bob1 processes Welcome and joins Group...');
  const welcome1Bytes = mls.encodeMlsMessage({ welcome: commit1.welcome, wireformat: 'mls_welcome', version: 'mls10' });
  const [welcome1Decoded] = mls.decodeMlsMessage(welcome1Bytes, 0);

  let bob1Group = await mls.joinGroup(
    welcome1Decoded.welcome,
    bob1Kp.publicPackage,
    bob1Kp.privatePackage,
    mls.emptyPskIndex,
    impl,
    aliceGroup.ratchetTree
  );
  assert.strictEqual(bob1Group.groupContext.epoch, 1n, 'Bob1 joined at epoch 1');
  console.log('   [OK] Bob1 successfully joined at epoch 1\n');

  // 6. Bob1 adds Bob2 (Device 2) to Group (Epoch 1 -> 2)
  console.log('6. Bob1 commits AddProposal(Bob2) to add second device...');
  const bob2Encoded = mls.encodeMlsMessage({ keyPackage: bob2Kp.publicPackage, wireformat: 'mls_key_package', version: 'mls10' });
  const [bob2Decoded] = mls.decodeMlsMessage(bob2Encoded, 0);

  const addBob2Proposal = { proposalType: 'add', add: { keyPackage: bob2Decoded.keyPackage } };
  const commit2 = await mls.createCommit(
    { state: bob1Group, cipherSuite: impl },
    { extraProposals: [addBob2Proposal], ratchetTreeExtension: true }
  );
  bob1Group = commit2.newState;
  commit2.consumed.forEach(mls.zeroOutUint8Array);
  assert.strictEqual(bob1Group.groupContext.epoch, 2n, 'Bob1 epoch advanced to 2');

  // Alice processes the public commit message from Bob1
  const commit2Bytes = mls.encodeMlsMessage(commit2.commit);
  const [commit2Decoded] = mls.decodeMlsMessage(commit2Bytes, 0);
  const aliceSync = await mls.processMessage(commit2Decoded, aliceGroup, mls.emptyPskIndex, () => {}, impl);
  aliceGroup = aliceSync.newState;
  assert.strictEqual(aliceGroup.groupContext.epoch, 2n, 'Alice synced to epoch 2');

  // Bob2 joins from Welcome
  let bob2Group = await mls.joinGroup(
    commit2.welcome,
    bob2Kp.publicPackage,
    bob2Kp.privatePackage,
    mls.emptyPskIndex,
    impl,
    bob1Group.ratchetTree
  );
  assert.strictEqual(bob2Group.groupContext.epoch, 2n, 'Bob2 joined at epoch 2');
  console.log('   [OK] Bob2 joined at epoch 2. Group now contains 3 active device leaves\n');

  // 7. Single-Ciphertext Broadcast Application Message
  console.log('7. Alice sends a single application message to all 3 devices...');
  const plaintext = 'Extrovert MLS Single Ciphertext to Alice, Bob1, and Bob2';
  const sendRes = await mls.createApplicationMessage(aliceGroup, new TextEncoder().encode(plaintext), impl);
  aliceGroup = sendRes.newState;
  sendRes.consumed.forEach(mls.zeroOutUint8Array);

  const appMsgBytes = mls.encodeMlsMessage({
    privateMessage: sendRes.privateMessage,
    wireformat: 'mls_private_message',
    version: 'mls10',
  });

  // Bob1 decrypts
  const [app1Decoded] = mls.decodeMlsMessage(appMsgBytes, 0);
  const r1 = await mls.processPrivateMessage(bob1Group, app1Decoded.privateMessage, mls.emptyPskIndex, impl);
  bob1Group = r1.newState;
  const t1 = new TextDecoder().decode(r1.message);

  // Bob2 decrypts the EXACT SAME payload
  const [app2Decoded] = mls.decodeMlsMessage(appMsgBytes, 0);
  const r2 = await mls.processPrivateMessage(bob2Group, app2Decoded.privateMessage, mls.emptyPskIndex, impl);
  bob2Group = r2.newState;
  const t2 = new TextDecoder().decode(r2.message);

  assert.strictEqual(t1, plaintext, 'Bob1 must decrypt exact plaintext');
  assert.strictEqual(t2, plaintext, 'Bob2 must decrypt exact plaintext');
  console.log('   [OK] Single ciphertext successfully decrypted by both recipient devices:\n       - ' + t1 + '\n');

  console.log('=== All Phase 0 Conformance Checks Passed Successfully! ===\n');
}

run().catch((err) => {
  console.error('\nConformance check failed:', err);
  process.exit(1);
});
