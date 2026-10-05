'use strict';

/**
 * End-to-End Chat Test for MLS (RFC 9420)
 * Validates:
 * 1. Two users registering MLS devices and KeyPackage batches
 * 2. 1:1 DM Group creation & Welcome delivery
 * 3. Bidirectional DM messaging (Alice -> Bob, Bob -> Alice)
 * 4. Multi-device expansion: Bob adds 2nd device (Mobile)
 * 5. Single-ciphertext broadcast: Alice sends one message, BOTH Bob devices decrypt!
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const tmpDb = '/tmp/extrovert-mls-e2e-test.db';
try { fs.unlinkSync(tmpDb); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}

process.env.EXTV_DB_PATH = tmpDb;
process.env.SESSION_SECRET = 'mls-e2e-secret-1234567890';
process.env.PORT = 0;

const app = require('../src/server');
const db = require('../src/db');

// Load MLS library
global.window = global;
if (!global.crypto) global.crypto = crypto.webcrypto;
require('../public/lib/mls.js');
const mls = window.MLS;

async function run() {
  console.log('=== Starting Extrovert MLS End-to-End Live Chat Test ===\n');

  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port;

  try {
    const cs = mls.getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519');
    const impl = await mls.getCiphersuiteImpl(cs);

    // 1. Create Alice and Bob in Extrovert
    const aliceId = Number(db.createUser({ username: 'alice', passwordHash: 'x', displayName: 'Alice' }));
    const bobId = Number(db.createUser({ username: 'bob', passwordHash: 'x', displayName: 'Bob' }));

    db.createOAuthApp({ name: 'a1', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'ca1', clientSecret: 'sa1', scopes: 'read write follow read:direct write:direct', ownerId: aliceId });
    db.createOAuthApp({ name: 'b1', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'cb1', clientSecret: 'sb1', scopes: 'read write follow read:direct write:direct', ownerId: bobId });

    const atok = crypto.randomBytes(32).toString('hex');
    const btok1 = crypto.randomBytes(32).toString('hex');
    const btok2 = crypto.randomBytes(32).toString('hex');
    db.createOAuthToken(atok, null, db.getOAuthAppByClientId('ca1').id, aliceId, 'read write follow read:direct write:direct', Date.now() + 86400000);
    db.createOAuthToken(btok1, null, db.getOAuthAppByClientId('cb1').id, bobId, 'read write follow read:direct write:direct', Date.now() + 86400000);
    db.createOAuthToken(btok2, null, db.getOAuthAppByClientId('cb1').id, bobId, 'read write follow read:direct write:direct', Date.now() + 86400000);

    async function req(url, opts = {}) {
      const headers = { Authorization: 'Bearer ' + opts.token };
      if (opts.body) headers['Content-Type'] = 'application/json';
      const r = await fetch(base + url, {
        method: opts.method || 'GET',
        headers,
        body: opts.body ? JSON.stringify(opts.body) : undefined,
      });
      return { status: r.status, json: await r.json().catch(() => null) };
    }

    // 2. Initialize Alice (Device 1)
    console.log('1. Registering Alice Device 1 and publishing 20 KeyPackages...');
    const aliceCred = { credentialType: 'basic', identity: new TextEncoder().encode(`user:${aliceId}:dev:alice1`) };
    const aliceReg = await req('/mls/device/register', {
      token: atok,
      method: 'POST',
      body: { device_id: 'alice1', device_name: 'Alice Laptop', signing_key_pub: 'ed_alice1' }
    });
    assert.strictEqual(aliceReg.status, 201);

    const alicePkgs = [];
    const aliceKps = [];
    for (let i = 0; i < 20; i++) {
      const kp = await mls.generateKeyPackage(aliceCred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
      aliceKps.push(kp);
      const ref = await mls.makeKeyPackageRef(kp.publicPackage, impl.hash);
      const enc = mls.encodeMlsMessage({ keyPackage: kp.publicPackage, wireformat: 'mls_key_package', version: 'mls10' });
      alicePkgs.push({ data: Buffer.from(enc).toString('base64'), ciphersuite: 1, keypackage_ref: Buffer.from(ref).toString('hex') });
    }
    await req('/mls/keypackages', { token: atok, method: 'POST', body: { device_id: 'alice1', keypackages: alicePkgs } });
    console.log('   [OK] Alice initialized\n');

    // 3. Initialize Bob (Device 1 - Laptop)
    console.log('2. Registering Bob Device 1 (Laptop) and publishing 20 KeyPackages...');
    const bob1Cred = { credentialType: 'basic', identity: new TextEncoder().encode(`user:${bobId}:dev:bob1`) };
    await req('/mls/device/register', {
      token: btok1,
      method: 'POST',
      body: { device_id: 'bob1', device_name: 'Bob Laptop', signing_key_pub: 'ed_bob1' }
    });

    const bob1Pkgs = [];
    const bob1Kps = [];
    for (let i = 0; i < 20; i++) {
      const kp = await mls.generateKeyPackage(bob1Cred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
      bob1Kps.push(kp);
      const ref = await mls.makeKeyPackageRef(kp.publicPackage, impl.hash);
      const enc = mls.encodeMlsMessage({ keyPackage: kp.publicPackage, wireformat: 'mls_key_package', version: 'mls10' });
      bob1Pkgs.push({ data: Buffer.from(enc).toString('base64'), ciphersuite: 1, keypackage_ref: Buffer.from(ref).toString('hex') });
    }
    await req('/mls/keypackages', { token: btok1, method: 'POST', body: { device_id: 'bob1', keypackages: bob1Pkgs } });
    console.log('   [OK] Bob Device 1 initialized\n');

    // 4. Alice initiates DM conversation with Bob
    console.log('3. Alice fetches Bob KeyPackage and initializes group dm:alice_bob...');
    const claimBob = await req('/mls/keypackages/' + bobId, { token: atok });
    assert.strictEqual(claimBob.status, 200);
    assert.strictEqual(claimBob.json.keypackages.length, 1);
    const bobKpWire = Buffer.from(claimBob.json.keypackages[0].keypackage_data, 'base64');
    const [decBobKp] = mls.decodeMlsMessage(bobKpWire, 0);

    const dmGroupId = 'dm:' + Math.min(aliceId, bobId) + '_' + Math.max(aliceId, bobId);
    const aliceInitKp = await mls.generateKeyPackage(aliceCred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
    let aliceGroup = await mls.createGroup(new TextEncoder().encode(dmGroupId), aliceInitKp.publicPackage, aliceInitKp.privatePackage, [], impl);

    const addBobProposal = { proposalType: 'add', add: { keyPackage: decBobKp.keyPackage } };
    const commitRes1 = await mls.createCommit(
      { state: aliceGroup, cipherSuite: impl },
      { extraProposals: [addBobProposal], ratchetTreeExtension: true }
    );
    aliceGroup = commitRes1.newState;
    commitRes1.consumed.forEach(mls.zeroOutUint8Array);

    const welcomeEnc = mls.encodeMlsMessage({ welcome: commitRes1.welcome, wireformat: 'mls_welcome', version: 'mls10' });
    const commitEnc = mls.encodeMlsMessage(commitRes1.commit);

    const initRes = await req('/mls/groups/init', {
      token: atok,
      method: 'POST',
      body: {
        group_id: dmGroupId,
        initial_commit: Buffer.from(commitEnc).toString('base64'),
        welcomes: [{ user_id: bobId, device_id: 'bob1', welcome_data: Buffer.from(welcomeEnc).toString('base64') }]
      }
    });
    assert.strictEqual(initRes.status, 201);
    console.log('   [OK] Group initialized on server at epoch 0 with Welcome queued for Bob1\n');

    // 5. Bob Device 1 polls and consumes Welcome
    console.log('4. Bob Device 1 fetches Welcome and joins group...');
    const bobWelcomes = await req('/mls/welcomes?device_id=bob1', { token: btok1 });
    assert.strictEqual(bobWelcomes.status, 200);
    assert.strictEqual(bobWelcomes.json.welcomes.length, 1);

    const welcomeMsgBytes = Buffer.from(bobWelcomes.json.welcomes[0].welcome_data, 'base64');
    const [decWelcome] = mls.decodeMlsMessage(welcomeMsgBytes, 0);

    let bob1Group = await mls.joinGroup(
      decWelcome.welcome,
      bob1Kps[0].publicPackage,
      bob1Kps[0].privatePackage,
      mls.emptyPskIndex,
      impl,
      aliceGroup.ratchetTree
    );
    assert.strictEqual(bob1Group.groupContext.epoch, 1n);

    await req('/mls/welcomes/ack', {
      token: btok1,
      method: 'POST',
      body: { welcome_id: bobWelcomes.json.welcomes[0].id, device_id: 'bob1' }
    });
    console.log('   [OK] Bob Device 1 joined group at epoch 1\n');

    // 6. Alice sends message to Bob
    console.log('5. Alice encrypts application message and sends to Bob...');
    const m1Plain = 'Hey Bob, this is encrypted with standard MLS RFC 9420!';
    const sendM1 = await mls.createApplicationMessage(aliceGroup, new TextEncoder().encode(m1Plain), impl);
    aliceGroup = sendM1.newState;
    sendM1.consumed.forEach(mls.zeroOutUint8Array);

    const m1Wire = mls.encodeMlsMessage({ privateMessage: sendM1.privateMessage, wireformat: 'mls_private_message', version: 'mls10' });

    // Bob decrypts
    const [decM1] = mls.decodeMlsMessage(m1Wire, 0);
    const recvM1 = await mls.processPrivateMessage(bob1Group, decM1.privateMessage, mls.emptyPskIndex, impl);
    bob1Group = recvM1.newState;
    const m1Decrypted = new TextDecoder().decode(recvM1.message);
    assert.strictEqual(m1Decrypted, m1Plain);
    console.log('   [OK] Bob successfully decrypted Alice message:\n       "' + m1Decrypted + '"\n');

    // 7. Bob replies to Alice
    console.log('6. Bob replies to Alice...');
    const m2Plain = 'Confirmed Alice! Perfectly decrypted without any Olm fan-out envelopes!';
    const sendM2 = await mls.createApplicationMessage(bob1Group, new TextEncoder().encode(m2Plain), impl);
    bob1Group = sendM2.newState;
    sendM2.consumed.forEach(mls.zeroOutUint8Array);

    const m2Wire = mls.encodeMlsMessage({ privateMessage: sendM2.privateMessage, wireformat: 'mls_private_message', version: 'mls10' });

    // Alice decrypts
    const [decM2] = mls.decodeMlsMessage(m2Wire, 0);
    const recvM2 = await mls.processPrivateMessage(aliceGroup, decM2.privateMessage, mls.emptyPskIndex, impl);
    aliceGroup = recvM2.newState;
    const m2Decrypted = new TextDecoder().decode(recvM2.message);
    assert.strictEqual(m2Decrypted, m2Plain);
    console.log('   [OK] Alice successfully decrypted Bob reply:\n       "' + m2Decrypted + '"\n');

    // 8. Multi-Device Expansion: Bob registers Device 2 (Mobile)
    console.log('7. Bob registers Device 2 (Mobile) and joins conversation...');
    const bob2Cred = { credentialType: 'basic', identity: new TextEncoder().encode(`user:${bobId}:dev:bob2`) };
    await req('/mls/device/register', {
      token: btok2,
      method: 'POST',
      body: { device_id: 'bob2', device_name: 'Bob Mobile', signing_key_pub: 'ed_bob2' }
    });

    const bob2Kp = await mls.generateKeyPackage(bob2Cred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
    const bob2Ref = await mls.makeKeyPackageRef(bob2Kp.publicPackage, impl.hash);
    const bob2KpWire = mls.encodeMlsMessage({ keyPackage: bob2Kp.publicPackage, wireformat: 'mls_key_package', version: 'mls10' });
    await req('/mls/keypackages', {
      token: btok2,
      method: 'POST',
      body: { device_id: 'bob2', keypackages: [{ data: Buffer.from(bob2KpWire).toString('base64'), ciphersuite: 1, keypackage_ref: Buffer.from(bob2Ref).toString('hex') }] }
    });

    // Bob Laptop adds Bob Mobile to the group via AddProposal + Commit
    const addBob2Proposal = { proposalType: 'add', add: { keyPackage: bob2Kp.publicPackage } };
    const commitRes2 = await mls.createCommit(
      { state: bob1Group, cipherSuite: impl },
      { extraProposals: [addBob2Proposal], ratchetTreeExtension: true }
    );
    bob1Group = commitRes2.newState;
    commitRes2.consumed.forEach(mls.zeroOutUint8Array);

    const welcome2Enc = mls.encodeMlsMessage({ welcome: commitRes2.welcome, wireformat: 'mls_welcome', version: 'mls10' });
    const commit2Enc = mls.encodeMlsMessage(commitRes2.commit);

    // Commit to server (Epoch 1 -> 2)
    const commitPost = await req('/mls/groups/' + dmGroupId + '/commit', {
      token: btok1,
      method: 'POST',
      body: {
        current_epoch: 1,
        commit_message: Buffer.from(commit2Enc).toString('base64'),
        welcomes: [{ user_id: bobId, device_id: 'bob2', welcome_data: Buffer.from(welcome2Enc).toString('base64') }]
      }
    });
    assert.strictEqual(commitPost.status, 200);
    assert.strictEqual(commitPost.json.new_epoch, 2);

    // Alice syncs to epoch 2 by processing the commit
    const [decCommit2] = mls.decodeMlsMessage(commit2Enc, 0);
    const aliceSync = await mls.processMessage(decCommit2, aliceGroup, mls.emptyPskIndex, () => {}, impl);
    aliceGroup = aliceSync.newState;
    assert.strictEqual(aliceGroup.groupContext.epoch, 2n);

    // Bob Mobile joins from Welcome at epoch 2
    let bob2Group = await mls.joinGroup(
      commitRes2.welcome,
      bob2Kp.publicPackage,
      bob2Kp.privatePackage,
      mls.emptyPskIndex,
      impl,
      bob1Group.ratchetTree
    );
    assert.strictEqual(bob2Group.groupContext.epoch, 2n);
    console.log('   [OK] Bob Mobile joined at epoch 2. Group now has 3 leaves\n');

    // 9. Single-Ciphertext Broadcast to All Devices
    console.log('8. Alice sends ONE message to the group; verifying BOTH of Bob\'s devices decrypt it...');
    const broadcastPlain = 'One ciphertext to Bob Laptop and Bob Mobile simultaneously!';
    const sendBcast = await mls.createApplicationMessage(aliceGroup, new TextEncoder().encode(broadcastPlain), impl);
    aliceGroup = sendBcast.newState;
    sendBcast.consumed.forEach(mls.zeroOutUint8Array);

    const bcastWire = mls.encodeMlsMessage({ privateMessage: sendBcast.privateMessage, wireformat: 'mls_private_message', version: 'mls10' });

    // Bob Laptop decrypts
    const [decBcast1] = mls.decodeMlsMessage(bcastWire, 0);
    const recvBcast1 = await mls.processPrivateMessage(bob1Group, decBcast1.privateMessage, mls.emptyPskIndex, impl);
    bob1Group = recvBcast1.newState;
    const t1 = new TextDecoder().decode(recvBcast1.message);

    // Bob Mobile decrypts the EXACT SAME payload
    const [decBcast2] = mls.decodeMlsMessage(bcastWire, 0);
    const recvBcast2 = await mls.processPrivateMessage(bob2Group, decBcast2.privateMessage, mls.emptyPskIndex, impl);
    bob2Group = recvBcast2.newState;
    const t2 = new TextDecoder().decode(recvBcast2.message);

    assert.strictEqual(t1, broadcastPlain);
    assert.strictEqual(t2, broadcastPlain);
    console.log('   [OK] Bob Laptop decrypted: "' + t1 + '"');
    console.log('   [OK] Bob Mobile decrypted: "' + t2 + '"\n');

    console.log('=== Extrovert MLS Live E2E Verification Complete: 100% SUCCESS ===\n');
    process.exit(0);
  } finally {
    server.close();
    if (server.closeAllConnections) server.closeAllConnections();
    try { app.httpServer.close(); } catch {}
    try { fs.unlinkSync(tmpDb); } catch (_) {}
    try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
    try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}
  }
}

run().catch((err) => {
  console.error('\nMLS E2E Test failed:', err);
  process.exit(1);
});
