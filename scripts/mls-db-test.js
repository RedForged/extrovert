'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');

// Use a temporary database
const tmpDb = '/tmp/extrovert-mls-db-test.db';
try { fs.unlinkSync(tmpDb); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}

process.env.EXTV_DB_PATH = tmpDb;
process.env.SESSION_SECRET = 'mls-test-secret-1234567890';
const db = require('../src/db');

async function run() {
  console.log('=== Starting MLS Database & CAS Sequencer Test Suite ===\n');

  // Seed two users
  const u1Id = Number(db.createUser({ username: 'alice', passwordHash: 'hash1', displayName: 'Alice' }));
  const u2Id = Number(db.createUser({ username: 'bob', passwordHash: 'hash2', displayName: 'Bob' }));
  const u1 = { id: u1Id };
  const u2 = { id: u2Id };

  // 1. Device Registration & Quota
  console.log('1. Testing Device Registration & Quota...');
  const dev1 = db.registerMlsDevice(u1.id, 'alice_phone', 'Alice Phone', 'key_pub_alice_1');
  assert.strictEqual(dev1.device_id, 'alice_phone');
  assert.strictEqual(dev1.user_id, u1.id);

  const devices1 = db.getMlsDevices(u1.id);
  assert.strictEqual(devices1.length, 1);
  assert.strictEqual(devices1[0].device_id, 'alice_phone');

  // Register up to quota (10 devices)
  for (let i = 2; i <= 10; i++) {
    db.registerMlsDevice(u1.id, 'alice_dev_' + i, 'Device ' + i, 'key_pub_' + i);
  }
  const devices10 = db.getMlsDevices(u1.id);
  assert.strictEqual(devices10.length, 10, 'Must have 10 devices');

  // 11th device must throw QUOTA_EXCEEDED
  let quotaThrew = false;
  try {
    db.registerMlsDevice(u1.id, 'alice_dev_11', 'Device 11', 'key_pub_11');
  } catch (err) {
    quotaThrew = true;
    assert.strictEqual(err.code, 'QUOTA_EXCEEDED');
  }
  assert.ok(quotaThrew, 'Exceeding 10 devices must throw QUOTA_EXCEEDED');
  console.log('   [OK] Device registration and 10-device quota verified\n');

  // 2. KeyPackage Batch Upload & Status
  console.log('2. Testing KeyPackage Batch Upload & Status...');
  const bobDev1 = db.registerMlsDevice(u2.id, 'bob_laptop', 'Bob Laptop', 'key_pub_bob_1');
  const bobDev2 = db.registerMlsDevice(u2.id, 'bob_phone', 'Bob Phone', 'key_pub_bob_2');

  const packagesDev1 = [];
  for (let i = 0; i < 20; i++) {
    packagesDev1.push({ data: 'kp_dev1_' + i, ciphersuite: 1 });
  }
  const uploaded = db.saveMlsKeyPackages(u2.id, 'bob_laptop', packagesDev1);
  assert.strictEqual(uploaded, 20);

  const statusBefore = db.getMlsKeyPackageStatus(u2.id, 'bob_laptop');
  assert.strictEqual(statusBefore, 20);

  // 3. Claiming KeyPackages (Single-use)
  console.log('3. Testing Single-Use KeyPackage Claiming...');
  const claimed1 = db.claimMlsKeyPackage(u2.id, 'bob_laptop');
  assert.ok(claimed1, 'Must claim a keypackage');
  assert.strictEqual(claimed1.keypackage_data, 'kp_dev1_0');

  const statusAfter1 = db.getMlsKeyPackageStatus(u2.id, 'bob_laptop');
  assert.strictEqual(statusAfter1, 19, 'Pool count must decrement by 1');

  // Claim across user's devices
  db.saveMlsKeyPackages(u2.id, 'bob_phone', [{ data: 'kp_phone_1', ciphersuite: 1 }]);
  const userClaim = db.claimUserMlsKeyPackages(u2.id);
  assert.strictEqual(userClaim.length, 2, 'Should claim 1 for bob_laptop and 1 for bob_phone');
  assert.strictEqual(userClaim[0].device_id, 'bob_laptop');
  assert.strictEqual(userClaim[1].device_id, 'bob_phone');
  console.log('   [OK] KeyPackage pool and single-use claiming verified\n');

  // 4. Atomic Group Init & CAS Epoch Advancement
  console.log('4. Testing Atomic Group Init & CAS Commit Sequencer...');
  const initRes = db.initMlsGroup('dm:1_2', 0, [u1.id, u2.id], 'initial_commit_bytes', [
    { user_id: u2.id, device_id: 'bob_laptop', welcome_data: 'welcome_to_bob_laptop' }
  ], 'idem_init_1');
  assert.strictEqual(initRes.ok, true);
  assert.strictEqual(initRes.epoch, 1);

  // Duplicate init must fail
  let duplicateThrew = false;
  try {
    db.initMlsGroup('dm:1_2', 0, [u1.id, u2.id], 'commit_again');
  } catch (err) {
    duplicateThrew = true;
    assert.strictEqual(err.code, 'GROUP_EXISTS');
  }
  assert.ok(duplicateThrew, 'Duplicate group init must fail');

  // Idempotent init request returns identical response
  const idemRes = db.initMlsGroup('dm:1_2', 0, [u1.id, u2.id], null, [], 'idem_init_1');
  assert.deepStrictEqual(idemRes, initRes, 'Idempotent init call must return cached response');

  // Commit Epoch 1 -> 2
  const commitRes1 = db.commitMlsGroup('dm:1_2', 1, 'commit_bytes_epoch_2', [
    { user_id: u2.id, device_id: 'bob_phone', welcome_data: 'welcome_to_bob_phone' }
  ], 'idem_commit_1');
  assert.strictEqual(commitRes1.ok, true);
  assert.strictEqual(commitRes1.new_epoch, 2);

  // Commit with wrong epoch (Epoch conflict: expecting 1 when server is at 2)
  let conflictThrew = false;
  try {
    db.commitMlsGroup('dm:1_2', 1, 'stale_commit_bytes');
  } catch (err) {
    conflictThrew = true;
    assert.strictEqual(err.code, 'EPOCH_CONFLICT');
    assert.strictEqual(err.server_epoch, 2);
  }
  assert.ok(conflictThrew, 'Stale commit must throw EPOCH_CONFLICT with server_epoch');

  // Commit Epoch 2 -> 3
  const commitRes2 = db.commitMlsGroup('dm:1_2', 2, 'commit_bytes_epoch_3');
  assert.strictEqual(commitRes2.new_epoch, 3);
  console.log('   [OK] Group init, idempotency, and CAS epoch conflict sequencer verified\n');

  // 5. Commit Catch-Up (`mls_commits`)
  console.log('5. Testing Historical Commit Catch-Up...');
  const catchupAll = db.getMlsCommits('dm:1_2', -1);
  assert.strictEqual(catchupAll.length, 3, 'Must have commits for epochs 1, 2, and 3');
  assert.strictEqual(catchupAll[0].epoch, 1);
  assert.strictEqual(catchupAll[1].epoch, 2);
  assert.strictEqual(catchupAll[2].epoch, 3);

  const catchupSince1 = db.getMlsCommits('dm:1_2', 2);
  assert.strictEqual(catchupSince1.length, 1);
  assert.strictEqual(catchupSince1[0].epoch, 3);
  console.log('   [OK] Commit catch-up queries return ordered public commits\n');

  // 6. Welcomes & Acks
  console.log('6. Testing Welcome Queuing and Consumption...');
  const welcomesLaptop = db.getMlsWelcomes(u2.id, 'bob_laptop');
  assert.strictEqual(welcomesLaptop.length, 1);
  assert.strictEqual(welcomesLaptop[0].welcome_data, 'welcome_to_bob_laptop');

  const ack = db.ackMlsWelcome(welcomesLaptop[0].id, u2.id, 'bob_laptop');
  assert.ok(ack.changes > 0, 'Welcome ack must update row');

  const welcomesAfterAck = db.getMlsWelcomes(u2.id, 'bob_laptop');
  assert.strictEqual(welcomesAfterAck.length, 0, 'Consumed welcome must not appear');
  console.log('   [OK] Welcomes queued, queried, and acknowledged\n');

  // 7. Credential Backup
  console.log('7. Testing Credential Backup & Restore...');
  db.saveMlsBackup(u1.id, 'encrypted_master_signing_key_bytes', 'random_salt_123');
  const backup = db.getMlsBackup(u1.id);
  assert.ok(backup);
  assert.strictEqual(backup.backup_data, 'encrypted_master_signing_key_bytes');
  assert.strictEqual(backup.kek_salt, 'random_salt_123');
  console.log('   [OK] Credential backup vault stored and retrieved\n');

  console.log('=== All MLS Database Tests Passed Successfully! ===\n');
}

run().catch((err) => {
  console.error('\nMLS DB Test failed:', err);
  process.exit(1);
}).finally(() => {
  try { fs.unlinkSync(tmpDb); } catch (_) {}
  try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
  try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}
});
