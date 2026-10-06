'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Use a temporary database
const tmpDb = '/tmp/extrovert-mls-api-test.db';
try { fs.unlinkSync(tmpDb); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}

process.env.EXTV_DB_PATH = tmpDb;
process.env.SESSION_SECRET = 'mls-api-secret-1234567890';
process.env.PORT = 0;

const app = require('../src/server');
const db = require('../src/db');

async function run() {
  console.log('=== Starting MLS Server Endpoints (DS/AS) Integration Test ===\n');

  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const port = server.address().port;
  const base = 'http://127.0.0.1:' + port;

  try {
    // 1. Setup users & bearer tokens
    const aliceId = Number(db.createUser({ username: 'alice', passwordHash: 'x', displayName: 'Alice' }));
    const bobId = Number(db.createUser({ username: 'bob', passwordHash: 'x', displayName: 'Bob' }));

    db.createOAuthApp({ name: 'app1', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'c1', clientSecret: 's1', scopes: 'read write follow read:direct write:direct', ownerId: aliceId });
    db.createOAuthApp({ name: 'app2', description: '', website: '', redirectUris: 'https://x/cb', clientId: 'c2', clientSecret: 's2', scopes: 'read write follow read:direct write:direct', ownerId: bobId });

    const atok = crypto.randomBytes(32).toString('hex');
    const btok = crypto.randomBytes(32).toString('hex');
    db.createOAuthToken(atok, null, db.getOAuthAppByClientId('c1').id, aliceId, 'read write follow read:direct write:direct', Date.now() + 86400000);
    db.createOAuthToken(btok, null, db.getOAuthAppByClientId('c2').id, bobId, 'read write follow read:direct write:direct', Date.now() + 86400000);

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

    // 2. Device Registration
    console.log('1. Testing POST /mls/device/register...');
    const regAlice = await req('/mls/device/register', {
      token: atok,
      method: 'POST',
      body: { device_id: 'alice_laptop', device_name: 'Alice Laptop', signing_key_pub: 'ed25519_pub_alice_1' }
    });
    assert.strictEqual(regAlice.status, 201);
    assert.strictEqual(regAlice.json.device.device_id, 'alice_laptop');

    const regBob = await req('/mls/device/register', {
      token: btok,
      method: 'POST',
      body: { device_id: 'bob_desktop', device_name: 'Bob Desktop', signing_key_pub: 'ed25519_pub_bob_1' }
    });
    assert.strictEqual(regBob.status, 201);
    console.log('   [OK] Device registration successful\n');

    // 3. List Active Devices
    console.log('2. Testing GET /mls/devices...');
    const listAlice = await req('/mls/devices', { token: atok });
    assert.strictEqual(listAlice.status, 200);
    assert.strictEqual(listAlice.json.devices.length, 1);
    assert.strictEqual(listAlice.json.devices[0].device_id, 'alice_laptop');
    console.log('   [OK] Active devices listed\n');

    // 4. Batch Upload KeyPackages
    console.log('3. Testing POST /mls/keypackages (validation & batch upload)...');
    const MLS_LABEL = Buffer.from('MLS 1.0 KeyPackage Reference', 'utf8');
    function makeValidTestWire(index) {
      const inner = Buffer.from('synthetic_keypackage_data_for_device_testing_' + index);
      const wire = Buffer.concat([Buffer.from([0x00, 0x01, 0x00, 0x05]), inner]);
      const lenBuf = inner.length < 64
        ? Buffer.from([inner.length])
        : Buffer.from([((inner.length >> 8) & 0x3f) | 0x40, inner.length & 0xff]);
      const ref = crypto.createHash('sha256')
        .update(Buffer.concat([Buffer.from([MLS_LABEL.length]), MLS_LABEL, lenBuf, inner]))
        .digest('hex');
      return { data: wire.toString('base64'), ref };
    }

    // Verify rejection when keypackage_ref is missing
    const badUpload1 = await req('/mls/keypackages', {
      token: btok,
      method: 'POST',
      body: { device_id: 'bob_desktop', keypackages: [{ data: makeValidTestWire(0).data, ciphersuite: 1 }] }
    });
    assert.strictEqual(badUpload1.status, 400);
    assert.ok(badUpload1.json.error.includes('keypackage_ref'), 'Must reject missing keypackage_ref');

    // Verify rejection when MLSMessage wire framing is malformed
    const badUpload2 = await req('/mls/keypackages', {
      token: btok,
      method: 'POST',
      body: {
        device_id: 'bob_desktop',
        keypackages: [{
          data: Buffer.from([0x00, 0x00, 0x00, 0x00, 0x99]).toString('base64'),
          ciphersuite: 1,
          keypackage_ref: 'a'.repeat(64)
        }]
      }
    });
    assert.strictEqual(badUpload2.status, 400);
    assert.strictEqual(badUpload2.json.code, 'MalformedKeyPackageWire');

    // Verify rejection when keypackage_ref does not match semantic RefHash
    const testWire0 = makeValidTestWire(0);
    const badUpload3 = await req('/mls/keypackages', {
      token: btok,
      method: 'POST',
      body: {
        device_id: 'bob_desktop',
        keypackages: [{
          data: testWire0.data,
          ciphersuite: 1,
          keypackage_ref: '0'.repeat(64) // Mismatched ref
        }]
      }
    });
    assert.strictEqual(badUpload3.status, 400);
    assert.strictEqual(badUpload3.json.code, 'KeyPackageRefMismatch');

    const packages = [];
    for (let i = 0; i < 20; i++) {
      const item = makeValidTestWire(i);
      packages.push({
        data: item.data,
        ciphersuite: 1,
        keypackage_ref: item.ref
      });
    }
    const uploadRes = await req('/mls/keypackages', {
      token: btok,
      method: 'POST',
      body: { device_id: 'bob_desktop', keypackages: packages }
    });
    assert.strictEqual(uploadRes.status, 200);
    assert.strictEqual(uploadRes.json.saved, 20);
    console.log('   [OK] Wire framing verified, RefHash mismatch rejected, and 20 valid KeyPackages uploaded\n');

    // 5. KeyPackage Status
    console.log('4. Testing GET /mls/keypackages/status...');
    const statusRes = await req('/mls/keypackages/status?device_id=bob_desktop', { token: btok });
    assert.strictEqual(statusRes.status, 200);
    assert.strictEqual(statusRes.json.available, 20);
    console.log('   [OK] KeyPackage pool status reports 20 available\n');

    // 6. Claim KeyPackage for Target User
    console.log('5. Testing GET /mls/keypackages/:userId (claiming single-use package)...');
    const claimRes = await req('/mls/keypackages/' + bobId, { token: atok });
    assert.strictEqual(claimRes.status, 200);
    assert.strictEqual(claimRes.json.keypackages.length, 1);
    assert.strictEqual(claimRes.json.keypackages[0].keypackage_data, packages[0].data);
    assert.strictEqual(claimRes.json.keypackages[0].keypackage_ref, packages[0].keypackage_ref);

    // Verify Bob's pool decremented
    const statusAfter = await req('/mls/keypackages/status?device_id=bob_desktop', { token: btok });
    assert.strictEqual(statusAfter.json.available, 19);

    // Claim with exclude_device must skip the excluded device entirely
    const exclClaimRes = await req('/mls/keypackages/' + bobId + '?exclude_device=bob_desktop', { token: atok });
    assert.strictEqual(exclClaimRes.status, 200);
    assert.strictEqual(exclClaimRes.json.keypackages.length, 0, 'Excluded device must not be claimed');
    console.log('   [OK] KeyPackage claimed and decremented pool count to 19\n');

    // 7. Atomic Group Init
    console.log('6. Testing POST /mls/groups/init...');
    const initRes = await req('/mls/groups/init', {
      token: atok,
      method: 'POST',
      body: {
        group_id: 'dm:' + Math.min(aliceId, bobId) + '_' + Math.max(aliceId, bobId),
        initial_commit: 'initial_commit_wire_data',
        welcomes: [{ user_id: bobId, device_id: 'bob_desktop', welcome_data: 'welcome_bytes_bob' }],
        idempotency_key: 'init_key_1',
      }
    });
    assert.strictEqual(initRes.status, 201);
    assert.strictEqual(initRes.json.epoch, 1);

    // Duplicate init returns 409 GroupExists
    const dupRes = await req('/mls/groups/init', {
      token: atok,
      method: 'POST',
      body: { group_id: 'dm:' + Math.min(aliceId, bobId) + '_' + Math.max(aliceId, bobId) }
    });
    assert.strictEqual(dupRes.status, 409);
    assert.strictEqual(dupRes.json.error, 'GroupExists');
    console.log('   [OK] Group initialized at epoch 1 and duplicate creation rejected with 409\n');

    // 8. Commit with CAS Epoch Advancement
    console.log('7. Testing POST /mls/groups/:groupId/commit...');
    const dmGroupId = 'dm:' + Math.min(aliceId, bobId) + '_' + Math.max(aliceId, bobId);

    // Commit with wrong epoch (expects 1, pass 99) -> 409 EpochConflict
    const conflictRes = await req('/mls/groups/' + dmGroupId + '/commit', {
      token: atok,
      method: 'POST',
      body: { current_epoch: 99, commit_message: 'stale_commit_bytes' }
    });
    assert.strictEqual(conflictRes.status, 409);
    assert.strictEqual(conflictRes.json.error, 'EpochConflict');
    assert.strictEqual(conflictRes.json.server_epoch, 1);

    // Valid commit: 1 -> 2
    const commitRes = await req('/mls/groups/' + dmGroupId + '/commit', {
      token: atok,
      method: 'POST',
      body: {
        current_epoch: 1,
        commit_message: 'commit_bytes_epoch_2',
        welcomes: [{ user_id: bobId, device_id: 'bob_desktop', welcome_data: 'welcome_epoch_2' }],
        idempotency_key: 'commit_idem_1'
      }
    });
    assert.strictEqual(commitRes.status, 200);
    assert.strictEqual(commitRes.json.new_epoch, 2);
    console.log('   [OK] Epoch advanced to 2 and conflict handling verified\n');

    // 9. Catch-Up Commits
    console.log('8. Testing GET /mls/groups/:groupId/commits...');
    const commitsRes = await req('/mls/groups/' + dmGroupId + '/commits?since=-1', { token: btok });
    assert.strictEqual(commitsRes.status, 200);
    assert.strictEqual(commitsRes.json.commits.length, 2, 'Should have epoch 1 and epoch 2 commits');
    assert.strictEqual(commitsRes.json.commits[0].epoch, 1);
    assert.strictEqual(commitsRes.json.commits[1].epoch, 2);
    console.log('   [OK] Catch-up commits retrieved\n');

    // 10. Welcomes & Ack
    console.log('9. Testing GET /mls/welcomes & POST /mls/welcomes/ack...');
    const welcomesRes = await req('/mls/welcomes?device_id=bob_desktop', { token: btok });
    assert.strictEqual(welcomesRes.status, 200);
    assert.strictEqual(welcomesRes.json.welcomes.length, 2);

    const ackRes = await req('/mls/welcomes/ack', {
      token: btok,
      method: 'POST',
      body: { welcome_id: welcomesRes.json.welcomes[0].id, device_id: 'bob_desktop' }
    });
    assert.strictEqual(ackRes.status, 200);

    const afterAck = await req('/mls/welcomes?device_id=bob_desktop', { token: btok });
    assert.strictEqual(afterAck.json.welcomes.length, 1);
    console.log('   [OK] Welcomes fetched and acknowledged\n');

    // 11. Backup Vault
    console.log('10. Testing POST /mls/backup & GET /mls/backup...');
    const saveBk = await req('/mls/backup', {
      token: atok,
      method: 'POST',
      body: { backup_data: 'encrypted_vault_ciphertext', salt: 'salt_abc_123' }
    });
    assert.strictEqual(saveBk.status, 200);

    const getBk = await req('/mls/backup', { token: atok });
    assert.strictEqual(getBk.status, 200);
    assert.strictEqual(getBk.json.backup.backup_data, 'encrypted_vault_ciphertext');
    assert.strictEqual(getBk.json.backup.kek_salt, 'salt_abc_123');
    console.log('   [OK] Credential backup vault stored and retrieved\n');

    // 11. Stale Group Reset Recovery
    console.log('11. Testing POST /mls/groups/init reset_existing (stale group recovery)...');

    // Reset with a stale expected epoch must NOT wipe the group
    const badReset = await req('/mls/groups/init', {
      token: atok,
      method: 'POST',
      body: { group_id: dmGroupId, initial_commit: 'stale_reset_commit', reset_existing: true, expected_epoch: 99 }
    });
    assert.strictEqual(badReset.status, 409);
    assert.strictEqual(badReset.json.error, 'GroupExists');

    // Reset with the observed epoch wipes the dead group and re-initializes
    const okReset = await req('/mls/groups/init', {
      token: atok,
      method: 'POST',
      body: {
        group_id: dmGroupId,
        initial_commit: 'fresh_initial_commit_wire_data',
        welcomes: [{ user_id: bobId, device_id: 'bob_desktop', welcome_data: 'welcome_bytes_bob_reset' }],
        idempotency_key: 'init_key_reset',
        reset_existing: true,
        expected_epoch: badReset.json.epoch,
      }
    });
    assert.strictEqual(okReset.status, 201);
    assert.strictEqual(okReset.json.epoch, 1, 'Re-initialized group must restart at epoch 1');

    const freshCommits = await req('/mls/groups/' + dmGroupId + '/commits?since=-1', { token: btok });
    assert.strictEqual(freshCommits.json.commits.length, 1, 'Reset must wipe stale commits');
    assert.strictEqual(freshCommits.json.commits[0].epoch, 1);
    console.log('   [OK] CAS-checked stale group reset and re-initialization verified\n');

    console.log('=== All MLS API Endpoint Tests Passed Successfully! ===\n');
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
  console.error('\nMLS API Test failed:', err);
  process.exit(1);
});
