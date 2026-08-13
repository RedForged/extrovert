'use strict';

/**
 * multi-device-test.js
 * Comprehensive end-to-end verification of Multi-ID (Per-Device E2EE)
 * and Password-derived History Sync in Extrovert.
 */

const assert = require('node:assert');
const crypto = require('node:crypto');
const Olm = require('@matrix-org/olm');
const db = require('../src/db');

async function run() {
  console.log('--- Starting Multi-Device E2EE Verification Test ---');
  await Olm.init();

  // 1. Setup Test Users
  const rand = crypto.randomBytes(4).toString('hex');
  const aliceName = 'alice_m_' + rand;
  const bobName = 'bob_m_' + rand;
  const aliceId = db.createUser({ username: aliceName, passwordHash: 'hash123', displayName: 'Alice Multi' });
  const bobId = db.createUser({ username: bobName, passwordHash: 'hash123', displayName: 'Bob Multi' });
  db.follow(aliceId, bobId);
  db.follow(bobId, aliceId);

  console.log('✓ Users Alice and Bob created and mutually following.');

  // 2. Helper to create a client Olm Account & generate prekeys
  function createDevice(name) {
    const account = new Olm.Account();
    account.create();
    account.generate_fallback_key();
    account.generate_one_time_keys(5);
    const idKeys = JSON.parse(account.identity_keys());
    const otks = JSON.parse(account.one_time_keys()).curve25519;
    const fb = Object.values(JSON.parse(account.fallback_key()).curve25519)[0];
    const deviceId = 'dev_' + crypto.randomBytes(8).toString('hex');
    const cleanOtks = Object.keys(otks).map(k => ({ id: k, public_key: otks[k] }));

    return {
      name,
      deviceId,
      account,
      idKeys,
      fallbackKey: fb,
      oneTimeKeys: cleanOtks,
      sessions: {}
    };
  }

  // Alice has 2 devices: Phone and Laptop
  const alicePhone = createDevice('Alice Phone');
  const aliceLaptop = createDevice('Alice Laptop');

  // Bob has 2 devices: Desktop and Tablet
  const bobDesktop = createDevice('Bob Desktop');
  const bobTablet = createDevice('Bob Tablet');

  // 3. Register devices on server
  db.registerUserDevice(aliceId, alicePhone.deviceId, alicePhone.idKeys.curve25519, alicePhone.idKeys.ed25519, alicePhone.fallbackKey, alicePhone.name);
  db.addDevicePrekeys(aliceId, alicePhone.deviceId, alicePhone.oneTimeKeys);

  db.registerUserDevice(aliceId, aliceLaptop.deviceId, aliceLaptop.idKeys.curve25519, aliceLaptop.idKeys.ed25519, aliceLaptop.fallbackKey, aliceLaptop.name);
  db.addDevicePrekeys(aliceId, aliceLaptop.deviceId, aliceLaptop.oneTimeKeys);

  db.registerUserDevice(bobId, bobDesktop.deviceId, bobDesktop.idKeys.curve25519, bobDesktop.idKeys.ed25519, bobDesktop.fallbackKey, bobDesktop.name);
  db.addDevicePrekeys(bobId, bobDesktop.deviceId, bobDesktop.oneTimeKeys);

  db.registerUserDevice(bobId, bobTablet.deviceId, bobTablet.idKeys.curve25519, bobTablet.idKeys.ed25519, bobTablet.fallbackKey, bobTablet.name);
  db.addDevicePrekeys(bobId, bobTablet.deviceId, bobTablet.oneTimeKeys);

  console.log('✓ Alice (2 devices) and Bob (2 devices) registered on server.');

  // 4. Verify getUserDevices returns all devices
  const aliceDevices = db.getUserDevices(aliceId);
  const bobDevices = db.getUserDevices(bobId);
  assert.strictEqual(aliceDevices.length, 2, 'Alice should have 2 registered devices');
  assert.strictEqual(bobDevices.length, 2, 'Bob should have 2 registered devices');
  console.log('✓ getUserDevices correctly returns all registered devices.');

  // 5. Test Bundle Fetch: Alice Phone queries Bob bundle
  const recipientBundle = db.claimAllDevicePrekeysForUser(bobId);
  const senderBundle = db.claimAllDevicePrekeysForUser(aliceId);

  assert.strictEqual(recipientBundle.length, 2, 'Bob bundle should contain 2 active recipient devices');
  assert.strictEqual(senderBundle.length, 2, 'Sender bundle should contain 2 active sender devices');
  console.log('✓ Bundle claim returned prekeys for all devices.');

  // 6. Alice Phone encrypts a message fan-out to Bob Desktop, Bob Tablet, and Alice Laptop
  const plaintext = 'Hello Bob, this is a multi-device encrypted message!';
  const deviceCiphertexts = {};

  // For Bob Desktop
  const devBobDesk = recipientBundle.find(d => d.device_id === bobDesktop.deviceId);
  const otkDesk = devBobDesk.one_time_key ? devBobDesk.one_time_key.public_key : devBobDesk.fallback_key;
  const aliceToBobDeskSess = new Olm.Session();
  aliceToBobDeskSess.create_outbound(alicePhone.account, devBobDesk.identity_key, otkDesk);
  const deskEnc = aliceToBobDeskSess.encrypt(plaintext);
  deviceCiphertexts[bobDesktop.deviceId] = { t: deskEnc.type, b: deskEnc.body };

  // For Bob Tablet
  const devBobTab = recipientBundle.find(d => d.device_id === bobTablet.deviceId);
  const otkTab = devBobTab.one_time_key ? devBobTab.one_time_key.public_key : devBobTab.fallback_key;
  const aliceToBobTabSess = new Olm.Session();
  aliceToBobTabSess.create_outbound(alicePhone.account, devBobTab.identity_key, otkTab);
  const tabEnc = aliceToBobTabSess.encrypt(plaintext);
  deviceCiphertexts[bobTablet.deviceId] = { t: tabEnc.type, b: tabEnc.body };

  // For Alice Laptop (sender other device)
  const devAliceLap = senderBundle.find(d => d.device_id === aliceLaptop.deviceId);
  const otkLap = devAliceLap.one_time_key ? devAliceLap.one_time_key.public_key : devAliceLap.fallback_key;
  const aliceToLaptopSess = new Olm.Session();
  aliceToLaptopSess.create_outbound(alicePhone.account, devAliceLap.identity_key, otkLap);
  const lapEnc = aliceToLaptopSess.encrypt(plaintext);
  deviceCiphertexts[aliceLaptop.deviceId] = { t: lapEnc.type, b: lapEnc.body };

  const envelope = {
    v: 2,
    sender_device_id: alicePhone.deviceId,
    devices: deviceCiphertexts
  };

  console.log('✓ Fan-out encryption created envelope for all target devices.');

  // 7. Test Decryption on Bob Desktop
  const bobDeskCipher = envelope.devices[bobDesktop.deviceId];
  const bobDeskSess = new Olm.Session();
  bobDeskSess.create_inbound(bobDesktop.account, bobDeskCipher.b);
  bobDesktop.account.remove_one_time_keys(bobDeskSess);
  const bobDeskPlain = bobDeskSess.decrypt(bobDeskCipher.t, bobDeskCipher.b);
  assert.strictEqual(bobDeskPlain, plaintext, 'Bob Desktop must successfully decrypt plaintext');
  console.log('✓ Bob Desktop decrypted message successfully.');

  // 8. Test Decryption on Bob Tablet
  const bobTabCipher = envelope.devices[bobTablet.deviceId];
  const bobTabSess = new Olm.Session();
  bobTabSess.create_inbound(bobTablet.account, bobTabCipher.b);
  bobTablet.account.remove_one_time_keys(bobTabSess);
  const bobTabPlain = bobTabSess.decrypt(bobTabCipher.t, bobTabCipher.b);
  assert.strictEqual(bobTabPlain, plaintext, 'Bob Tablet must successfully decrypt plaintext');
  console.log('✓ Bob Tablet decrypted message successfully.');

  // 9. Test Decryption on Alice Laptop (Sender copy across devices)
  const aliceLapCipher = envelope.devices[aliceLaptop.deviceId];
  const aliceLapSess = new Olm.Session();
  aliceLapSess.create_inbound(aliceLaptop.account, aliceLapCipher.b);
  aliceLaptop.account.remove_one_time_keys(aliceLapSess);
  const aliceLapPlain = aliceLapSess.decrypt(aliceLapCipher.t, aliceLapCipher.b);
  assert.strictEqual(aliceLapPlain, plaintext, 'Alice Laptop must successfully decrypt sender copy');
  console.log('✓ Alice Laptop decrypted sender copy successfully.');

  // 10. Test Password History Backup & Restore
  const historyData = {
    'conv:1:2': [
      { id: 101, from_id: aliceId, plaintext: plaintext, created_at: Date.now() }
    ]
  };
  const rawJson = JSON.stringify(historyData);

  // Derive KEK from password
  const salt = Buffer.from('alice_multitest');
  const kek = crypto.pbkdf2Sync('password123', salt, 600000, 32, 'sha256');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  const encHistory = Buffer.concat([cipher.update(rawJson, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const backupBlob = Buffer.concat([iv, encHistory, tag]).toString('base64');

  // Save to DB
  db.setUserHistoryBackup(aliceId, backupBlob);
  console.log('✓ Saved password-encrypted history backup.');

  // Retrieve and decrypt from a new device (Alice Browser 3)
  const retrieved = db.getUserHistoryBackup(aliceId);
  assert.ok(retrieved && retrieved.backup_data, 'History backup must exist in DB');

  const buf = Buffer.from(retrieved.backup_data, 'base64');
  const rIv = buf.subarray(0, 12);
  const rTag = buf.subarray(buf.length - 16);
  const rEnc = buf.subarray(12, buf.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, rIv);
  decipher.setAuthTag(rTag);
  const restoredJson = Buffer.concat([decipher.update(rEnc), decipher.final()]).toString('utf8');
  const restoredData = JSON.parse(restoredJson);

  assert.strictEqual(restoredData['conv:1:2'][0].plaintext, plaintext, 'Restored history must match original');
  console.log('✓ Password-only history backup restored successfully on new device.');

  // 11. Cleanup test users
  db.deleteUser(aliceId);
  db.deleteUser(bobId);
  console.log('✓ Cleaned up test data.');

  console.log('\n========================================');
  console.log('🎉 ALL MULTI-DEVICE E2EE TESTS PASSED! 🎉');
  console.log('========================================\n');
}

run().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
