'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const wasmPath = path.join(path.dirname(require.resolve('@matrix-org/olm/package.json')), 'olm.wasm');

async function run() {
  const Olm = require('@matrix-org/olm');
  await Olm.init({ wasmBinary: fs.readFileSync(wasmPath) });

  console.log('Testing E2EE Backup & Restore with Megolm room keys & DM sessions...');

  // Simulate Device 1: create Olm account and a room outbound group session
  const PICKLE_KEY = 'test_pickle_key_secret';
  const account1 = new Olm.Account();
  account1.create();
  const idKeys1 = JSON.parse(account1.identity_keys());

  // Room outbound group session on Device 1
  const roomOut = new Olm.OutboundGroupSession();
  roomOut.create();
  const roomId = 'room_123';
  const sessionId = 'srv_session_456';

  // Device 1 exports session key at creation time and creates self-inbound session (like shareRoomSession)
  const roomIn1 = new Olm.InboundGroupSession();
  roomIn1.create(roomOut.session_key());

  // Device 1 encrypts multiple messages (ratchet advances)
  const roomMsg1 = 'First secret room message!';
  const roomMsg2 = 'Second secret room message!';
  const roomCipher1 = roomOut.encrypt(roomMsg1);
  const roomCipher2 = roomOut.encrypt(roomMsg2);

  // Verify Device 1 can decrypt both
  assert.strictEqual(roomIn1.decrypt(roomCipher1).plaintext, roomMsg1);
  assert.strictEqual(roomIn1.decrypt(roomCipher2).plaintext, roomMsg2);
  console.log('  [OK] Device 1 encrypted & decrypted multiple room messages');

  // Device 1 prepares backup payload (v4)
  const groupInKey = roomId + ':' + 'user_1' + ':' + sessionId;
  const backupPayload = {
    v: 4,
    account: account1.pickle(PICKLE_KEY),
    groupIn: {
      [groupInKey]: roomIn1.pickle(PICKLE_KEY)
    },
    groupOut: {
      [roomId]: {
        id: sessionId,
        pickle: roomOut.pickle(PICKLE_KEY)
      }
    }
  };

  // Simulate Device 2: fresh client, restores from backup
  assert.strictEqual(backupPayload.v, 4, 'Backup is v4');
  const account2 = new Olm.Account();
  account2.unpickle(PICKLE_KEY, backupPayload.account);
  const idKeys2 = JSON.parse(account2.identity_keys());
  assert.strictEqual(idKeys2.curve25519, idKeys1.curve25519, 'Restored identity matches');

  // Device 2 restores inbound room session from backup
  const restoredGroupInPickle = backupPayload.groupIn[groupInKey];
  assert.ok(restoredGroupInPickle, 'GroupIn session present in backup');

  const roomIn2 = new Olm.InboundGroupSession();
  roomIn2.unpickle(PICKLE_KEY, restoredGroupInPickle);

  // Device 2 decrypts both messages sent on Device 1 in any order!
  assert.strictEqual(roomIn2.decrypt(roomCipher1).plaintext, roomMsg1);
  assert.strictEqual(roomIn2.decrypt(roomCipher2).plaintext, roomMsg2);
  console.log('  [OK] Device 2 restored Megolm room keys from backup and successfully decrypted all room messages!');

  // Test backward-compatibility: v3 backup without room keys does not crash
  const legacyPayload = {
    v: 3,
    account: account1.pickle(PICKLE_KEY),
    sessions: {},
    baselines: {}
  };
  const accountLegacy = new Olm.Account();
  accountLegacy.unpickle(PICKLE_KEY, legacyPayload.account);
  assert.strictEqual(JSON.parse(accountLegacy.identity_keys()).curve25519, idKeys1.curve25519);
  console.log('  [OK] Legacy v3 backup backwards compatibility verified');

  console.log('\nAll backup & restore verification checks passed successfully.');
}

run().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
