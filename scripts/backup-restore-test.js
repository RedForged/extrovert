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

  // ---- Restored device vs. per-device ciphertext sealed to a dead identity ----
  // Regression for '[unable to decrypt]' after restore: a device that replaces a
  // previously-registered blank account finds messages whose v2 envelope has its
  // device slot sealed to the DEAD blank identity. Mirrors public/e2ee.js
  // cipherCandidates(): the decrypt ladder must fall back to the primary t/b
  // cipher (and sibling slots) instead of failing on the dead slot.
  console.log('Testing restored device decrypts messages sealed to its dead device slot...');

  // Sender Alice builds a PreKey message to Device 1's real account.
  const aliceAcc = new Olm.Account();
  aliceAcc.create();
  const aliceIdKeys = JSON.parse(aliceAcc.identity_keys());
  account1.generate_one_time_keys(1);
  const bobOtk = Object.values(JSON.parse(account1.one_time_keys()).curve25519)[0];
  const aliceSess = new Olm.Session();
  aliceSess.create_outbound(aliceAcc, idKeys1.curve25519, bobOtk);
  const secret = 'message sent while the blank device was registered';
  const dev1Cipher = aliceSess.encrypt(secret);

  // A second recipient device slot, sealed to a DEAD blank account (this is
  // what the envelope looked like when the blank device was registered).
  const blankAcc = new Olm.Account();
  blankAcc.create();
  const blankIdKeys = JSON.parse(blankAcc.identity_keys());
  blankAcc.generate_one_time_keys(1);
  const blankOtk = Object.values(JSON.parse(blankAcc.one_time_keys()).curve25519)[0];
  const aliceToBlank = new Olm.Session();
  aliceToBlank.create_outbound(aliceAcc, blankIdKeys.curve25519, blankOtk);
  const deadCipher = aliceToBlank.encrypt('junk for the dead identity');

  const envelope = {
    v: 2,
    sender_device_id: 'alice-dev',
    devices: { dev1: { t: dev1Cipher.type, b: dev1Cipher.body }, dev2: { t: deadCipher.type, b: deadCipher.body } },
    t: dev1Cipher.type,
    b: dev1Cipher.body,
  };

  // Device 1 receives the message; the vault snapshot is taken BEFORE its own
  // decrypt (a consumed ratchet key is not replayable from a later snapshot).
  const bobInbound = new Olm.Session();
  bobInbound.create_inbound(account1, envelope.devices.dev1.b);
  account1.remove_one_time_keys(bobInbound);
  const bobInboundPickle = bobInbound.pickle(PICKLE_KEY);

  // Device 1 decrypts normally (its own slot) on its live copy.
  const d1Live = new Olm.Session();
  d1Live.unpickle(PICKLE_KEY, bobInboundPickle);
  assert.strictEqual(d1Live.decrypt(envelope.devices.dev1.t, envelope.devices.dev1.b), secret);

  // The vault carries Device 1's inbound session; Device 2 restores it.
  backupPayload.sessions = backupPayload.sessions || {};
  backupPayload.sessions['in:2:1:alice-dev'] = bobInboundPickle;
  const restoredInbound = new Olm.Session();
  restoredInbound.unpickle(PICKLE_KEY, backupPayload.sessions['in:2:1:alice-dev']);

  // Device 2's restored identity matches Device 1's, but its device slot in the
  // envelope is sealed to the dead blank identity: that slot alone fails.
  let deadSlotFailed = false;
  try {
    const deadIn = new Olm.Session();
    deadIn.create_inbound(account2, envelope.devices.dev2.b);
  } catch (_) { deadSlotFailed = true; }
  assert.ok(deadSlotFailed, 'the dead device slot cannot be opened by the restored account');

  // Mirror of public/e2ee.js cipherCandidates(e, myDevId): my slot, then t/b,
  // then sibling slots. The ladder tries them in order until one decrypts.
  function cipherCandidates(e, myDevId) {
    const out = [];
    if (!e || e.v !== 2 || !e.devices) {
      if (e && e.t !== undefined && e.b !== undefined) out.push(e);
      return out;
    }
    if (e.devices[myDevId] && e.devices[myDevId].t !== undefined && e.devices[myDevId].b !== undefined) out.push(e.devices[myDevId]);
    if (e.t !== undefined && e.b !== undefined) out.push({ t: e.t, b: e.b });
    Object.keys(e.devices).forEach((k) => {
      const c = e.devices[k];
      if (k !== myDevId && c && c.t !== undefined && c.b !== undefined) out.push(c);
    });
    return out;
  }
  const candidates = cipherCandidates(envelope, 'dev2');
  assert.ok(candidates.length >= 2, 'candidates include the primary t/b cipher beyond the dead slot');
  let plain = null;
  for (const c of candidates) {
    try { plain = restoredInbound.decrypt(c.t, c.b); break; } catch (_) {}
  }
  assert.strictEqual(plain, secret, 'restored device decrypted via cipher-candidate fallback (not the dead slot)');
  console.log('  [OK] Restored device decrypted the message despite its dead device slot in the envelope');

  console.log('\nAll backup & restore verification checks passed successfully.');
}

run().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
