'use strict';
// Full lifecycle test for Extrovert E2EE
// Tests consecutive PreKey messages (t=0 series), two-way turns with DH ratchet advancements,
// history reloads on both sides, multi-device chain transitions, and Megolm room key exchanges.
// Run: node scripts/e2ee-full-lifecycle-test.js

const fs = require('fs');
const path = require('path');
const Olm = require('@matrix-org/olm');

const wasmPath = path.join(path.dirname(require.resolve('@matrix-org/olm/package.json')), 'olm.wasm');
const PICKLE_KEY = 'test-pickle-key';

let failures = 0;
function ok(cond, msg) {
  console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg);
  if (!cond) failures++;
}

async function main() {
  await Olm.init({ wasmBinary: fs.readFileSync(wasmPath) });

  const newAccount = () => {
    const a = new Olm.Account();
    a.create();
    a.generate_one_time_keys(10);
    return a;
  };

  console.log('\nTEST 1: Consecutive PreKey messages without reply (t=0 series)');
  const alice = newAccount();
  const bob = newAccount();
  const bobId = JSON.parse(bob.identity_keys());
  const bobOtks = JSON.parse(bob.one_time_keys());
  const bobOtk1 = Object.values(bobOtks.curve25519)[0];

  const aOut = new Olm.Session();
  aOut.create_outbound(alice, bobId.curve25519, bobOtk1);
  const aBaselinePickle = aOut.pickle(PICKLE_KEY);

  const m1 = aOut.encrypt('Alice msg 1');
  const m2 = aOut.encrypt('Alice msg 2');
  const m3 = aOut.encrypt('Alice msg 3');

  ok(m1.type === 0, 'm1 is type 0 (PreKey)');
  ok(m2.type === 0, 'm2 is type 0 (PreKey)');
  ok(m3.type === 0, 'm3 is type 0 (PreKey)');

  // Bob decrypt logic mimicking e2ee.js
  let bobBaselinePickle = null;
  let bobBaseline = null;
  let bobLive = null;
  const bobLocalMsgs = {};

  function bobDecrypt(msg) {
    if (bobLocalMsgs[msg.body]) return bobLocalMsgs[msg.body];
    if (bobBaseline && bobBaseline.matches_inbound(msg.body)) {
      const p = bobBaseline.decrypt(msg.type, msg.body);
      bobLocalMsgs[msg.body] = p;
      return p;
    }
    if (bobLive && bobLive.matches_inbound(msg.body)) {
      const p = bobLive.decrypt(msg.type, msg.body);
      bobLocalMsgs[msg.body] = p;
      return p;
    }
    if (msg.type === 0) {
      const ns = new Olm.Session();
      try {
        ns.create_inbound(bob, msg.body);
        bob.remove_one_time_keys(ns);
        bobBaselinePickle = ns.pickle(PICKLE_KEY);
        bobBaseline = ns;
        bobLive = ns;
        const p = ns.decrypt(msg.type, msg.body);
        bobLocalMsgs[msg.body] = p;
        return p;
      } catch (e) {
        if (bobBaseline) return bobBaseline.decrypt(msg.type, msg.body);
        if (bobLive) return bobLive.decrypt(msg.type, msg.body);
        throw e;
      }
    }
    if (bobBaseline) return bobBaseline.decrypt(msg.type, msg.body);
    if (bobLive) return bobLive.decrypt(msg.type, msg.body);
    throw new Error('Cannot decrypt');
  }

  ok(bobDecrypt(m1) === 'Alice msg 1', 'Bob decrypts m1');
  ok(bobDecrypt(m2) === 'Alice msg 2', 'Bob decrypts m2 (t=0 from same chain without BAD_MESSAGE_KEY_ID)');
  ok(bobDecrypt(m3) === 'Alice msg 3', 'Bob decrypts m3 (t=0 from same chain)');

  console.log('\nTEST 2: Bob reloads chat page and replays history');
  // Reset in-memory session from baseline pickle
  bobBaseline = new Olm.Session();
  bobBaseline.unpickle(PICKLE_KEY, bobBaselinePickle);
  // Clear local cache to verify cryptographic replay
  Object.keys(bobLocalMsgs).forEach(k => delete bobLocalMsgs[k]);

  ok(bobDecrypt(m1) === 'Alice msg 1', 'Bob replay m1 from baseline');
  ok(bobDecrypt(m2) === 'Alice msg 2', 'Bob replay m2 from baseline');
  ok(bobDecrypt(m3) === 'Alice msg 3', 'Bob replay m3 from baseline');

  console.log('\nTEST 3: Bob replies (advancing DH ratchet) and Alice decrypts');
  const r1 = bobLive.encrypt('Bob reply 1');
  const r2 = bobLive.encrypt('Bob reply 2');
  ok(r1.type === 1, 'r1 is type 1 (established session)');

  ok(aOut.decrypt(r1.type, r1.body) === 'Bob reply 1', 'Alice decrypts r1');
  ok(aOut.decrypt(r2.type, r2.body) === 'Bob reply 2', 'Alice decrypts r2');

  console.log('\nTEST 4: Alice self-session for own sent messages');
  const aliceSelfKeys = JSON.parse(alice.identity_keys());
  alice.generate_one_time_keys(1);
  const aliceSelfOtks = JSON.parse(alice.one_time_keys());
  const aSelfOtk = Object.values(aliceSelfOtks.curve25519)[0];

  const aSelfOut = new Olm.Session();
  aSelfOut.create_outbound(alice, aliceSelfKeys.curve25519, aSelfOtk);
  const aSelfInit = aSelfOut.encrypt('__init__');
  const aSelfIn = new Olm.Session();
  aSelfIn.create_inbound(alice, aSelfInit.body);
  alice.remove_one_time_keys(aSelfIn);
  const aSelfInBaseline = aSelfIn.pickle(PICKLE_KEY);

  const own1 = aSelfOut.encrypt('Alice msg 1');
  const own2 = aSelfOut.encrypt('Alice msg 2');
  const own3 = aSelfOut.encrypt('Alice msg 3');

  ok(aSelfIn.decrypt(own1.type, own1.body) === 'Alice msg 1', 'Alice reads own 1');
  ok(aSelfIn.decrypt(own2.type, own2.body) === 'Alice msg 2', 'Alice reads own 2');
  ok(aSelfIn.decrypt(own3.type, own3.body) === 'Alice msg 3', 'Alice reads own 3');

  // Reload self-session from baseline
  const aSelfInReloaded = new Olm.Session();
  aSelfInReloaded.unpickle(PICKLE_KEY, aSelfInBaseline);
  ok(aSelfInReloaded.decrypt(own1.type, own1.body) === 'Alice msg 1', 'Alice reads own 1 after reload');
  ok(aSelfInReloaded.decrypt(own2.type, own2.body) === 'Alice msg 2', 'Alice reads own 2 after reload');
  ok(aSelfInReloaded.decrypt(own3.type, own3.body) === 'Alice msg 3', 'Alice reads own 3 after reload');

  console.log('\nTEST 5: Two-way multi-turn conversation and message 4');
  const m4 = aOut.encrypt('Alice msg 4');
  ok(bobLive.decrypt(m4.type, m4.body) === 'Alice msg 4', 'Bob decrypts post-reply m4 with live session');

  console.log('\nTEST 6: Room Megolm session key exchange with matches_inbound');
  const carol = newAccount();
  const carolId = JSON.parse(carol.identity_keys());
  const carolOtks = JSON.parse(carol.one_time_keys());
  const carolOtk = Object.values(carolOtks.curve25519)[0];

  // Alice room Megolm outbound session
  const roomOut = new Olm.OutboundGroupSession();
  roomOut.create();
  const roomSessionKey = roomOut.session_key();

  // Alice shares to Bob using 1:1 Olm session
  const a2bRoom = new Olm.Session();
  a2bRoom.create_outbound(alice, bobId.curve25519, Object.values(JSON.parse(bob.one_time_keys()).curve25519)[0] || bobOtk1);
  const encKeyForBob = a2bRoom.encrypt(roomSessionKey);

  // Bob imports room key
  let bRoom1to1 = new Olm.Session();
  bRoom1to1.create_inbound(bob, encKeyForBob.body);
  bob.remove_one_time_keys(bRoom1to1);
  const recoveredSessionKey = bRoom1to1.decrypt(encKeyForBob.type, encKeyForBob.body);
  ok(recoveredSessionKey === roomSessionKey, 'Bob recovers room session key');

  const bobRoomIn = new Olm.InboundGroupSession();
  bobRoomIn.create(recoveredSessionKey);

  const roomMsg1 = roomOut.encrypt('Welcome to the room!');
  const decRes = bobRoomIn.decrypt(roomMsg1);
  ok(decRes && decRes.plaintext === 'Welcome to the room!', 'Bob decrypts Megolm room message');

  // Alice sends another room key update on same 1:1 session (encKey2 is type 0 or 1)
  const encKey2 = a2bRoom.encrypt('rotated-key');
  if (bRoom1to1.matches_inbound(encKey2.body)) {
    const rec2 = bRoom1to1.decrypt(encKey2.type, encKey2.body);
    ok(rec2 === 'rotated-key', 'Bob decrypts subsequent room key using matches_inbound without error');
  } else {
    ok(false, 'bRoom1to1 should match inbound');
  }

  [alice, bob, carol, aOut, aSelfOut, aSelfIn, aSelfInReloaded, roomOut, bobRoomIn].forEach(o => {
    try { if (o && o.free) o.free(); } catch (_) {}
  });

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL FULL LIFECYCLE TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
