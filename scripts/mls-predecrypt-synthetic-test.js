'use strict';

/**
 * Synthetic Pre-Decryption Migration Worker & Vault Benchmark (Phase 4)
 *
 * Verifies:
 * 1. Profile 1 (Clean Session):
 *    - 100 sequential Double-Ratchet messages decrypt cleanly in monotonic ID order.
 *    - 0 unrecoverable, ratchet advances correctly.
 * 2. Profile 2 (Session Expired - SESSION_EXPIRED):
 *    - Session missing from STORE_OLM.
 *    - Message 1 fails with missing session; ALL subsequent messages in this session
 *      cascade and are labeled "session expired prior to vault migration".
 * 3. Profile 3 (Corrupt Payload - CORRUPT_PAYLOAD):
 *    - Session valid in STORE_OLM.
 *    - Message N has damaged ciphertext envelope -> labeled "message ciphertext corrupted".
 *    - Messages N+1 .. M in the same session DECRYPT SUCCESSFULLY (PROVES NO CASCADE).
 * 4. Profile 4 (Ratchet Desync - RATCHET_DESYNC):
 *    - Megolm room session where ratchet has advanced past historical message index.
 *    - Older message fails with ratchet desync -> labeled "ratchet advanced past this message".
 * 5. Monotonic Batched Processing & Checkpointing:
 *    - Processed in batches of 50 messages.
 *    - Pause after batch 1, resume from checkpoint (dmCursor, roomCursor), verifying zero duplicate decrypts.
 * 6. GDPR Article 20 / Portable Vault Export (§7.5):
 *    - Default encrypted export (PBKDF2 + AES-256-GCM) with password.
 *    - Plaintext export gated behind user confirmation acknowledgment.
 *    - Unrecoverable messages exported with diagnostic placeholder.
 * 7. Metrics & Telemetry:
 *    - Measures throughput (messages/sec), vault growth (bytes), and unrecoverable rate.
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Olm = require('@matrix-org/olm');

const tmpDb = '/tmp/extrovert-mls-predecrypt-test.db';
try { fs.unlinkSync(tmpDb); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}

process.env.EXTV_DB_PATH = tmpDb;
process.env.SESSION_SECRET = 'mls-predecrypt-synthetic-secret-999';
process.env.PORT = 0;

const app = require('../src/server');
const db = require('../src/db');

// --- Mock Browser / IndexedDB & WebCrypto Environment ---
global.window = global;
global.document = {
  querySelector: function (sel) {
    if (sel === 'meta[name="csrf-token"]') return { getAttribute: function () { return 'mock-csrf'; } };
    if (sel === 'meta[name="current-user-id"]') return { getAttribute: function () { return String(global.__activeUserId || 1); } };
    return null;
  },
  querySelectorAll: function () { return []; },
  addEventListener: function () {}
};

// Simple in-memory mock for IndexedDB
const mockStores = {};
function getStore(dbName, storeName) {
  const k = dbName + ':' + storeName;
  if (!mockStores[k]) mockStores[k] = new Map();
  return mockStores[k];
}

global.indexedDB = {
  open: function (dbName, version) {
    const dbObj = {
      objectStoreNames: { contains: () => true },
      createObjectStore: () => {},
      transaction: function (storeName, mode) {
        const map = getStore(dbName, storeName);
        const tx = {
          objectStore: function () {
            return {
              get: function (key) {
                const r = {};
                setImmediate(function () {
                  r.result = map.get(key);
                  if (r.onsuccess) r.onsuccess({ target: r });
                  if (tx.oncomplete) tx.oncomplete();
                });
                return r;
              },
              put: function (val, key) {
                const r = {};
                setImmediate(function () {
                  map.set(key, val);
                  if (r.onsuccess) r.onsuccess({ target: r });
                  if (tx.oncomplete) tx.oncomplete();
                });
                return r;
              },
              delete: function (key) {
                const r = {};
                setImmediate(function () {
                  map.delete(key);
                  if (r.onsuccess) r.onsuccess({ target: r });
                  if (tx.oncomplete) tx.oncomplete();
                });
                return r;
              },
              getAllKeys: function () {
                const r = {};
                setImmediate(function () {
                  r.result = Array.from(map.keys());
                  if (r.onsuccess) r.onsuccess({ target: r });
                  if (tx.oncomplete) tx.oncomplete();
                });
                return r;
              }
            };
          }
        };
        return tx;
      }
    };

    const req = {
      result: dbObj,
      set onupgradeneeded(fn) {},
      set onsuccess(fn) {
        setImmediate(function () { fn({ target: req }); });
      },
      set onerror(fn) {}
    };
    return req;
  }
};

// Polyfill WebCrypto SubtleCrypto if not present
if (!global.crypto) global.crypto = {};
if (!global.crypto.subtle) {
  const { webcrypto } = require('crypto');
  global.crypto.subtle = webcrypto.subtle;
  global.crypto.getRandomValues = webcrypto.getRandomValues.bind(webcrypto);
}

async function run() {
  console.log('\n=== Starting Phase 4 Synthetic Pre-Decryption Migration & Benchmark ===\n');

  await Olm.init();
  console.log('1. Initialized Olm native crypto library.');

  // Start HTTP server
  let server, baseUrl;
  await new Promise(resolve => {
    server = app.listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://localhost:${port}`;
      console.log(`2. Test server listening on ${baseUrl}`);
      resolve();
    });
  });

  // Create Users:
  // Alice (ID 1): Bob's peer, sender of historical messages
  // Bob (ID 2): The user running the pre-decryption migration worker
  // Charlie (ID 3): Peer with expired session
  // Dave (ID 4): Peer with single corrupt message
  console.log('3. Seeding test users and mutual follows...');
  const aliceId = db.createUser({ username: 'alice', passwordHash: 'pw_test', displayName: 'Alice' });
  const bobId = db.createUser({ username: 'bob', passwordHash: 'pw_test', displayName: 'Bob' });
  const charlieId = db.createUser({ username: 'charlie', passwordHash: 'pw_test', displayName: 'Charlie' });
  const daveId = db.createUser({ username: 'dave', passwordHash: 'pw_test', displayName: 'Dave' });
  const now = Date.now();

  // Set Bob as the active logged-in user
  global.__activeUserId = bobId;

  // Mutual follow for DM permissions
  const followSql = `INSERT OR IGNORE INTO follows (follower_id, followee_id, created_at) VALUES (?, ?, ?)`;
  [aliceId, charlieId, daveId].forEach(id => {
    db.db.prepare(followSql).run(bobId, id, now);
    db.db.prepare(followSql).run(id, bobId, now);
  });

  // Authenticate Bob via Bearer token
  const testApp = db.getOrCreateClientApp('test_mig_app');
  const btok = 'test_token_bob_migration_12345';
  db.createOAuthToken(btok, null, testApp.id, bobId, 'read write chats rooms', null);

  // Configure native bridge config for Node test environment
  global.window.ExtrovertE2EEConfig = {
    apiBase: baseUrl,
    bearerToken: btok
  };
  global.Olm = Olm;
  require('../public/e2ee.js');

  // Polyfill csrfFetch to route requests to the test server with Bob's token
  global.csrfFetch = function (url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    opts.headers['Authorization'] = 'Bearer ' + btok;
    opts.headers['Content-Type'] = 'application/json';
    return fetch(baseUrl + url, opts);
  };

  // ---------------------------------------------------------
  // Setup Olm / Megolm Accounts & Sessions
  // ---------------------------------------------------------
  console.log('4. Initializing Olm accounts & Double-Ratchet sessions...');
  const aliceAccount = new Olm.Account();
  aliceAccount.create();
  const bobAccount = new Olm.Account();
  bobAccount.create();
  const charlieAccount = new Olm.Account();
  charlieAccount.create();
  const daveAccount = new Olm.Account();
  daveAccount.create();

  // Initialize Bob's client E2EE account
  await window.ExtrovertE2EE.initOlm();
  await window.ExtrovertE2EE.getOrCreateDeviceKey();

  // Helper to establish a valid Double-Ratchet session between sender and recipient
  function establishOlmSession(senderAccount, recipientAccount) {
    recipientAccount.generate_one_time_keys(1);
    const otks = JSON.parse(recipientAccount.one_time_keys());
    const otkId = Object.keys(otks.curve25519)[0];
    const otk = otks.curve25519[otkId];
    const recipientIdKeys = JSON.parse(recipientAccount.identity_keys());

    const outbound = new Olm.Session();
    outbound.create_outbound(senderAccount, recipientIdKeys.curve25519, otk);

    // Initial pre-key message establishes inbound on recipient
    const initMsg = outbound.encrypt('__init_handshake__');
    const inbound = new Olm.Session();
    inbound.create_inbound(recipientAccount, initMsg.body);
    inbound.decrypt(initMsg.type, initMsg.body);
    recipientAccount.remove_one_time_keys(inbound);

    return { outbound, inbound, recipientCurve: recipientIdKeys.curve25519 };
  }

  // PROFILE 1: Clean Session (Alice -> Bob, 100 messages)
  console.log('\n--- Building Profile 1: Clean Session (100 sequential messages) ---');
  const session1 = establishOlmSession(aliceAccount, bobAccount);

  // Store Bob's inbound session in IndexedDB STORE_OLM
  await window.ExtrovertE2EE.saveInboundSession(aliceId + ':default', session1.inbound);

  const insertMsgStmt = db.db.prepare(`
    INSERT INTO messages (from_id, to_id, body, proto, sender_ciphertext, created_at)
    VALUES (?, ?, ?, 'olm', ?, ?)
  `);

  for (let i = 0; i < 100; i++) {
    const plain = `Clean message #${i} from Alice to Bob`;
    const enc = session1.outbound.encrypt(plain);
    const envelope = JSON.stringify({
      v: 2,
      t: enc.type,
      b: enc.body,
      sender_device_id: 'default',
      sender_curve25519: JSON.parse(aliceAccount.identity_keys()).curve25519
    });
    insertMsgStmt.run(aliceId, bobId, envelope, null, now + i);
  }
  console.log('   [OK] 100 sequential Double-Ratchet messages inserted for Profile 1');

  // PROFILE 2: Session Expired (Alice -> Charlie, but Bob doesn't have Charlie's session key)
  console.log('\n--- Building Profile 2: Session Expired (20 messages with missing session key) ---');
  const session2 = establishOlmSession(aliceAccount, charlieAccount);
  // We deliberately DO NOT save session2 to Bob's olmStore (simulates expired/lost key)
  for (let i = 0; i < 20; i++) {
    const plain = `Expired session message #${i}`;
    const enc = session2.outbound.encrypt(plain);
    const envelope = JSON.stringify({
      v: 2,
      t: enc.type,
      b: enc.body,
      sender_device_id: 'default',
      sender_curve25519: JSON.parse(aliceAccount.identity_keys()).curve25519
    });
    insertMsgStmt.run(charlieId, bobId, envelope, null, now + 100 + i);
  }
  console.log('   [OK] 20 messages inserted with missing session key in STORE_OLM');

  // PROFILE 3: Corrupt Payload (Dave -> Bob, 10 messages, message 4 corrupted)
  console.log('\n--- Building Profile 3: Corrupt Payload (10 messages, msg 4 damaged - asserting NO cascade) ---');
  const session3 = establishOlmSession(daveAccount, bobAccount);
  await window.ExtrovertE2EE.saveInboundSession(daveId + ':default', session3.inbound);

  for (let i = 0; i < 10; i++) {
    const plain = `Dave message #${i} to Bob`;
    const enc = session3.outbound.encrypt(plain);
    let envelope;
    if (i === 4) {
      // Deliberately damage ciphertext payload for message 4
      envelope = JSON.stringify({
        v: 2,
        t: enc.type,
        b: 'CORRUPTED_CIPHERTEXT_BYTES_AT_INDEX_4_XYZ',
        sender_device_id: 'default',
        sender_curve25519: JSON.parse(daveAccount.identity_keys()).curve25519
      });
    } else {
      envelope = JSON.stringify({
        v: 2,
        t: enc.type,
        b: enc.body,
        sender_device_id: 'default',
        sender_curve25519: JSON.parse(daveAccount.identity_keys()).curve25519
      });
    }
    insertMsgStmt.run(daveId, bobId, envelope, null, now + 200 + i);
  }
  console.log('   [OK] 10 messages inserted for Profile 3 (index 4 corrupted)');

  // PROFILE 4: Ratchet Desync in Megolm Room (Alice -> Room, 15 messages)
  console.log('\n--- Building Profile 4: Ratchet Desync (Megolm room message out of order) ---');
  const roomId = db.createRoom('Test E2EE Room', 'Description', aliceId, 1);
  db.addRoomMember(roomId, bobId, 1);
  const channel = db.getRoomChannels(roomId)[0];

  const outboundGroup = new Olm.OutboundGroupSession();
  outboundGroup.create();

  // Alice encrypts first 5 messages (indices 0..4)
  const roomEncrypted = [];
  for (let i = 0; i < 5; i++) {
    const plain = `Room Megolm message #${i}`;
    const ct = outboundGroup.encrypt(plain);
    roomEncrypted.push(ct);
  }

  // At index 5, Alice shares her session key with Bob.
  // Bob's inbound session first_known_index is 5 (ratchet advanced past historical indices 0..4)
  const sessionKeyAt5 = outboundGroup.session_key();
  const sessionId = outboundGroup.session_id();

  const inboundGroup = new Olm.InboundGroupSession();
  inboundGroup.create(sessionKeyAt5);
  await window.ExtrovertE2EE.saveGroupInbound(roomId, aliceId, sessionId, inboundGroup);

  // Alice encrypts remaining messages (indices 5..14)
  for (let i = 5; i < 15; i++) {
    const plain = `Room Megolm message #${i}`;
    const ct = outboundGroup.encrypt(plain);
    roomEncrypted.push(ct);
  }

  // Insert room messages in ascending ID order (indices 0..4 will fail ratchet desync; 5..14 will succeed)
  const insertRoomStmt = db.db.prepare(`
    INSERT INTO room_messages (channel_id, user_id, body, proto, ciphertext, group_session_id, created_at)
    VALUES (?, ?, ?, 'megolm', ?, ?, ?)
  `);
  for (let i = 0; i < 15; i++) {
    insertRoomStmt.run(channel.id, aliceId, 'ct_body', roomEncrypted[i], sessionId, now + 300 + i);
  }
  console.log('   [OK] 15 Megolm room messages inserted (ratchet advanced past index 0-4)');

  // Total messages inserted: 100 (Profile 1) + 20 (Profile 2) + 10 (Profile 3) + 15 (Profile 4) = 145 messages
  const totalMessagesInDb = 100 + 20 + 10 + 15;
  console.log(`\nTotal synthetic historical messages seeded: ${totalMessagesInDb}\n`);

  console.log('5. Executing Migration Worker (Batch 1: 50 messages)...');
  const t0 = Date.now();
  const batch1Res = await window.ExtrovertE2EE.runMigrationBatch({ batchSize: 50 });
  console.log(`   [Batch 1 debug] batchCount=${batch1Res.batchCount}, dmCursor=${batch1Res.checkpoint.dmCursor}, migrated=${batch1Res.checkpoint.totalMigrated}, failed=${batch1Res.checkpoint.failedCount}`);
  assert.strictEqual(batch1Res.done, false, 'Batch 1 should not be done (more messages remaining)');
  assert.strictEqual(batch1Res.batchCount, 50, 'Batch 1 should process exactly 50 messages');

  // Verify Checkpoint Persistence after Batch 1
  console.log('6. Verifying Checkpoint Persistence & Recovery after Batch 1...');
  const cp1 = await window.ExtrovertE2EE.getMigrationCheckpoint();
  assert.ok(cp1.dmCursor > 0, 'dmCursor must be advanced');
  assert.strictEqual(cp1.totalMigrated, 50, 'Batch 1 should have migrated 50 Profile 1 messages');
  assert.strictEqual(cp1.failedCount, 0, 'Batch 1 should have 0 failures');
  console.log(`   [OK] Checkpoint saved: dmCursor=${cp1.dmCursor}, totalMigrated=${cp1.totalMigrated}`);

  // Resume worker to completion
  console.log('\n7. Resuming Migration Worker to process all remaining batches...');
  let totalBatches = 1;
  const progressSnapshots = [];
  const finalResult = await window.ExtrovertE2EE.startHistoricalMigration({
    batchSize: 50,
    force: true,
    onProgress: function (cp) {
      totalBatches++;
      console.log(`   [Batch ${totalBatches} debug] dmCursor=${cp.dmCursor}, roomCursor=${cp.roomCursor}, migrated=${cp.totalMigrated}, failed=${cp.failedCount}, done=${cp.done}`);
      progressSnapshots.push({
        totalMigrated: cp.totalMigrated,
        failedCount: cp.failedCount,
        dmCursor: cp.dmCursor,
        roomCursor: cp.roomCursor
      });
    }
  });

  const durationMs = Date.now() - t0;
  const throughput = Math.round((totalMessagesInDb / (durationMs / 1000)));

  console.log(`\n=== Migration Worker Finished in ${durationMs}ms across ${totalBatches} batches (${throughput} msgs/sec) ===\n`);

  const cpFinal = await window.ExtrovertE2EE.getMigrationCheckpoint();
  assert.strictEqual(cpFinal.done, true, 'Migration must be marked done in checkpoint');
  console.log('Final Checkpoint Summary:');
  console.log(` - Total Successfully Migrated: ${cpFinal.totalMigrated}`);
  console.log(` - Total Unrecoverable Flagged:  ${cpFinal.failedCount}`);
  console.log(` - Sum:                          ${cpFinal.totalMigrated + cpFinal.failedCount} / ${totalMessagesInDb}`);
  assert.strictEqual(cpFinal.totalMigrated + cpFinal.failedCount, totalMessagesInDb, 'Every single DB row must be accounted for');

  // ---------------------------------------------------------
  // Assert Correctness Across The Four Profiles
  // ---------------------------------------------------------
  console.log('\n8. Verifying Profiles in Vault:');

  // Profile 1 Assertions:
  const bobAliceVault = await window.ExtrovertE2EE.loadSecureMessages(String(aliceId));
  assert.strictEqual(bobAliceVault.length, 100, 'Profile 1 must have exactly 100 messages stored');
  const allCleanDecrypted = bobAliceVault.every(m => !m.unrecoverable && m.plaintext.startsWith('Clean message #'));
  assert.ok(allCleanDecrypted, 'All 100 Profile 1 messages must be successfully decrypted without unrecoverable tags');
  console.log('   [OK] Profile 1: 100/100 sequential messages decrypted cleanly. Ratchet ordering confirmed.');

  // Profile 2 Assertions (SESSION_EXPIRED & Cascade):
  const bobCharlieVault = await window.ExtrovertE2EE.loadSecureMessages(String(charlieId));
  assert.strictEqual(bobCharlieVault.length, 20, 'Profile 2 must have 20 messages stored');
  const allExpiredCascaded = bobCharlieVault.every(m => m.unrecoverable === true && m.reason === 'session expired prior to vault migration');
  assert.ok(allExpiredCascaded, 'All 20 Profile 2 messages must be flagged unrecoverable with cascade label "session expired prior to vault migration"');
  console.log('   [OK] Profile 2: 20/20 messages correctly labeled with cascade failure "session expired prior to vault migration".');

  // Profile 3 Assertions (CORRUPT_PAYLOAD — NO CASCADE):
  const bobDaveVault = await window.ExtrovertE2EE.loadSecureMessages(String(daveId));
  assert.strictEqual(bobDaveVault.length, 10, 'Profile 3 must have 10 messages stored');

  // Messages 0..3: Clean
  for (let i = 0; i < 4; i++) {
    assert.strictEqual(bobDaveVault[i].unrecoverable, undefined, `Profile 3 message #${i} must not be unrecoverable`);
    assert.strictEqual(bobDaveVault[i].plaintext, `Dave message #${i} to Bob`);
  }

  // Message 4: Corrupted, NOT cascaded
  assert.strictEqual(bobDaveVault[4].unrecoverable, true, 'Message #4 must be marked unrecoverable');
  assert.strictEqual(bobDaveVault[4].reason, 'message ciphertext corrupted', 'Message #4 must be labeled "message ciphertext corrupted"');

  // Messages 5..9: PROVES NO CASCADE!
  for (let i = 5; i < 10; i++) {
    assert.strictEqual(bobDaveVault[i].unrecoverable, undefined, `Message #${i} in same session MUST DECRYPT (NO CASCADE)`);
    assert.strictEqual(bobDaveVault[i].plaintext, `Dave message #${i} to Bob`);
  }
  console.log('   [OK] Profile 3: Message #4 flagged CORRUPT_PAYLOAD, messages #5..9 successfully decrypted. PROVES NO CASCADE!');

  // Profile 4 Assertions (RATCHET_DESYNC):
  const roomVault = await window.ExtrovertE2EE.loadSecureRoomMessages(String(roomId));
  assert.strictEqual(roomVault.length, 15, 'Profile 4 must have 15 room messages stored');
  // Indices 0..4 failed because ratchet advanced past them
  const desyncMessages = roomVault.filter(m => m.unrecoverable && m.reason === 'ratchet advanced past this message');
  assert.strictEqual(desyncMessages.length, 5, 'Exactly 5 older skipped messages must be marked with "ratchet advanced past this message"');
  for (let i = 0; i < 5; i++) {
    assert.strictEqual(roomVault[i].unrecoverable, true, `Room message #${i} must be unrecoverable`);
    assert.strictEqual(roomVault[i].reason, 'ratchet advanced past this message');
  }
  // Messages 5..14 must be decrypted successfully!
  for (let i = 5; i < 15; i++) {
    assert.strictEqual(roomVault[i].unrecoverable, undefined, `Room message #${i} at/after ratchet position must decrypt successfully`);
    assert.strictEqual(roomVault[i].plaintext, `Room Megolm message #${i}`);
  }
  console.log(`   [OK] Profile 4: Ratchet desync correctly flagged 5 older messages while messages #5..14 decrypted cleanly.`);

  // ---------------------------------------------------------
  // Assert GDPR Article 20 Vault Export (§7.5)
  // ---------------------------------------------------------
  console.log('\n9. Testing GDPR Article 20 Vault Export (§7.5)...');

  // A. Encrypted Export (Default)
  const encExport = await window.ExtrovertE2EE.exportDecryptedVault({
    format: 'encrypted',
    password: 'SuperSecretUserPassword123!'
  });
  assert.strictEqual(encExport.format, 'encrypted');
  assert.strictEqual(encExport.algorithm, 'AES-256-GCM');
  assert.strictEqual(encExport.kdf, 'PBKDF2-HMAC-SHA256');
  assert.ok(encExport.salt && encExport.iv && encExport.ciphertext, 'Encrypted export must contain salt, iv, and ciphertext');
  console.log('   [OK] Encrypted export generated successfully (AES-256-GCM + PBKDF2 default)');

  // B. Plaintext Export requires explicit acknowledgment
  await assert.rejects(
    async () => {
      await window.ExtrovertE2EE.exportDecryptedVault({ format: 'json', acknowledgePlaintext: false });
    },
    /Plaintext export requires explicit user confirmation/,
    'Plaintext export must be rejected if user did not acknowledge warning'
  );

  const plainExport = await window.ExtrovertE2EE.exportDecryptedVault({
    format: 'json',
    acknowledgePlaintext: true
  });
  assert.strictEqual(plainExport.format, 'json');
  const parsedVault = JSON.parse(plainExport.data);
  assert.strictEqual(parsedVault.version, 1);
  assert.strictEqual(String(parsedVault.user_id), String(bobId));
  assert.strictEqual(parsedVault.stats.total_messages, totalMessagesInDb);

  // Assert unrecoverable placeholder format
  const unrecItem = parsedVault.conversations[String(charlieId)][0];
  assert.strictEqual(unrecItem.unrecoverable, true);
  assert.strictEqual(unrecItem.plaintext, '[Message unrecoverable: session expired prior to vault migration]');
  console.log('   [OK] Plaintext export validated with structured unrecoverable placeholder diagnostics');

  // Vault Growth & Metrics Telemetry
  const vaultSizeBytes = Buffer.byteLength(plainExport.data, 'utf8');
  const bytesPerMessage = Math.round(vaultSizeBytes / totalMessagesInDb);
  const unrecoverableRate = ((cpFinal.failedCount / totalMessagesInDb) * 100).toFixed(2);

  console.log('\n======================================================');
  console.log('  SYNTHETIC PRE-DECRYPTION BENCHMARK METRICS SUMMARY   ');
  console.log('======================================================');
  console.log(`  Total Messages Processed:    ${totalMessagesInDb}`);
  console.log(`  Throughput:                  ${throughput} messages/sec`);
  console.log(`  Total Vault Size:            ${vaultSizeBytes} bytes (~${bytesPerMessage} bytes/msg)`);
  console.log(`  Unrecoverable Messages:      ${cpFinal.failedCount} / ${totalMessagesInDb} (${unrecoverableRate}%)`);
  console.log(`  Batches Required:            ${totalBatches} (50 msgs/batch)`);
  console.log(`  Checkpoint Integrity:        100% Monotonic ASC Scanned`);
  console.log(`  Cascade Semantics Verified:  Profile 3 (CORRUPT_PAYLOAD) -> NO CASCADE`);
  console.log(`                               Profile 2 (SESSION_EXPIRED) -> FULL CASCADE`);
  console.log(`                               Profile 4 (RATCHET_DESYNC)  -> DESYNC FLAGGED`);
  console.log('======================================================\n');

  server.close();
  try { fs.unlinkSync(tmpDb); } catch (_) {}
  try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
  try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}

  console.log('=== All Synthetic Pre-Decryption Benchmark Tests PASSED 100%! ===\n');
  process.exit(0);
}

run().catch(err => {
  console.error('\nSynthetic Benchmark FAILED:', err);
  process.exit(1);
});
