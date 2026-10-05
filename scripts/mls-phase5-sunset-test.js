'use strict';

/**
 * Phase 5 Sunset & Decommissioning Preparation Verification Suite
 *
 * Verifies:
 * 1. Feature Flag (E2EE_LEGACY_ENABLED):
 *    - Defaults to true. When false, Olm crypto initialization is skipped.
 * 2. Dynamic Activity Anchor & State Machine (§7.3):
 *    - LegacyActive -> CoexistenceAndMigrating -> RetentionWindow -> PurgeEligible.
 *    - Gate 1: now - max(firstMlsSessionAt, lastLegacyActivityAt) >= 180 days.
 *    - Gate 2: hasCompletedFullScan === true.
 *    - Offline device safety: 200 days elapsed with hasCompletedFullScan === false remains purgeEligible: false!
 *    - Late legacy activity reset: legacy message received resets the 180-day clock.
 * 3. Privacy-Preserving Migration Telemetry:
 *    - POST /mls/migration/status enforces coarse buckets: "0", "1-10", "11-100", "100+".
 *    - Rejects raw or invalid count formats with 400.
 *    - Aggregates fleet migration coverage without exposing device IDs.
 * 4. Server-Side Traffic Sunset Instrumentation (Criterion 2):
 *    - Increments daily counters for proto_mls and proto_legacy on message creation.
 *    - GET /mls/migration/fleet-summary computes consecutive zero-legacy days and sunset eligibility.
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');

const tmpDb = '/tmp/extrovert-mls-phase5-test.db';
try { fs.unlinkSync(tmpDb); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}

process.env.EXTV_DB_PATH = tmpDb;
process.env.SESSION_SECRET = 'mls-phase5-test-secret-123';
process.env.PORT = 0;

const app = require('../src/server');
const db = require('../src/db');

// Mock Browser Environment
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

// In-memory mock IndexedDB
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
              },
              clear: function () {
                const r = {};
                setImmediate(function () {
                  map.clear();
                  if (r.onsuccess) r.onsuccess({ target: r });
                  if (tx.oncomplete) tx.oncomplete();
                });
                return r;
              },
              openCursor: function () {
                const r = {};
                const keys = Array.from(map.keys());
                let idx = 0;
                function advance() {
                  if (idx >= keys.length) {
                    r.result = null;
                    if (r.onsuccess) r.onsuccess({ target: r });
                    if (tx.oncomplete) tx.oncomplete();
                    return;
                  }
                  const k = keys[idx++];
                  r.result = {
                    key: k,
                    value: map.get(k),
                    delete: function () { map.delete(k); },
                    continue: function () { setImmediate(advance); }
                  };
                  if (r.onsuccess) r.onsuccess({ target: r });
                }
                setImmediate(advance);
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

if (!global.crypto) global.crypto = {};
if (!global.crypto.subtle) {
  const { webcrypto } = require('crypto');
  global.crypto.subtle = webcrypto.subtle;
  global.crypto.getRandomValues = webcrypto.getRandomValues.bind(webcrypto);
}

async function run() {
  console.log('\n=== Starting Phase 5 Sunset & Decommissioning Preparation Test ===\n');

  let server, baseUrl;
  await new Promise(resolve => {
    server = app.listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://localhost:${port}`;
      console.log(`1. Test server listening on ${baseUrl}`);
      resolve();
    });
  });

  const aliceId = db.createUser({ username: 'alice_p5', passwordHash: 'pw_test', displayName: 'Alice' });
  const bobId = db.createUser({ username: 'bob_p5', passwordHash: 'pw_test', displayName: 'Bob' });
  global.__activeUserId = aliceId;

  const testApp = db.getOrCreateClientApp('test_p5_app');
  const btok = 'test_token_p5_12345';
  db.createOAuthToken(btok, null, testApp.id, aliceId, 'read write chats rooms', null);

  global.window.ExtrovertE2EEConfig = { apiBase: baseUrl, bearerToken: btok };
  require('../public/e2ee.js');

  global.csrfFetch = function (url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    opts.headers['Authorization'] = 'Bearer ' + btok;
    opts.headers['Content-Type'] = 'application/json';
    return fetch(baseUrl + url, opts);
  };

  // -------------------------------------------------------------
  // Test 1: Feature Flag (E2EE_LEGACY_ENABLED)
  // -------------------------------------------------------------
  console.log('2. Testing Feature Flag (E2EE_LEGACY_ENABLED)...');
  assert.strictEqual(window.ExtrovertE2EE.legacyEnabled(), true, 'Legacy E2EE must be enabled by default');

  // Verify disabling flag skips Olm
  window.ExtrovertConfig = { legacyE2eeEnabled: false };
  assert.strictEqual(window.ExtrovertE2EE.legacyEnabled(), false);
  const disabledInit = await window.ExtrovertE2EE.initOlm();
  assert.strictEqual(disabledInit, false, 'initOlm must resolve false immediately when legacy flag is false');
  // Restore default enabled
  window.ExtrovertConfig = { legacyE2eeEnabled: true };
  assert.strictEqual(window.ExtrovertE2EE.legacyEnabled(), true);
  console.log('   [OK] Feature flag legacyEnabled validated (default true; kill-switch functional)');

  // -------------------------------------------------------------
  // Test 2: Client Dynamic Activity Anchor & State Machine (§7.3)
  // -------------------------------------------------------------
  console.log('\n3. Testing Client Dynamic Activity Anchor & State Machine (§7.3)...');

  // Case A: Fresh device, no MLS session yet -> LegacyActive
  const secureStore = getStore('extrovert-e2ee', 'securemsgs');
  secureStore.clear();

  let status = await window.ExtrovertE2EE.getLegacyLifecycleStatus();
  assert.strictEqual(status.state, 'LegacyActive');
  assert.strictEqual(status.purgeEligible, false, 'Fresh device must not be purge eligible');
  console.log('   [OK] State 1: LegacyActive verified (no MLS session registered)');

  // Case B: First MLS session recorded, but migration NOT complete -> CoexistenceAndMigrating
  const now = Date.now();
  secureStore.set('first_mls_session_at', now);
  status = await window.ExtrovertE2EE.getLegacyLifecycleStatus();
  assert.strictEqual(status.state, 'CoexistenceAndMigrating');
  assert.strictEqual(status.purgeEligible, false, 'Unmigrated device must not be purge eligible');
  console.log('   [OK] State 2: CoexistenceAndMigrating verified (MLS active, migration incomplete)');

  // Case C: Offline-Device Safety Test!
  // User went offline for 200 days, but NEVER completed full migration scan!
  const DAY_MS = 86400 * 1000;
  secureStore.set('first_mls_session_at', now - (200 * DAY_MS));
  // checkpoint still hasCompletedFullScan === false
  status = await window.ExtrovertE2EE.getLegacyLifecycleStatus();
  assert.strictEqual(status.hasCompletedFullScan, false);
  assert.strictEqual(status.purgeEligible, false, 'CRITICAL: Offline device >180 days WITHOUT migration MUST NOT PURGE!');
  console.log('   [OK] Offline-Device Safety: 200 days elapsed with unmigrated vault remains purgeEligible: false');

  // Case D: Migration completes (hasCompletedFullScan: true), but 180 days have NOT elapsed -> RetentionWindow
  await window.ExtrovertE2EE.getOrCreateDeviceKey();
  await window.ExtrovertE2EE.saveMigrationCheckpoint({
    dmCursor: 100,
    roomCursor: 50,
    totalMigrated: 150,
    failedCount: 0,
    hasCompletedFullScan: true,
    done: true
  });
  secureStore.set('first_mls_session_at', now - (10 * DAY_MS)); // 10 days ago
  status = await window.ExtrovertE2EE.getLegacyLifecycleStatus();
  assert.strictEqual(status.state, 'RetentionWindow');
  assert.strictEqual(status.purgeEligible, false, 'RetentionWindow must not be purge eligible before 180 days');
  console.log('   [OK] State 3: RetentionWindow verified (migration complete, 180-day clock ticking)');

  // Case E: Late Legacy Activity Clock Reset!
  // 185 days since first MLS, BUT a legacy message was received 5 days ago!
  secureStore.set('first_mls_session_at', now - (185 * DAY_MS));
  secureStore.set('last_legacy_activity_at', now - (5 * DAY_MS)); // activity 5 days ago
  status = await window.ExtrovertE2EE.getLegacyLifecycleStatus();
  assert.strictEqual(status.state, 'RetentionWindow');
  assert.strictEqual(status.purgeEligible, false, 'Recent legacy activity resets 180-day clock and blocks purge!');
  console.log('   [OK] Dynamic Activity Anchor: Legacy activity at day 180 resets clock, preventing purge');

  // Case F: Both Gates Met -> PurgeEligible!
  // 181 days since BOTH first MLS and last legacy activity, and migration complete!
  secureStore.set('first_mls_session_at', now - (185 * DAY_MS));
  secureStore.set('last_legacy_activity_at', now - (181 * DAY_MS));
  status = await window.ExtrovertE2EE.getLegacyLifecycleStatus();
  assert.strictEqual(status.state, 'PurgeEligible');
  assert.strictEqual(status.purgeEligible, true, 'Device meeting both time anchor and migration scan is PurgeEligible');
  console.log('   [OK] State 4: PurgeEligible verified (Gate 1 time + Gate 2 migration complete)');

  // Case G: Purge Legacy Sessions -> Terminal State OlmPurged!
  await window.ExtrovertE2EE.purgeLegacySessions();
  status = await window.ExtrovertE2EE.getLegacyLifecycleStatus();
  assert.strictEqual(status.state, 'OlmPurged', 'Must transition to terminal OlmPurged state after purge');
  assert.ok(status.olmPurgedAt > 0, 'olmPurgedAt must be recorded in secure store');
  assert.strictEqual(window.ExtrovertE2EE.isOlmPurged(), true);

  // Terminal state behavior: inbound legacy messages return placeholder and never reload WASM
  const olmPlaceholder = await window.ExtrovertE2EE.decryptDm({ body: '{"v":1,"ciphertext":"abc"}' }, false, '2', 'testkey');
  assert.strictEqual(olmPlaceholder, '[Legacy message — encryption retired]', 'In OlmPurged, legacy DM decrypt must return retired placeholder');
  const megolmPlaceholder = await window.ExtrovertE2EE.decryptRoomMessage('room-1', '2', 'ciphertext-xyz', 'group-sess-1');
  assert.strictEqual(megolmPlaceholder, '[Legacy message — encryption retired]', 'In OlmPurged, legacy room decrypt must return retired placeholder');
  const olmInitRet = await window.ExtrovertE2EE.initOlm();
  assert.strictEqual(olmInitRet, false, 'In OlmPurged, initOlm must not attempt to reload WASM');
  console.log('   [OK] State 5: Terminal OlmPurged verified (undecryptable legacy shows "[Legacy message — encryption retired]")');

  // -------------------------------------------------------------
  // Test 3: Privacy-Preserving Migration Telemetry
  // -------------------------------------------------------------
  console.log('\n4. Testing Privacy-Preserving Migration Telemetry...');

  // A. Rejects invalid or unbucketed telemetry
  const badRes = await fetch(baseUrl + '/mls/migration/status', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + btok, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      has_completed_full_scan: true,
      total_migrated: 100,
      unrecoverable_count_bucket: 'EXACT_COUNT_5' // Invalid! Must be coarse bucket
    })
  });
  assert.strictEqual(badRes.status, 400, 'Server must reject unbucketed unrecoverable counts');

  // B. Accepts valid coarse bucket ("0", "1-10", "11-100", "100+")
  const goodRes = await fetch(baseUrl + '/mls/migration/status', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + btok, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      has_completed_full_scan: true,
      total_migrated: 250,
      unrecoverable_count_bucket: '1-10',
      blocked_by_policy: false
    })
  });
  assert.strictEqual(goodRes.status, 200, 'Valid bucket telemetry must be accepted with 200');

  // C. Client helper reportMigrationStatus()
  const clientReportRes = await window.ExtrovertE2EE.reportMigrationStatus();
  assert.strictEqual(clientReportRes.ok, true, 'Client reportMigrationStatus helper must succeed');
  console.log('   [OK] Privacy-preserving bucket reporting validated (0, 1-10, 11-100, 100+)');

  // -------------------------------------------------------------
  // Test 4: Server-Side Traffic Sunset Instrumentation (Criterion 2)
  // -------------------------------------------------------------
  console.log('\n5. Testing Server-Side Traffic Sunset Instrumentation...');

  // Record live traffic via sendMessage and sendRoomMessage
  db.sendMessage(aliceId, bobId, 'Hello MLS DM', null, null, 'mls', null);
  db.sendMessage(aliceId, bobId, 'Legacy Olm DM', null, null, 'olm', null);

  const initialSunset = db.getLegacyTrafficSunsetStatus();
  assert.strictEqual(initialSunset.consecutive_zero_legacy_days, 0, 'Cannot be zero days while legacy traffic exists today');
  assert.strictEqual(initialSunset.sunset_eligible, false, 'Sunset cannot be eligible while legacy traffic is recorded');

  // Simulate 30 consecutive days of zero legacy traffic in database
  const todayDate = new Date();
  for (let i = 1; i <= 30; i++) {
    const d = new Date(todayDate.getTime() - (i * DAY_MS)).toISOString().slice(0, 10);
    db.db.prepare(`
      INSERT INTO mls_traffic_stats (date, proto_mls, proto_legacy)
      VALUES (?, 100, 0)
      ON CONFLICT(date) DO UPDATE SET proto_mls = 100, proto_legacy = 0
    `).run(d);
  }

  // Clear today's legacy counter to simulate Day 30 complete sunset
  const todayStr = todayDate.toISOString().slice(0, 10);
  db.db.prepare(`UPDATE mls_traffic_stats SET proto_legacy = 0 WHERE date = ?`).run(todayStr);

  const sunsetCheck = db.getLegacyTrafficSunsetStatus();
  assert.ok(sunsetCheck.consecutive_zero_legacy_days >= 30, 'Must record >= 30 consecutive days of zero legacy traffic');
  assert.strictEqual(sunsetCheck.sunset_eligible, true, 'Criterion 2 must be satisfied after 30 days zero legacy');
  console.log(`   [OK] Traffic Sunset Criteria: ${sunsetCheck.consecutive_zero_legacy_days} consecutive zero-legacy days verified (sunset_eligible: true)`);

  // -------------------------------------------------------------
  // Test 5: Multi-Criteria Fleet Telemetry & Sunset Gating
  // -------------------------------------------------------------
  console.log('\n6. Testing Multi-Criteria Fleet Telemetry & Config Transport...');

  // Verify GET /mls/config endpoint
  const cfgRes = await fetch(baseUrl + '/mls/config');
  const cfgJson = await cfgRes.json();
  assert.strictEqual(cfgJson.ok, true);
  assert.strictEqual(cfgJson.legacy_e2ee_enabled, true, 'Legacy E2EE enabled by default');
  assert.ok(cfgJson.migration_start_date, 'migration_start_date must be provided');
  assert.ok(cfgJson.sunset_cutoff_date, 'sunset_cutoff_date must be provided');
  assert.ok(cfgJson.days_remaining_to_cutoff > 0, 'days_remaining_to_cutoff must be positive');
  console.log(`   [OK] GET /mls/config transport verified (legacy_e2ee_enabled=${cfgJson.legacy_e2ee_enabled}, ${cfgJson.days_remaining_to_cutoff} days remaining)`);

  // Verify GET /mls/migration/fleet-summary sub-criteria structure
  const fleetRes = await fetch(baseUrl + '/mls/migration/fleet-summary', {
    headers: { 'Authorization': 'Bearer ' + btok }
  });
  const fleetJson = await fleetRes.json();
  assert.strictEqual(fleetJson.ok, true);
  assert.strictEqual(fleetJson.traffic_sunset.ready, true, 'Traffic sunset sub-criterion is ready');
  assert.strictEqual(fleetJson.fleet_migration.ready, false, 'Fleet migration sub-criterion not ready (<100% users)');
  assert.strictEqual(fleetJson.all_criteria_met, false, 'all_criteria_met MUST be false when fleet coverage is incomplete');
  assert.strictEqual(fleetJson.force_sunset_active, false, 'force_sunset_active is false');
  console.log(`   [OK] Fleet Migration Summary sub-criteria verified: traffic_ready=${fleetJson.traffic_sunset.ready}, fleet_ready=${fleetJson.fleet_migration.ready}, all_criteria_met=${fleetJson.all_criteria_met}`);

  // -------------------------------------------------------------
  // Test 6: Operator Safety Guard & Audit for MLS_FORCE_SUNSET
  // -------------------------------------------------------------
  console.log('\n7. Testing Operator Safety & Audit for MLS_FORCE_SUNSET...');

  process.env.E2EE_LEGACY_ENABLED = 'false';
  process.env.MLS_FORCE_SUNSET = 'true';
  process.env.MLS_FORCE_SUNSET_OPERATOR = 'ops-oncall@extrovert.eu';
  // Without MLS_FORCE_SUNSET_ACK, safety guard must prevent sunset!
  delete process.env.MLS_FORCE_SUNSET_ACK;
  assert.strictEqual(db.isLegacyE2eeEnabled(), true, 'Safety Guard: without MLS_FORCE_SUNSET_ACK="I_ACCEPT_DATA_LOSS", legacy MUST remain enabled!');

  // With MLS_FORCE_SUNSET_ACK, force sunset engages and records audit
  process.env.MLS_FORCE_SUNSET_ACK = 'I_ACCEPT_DATA_LOSS';
  assert.strictEqual(db.isLegacyE2eeEnabled(), false, 'Force Sunset engages when explicit ACK is provided');

  const auditEntry = db.db.prepare(`SELECT * FROM mls_sunset_audit WHERE event = 'force_sunset_engaged'`).get();
  assert.ok(auditEntry, 'Audit record MUST be inserted into mls_sunset_audit');
  assert.strictEqual(auditEntry.acknowledged_by, 'I_ACCEPT_DATA_LOSS');
  assert.strictEqual(auditEntry.operator_name, 'ops-oncall@extrovert.eu');
  assert.ok(auditEntry.migration_start_date.length > 0, 'Must record resolved migration_start_date');
  assert.ok(auditEntry.sunset_cutoff_date.length > 0, 'Must record resolved sunset_cutoff_date');
  assert.strictEqual(auditEntry.required_coverage_pct, 99, 'Must record required_coverage_pct');
  console.log('   [OK] Loud and Audited: MLS_FORCE_SUNSET records operator attribution and resolved dates');

  // Verify fleet summary reflects force_sunset_active: true
  const forceFleetRes = await fetch(baseUrl + '/mls/migration/fleet-summary', {
    headers: { 'Authorization': 'Bearer ' + btok }
  });
  const forceFleetJson = await forceFleetRes.json();
  assert.strictEqual(forceFleetJson.force_sunset_active, true, 'force_sunset_active reflected in fleet summary');
  assert.strictEqual(forceFleetJson.all_criteria_met, true, 'all_criteria_met overridden to true when force_sunset_active');
  console.log('   [OK] Force sunset visible in GET /mls/migration/fleet-summary (force_sunset_active: true)');

  // Reset env vars
  delete process.env.E2EE_LEGACY_ENABLED;
  delete process.env.MLS_FORCE_SUNSET;
  delete process.env.MLS_FORCE_SUNSET_ACK;
  delete process.env.MLS_FORCE_SUNSET_OPERATOR;

  // -------------------------------------------------------------
  // Test 7: Precision Active Denominator & Negative Heuristic (Criterion 1)
  // -------------------------------------------------------------
  console.log('\n8. Testing Precision Active Denominator & Negative Heuristic...');

  // User 1 (Alice) has sent/received messages in 30d -> counted in active_users_30d
  const initialFleet = db.getFleetMigrationSummary();
  assert.ok(initialFleet.fleet_migration.active_users_30d > 0, 'active_users_30d must count users with 30d message activity');
  assert.ok(initialFleet.fleet_migration.required_coverage_pct >= 99);

  // Add Charlie: register MLS device
  const charlieId = db.createUser({ username: 'charlie_p5_active', passwordHash: 'pw_test', displayName: 'Charlie' });
  db.registerMlsDevice(charlieId, 'charlie_dev_1', 'Charlie Phone', 'test_cred_charlie');
  // Charlie sends legacy message -> NOT migrated despite having MLS device!
  db.sendMessage(charlieId, aliceId, 'Charlie legacy message', null, null, 'olm', null);

  const fleetWithLegacyCharlie = db.getFleetMigrationSummary();
  // Charlie had legacy traffic in last 30d, so negative condition fails
  const charlieIsMigrated = (fleetWithLegacyCharlie.fleet_migration.migrated_active_users > initialFleet.fleet_migration.migrated_active_users);
  assert.strictEqual(charlieIsMigrated, false, 'Negative condition: User with MLS device receiving/sending legacy traffic MUST NOT be counted as migrated');
  console.log('   [OK] Negative heuristic: user with MLS device and active legacy traffic is not marked migrated');

  // -------------------------------------------------------------
  // Test 8: Layer 2 Client Defense & Recovery Path
  // -------------------------------------------------------------
  console.log('\n9. Testing Layer 2 Client Defense & Recovery Path...');

  // Simulate client where legacy is disabled before full scan
  window.ExtrovertConfig = { legacyE2eeEnabled: false };
  secureStore.delete('olm_purged_at');
  await window.ExtrovertE2EE.saveMigrationCheckpoint({
    dmCursor: 0,
    roomCursor: 0,
    totalMigrated: 0,
    failedCount: 0,
    hasCompletedFullScan: false,
    done: false
  });

  const blockedStatus = await window.ExtrovertE2EE.getLegacyLifecycleStatus();
  assert.strictEqual(blockedStatus.state, 'BlockedByServerPolicy', 'Client must enter BlockedByServerPolicy state');

  // startHistoricalMigration must reject with BLOCKED_BY_POLICY and arm recovery timer
  let blockedErr = null;
  try {
    await window.ExtrovertE2EE.startHistoricalMigration();
  } catch (err) {
    blockedErr = err;
  }
  assert.ok(blockedErr, 'startHistoricalMigration must reject when blocked by server policy');
  assert.strictEqual(blockedErr.code, 'BLOCKED_BY_POLICY');
  assert.strictEqual(window.ExtrovertE2EE.isRecoveryPollArmed(), true, 'Recovery poll timer must be armed when blocked');
  assert.strictEqual(window.ExtrovertE2EE.getRecoveryPollIntervalMs(), 15 * 60 * 1000, 'Initial poll interval must be 15 minutes');
  console.log('   [OK] Layer 2 defense: client detects BlockedByServerPolicy and arms 15-minute recovery timer');

  // -------------------------------------------------------------
  // Test 9: Exponential Backoff on Poll Failure
  // -------------------------------------------------------------
  console.log('\n10. Testing Exponential Backoff on Poll Failure...');
  // Force fetch failure by intercepting global.fetch temporarily
  const origFetch = global.fetch;
  global.fetch = function () {
    return Promise.reject(new Error('Simulated network/server outage'));
  };

  // Attempt 1 fails -> backs off to 30 min
  try { await window.ExtrovertE2EE.checkRecoveryConfig(); } catch (_) {}
  assert.strictEqual(window.ExtrovertE2EE.getRecoveryPollIntervalMs(), 30 * 60 * 1000, 'Backoff attempt 1 must double to 30 minutes');

  // Attempt 2 fails -> backs off to 60 min (cap)
  try { await window.ExtrovertE2EE.checkRecoveryConfig(); } catch (_) {}
  assert.strictEqual(window.ExtrovertE2EE.getRecoveryPollIntervalMs(), 60 * 60 * 1000, 'Backoff attempt 2 must cap at 60 minutes');

  // Attempt 3 fails -> remains capped at 60 min
  try { await window.ExtrovertE2EE.checkRecoveryConfig(); } catch (_) {}
  assert.strictEqual(window.ExtrovertE2EE.getRecoveryPollIntervalMs(), 60 * 60 * 1000, 'Backoff attempt 3 must remain at 60 minutes');
  console.log('   [OK] Exponential backoff verified: 15m -> 30m -> 60m cap on network/server failure');

  // Restore working fetch
  global.fetch = origFetch;

  // -------------------------------------------------------------
  // Test 10: Client Recovery on Server Re-enable
  // -------------------------------------------------------------
  console.log('\n11. Testing Client Recovery on Server Re-enable...');
  // Server re-enables legacy
  delete process.env.E2EE_LEGACY_ENABLED;
  await window.ExtrovertE2EE.checkRecoveryConfig();
  assert.strictEqual(window.ExtrovertE2EE.legacyEnabled(), true, 'Client must observe legacy_e2ee_enabled: true and unblock');
  assert.strictEqual(window.ExtrovertE2EE.isRecoveryPollArmed(), false, 'Recovery poll timer must be disarmed on recovery');
  assert.strictEqual(window.ExtrovertE2EE.getRecoveryPollIntervalMs(), 15 * 60 * 1000, 'Poll interval must reset to 15 minutes');
  console.log('   [OK] Client Recovery: client polls /mls/config, unblocks, disarms timer, and resets backoff');

  // -------------------------------------------------------------
  // Test 11: OlmPurged Client Never Arms Recovery Poll
  // -------------------------------------------------------------
  console.log('\n12. Testing OlmPurged Client Never Arms Recovery Timer...');
  secureStore.set('olm_purged_at', Date.now());
  const purgedStatus = await window.ExtrovertE2EE.getLegacyLifecycleStatus();
  assert.strictEqual(purgedStatus.state, 'OlmPurged');

  window.ExtrovertE2EE.clearRecoveryPoll();
  await window.ExtrovertE2EE.startHistoricalMigration();
  assert.strictEqual(window.ExtrovertE2EE.isRecoveryPollArmed(), false, 'OlmPurged client must never arm recovery poll');
  console.log('   [OK] OlmPurged clients never arm recovery poll timer');

  // -------------------------------------------------------------
  // Test 12: Rolling 7-Day Failure Telemetry & pct_users_with_any_failures_7d
  // -------------------------------------------------------------
  console.log('\n13. Testing Rolling 7-Day Failure Telemetry in Fleet Summary...');
  // User 1 reported 0 failures; let's record user 2 with failures
  db.recordMigrationTelemetry(2, true, 50, '1-10', false);
  const summaryRes = await fetch(baseUrl + '/mls/migration/fleet-summary', {
    headers: { 'Authorization': 'Bearer ' + btok }
  });
  const summaryJson = await summaryRes.json();
  assert.ok(typeof summaryJson.fleet_migration.pct_users_with_any_failures_7d === 'number', 'Must expose pct_users_with_any_failures_7d');
  assert.ok(typeof summaryJson.fleet_migration.reporters_7d === 'number', 'Must expose reporters_7d');
  assert.strictEqual(summaryJson.fleet_migration.reporters_7d, 2, '2 users reported in last 7 days');
  assert.strictEqual(summaryJson.fleet_migration.failures_7d, 1, '1 user reported failures in last 7 days');
  assert.strictEqual(summaryJson.fleet_migration.pct_users_with_any_failures_7d, 50, '50% of 7-day reporters have failures');
  console.log(`   [OK] Rolling 7-day failure telemetry verified: reporters=${summaryJson.fleet_migration.reporters_7d}, failures=${summaryJson.fleet_migration.failures_7d}, pct=${summaryJson.fleet_migration.pct_users_with_any_failures_7d}%`);

  // -------------------------------------------------------------
  // Test 13: Sticky Tier 2 Retention & Force Revert Override
  // -------------------------------------------------------------
  console.log('\n14. Testing Sticky Tier 2 Retention & Force Revert Override...');
  delete secureStore.get('olm_purged_at'); // un-purge for lifecycle check
  
  // Set Tier 2 on server
  process.env.MLS_MIGRATION_TIER = '2';
  delete process.env.MLS_MIGRATION_TIER_FORCE_REVERT;
  await window.ExtrovertE2EE.checkRecoveryConfig();
  assert.strictEqual(window.ExtrovertConfig.legacyRetentionDays, 365, 'Client learns 365-day retention from Tier 2');

  // Server reverts to Tier 1 without force_tier_revert -> Sticky defense MUST ignore downgrade!
  process.env.MLS_MIGRATION_TIER = '1';
  await window.ExtrovertE2EE.checkRecoveryConfig();
  assert.strictEqual(window.ExtrovertConfig.legacyRetentionDays, 365, 'Sticky Defense: Client MUST keep 365-day retention when downgrade lacks force revert');

  // Server reverts to Tier 1 WITH force_tier_revert -> Reversion MUST be accepted!
  process.env.MLS_MIGRATION_TIER_FORCE_REVERT = 'true';
  await window.ExtrovertE2EE.checkRecoveryConfig();
  assert.strictEqual(window.ExtrovertConfig.legacyRetentionDays, 180, 'Force Revert: Client resets to 180-day retention when force_tier_revert is true');
  console.log('   [OK] Sticky Tier 2 retention preserved across unforced downgrade; explicit force revert resets to 180 days');

  delete process.env.MLS_MIGRATION_TIER;
  delete process.env.MLS_MIGRATION_TIER_FORCE_REVERT;

  // Clean up
  server.close();
  try { fs.unlinkSync(tmpDb); } catch (_) {}
  try { fs.unlinkSync(tmpDb + '-wal'); } catch (_) {}
  try { fs.unlinkSync(tmpDb + '-shm'); } catch (_) {}

  console.log('\n=== All Phase 5 Sunset & Decommissioning Preparation Tests PASSED 100%! ===\n');
  process.exit(0);
}

run().catch(err => {
  console.error('\nPhase 5 Test FAILED:', err);
  process.exit(1);
});
