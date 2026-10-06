'use strict';

/**
 * Regression tests for the browser MLS client (public/mls-client.js):
 *
 * 1. IndexedDB open/repair: the shared 'extrovert_crypto' database must open at
 *    whatever version it already is (e2ee.js may have bumped past the version
 *    mls-client.js used to pin — a pinned lower version throws VersionError) and
 *    must create any missing object stores from either module's schema.
 * 2. Member matching: removeMemberFromRoomGroup must match user IDs exactly
 *    (user:12 must not collide with user:2) and must remove ALL device leaves.
 * 3. addMemberToRoomGroup must issue one Add + Welcome per claimed device
 *    KeyPackage, not just the first.
 * 4. Leave-room: a pending Remove proposal must be committed by the next member
 *    activity (commitPendingProposals) so the leaver's leaf actually leaves the
 *    ratchet tree — RFC 9420 forbids committing one's own removal.
 *
 * Membership changes are verified against a second real ts-mls client (Eve)
 * processing the exact commit bytes sent to the delivery service.
 */

const assert = require('assert');

global.window = global;
if (!global.crypto) {
  global.crypto = require('crypto').webcrypto;
}
global.document = {
  readyState: 'complete',
  querySelector: function () { return null; },
  querySelectorAll: function () { return []; },
  addEventListener: function () {},
};
global.__mlsCurrentUserId = 1;

require('../public/lib/mls.js');
const mls = global.MLS;

// ---------------------------------------------------------------------------
// Mock IndexedDB with faithful version semantics (VersionError when opening
// below the existing version, upgradeneeded on create/upgrade).
// ---------------------------------------------------------------------------

function makeMockIndexedDB() {
  const recs = new Map();

  function makeDb(rec) {
    const db = {
      version: rec.version,
      closed: false,
      objectStoreNames: {
        contains: (name) => rec.stores.has(name),
      },
      createObjectStore: (name) => {
        rec.stores.set(name, new Map());
        return {};
      },
      transaction: (name) => {
        const store = rec.stores.get(name);
        return {
          oncomplete: null,
          onerror: null,
          objectStore: () => ({
            get: (key) => {
              const req = {};
              setImmediate(() => {
                req.result = store.get(key);
                if (req.onsuccess) req.onsuccess({ target: req });
              });
              return req;
            },
            put: (val, key) => {
              const req = {};
              setImmediate(() => {
                store.set(key, val);
                req.result = key;
                if (req.onsuccess) req.onsuccess({ target: req });
              });
              return req;
            },
            delete: (key) => {
              const req = {};
              setImmediate(() => {
                store.delete(key);
                if (req.onsuccess) req.onsuccess({ target: req });
              });
              return req;
            },
            getAllKeys: () => {
              const req = {};
              setImmediate(() => {
                req.result = Array.from(store.keys());
                if (req.onsuccess) req.onsuccess({ target: req });
              });
              return req;
            },
            getAll: () => {
              const req = {};
              setImmediate(() => {
                req.result = Array.from(store.values());
                if (req.onsuccess) req.onsuccess({ target: req });
              });
              return req;
            },
          }),
        };
      },
      close: () => { db.closed = true; },
    };
    return db;
  }

  return {
    open(name, requestedVersion) {
      const req = {};
      setImmediate(() => {
        let rec = recs.get(name);
        const requested = requestedVersion === undefined ? undefined : Number(requestedVersion);
        if (!rec) {
          rec = { version: requested || 1, stores: new Map() };
          recs.set(name, rec);
          req.result = makeDb(rec);
          if (req.onupgradeneeded) req.onupgradeneeded({ target: req, oldVersion: 0, newVersion: rec.version });
          if (req.onsuccess) req.onsuccess({ target: req });
          return;
        }
        if (requested !== undefined && requested < rec.version) {
          req.error = Object.assign(new Error('requested version is lower than existing version'), { name: 'VersionError' });
          if (req.onerror) req.onerror({ target: req });
          return;
        }
        const oldVersion = rec.version;
        if (requested !== undefined && requested > rec.version) {
          rec.version = requested;
          req.result = makeDb(rec);
          if (req.onupgradeneeded) req.onupgradeneeded({ target: req, oldVersion, newVersion: rec.version });
          if (req.onsuccess) req.onsuccess({ target: req });
          return;
        }
        req.result = makeDb(rec);
        if (req.onsuccess) req.onsuccess({ target: req });
      });
      return req;
    },
    seed(name, version, storeNames) {
      const rec = { version, stores: new Map() };
      for (const s of storeNames) rec.stores.set(s, new Map());
      recs.set(name, rec);
      return rec;
    },
    recs,
  };
}

// ---------------------------------------------------------------------------
// Mock delivery service
// ---------------------------------------------------------------------------

function makeRouter() {
  const state = {
    requests: [],
    commits: [],
    registrations: [],
    pendingProposals: [],
    claimable: {},
    backup: null,
  };

  state.setPendingProposals = (p) => { state.pendingProposals = p; };
  state.lastCommit = () => state.commits[state.commits.length - 1];
  state.inits = [];
  state.initResponses = [];

  function json(obj) {
    return Promise.resolve({ status: 200, json: () => Promise.resolve(obj) });
  }

  state.fetch = function (url, opts) {
    const method = (opts && opts.method) || 'GET';
    const body = opts && opts.body ? JSON.parse(opts.body) : null;
    state.requests.push({ method, url, body });
    const qIdx = url.indexOf('?');
    const path = qIdx === -1 ? url : url.slice(0, qIdx);
    const query = {};
    if (qIdx !== -1) {
      new URLSearchParams(url.slice(qIdx + 1)).forEach(function (v, k) { query[k] = v; });
    }

    if (path.includes('/mls/keypackages/status')) return json({ ok: true, available: 20 });
    if (path.includes('/mls/welcomes')) return json({ ok: true, welcomes: [] });
    if (path.endsWith('/mls/backup') && method === 'POST') {
      state.backup = { backup_data: body.backup_data, kek_salt: body.salt };
      return json({ ok: true });
    }
    if (path.endsWith('/mls/backup')) return json({ ok: true, backup: state.backup });
    if (path.includes('/mls/groups/') && path.includes('/proposals') && method === 'GET') {
      const pending = state.pendingProposals;
      state.pendingProposals = [];
      return json({ ok: true, proposals: pending });
    }
    if (path.includes('/mls/groups/') && path.includes('/commits')) return json({ ok: true, commits: [] });
    if (path.endsWith('/mls/groups/init') && method === 'POST') {
      state.inits.push(body);
      if (state.initResponses.length) return json(state.initResponses.shift());
      return json({ ok: true, group_id: body.group_id, epoch: 1 });
    }
    if (path.includes('/mls/groups/') && path.includes('/commit') && method === 'POST') {
      state.commits.push(body);
      return json({ ok: true, new_epoch: body.current_epoch + 1 });
    }
    if (method === 'GET' && /\/mls\/keypackages\/\d+$/.test(path)) {
      const uid = path.split('/').pop();
      let kps = state.claimable[uid] || [];
      if (query.exclude_device) kps = kps.filter((k) => k.device_id !== query.exclude_device);
      return json({ ok: true, user_id: Number(uid), keypackages: kps });
    }
    if (path.includes('/mls/device/register')) {
      state.registrations.push(body);
      return json({ ok: true, device: {} });
    }
    if (path.includes('/mls/keypackages') && method === 'POST') {
      return json({ ok: true, saved: (body.keypackages || []).length });
    }
    return json({ ok: true });
  };

  return state;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function loadClient(idb, router) {
  global.indexedDB = idb;
  global.fetch = router.fetch;
  const path = require.resolve('../public/mls-client.js');
  delete require.cache[path];
  require('../public/mls-client.js');
  return global.ExtrovertMLS;
}

function b64(u8) {
  return Buffer.from(u8).toString('base64');
}

async function encryptKd(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return b64(out);
}

function leafIdents(state) {
  const out = [];
  for (const n of state.ratchetTree) {
    if (n && n.nodeType === 'leaf' && n.leaf) {
      out.push(new TextDecoder().decode(n.leaf.credential.identity));
    }
  }
  return out;
}

async function applyCommitB64(state, commitB64) {
  const dec = mls.decodeMlsMessage(new Uint8Array(Buffer.from(commitB64, 'base64')), 0)[0];
  assert.ok(dec && dec.privateMessage, 'commit must decode as an MLS private message');
  const r = await mls.processPrivateMessage(state, dec.privateMessage, mls.emptyPskIndex, impl);
  assert.strictEqual(r.kind, 'newState');
  return r.newState;
}

let impl;

async function genKp(ident) {
  const cred = { credentialType: 'basic', identity: new TextEncoder().encode(ident) };
  return mls.generateKeyPackage(cred, mls.defaultCapabilities(), mls.defaultLifetime, [], impl);
}

async function wireKp(kp, deviceId) {
  const encoded = mls.encodeMlsMessage({ keyPackage: kp.publicPackage, wireformat: 'mls_key_package', version: 'mls10' });
  return { id: deviceId.length * 7 + 1, device_id: deviceId, keypackage_data: b64(encoded), ciphersuite: 1 };
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

async function scenarioLegacyDbRepair() {
  console.log('1. Legacy e2ee-created DB (v4, only mls_msg_cache) is repaired and init succeeds...');

  const idb = makeMockIndexedDB();
  idb.seed('extrovert_crypto', 4, ['mls_msg_cache']);
  const router = makeRouter();

  const client = loadClient(idb, router);
  await client.init();
  assert.strictEqual(client.ready(), true, 'MLS engine must be ready after init');

  const rec = idb.recs.get('extrovert_crypto');
  for (const s of ['crypto', 'mls_keys', 'mls_groups', 'mls_msg_cache']) {
    assert.ok(rec.stores.has(s), 'store ' + s + ' must exist after repair');
  }
  assert.ok(rec.version > 4, 'repair must bump the DB version');
  assert.strictEqual(router.registrations.length, 1, 'device must register exactly once');
  console.log('   [OK] missing stores created via version bump (now v' + rec.version + '), init clean');
}

async function scenarioHighVersionDbNoVersionError() {
  console.log('2. DB already at v7 missing mls_keys opens without VersionError and is repaired...');

  const idb = makeMockIndexedDB();
  idb.seed('extrovert_crypto', 7, ['crypto', 'mls_groups', 'mls_msg_cache']);
  const router = makeRouter();

  const client = loadClient(idb, router);
  await client.init();
  assert.strictEqual(client.ready(), true, 'MLS engine must be ready on a higher-version DB');

  const rec = idb.recs.get('extrovert_crypto');
  assert.strictEqual(rec.version, 8, 'repair must bump 7 -> 8');
  assert.ok(rec.stores.has('mls_keys'), 'mls_keys store must be created');
  console.log('   [OK] no VersionError on v7 DB, mls_keys created at v8');
}

async function scenarioMembershipFixes() {
  console.log('3. Membership fixes verified against a second real MLS client (Eve)...');

  const idb = makeMockIndexedDB();
  const rec = idb.seed('extrovert_crypto', 4, ['crypto', 'mls_keys', 'mls_groups']);
  const router = makeRouter();

  // Group layout (leaf order matters for the user:12 vs user:2 substring trap):
  //   leaf 0: me     user:1:dev:devLocal
  //   leaf 1: Eve    user:12:dev:devC   (must never be matched for user 2)
  //   leaf 2: Bob1   user:2:dev:devA
  //   leaf 3: Bob2   user:2:dev:devB
  const myKp = await genKp('user:1:dev:devLocal');
  const eveKp = await genKp('user:12:dev:devC');
  const bob1Kp = await genKp('user:2:dev:devA');
  const bob2Kp = await genKp('user:2:dev:devB');

  let alice = await mls.createGroup(new TextEncoder().encode('room:1'), myKp.publicPackage, myKp.privatePackage, [], impl);

  async function addCommit(state, kp) {
    return mls.createCommit(
      { state, cipherSuite: impl },
      { extraProposals: [{ proposalType: 'add', add: { keyPackage: kp.publicPackage } }], ratchetTreeExtension: true }
    );
  }

  const addEve = await addCommit(alice, eveKp);
  const addB1 = await addCommit(addEve.newState, bob1Kp);
  const addB2 = await addCommit(addB1.newState, bob2Kp);
  alice = addB2.newState;

  assert.deepStrictEqual(leafIdents(alice),
    ['user:1:dev:devLocal', 'user:12:dev:devC', 'user:2:dev:devA', 'user:2:dev:devB'],
    'test tree layout must match expectations');

  let eve = await mls.joinGroup(addEve.welcome, eveKp.publicPackage, eveKp.privatePackage, mls.emptyPskIndex, impl);
  eve = await applyCommitB64(eve, b64(mls.encodeMlsMessage(addB1.commit)));
  eve = await applyCommitB64(eve, b64(mls.encodeMlsMessage(addB2.commit)));

  // Seed the browser's local stores exactly as saveGroupState/initDevice would.
  const devKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  rec.stores.get('crypto').set('deviceKey', devKey);
  rec.stores.get('mls_keys').set('deviceId', 'devLocal');
  rec.stores.get('mls_keys').set('credential', {
    credentialType: 'basic',
    identity: new TextEncoder().encode('user:1:dev:devLocal'),
  });
  rec.stores.get('mls_groups').set('room:1', await encryptKd(devKey, mls.encodeGroupState(alice)));

  router.claimable['3'] = [
    await wireKp(await genKp('user:3:dev:devD'), 'devD'),
    await wireKp(await genKp('user:3:dev:devE'), 'devE'),
  ];

  const client = loadClient(idb, router);
  await client.init();
  assert.strictEqual(client.ready(), true);

  console.log('   3a. removeMemberFromRoomGroup(1, 2) removes both user-2 devices and spares user 12...');
  await client.removeMemberFromRoomGroup(1, 2);
  const f2 = router.lastCommit();
  assert.deepStrictEqual(f2.members_removed,
    [{ user_id: 2, device_id: 'devA' }, { user_id: 2, device_id: 'devB' }],
    'both user-2 device leaves must be removed');
  assert.ok(!f2.members_removed.some((m) => m.device_id === 'devC'), 'user 12 must not be touched');
  eve = await applyCommitB64(eve, f2.commit_message);
  assert.deepStrictEqual(leafIdents(eve), ['user:1:dev:devLocal', 'user:12:dev:devC']);
  console.log('   [OK] exact ID match, all device leaves removed, Eve confirms the tree');

  console.log('   3b. addMemberToRoomGroup(1, 3) adds every claimed device KeyPackage...');
  const stateAfterF3 = await client.addMemberToRoomGroup(1, 3);
  const f3 = router.lastCommit();
  assert.strictEqual(f3.welcomes.length, 2, 'one Welcome per device');
  assert.deepStrictEqual(f3.members_added.map((m) => m.device_id), ['devD', 'devE']);
  assert.ok(f3.welcomes.every((w) => w.welcome_data), 'welcomes must carry data');
  eve = await applyCommitB64(eve, f3.commit_message);
  assert.deepStrictEqual(leafIdents(eve),
    ['user:1:dev:devLocal', 'user:12:dev:devC', 'user:3:dev:devD', 'user:3:dev:devE']);
  console.log('   [OK] both device leaves added, both Welcomes queued');

  console.log('   3c. pending Remove proposal is committed by the next room send (leave flow)...');
  // As leaveRoomGroup does: a standalone PublicMessage Remove proposal whose
  // commit nobody made yet. devD (leaf 2) "leaves".
  const pending = await mls.createProposal(stateAfterF3, true, { proposalType: 'remove', remove: { removed: 2 } }, impl);
  router.setPendingProposals([{
    proposal_ref: 'ref_leave_1',
    proposal_type: 3,
    epoch: Number(stateAfterF3.groupContext.epoch),
    proposal_data: b64(mls.encodeMlsMessage(pending.message)),
  }]);

  const sent = await client.encryptRoomMessage(1, 'after leave', []);
  assert.ok(sent && sent.body, 'message must encrypt after draining pending proposals');
  const f4 = router.lastCommit();
  assert.deepStrictEqual(f4.proposals_consumed, ['ref_leave_1'], 'consumed refs must be reported to the DS');
  eve = await applyCommitB64(eve, f4.commit_message);
  assert.deepStrictEqual(leafIdents(eve),
    ['user:1:dev:devLocal', 'user:12:dev:devC', 'user:3:dev:devE'],
    'leaver leaf must be gone from the ratchet tree');
  console.log('   [OK] leave proposal committed, leaver removed from the tree, send unaffected');
}

async function scenarioStaleGroupResetRecovery() {
  console.log('4. Stale server group with no local state recovers via CAS reset...');

  const idb = makeMockIndexedDB();
  const rec = idb.seed('extrovert_crypto', 4, ['crypto', 'mls_keys', 'mls_groups']);
  const router = makeRouter();

  const devKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  rec.stores.get('crypto').set('deviceKey', devKey);
  rec.stores.get('mls_keys').set('deviceId', 'devLocal');
  rec.stores.get('mls_keys').set('credential', {
    credentialType: 'basic',
    identity: new TextEncoder().encode('user:1:dev:devLocal'),
  });
  rec.stores.get('mls_groups').set('dm:1_2', 'AAAAAAAAAAAAAAAA');

  const peerKp = await genKp('user:2:dev:devPeer');
  router.claimable['2'] = [await wireKp(peerKp, 'devPeer')];
  const ownKp = await genKp('user:1:dev:devOld');
  router.claimable['1'] = [await wireKp(ownKp, 'devOld')];

  router.initResponses = [{ error: 'GroupExists', epoch: 3 }];

  const client = loadClient(idb, router);
  await client.init();

  const sent = await client.encryptDmMessage(2, 'hello after recovery');
  assert.ok(sent && sent.body, 'message must encrypt after stale group recovery');

  assert.strictEqual(router.inits.length, 2, 'init must be retried once with reset_existing');
  assert.strictEqual(router.inits[0].reset_existing, undefined, 'first init must not reset');
  assert.strictEqual(router.inits[1].reset_existing, true, 'retry must request a reset');
  assert.strictEqual(router.inits[1].expected_epoch, 3, 'reset must be CAS-checked against the observed epoch');

  const ownClaimReq = router.requests.find((r) => r.url.includes('/mls/keypackages/1?'));
  assert.ok(ownClaimReq && ownClaimReq.url.includes('exclude_device=devLocal'),
    'own other devices must be claimed excluding the current device');

  const welcomeDevices = router.inits[1].welcomes.map((w) => w.user_id + ':' + w.device_id).sort();
  assert.deepStrictEqual(welcomeDevices, ['1:devOld', '2:devPeer'],
    'peer devices and own other devices must both receive Welcomes');

  const stored = rec.stores.get('mls_groups').get('dm:1_2');
  assert.notStrictEqual(stored, 'AAAAAAAAAAAAAAAA', 'corrupt stale blob must be replaced with fresh state');
  console.log('   [OK] CAS reset re-init, corrupt-blob cleanup, own-device exclusion, welcomes for all devices');
}

async function scenarioPasswordBackupRestore() {
  console.log('5. Password backup: new device restores history + message cache with just the password...');

  const PW = 'correct horse battery staple';

  // --- Device A: owns the group state; a real peer sends a message ----------
  const idbA = makeMockIndexedDB();
  const recA = idbA.seed('extrovert_crypto', 1, ['crypto', 'mls_keys', 'mls_groups', 'mls_msg_cache', 'mls_history']);
  const router = makeRouter();

  const devKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  recA.stores.get('crypto').set('deviceKey', devKey);
  recA.stores.get('mls_keys').set('deviceId', 'devLocal');
  recA.stores.get('mls_keys').set('credential', {
    credentialType: 'basic',
    identity: new TextEncoder().encode('user:1:dev:devLocal'),
  });

  const myKp = await genKp('user:1:dev:devLocal');
  const peerKp = await genKp('user:2:dev:devPeer');
  const alice = await mls.createGroup(new TextEncoder().encode('dm:1_2'), myKp.publicPackage, myKp.privatePackage, [], impl);
  const addPeer = await mls.createCommit(
    { state: alice, cipherSuite: impl },
    { extraProposals: [{ proposalType: 'add', add: { keyPackage: peerKp.publicPackage } }], ratchetTreeExtension: true }
  );
  const aliceState = addPeer.newState;
  const peerState = await mls.joinGroup(addPeer.welcome, peerKp.publicPackage, peerKp.privatePackage, mls.emptyPskIndex, impl);

  // The peer's message — never opened on device A; only the backup can save it.
  const peerSend = await mls.createApplicationMessage(peerState, new TextEncoder().encode('peer secret'), impl);
  const peerCipher = b64(mls.encodeMlsMessage({
    privateMessage: peerSend.privateMessage,
    wireformat: 'mls_private_message',
    version: 'mls10',
  }));

  recA.stores.get('mls_groups').set('dm:1_2', await encryptKd(devKey, mls.encodeGroupState(aliceState)));
  recA.stores.get('mls_msg_cache').set('42', 'aia sent this earlier');

  const clientA = loadClient(idbA, router);
  await clientA.init();
  const unlocked = await clientA.unlockBackup(PW);
  assert.ok(unlocked && unlocked.created, 'first unlock must create and upload the backup');
  assert.ok(router.backup && router.backup.backup_data, 'encrypted backup must reach the server');
  await clientA.backupNow();

  const firstBlob = JSON.parse(new TextDecoder().decode(new Uint8Array(Buffer.from(router.backup.backup_data, 'base64'))));
  assert.ok(firstBlob.bk_id && firstBlob.wrappedBk && firstBlob.payload, 'blob must wrap a backup key with the password');

  // --- Device B: brand new device, password only ---------------------------
  const idbB = makeMockIndexedDB();
  idbB.seed('extrovert_crypto', 1, ['crypto', 'mls_keys', 'mls_groups', 'mls_msg_cache', 'mls_history']);
  const clientB = loadClient(idbB, router);
  await clientB.init();
  const restored = await clientB.unlockBackup(PW);
  assert.ok(restored && restored.restored, 'backup must restore on the new device');

  const recB = idbB.recs.get('extrovert_crypto');
  assert.strictEqual(recB.stores.get('mls_msg_cache').get('42'), 'aia sent this earlier',
    'message cache must restore');

  const pt = await clientB.decryptDmMessage(2, peerCipher);
  assert.strictEqual(pt, 'peer secret', 'old peer message must decrypt on the new device via restored state');
  console.log('   [OK] new device decrypts full history with just the password');

  // --- Wrong password must not unlock --------------------------------------
  const idbC = makeMockIndexedDB();
  idbC.seed('extrovert_crypto', 1, ['crypto', 'mls_keys', 'mls_groups']);
  const clientC = loadClient(idbC, router);
  await clientC.init();
  let wrongPwThrew = false;
  try {
    await clientC.unlockBackup('wrong password entirely');
  } catch (err) {
    wrongPwThrew = true;
  }
  assert.ok(wrongPwThrew, 'wrong password must not unlock the backup');
  console.log('   [OK] wrong password rejected');

  // --- Device A restarted: no password, backups must continue --------------
  const clientD = loadClient(idbA, router);
  await clientD.init();
  await clientD.encryptDmMessage(2, 'second message');
  await clientD.backupNow();
  const latestBlob = JSON.parse(new TextDecoder().decode(new Uint8Array(Buffer.from(router.backup.backup_data, 'base64'))));
  assert.strictEqual(latestBlob.wrappedBk, firstBlob.wrappedBk,
    'password-less sessions must keep the existing password wrapping');
  assert.strictEqual(latestBlob.bk_id, firstBlob.bk_id, 'the backup key must stay stable across sessions');
  console.log('   [OK] password-less sessions keep backing up under the same wrapped key');
}

async function scenarioCrossDeviceMessageSync() {
  console.log('6. Reported flow: send on laptop, open on phone — message must arrive decrypted...');

  const PW = 'correct horse battery staple';

  // --- Laptop A ------------------------------------------------------------
  const idbA = makeMockIndexedDB();
  const recA = idbA.seed('extrovert_crypto', 1, ['crypto', 'mls_keys', 'mls_groups', 'mls_msg_cache', 'mls_history']);
  const router = makeRouter();

  const devKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  recA.stores.get('crypto').set('deviceKey', devKey);
  recA.stores.get('mls_keys').set('deviceId', 'devLocal');
  recA.stores.get('mls_keys').set('credential', {
    credentialType: 'basic',
    identity: new TextEncoder().encode('user:1:dev:devLocal'),
  });
  router.claimable['2'] = [await wireKp(await genKp('user:2:dev:devPeer'), 'devPeer')];

  const clientA = loadClient(idbA, router);
  await clientA.init();
  await clientA.unlockBackup(PW);
  const blobBeforeSend = router.backup.backup_data;

  const sent = await clientA.encryptDmMessage(2, 'hello from laptop');
  assert.ok(sent && sent.body);
  assert.notStrictEqual(router.backup.backup_data, blobBeforeSend,
    'a send must upload the backup immediately, not on a debounce');
  recA.stores.get('mls_msg_cache').set('77', 'hello from laptop');
  await clientA.backupNow();

  // --- Phone C logs in with the password AFTER the send --------------------
  const idbC = makeMockIndexedDB();
  idbC.seed('extrovert_crypto', 1, ['crypto', 'mls_keys', 'mls_groups', 'mls_msg_cache', 'mls_history']);
  const clientC = loadClient(idbC, router);
  await clientC.init();
  await clientC.unlockBackup(PW);
  const recC = idbC.recs.get('extrovert_crypto');
  assert.strictEqual(recC.stores.get('mls_msg_cache').get('77'), 'hello from laptop',
    'phone must restore the just-sent message as plaintext');

  // --- Freshness gap: laptop sends again AFTER the phone already synced ----
  await clientA.encryptDmMessage(2, 'second message');
  recA.stores.get('mls_msg_cache').set('78', 'second message');
  await clientA.backupNow();
  assert.strictEqual(recC.stores.get('mls_msg_cache').get('78'), undefined,
    'precondition: the later message is not on the phone yet');
  await clientC.syncBackup();
  assert.strictEqual(recC.stores.get('mls_msg_cache').get('78'), 'second message',
    'phone must pull newer backups without re-entering the password');
  console.log('   [OK] send uploads promptly and the phone syncs newer messages without the password');
}

async function scenarioRoomFreshInit() {
  console.log('7. Room fresh-init: first send to a room builds the group for all devices...');

  const idb = makeMockIndexedDB();
  const rec = idb.seed('extrovert_crypto', 1, ['crypto', 'mls_keys', 'mls_groups', 'mls_msg_cache', 'mls_history']);
  const router = makeRouter();

  const devKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  rec.stores.get('crypto').set('deviceKey', devKey);
  rec.stores.get('mls_keys').set('deviceId', 'devLocal');
  rec.stores.get('mls_keys').set('credential', {
    credentialType: 'basic',
    identity: new TextEncoder().encode('user:1:dev:devLocal'),
  });

  router.claimable['2'] = [await wireKp(await genKp('user:2:dev:devA'), 'devA')];
  router.claimable['3'] = [
    await wireKp(await genKp('user:3:dev:devB'), 'devB'),
    await wireKp(await genKp('user:3:dev:devC'), 'devC'),
  ];
  router.claimable['1'] = [await wireKp(await genKp('user:1:dev:devOther'), 'devOther')];
  router.claimable['4'] = [];

  const client = loadClient(idb, router);
  await client.init();

  const sent = await client.encryptRoomMessage(1, 'hello room', [2, 3, 4]);
  assert.ok(sent && sent.body, 'room message must encrypt on fresh init');

  assert.strictEqual(router.inits.length, 1, 'room group must initialize once');
  const initBody = router.inits[0];
  const welcomeDevices = initBody.welcomes.map((w) => w.user_id + ':' + w.device_id).sort();
  assert.deepStrictEqual(welcomeDevices, ['1:devOther', '2:devA', '3:devB', '3:devC'],
    'all member devices and own other devices must receive Welcomes');
  console.log('   [OK] room group created, welcomes queued for every device');
}

async function run() {
  console.log('=== Starting MLS Browser Client Regression Test Suite ===\n');
  const cs = mls.getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519');
  impl = await mls.getCiphersuiteImpl(cs);

  await scenarioLegacyDbRepair();
  await scenarioHighVersionDbNoVersionError();
  await scenarioMembershipFixes();
  await scenarioStaleGroupResetRecovery();
  await scenarioPasswordBackupRestore();
  await scenarioCrossDeviceMessageSync();
  await scenarioRoomFreshInit();

  console.log('\n=== All MLS Browser Client Regression Assertions PASSED ===');
}

run().catch((err) => {
  console.error('MLS browser client regression test FAILED:', err);
  process.exit(1);
});
