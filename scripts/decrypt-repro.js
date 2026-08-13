'use strict';
// End-to-end reproduction of the web client's Olm DM flow against a live server.
// Two simulated browsers (cookie + CSRF + exact protocol from public/e2ee.js),
// one per user. Mirrors the client logic line-for-line where it matters:
// account creation, prekey publishing, self-sessions, outbound session
// creation, encrypt/send, inbound decrypt ladder (baseline -> live -> fresh
// PreKey), and pickle persistence across simulated page reloads.
//
// Run: node scripts/decrypt-repro.js

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const bcrypt = require('bcryptjs');

const TEST_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'extrovert-decrypt-'));
process.env.EXTV_DB_PATH = path.join(TEST_DIR, 'extrovert.db');
process.env.EXTV_SESSION_DB_PATH = path.join(TEST_DIR, 'sessions.db');
process.env.SESSION_SECRET = 'decrypt-repro-secret';
process.env.SECRET = 'decrypt-repro-secret';
process.env.PORT = String(35000 + Math.floor(Math.random() * 500));

const app = require('../src/server');
const db = require('../src/db');

const PICKLE_KEY = 'extrovert-olm-pickle-v1';
let failures = 0;
function ok(cond, msg) {
  console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg);
  if (!cond) failures++;
}

// ---- Fake IndexedDB: mirrors stores STORE_OLM keys ('account', 'session:<id>',
// 'sessionBase:<id>', 'selfOutbound', 'selfInbound', 'sessionIdent:<id>').
// The real client AES-GCM-wraps pickles with the device key; that layer is
// transparent to protocol behavior, so we store raw pickles.
class FakeIDB {
  constructor() { this.map = new Map(); }
  get(key) { return Promise.resolve(this.map.has(key) ? this.map.get(key) : null); }
  set(key, value) { this.map.set(key, value); return Promise.resolve(); }
}

// ---- One simulated browser session (mirrors public/e2ee.js) ----
class SimBrowser {
  constructor(base, username, password, userId) {
    this.base = base;
    this.username = username;
    this.password = password;
    this.userId = userId;
    this.idb = new FakeIDB();
    this.cookie = '';
    this.csrf = '';
    this.account = null;        // Olm.Account
    this.myIdKeys = null;
    this.sessions = {};         // otherIdStr -> Olm.Session (in-memory)
    this.selfOutbound = null;
    this.selfInbound = null;
    this.selfInboundBaseline = null;
  }

  async withCookie(url, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (this.cookie) headers['Cookie'] = this.cookie;
    const r = await fetch(this.base + url, { ...opts, headers, redirect: 'manual' });
    const sc = r.headers.get('set-cookie');
    if (sc) {
      const sid = sc.split(';')[0];
      this.cookie = sid; // login regenerates the session
    }
    return r;
  }

  async login() {
    const page = await this.withCookie('/login');
    const html = await page.text();
    const csrfMatch = html.match(/name="_csrf" value="([^"]+)"/);
    if (!csrfMatch) throw new Error('no CSRF on login page');
    await this.withCookie('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(this.username)}&password=${encodeURIComponent(this.password)}&_csrf=${encodeURIComponent(csrfMatch[1])}`,
    });
    const chats = await this.withCookie('/chats');
    const meta = (await chats.text()).match(/name="csrf-token" content="([^"]+)"/);
    if (!meta) throw new Error('no csrf-token meta after login');
    this.csrf = meta[1];
  }

  async csrfFetch(url, opts = {}) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (opts.body && !opts.headers['Content-Type']) opts.headers['Content-Type'] = 'application/json';
    opts.headers['X-CSRF-Token'] = this.csrf;
    return this.withCookie(url, opts);
  }

  // --- account creation + publishing (createAndPublishAccount) ---
  async initCrypto() {
    this.account = new Olm.Account();
    this.account.create();
    const k = JSON.parse(this.account.identity_keys());
    this.myIdKeys = { curve25519: k.curve25519, ed25519: k.ed25519 };
    this.account.generate_fallback_key();
    this.account.generate_one_time_keys(5);
    await this.publishPrekeys();
    await this.ensureSelfSessions();
  }

  async publishPrekeys() {
    const keys = JSON.parse(this.account.one_time_keys());
    const otks = Object.keys(keys.curve25519).map((id) => ({ id, public_key: keys.curve25519[id] }));
    let fallback = JSON.parse(this.account.fallback_key());
    let fbKeys = Object.keys(fallback.curve25519 || {});
    if (!fbKeys.length) {
      try {
        this.account.generate_fallback_key();
        fallback = JSON.parse(this.account.fallback_key());
        fbKeys = Object.keys(fallback.curve25519 || {});
      } catch (_) {}
    }
    const fb = fbKeys.length ? fallback.curve25519[fbKeys[0]] : undefined;
    const r = await this.csrfFetch('/chats/prekeys', {
      method: 'POST',
      body: JSON.stringify({ identity_key: this.myIdKeys.curve25519, ed25519_key: this.myIdKeys.ed25519, fallback_key: fb, one_time_keys: otks }),
    });
    if (r.status !== 200) throw new Error('prekeys publish failed: ' + r.status + ' ' + (await r.text()));
    await r.json();
    this.account.mark_keys_as_published();
    await this.saveAccount();
  }

  // --- self sessions (ensureSelfSessions) ---
  async ensureSelfSessions() {
    if (this.selfOutbound) return;
    const loadedOut = await this.idb.get('selfOutbound');
    const loadedIn = await this.idb.get('selfInbound');
    if (loadedOut && loadedIn) {
      this.selfOutbound = new Olm.Session(); this.selfOutbound.unpickle(PICKLE_KEY, loadedOut);
      this.selfInbound = new Olm.Session(); this.selfInbound.unpickle(PICKLE_KEY, loadedIn);
      this.selfInboundBaseline = loadedIn;
      return;
    }
    this.account.generate_one_time_keys(1);
    const keys = JSON.parse(this.account.one_time_keys());
    const otkIds = Object.keys(keys.curve25519);
    if (!otkIds.length) throw new Error('Could not generate self prekey.');
    this.selfOutbound = new Olm.Session();
    this.selfOutbound.create_outbound(this.account, this.myIdKeys.curve25519, keys.curve25519[otkIds[0]]);
    const initMsg = this.selfOutbound.encrypt('__e2ee_self_init__');
    this.selfInbound = new Olm.Session();
    this.selfInbound.create_inbound(this.account, initMsg.body);
    this.account.remove_one_time_keys(this.selfInbound);
    this.selfInboundBaseline = this.selfInbound.pickle(PICKLE_KEY);
    await this.saveSelfSessions();
    await this.saveAccount();
  }

  async saveAccount() {
    await this.idb.set('account', this.account.pickle(PICKLE_KEY));
  }
  async saveSession(idStr, session) {
    await this.idb.set('session:' + idStr, session.pickle(PICKLE_KEY));
  }
  async saveSessionBaseline(idStr, session) {
    await this.idb.set('sessionBase:' + idStr, session.pickle(PICKLE_KEY));
  }
  async saveSelfSessions() {
    if (this.selfOutbound) await this.idb.set('selfOutbound', this.selfOutbound.pickle(PICKLE_KEY));
    if (this.selfInbound) {
      const inboundPickle = this.selfInboundBaseline || this.selfInbound.pickle(PICKLE_KEY);
      await this.idb.set('selfInbound', inboundPickle);
    }
  }

  // --- outbound session ladder (getOrCreateOutboundSession, without the
  // safety/rekey network checks which don't affect the happy path) ---
  async getOrCreateOutboundSession(other) {
    const idStr = String(other.userId);
    if (this.sessions[idStr]) return this.sessions[idStr];
    const livePickle = await this.idb.get('session:' + idStr);
    if (livePickle) {
      const s = new Olm.Session();
      s.unpickle(PICKLE_KEY, livePickle);
      this.sessions[idStr] = s;
      return s;
    }
    const r = await this.csrfFetch('/chats/' + encodeURIComponent(other.username) + '/bundle');
    if (r.status !== 200) throw new Error('bundle fetch failed: ' + r.status + ' ' + (await r.text()));
    const bundle = await r.json();
    if (!bundle.identity_key || (!bundle.one_time_key && !bundle.fallback_key)) {
      throw new Error('Recipient has no encryption keys yet');
    }
    const s = new Olm.Session();
    s.create_outbound(this.account, bundle.identity_key, bundle.one_time_key ? bundle.one_time_key.public_key : bundle.fallback_key);
    await this.saveSessionBaseline(idStr, s);
    await this.saveSession(idStr, s);
    await this.idb.set('sessionIdent:' + idStr, bundle.identity_key);
    this.sessions[idStr] = s;
    return s;
  }

  // Force a fresh outbound session from the peer's current bundle (mirrors
  // rebuildOutboundAndAck in the rekey heal).
  async rebuildOutboundSession(other) {
    const idStr = String(other.userId);
    const r = await this.csrfFetch('/chats/' + encodeURIComponent(other.username) + '/bundle');
    if (r.status !== 200) throw new Error('bundle fetch failed: ' + r.status + ' ' + (await r.text()));
    const bundle = await r.json();
    if (!bundle.identity_key || (!bundle.one_time_key && !bundle.fallback_key)) {
      throw new Error('Recipient has no encryption keys yet');
    }
    const s = new Olm.Session();
    s.create_outbound(this.account, bundle.identity_key, bundle.one_time_key ? bundle.one_time_key.public_key : bundle.fallback_key);
    await this.saveSessionBaseline(idStr, s);
    await this.saveSession(idStr, s);
    await this.idb.set('sessionIdent:' + idStr, bundle.identity_key);
    this.sessions[idStr] = s;
    return s;
  }

  // --- encrypt + send (encryptOlm + the send-form submit) ---
  async sendTo(other, plaintext) {
    const idStr = String(other.userId);
    const out = await this.getOrCreateOutboundSession(other);
    await this.ensureSelfSessions();
    const enc = out.encrypt(plaintext);
    const selfEnc = this.selfOutbound.encrypt(plaintext);
    await this.saveSession(idStr, out);
    await this.saveSelfSessions();
    const recipientCipher = JSON.stringify({ t: enc.type, b: enc.body });
    const senderCipher = JSON.stringify({ t: selfEnc.type, b: selfEnc.body });
    const params = new URLSearchParams();
    params.set('proto', 'olm');
    params.set('body', recipientCipher);
    params.set('sender_ciphertext', senderCipher);
    const r = await this.csrfFetch('/chats/' + encodeURIComponent(other.username) + '/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    if (r.status !== 200 && r.status !== 302) throw new Error('send failed: ' + r.status + ' ' + (await r.text()));
  }

  // --- inbound decrypt ladder (decryptOlm incoming path, exact mirror) ---
  async decryptOlm(msg, isOwn, otherIdStr, theirCurve25519) {
    if (isOwn) {
      const env = JSON.parse(msg.sender_ciphertext || msg.body);
      await this.ensureSelfSessions();
      if (!this.selfInbound) throw new Error('No self-inbound session');
      try {
        return this.selfInbound.decrypt(env.t, env.b);
      } catch (err) {
        if (this.selfInboundBaseline) {
          this.resetSelfInboundBaseline();
          return this.selfInbound.decrypt(env.t, env.b);
        }
        throw err;
      }
    }
    const e = JSON.parse(msg.body);
    const livePickle = await this.idb.get('session:' + otherIdStr);
    const live = livePickle ? (() => { const s = new Olm.Session(); s.unpickle(PICKLE_KEY, livePickle); return s; })() : null;
    if (live) {
      try {
        const plain = live.decrypt(e.t, e.b);
        await this.saveSession(otherIdStr, live);
        return plain;
      } catch (_) {}
    }
    const basePickle = await this.idb.get('sessionBase:' + otherIdStr);
    const base = basePickle ? (() => { const s = new Olm.Session(); s.unpickle(PICKLE_KEY, basePickle); return s; })() : null;
    if (base) {
      try {
        const plain = base.decrypt(e.t, e.b);
        if (!live) await this.saveSession(otherIdStr, base);
        return plain;
      } catch (_) {}
    }
    if (e.t === 0) {
      const ns = new Olm.Session();
      try {
        ns.create_inbound(this.account, e.b);
        this.account.remove_one_time_keys(ns);
        if (theirCurve25519) await this.idb.set('sessionIdent:' + otherIdStr, theirCurve25519);
        await this.saveSessionBaseline(otherIdStr, ns);
        const plain = ns.decrypt(e.t, e.b);
        await this.saveSession(otherIdStr, ns);
        await this.saveAccount();
        return plain;
      } catch (createErr) {
        if (base) {
          try {
            const pBase = base.decrypt(e.t, e.b);
            if (!live) await this.saveSession(otherIdStr, base);
            return pBase;
          } catch (_) {}
        }
        throw createErr;
      }
    }
    throw new Error('No session for sender and message could not be decrypted.');
  }

  resetSelfInboundBaseline() {
    if (!this.selfInboundBaseline) return;
    this.selfInbound = new Olm.Session();
    this.selfInbound.unpickle(PICKLE_KEY, this.selfInboundBaseline);
  }

  // Simulate a page reload: drop in-memory state, restore pickles from IDB.
  async reload() {
    this.sessions = {};
    this.selfOutbound = null;
    this.selfInbound = null;
    const acctPickle = await this.idb.get('account');
    if (acctPickle) {
      this.account = new Olm.Account();
      this.account.unpickle(PICKLE_KEY, acctPickle);
      const k = JSON.parse(this.account.identity_keys());
      this.myIdKeys = { curve25519: k.curve25519, ed25519: k.ed25519 };
    }
    await this.ensureSelfSessions(); // mirrors loadSelfSessions() in ensureReady
    // NOTE: decryptExistingMessages also calls resetSelfInboundBaseline +
    // resetSessionBaseline(otherIdStr) per conversation; we do it in the test
    // helper when needed to stay faithful.
  }

  // Simulate the explicit "Reset encryption keys" flow: purge session pickles,
  // mint + publish a fresh identity, recreate the self-session pair.
  async resetKeys() {
    for (const k of [...this.idb.map.keys()]) {
      if (k === 'account') continue;
      if (k.startsWith('session:') || k.startsWith('sessionBase:') ||
          k.startsWith('sessionIdent:') || k.startsWith('self')) {
        this.idb.map.delete(k);
      }
    }
    this.sessions = {};
    this.selfOutbound = null;
    this.selfInbound = null;
    this.selfInboundBaseline = null;
    await this.initCrypto();
  }
}

async function main() {
  const OlmMod = require('@matrix-org/olm');
  const wasmPath = path.join(path.dirname(require.resolve('@matrix-org/olm/package.json')), 'olm.wasm');
  await OlmMod.init({ wasmBinary: fs.readFileSync(wasmPath) });
  global.Olm = OlmMod;

  const base = 'http://localhost:' + process.env.PORT;

  const aliceId = db.createUser({ username: 'alice', passwordHash: bcrypt.hashSync('pw1', 10), displayName: 'Alice' });
  const bobId = db.createUser({ username: 'bob', passwordHash: bcrypt.hashSync('pw2', 10), displayName: 'Bob' });
  db.follow(aliceId, bobId);
  db.follow(bobId, aliceId);

  const alice = new SimBrowser(base, 'alice', 'pw1', aliceId);
  const bob = new SimBrowser(base, 'bob', 'pw2', bobId);

  await alice.login();
  await bob.login();
  console.log('logged in both simulated browsers');

  await alice.initCrypto();
  await bob.initCrypto();
  // Snapshot bob's account pickle as the browser's password backup would hold
  // it (all peer one-time keys still present, self-session pair created).
  const bobAccountBackup = await bob.idb.get('account');
  console.log('published identities + prekeys + self-sessions for both');

  const aliceCurve = alice.myIdKeys.curve25519;
  const bobCurve = bob.myIdKeys.curve25519;

  const fetchMessages = (fromId, toId) => db.getMessages(fromId, toId)
    .filter((m) => m.from_id === fromId)
    .sort((a, b) => a.id - b.id);

  console.log('\nTEST 1: alice -> bob, first message (fresh PreKey session)');
  await alice.sendTo(bob, 'hello bob #1');
  let msgs = fetchMessages(aliceId, bobId);
  ok(msgs.length === 1, 'one message stored');
  let plain = await bob.decryptOlm(msgs[0], false, String(aliceId), aliceCurve);
  ok(plain === 'hello bob #1', "bob decrypts alice's first message -> " + JSON.stringify(plain));

  console.log('\nTEST 2: alice -> bob, follow-up messages (same chain)');
  await alice.sendTo(bob, 'hello bob #2');
  await alice.sendTo(bob, 'hello bob #3');
  msgs = fetchMessages(aliceId, bobId);
  ok(msgs.length === 3, 'three messages stored');
  plain = await bob.decryptOlm(msgs[1], false, String(aliceId), aliceCurve);
  ok(plain === 'hello bob #2', 'bob decrypts #2 -> ' + JSON.stringify(plain));
  plain = await bob.decryptOlm(msgs[2], false, String(aliceId), aliceCurve);
  ok(plain === 'hello bob #3', 'bob decrypts #3 -> ' + JSON.stringify(plain));

  console.log('\nTEST 3: bob -> alice reply (fresh outbound from bob)');
  await bob.sendTo(alice, 'hello alice #1');
  msgs = fetchMessages(bobId, aliceId);
  ok(msgs.length === 1, 'one reply stored');
  plain = await alice.decryptOlm(msgs[0], false, String(bobId), bobCurve);
  ok(plain === 'hello alice #1', "alice decrypts bob's reply -> " + JSON.stringify(plain));

  console.log('\nTEST 4: page reload on BOTH sides, then alice -> bob #4');
  await alice.reload();
  await bob.reload();
  await alice.sendTo(bob, 'hello bob #4');
  msgs = fetchMessages(aliceId, bobId);
  plain = await bob.decryptOlm(msgs[3], false, String(aliceId), aliceCurve);
  ok(plain === 'hello bob #4', 'bob decrypts #4 after reload -> ' + JSON.stringify(plain));

  console.log('\nTEST 5: after reload, bob -> alice #2, alice decrypts with restored session');
  await bob.sendTo(alice, 'hello alice #2');
  msgs = fetchMessages(bobId, aliceId);
  plain = await alice.decryptOlm(msgs[1], false, String(bobId), bobCurve);
  ok(plain === 'hello alice #2', "alice decrypts bob's #2 after reload -> " + JSON.stringify(plain));

  console.log('\nTEST 6: sender reads their OWN copies (self-session), incl. after reload');
  msgs = fetchMessages(aliceId, bobId);
  plain = await alice.decryptOlm(msgs[3], true, String(bobId), bobCurve);
  ok(plain === 'hello bob #4', 'alice decrypts own copy of #4 -> ' + JSON.stringify(plain));
  msgs = fetchMessages(bobId, aliceId);
  plain = await bob.decryptOlm(msgs[1], true, String(aliceId), aliceCurve);
  ok(plain === 'hello alice #2', "bob decrypts own copy of reply #2 -> " + JSON.stringify(plain));

  console.log('\nTEST 7: page-load replay — baseline fallback with live present (the fixed path)');
  // Bob's live session is post-#4. Replaying older messages must go through the
  // BASELINE (live.decrypt throws BAD_MESSAGE_MAC behind the ratchet) and must
  // NOT overwrite the live session. Only #4 is served from the plaintext cache
  // (its message key was already consumed — exactly why the browser caches
  // plaintexts locally). Note: the sim re-unpickles per call instead of
  // mirroring the in-memory hardening (live restore-from-pickle after a failed
  // decrypt), which is browser-only state.
  msgs = fetchMessages(aliceId, bobId);
  const cachedPlaintexts = new Map(); // msgId -> plaintext (as the browser's localMap)
  cachedPlaintexts.set(String(msgs[3].id), 'hello bob #4');
  const livePickleBefore = await bob.idb.get('session:' + String(aliceId));
  let replayed = 0;
  let replayOk = true;
  for (let i = 0; i < msgs.length; i++) {
    if (cachedPlaintexts.has(String(msgs[i].id))) { replayed++; continue; } // localMap hit
    const p = await bob.decryptOlm(msgs[i], false, String(aliceId), aliceCurve);
    cachedPlaintexts.set(String(msgs[i].id), p);
    replayed++;
    if (p !== 'hello bob #' + (i + 1)) replayOk = false;
  }
  const livePickleAfter = await bob.idb.get('session:' + String(aliceId));
  ok(replayed === 4, 'all 4 messages replayed (3 via baseline crypto + 1 cache hit)');
  ok(replayOk, 'baseline-replayed plaintexts correct');
  ok(livePickleBefore === livePickleAfter, 'baseline replay did not overwrite the live session');
  // A second "page load" hits the cache for every message: no crypto needed.
  const secondPass = msgs.every((m) => cachedPlaintexts.has(String(m.id)));
  ok(secondPass, 'second page load replays entirely from the local cache');

  console.log('\nTEST 8: fresh device (restored account, empty cache, no sessions)');
  // A fresh device restores the account pickle from the password backup (no
  // sessions, no plaintext cache) and can walk the chain from the first
  // PreKey message. The last message (#4) is a ratchet-advance that requires
  // the intermediate reply state this device never had — the browser shows
  // "[unable to decrypt]" for exactly that message and asks the peer to
  // rebuild (rekey), which heals the conversation on the next send. Assert
  // that exact behavior.
  const fresh = new SimBrowser(base, 'bob', 'pw2', bobId);
  await fresh.login();
  // Restore bob's ORIGINAL account pickle (mirrors unlockWithPassword): do NOT
  // mint/publish a new identity, that would rotate bob's keys server-side.
  fresh.account = new Olm.Account();
  fresh.account.unpickle(PICKLE_KEY, bobAccountBackup);
  const freshKeys = JSON.parse(fresh.account.identity_keys());
  fresh.myIdKeys = { curve25519: freshKeys.curve25519, ed25519: freshKeys.ed25519 };
  let freshOk = true;
  for (let i = 0; i < msgs.length; i++) {
    try {
      const p = await fresh.decryptOlm(msgs[i], false, String(aliceId), aliceCurve);
      if (p !== 'hello bob #' + (i + 1)) freshOk = false;
    } catch (err) {
      if (i === msgs.length - 1) {
        ok(/No session|BAD_MESSAGE/.test(err.message || err), 'fresh device: last message triggers rekey path (as designed)');
      } else {
        freshOk = false;
      }
    }
  }
  ok(freshOk, 'fresh device decrypts #1-#3 from the chain start');
  // The rekey heal: bob asks alice to rebuild, alice notices before her next
  // send, rebuilds the outbound session from a fresh prekey bundle and acks.
  const r = await fresh.csrfFetch('/chats/rekey/request', { method: 'POST', body: JSON.stringify({ other_id: aliceId }) });
  ok(r.status === 200, 'rekey request registered');
  const needed = await alice.csrfFetch('/chats/rekey/needed?requester_id=' + bobId).then((x) => x.json());
  ok(needed && needed.needed === true, 'alice sees the pending rekey request');
  await alice.rebuildOutboundSession(bob); // mirrors rebuildOutboundAndAck
  const ack = await alice.csrfFetch('/chats/rekey/ack', { method: 'POST', body: JSON.stringify({ requester_id: bobId }) });
  ok(ack.status === 200, 'rekey acked');
  await alice.sendTo(bob, 'hello bob #5');
  const newMsgs = fetchMessages(aliceId, bobId);
  const p5 = await fresh.decryptOlm(newMsgs[4], false, String(aliceId), aliceCurve);
  ok(p5 === 'hello bob #5', 'fresh device decrypts the rebuilt-session message -> ' + JSON.stringify(p5));

  console.log('\nTEST 9: receiver key reset heals the conversation (rotation detect + rebuild)');
  // The escape hatch for a permanently desynced device: bob resets his keys
  // (new identity published, old sessions purged). Alice's next send detects
  // the rotation via /chats/:username/safety and rebuilds her outbound session;
  // the fresh PreKey message decrypts on bob's reset device.
  const oldBobIdentity = db.getOlmIdentity(bobId).identity_key;
  await bob.resetKeys();
  const newBobIdentity = db.getOlmIdentity(bobId).identity_key;
  ok(newBobIdentity !== oldBobIdentity, 'reset published a new identity server-side');
  const safety = await alice.csrfFetch('/chats/bob/safety').then((x) => x.json());
  ok(safety.their_curve25519 === newBobIdentity, 'safety endpoint exposes the rotated identity');
  // /chats/prekeys/identity: bob's own view matches his local (reset) account.
  const ownId = await bob.csrfFetch('/chats/prekeys/identity').then((x) => x.json());
  ok(ownId.identity_key === newBobIdentity && ownId.identity_key === bob.myIdKeys.curve25519,
    '/chats/prekeys/identity matches the local account after reset');
  // Alice detects the rotation (mirrors checkOutboundSessionIdentity) and rebuilds.
  await alice.rebuildOutboundSession(bob);
  await alice.sendTo(bob, 'hello bob #6');
  const postReset = fetchMessages(aliceId, bobId);
  const p6 = await bob.decryptOlm(postReset[5], false, String(aliceId), alice.myIdKeys.curve25519);
  ok(p6 === 'hello bob #6', 'bob decrypts after key reset + sender rebuild -> ' + JSON.stringify(p6));
  // And bob can reply again on the rebuilt chain.
  await bob.sendTo(alice, 'hello alice #3');
  const replyMsgs = fetchMessages(bobId, aliceId);
  const pReply = await alice.decryptOlm(replyMsgs[2], false, String(bobId), bob.myIdKeys.curve25519);
  ok(pReply === 'hello alice #3', 'alice decrypts bob reply after reset -> ' + JSON.stringify(pReply));

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
