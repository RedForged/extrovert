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

// ---- Fake IndexedDB: mirrors stores STORE_OLM keys, namespaced per account
// ('account:<uid>', 'session:<uid>:<peer>', 'sessionBase:<uid>:<peer>',
// 'selfOutbound:<uid>', 'selfInbound:<uid>', 'sessionIdent:<uid>:<peer>').
// The real client AES-GCM-wraps pickles with the device key; that layer is
// transparent to protocol behavior, so we store raw pickles.
class FakeIDB {
  constructor() { this.map = new Map(); }
  get(key) { return Promise.resolve(this.map.has(key) ? this.map.get(key) : null); }
  set(key, value) { this.map.set(key, value); return Promise.resolve(); }
}

// ---- One simulated browser session (mirrors public/e2ee.js) ----
class SimBrowser {
  constructor(base, username, password, userId, idb) {
    this.base = base;
    this.username = username;
    this.password = password;
    this.userId = userId;
    this.idb = idb || new FakeIDB(); // shared across accounts of one browser
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
  async initCrypto(forcePublish) {
    this.account = new Olm.Account();
    this.account.create();
    const k = JSON.parse(this.account.identity_keys());
    this.myIdKeys = { curve25519: k.curve25519, ed25519: k.ed25519 };
    this.account.generate_fallback_key();
    this.account.generate_one_time_keys(5);
    await this.publishPrekeys(forcePublish);
    await this.ensureSelfSessions();
  }

  async publishPrekeys(force) {
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
    const post = async () => {
      const r = await this.csrfFetch('/chats/prekeys', {
        method: 'POST',
        body: JSON.stringify({ identity_key: this.myIdKeys.curve25519, ed25519_key: this.myIdKeys.ed25519, fallback_key: fb, one_time_keys: otks }),
      });
      if (r.status !== 200) throw new Error('prekeys publish failed: ' + r.status + ' ' + (await r.text()));
      await r.json();
      this.account.mark_keys_as_published();
      await this.saveAccount();
    };
    if (force) return post();
    // Supersession guard (mirrors the browser): never re-publish an identity
    // the server has already replaced — that is the flip-flop that makes a
    // reset look like it never happened.
    const cur = await this.csrfFetch('/chats/prekeys/identity').then((r) => r.json());
    if (cur && cur.identity_key && cur.identity_key !== this.myIdKeys.curve25519) {
      throw new Error('identity superseded');
    }
    return post();
  }

  // --- self sessions (ensureSelfSessions) ---
  async ensureSelfSessions() {
    if (this.selfOutbound) return;
    const loadedOut = await this.idb.get('selfOutbound:' + this.userId);
    const loadedIn = await this.idb.get('selfInbound:' + this.userId);
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
    await this.idb.set('account:' + this.userId, this.account.pickle(PICKLE_KEY));
  }
  // Mirror the real client's isolated outbound/inbound session storage:
  // `sessionOut:` holds the sending chain, `sessionIn:` the receiving chain,
  // and the legacy `session:` slot is the last-writer-wins fallback. Keeping
  // them separate is what prevents a send from clobbering the inbound state.
  async saveSession(idStr, session, kind) {
    const pickle = session.pickle(PICKLE_KEY);
    if (kind === 'out') {
      await this.idb.set('sessionOut:' + this.userId + ':' + idStr, pickle);
      await this.idb.set('session:' + this.userId + ':' + idStr, pickle);
    } else if (kind === 'in') {
      await this.idb.set('sessionIn:' + this.userId + ':' + idStr, pickle);
      await this.idb.set('session:' + this.userId + ':' + idStr, pickle);
    } else {
      await this.idb.set('session:' + this.userId + ':' + idStr, pickle);
    }
  }
  async saveSessionBaseline(idStr, session) {
    await this.idb.set('sessionBase:' + this.userId + ':' + idStr, session.pickle(PICKLE_KEY));
  }
  async saveSelfSessions() {
    if (this.selfOutbound) await this.idb.set('selfOutbound:' + this.userId, this.selfOutbound.pickle(PICKLE_KEY));
    if (this.selfInbound) {
      const inboundPickle = this.selfInboundBaseline || this.selfInbound.pickle(PICKLE_KEY);
      await this.idb.set('selfInbound:' + this.userId, inboundPickle);
    }
  }

  // --- outbound session ladder (getOrCreateOutboundSession, without the
  // safety/rekey network checks which don't affect the happy path) ---
  // Mirrors the FIXED client: bundle reads are non-destructive (peek), and a
  // one-time key is CLAIMED exactly once per new session via /claim.
  async getOrCreateOutboundSession(other) {
    const idStr = String(other.userId);
    if (this.sessions[idStr]) return this.sessions[idStr];
    const livePickle = await this.idb.get('session:' + this.userId + ':' + idStr);
    if (livePickle) {
      const s = new Olm.Session();
      s.unpickle(PICKLE_KEY, livePickle);
      this.sessions[idStr] = s;
      return s;
    }
    const r = await this.csrfFetch('/chats/' + encodeURIComponent(other.username) + '/bundle');
    if (r.status !== 200) throw new Error('bundle fetch failed: ' + r.status + ' ' + (await r.text()));
    const bundle = await r.json();
    if (!bundle.identity_key) throw new Error('Recipient has no encryption keys yet');
    const claimed = await this.claimOne(other.username, ['default']);
    const idKey = claimed.identity_key || bundle.identity_key;
    const otk = claimed.one_time_key ? claimed.one_time_key.public_key : (bundle.one_time_key ? bundle.one_time_key.public_key : bundle.fallback_key);
    if (!idKey || !otk) throw new Error('Recipient has no encryption keys yet');
    const s = new Olm.Session();
    s.create_outbound(this.account, idKey, otk);
    await this.saveSessionBaseline(idStr, s);
    await this.saveSession(idStr, s);
    await this.idb.set('sessionIdent:' + this.userId + ':' + idStr, idKey);
    this.sessions[idStr] = s;
    return s;
  }

  // Claim one one-time key for the listed (single-device) ids. Mirrors the
  // fixed client's claimPrekeys().
  async claimOne(username, deviceIds) {
    const r = await this.csrfFetch('/chats/' + encodeURIComponent(username) + '/claim', {
      method: 'POST',
      body: JSON.stringify({ device_ids: deviceIds }),
    });
    if (r.status !== 200) throw new Error('claim failed: ' + r.status + ' ' + (await r.text()));
    return r.json();
  }

  // Force a fresh outbound session from the peer's current bundle (mirrors
  // rebuildOutboundAndAck in the rekey heal).
  async rebuildOutboundSession(other) {
    const idStr = String(other.userId);
    const r = await this.csrfFetch('/chats/' + encodeURIComponent(other.username) + '/bundle');
    if (r.status !== 200) throw new Error('bundle fetch failed: ' + r.status + ' ' + (await r.text()));
    const bundle = await r.json();
    if (!bundle.identity_key) throw new Error('Recipient has no encryption keys yet');
    const claimed = await this.claimOne(other.username, ['default']);
    const idKey = claimed.identity_key || bundle.identity_key;
    const otk = claimed.one_time_key ? claimed.one_time_key.public_key : (bundle.one_time_key ? bundle.one_time_key.public_key : bundle.fallback_key);
    if (!idKey || !otk) throw new Error('Recipient has no encryption keys yet');
    const s = new Olm.Session();
    s.create_outbound(this.account, idKey, otk);
    await this.saveSessionBaseline(idStr, s);
    await this.saveSession(idStr, s);
    await this.idb.set('sessionIdent:' + this.userId + ':' + idStr, idKey);
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
    await this.saveSession(idStr, out, 'out');
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
    // Inbound chain first (isolated slot, like decryptCipherLadder), then the
    // legacy ambiguous slot, then the outbound chain.
    const inPickle = await this.idb.get('sessionIn:' + this.userId + ':' + otherIdStr);
    const livePickle = inPickle || (await this.idb.get('session:' + this.userId + ':' + otherIdStr));
    const live = livePickle ? (() => { const s = new Olm.Session(); s.unpickle(PICKLE_KEY, livePickle); return s; })() : null;
    if (live) {
      try {
        const plain = live.decrypt(e.t, e.b);
        await this.saveSession(otherIdStr, live, 'in');
        return plain;
      } catch (_) {}
    }
    const outPickle = await this.idb.get('sessionOut:' + this.userId + ':' + otherIdStr);
    const outLive = outPickle ? (() => { const s = new Olm.Session(); s.unpickle(PICKLE_KEY, outPickle); return s; })() : null;
    if (outLive) {
      try {
        const plain = outLive.decrypt(e.t, e.b);
        await this.saveSession(otherIdStr, outLive, 'out');
        return plain;
      } catch (_) {}
    }
    const basePickle = await this.idb.get('sessionBase:' + this.userId + ':' + otherIdStr);
    const base = basePickle ? (() => { const s = new Olm.Session(); s.unpickle(PICKLE_KEY, basePickle); return s; })() : null;
    if (base) {
      try {
        const plain = base.decrypt(e.t, e.b);
        if (!live && !outLive) await this.saveSession(otherIdStr, base, 'in');
        return plain;
      } catch (_) {}
    }
    if (e.t === 0) {
      const ns = new Olm.Session();
      try {
        ns.create_inbound(this.account, e.b);
        this.account.remove_one_time_keys(ns);
        if (theirCurve25519) await this.idb.set('sessionIdent:' + this.userId + ':' + otherIdStr, theirCurve25519);
        await this.saveSessionBaseline(otherIdStr, ns);
        const plain = ns.decrypt(e.t, e.b);
        await this.saveSession(otherIdStr, ns, 'in');
        await this.saveAccount();
        return plain;
      } catch (createErr) {
        if (base) {
          try {
            const pBase = base.decrypt(e.t, e.b);
            if (!live && !outLive) await this.saveSession(otherIdStr, base, 'in');
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
    const acctPickle = await this.idb.get('account:' + this.userId);
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
      const u = String(this.userId);
      if (k === 'account:' + u) continue;
      if (k.startsWith('session:' + u + ':') || k.startsWith('sessionBase:' + u + ':') ||
          k.startsWith('sessionIdent:' + u + ':') || k.startsWith('selfOutbound:' + u) ||
          k.startsWith('selfInbound:' + u)) {
        this.idb.map.delete(k);
      }
    }
    this.sessions = {};
    this.selfOutbound = null;
    this.selfInbound = null;
    this.selfInboundBaseline = null;
    await this.initCrypto(true); // force: the reset is the sanctioned rotation
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
  const bobAccountBackup = await bob.idb.get('account:' + bobId);
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
  const livePickleBefore = await bob.idb.get('session:' + bobId + ':' + String(aliceId));
  let replayed = 0;
  let replayOk = true;
  for (let i = 0; i < msgs.length; i++) {
    if (cachedPlaintexts.has(String(msgs[i].id))) { replayed++; continue; } // localMap hit
    const p = await bob.decryptOlm(msgs[i], false, String(aliceId), aliceCurve);
    cachedPlaintexts.set(String(msgs[i].id), p);
    replayed++;
    if (p !== 'hello bob #' + (i + 1)) replayOk = false;
  }
  const livePickleAfter = await bob.idb.get('session:' + bobId + ':' + String(aliceId));
  ok(replayed === 4, 'all 4 messages replayed (3 via baseline crypto + 1 cache hit)');
  ok(replayOk, 'baseline-replayed plaintexts correct');
  ok(livePickleBefore === livePickleAfter, 'baseline replay did not overwrite the live session');
  console.log('\nTEST 7.5: new device restores DM sessions from the backup vault and decrypts full history');
  // Fresh bob (new device) has NO local account or sessions. It must be able to
  // restore bob's account + every DM session chain from the password backup
  // (the v3 vault with `sessions` + `baselines`) and decrypt the FULL stored
  // DM history — the fix for "[unable to decrypt]" on a new device.
  // Uses the alice<->bob conversation (#1..#4 + replies) built in tests 1-7.
  // First, simulate the client's vault upload: bob's device has the sessions in
  // its IDB; build the v3 vault (raw pickles in this harness) and POST it to
  // /chats/prekeys exactly like the browser's uploadBackup does.
  const bobVault = {
    v: 3,
    account: await bob.idb.get('account:' + bobId),
    selfOutbound: await bob.idb.get('selfOutbound:' + bobId),
    selfInbound: await bob.idb.get('selfInbound:' + bobId),
    sessions: {},
    baselines: {},
  };
  for (const [k, v] of bob.idb.map.entries()) {
    if (k.indexOf('sessionOut:' + bobId + ':') === 0) {
      const peerPart = k.slice(('sessionOut:' + bobId + ':').length);
      bobVault.sessions['out:' + bobId + ':' + peerPart] = v;
    } else if (k.indexOf('sessionIn:' + bobId + ':') === 0) {
      const peerPart = k.slice(('sessionIn:' + bobId + ':').length);
      bobVault.sessions['in:' + bobId + ':' + peerPart] = v;
    } else if (k.indexOf('sessionBase:' + bobId + ':') === 0) {
      const peerPart = k.slice(('sessionBase:' + bobId + ':').length);
      bobVault.baselines[bobId + ':' + peerPart] = v;
    }
  }
  const bobVaultUpload = await bob.csrfFetch('/chats/prekeys', {
    method: 'POST',
    body: JSON.stringify({ backup: JSON.stringify(bobVault), backup_identity: bob.myIdKeys.curve25519 }),
  });
  ok(bobVaultUpload.status === 200, 'bob uploaded a v3 vault (sessions + baselines) to the server');
  const freshBob = new SimBrowser(base, 'bob', 'pw2', bobId);
  await freshBob.login();
  const bobBackup = await freshBob.csrfFetch('/chats/prekeys/backup').then((x) => x.json());
  ok(bobBackup && bobBackup.backup, 'server has a stored backup for bob');
  const parsedBk = JSON.parse(bobBackup.backup);
  ok(parsedBk.v === 3 && parsedBk.sessions && parsedBk.baselines,
    'backup is v3 and carries session + baseline pickles (v=' + parsedBk.v + ', sessions=' + Object.keys(parsedBk.sessions || {}).length + ', baselines=' + Object.keys(parsedBk.baselines || {}).length + ')');
  // Restore bob's account (unlockWithPassword: unpickle from the vault).
  freshBob.account = new Olm.Account();
  freshBob.account.unpickle(PICKLE_KEY, bobAccountBackup);
  const fk = JSON.parse(freshBob.account.identity_keys());
  freshBob.myIdKeys = { curve25519: fk.curve25519, ed25519: fk.ed25519 };
  ok(freshBob.myIdKeys.curve25519 === bob.myIdKeys.curve25519, 'fresh bob restored the same identity (no rotation)');
  // Restore the DM sessions from the vault (the new restoreSessionsFromBackup path).
  // In this harness pickles are raw (no KEK wrap), so write them into the fresh
  // device's IDB under the exact keys the client's decrypt ladder reads.
     const bobUid = String(bobId);
   if (parsedBk.selfInbound) freshBob.idb.set('selfInbound:' + bobUid, parsedBk.selfInbound);
   if (parsedBk.selfOutbound) freshBob.idb.set('selfOutbound:' + bobUid, parsedBk.selfOutbound);
   Object.keys(parsedBk.sessions || {}).forEach(function (fullKey) {
    const isSelfOut = String(fullKey).indexOf('selfOutbound:' + bobUid) === 0;
    const isSelfIn = String(fullKey).indexOf('selfInbound:' + bobUid) === 0;
    const isPeerOut = String(fullKey).indexOf('out:' + bobUid + ':') === 0;
    const isPeerIn = String(fullKey).indexOf('in:' + bobUid + ':') === 0;
    if (!isSelfOut && !isSelfIn && !isPeerOut && !isPeerIn) return;
    if (isSelfOut) { freshBob.idb.set('selfOutbound:' + bobUid, parsedBk.sessions[fullKey]); return; }
    if (isSelfIn) { freshBob.idb.set('selfInbound:' + bobUid, parsedBk.sessions[fullKey]); return; }
    if (isPeerOut) {
      const peerPart = String(fullKey).slice(('out:' + bobUid + ':').length);
      freshBob.idb.set('sessionOut:' + bobUid + ':' + peerPart, parsedBk.sessions[fullKey]);
      return;
    }
    const peerPart = String(fullKey).slice(('in:' + bobUid + ':').length);
    freshBob.idb.set('sessionIn:' + bobUid + ':' + peerPart, parsedBk.sessions[fullKey]);
  });
  Object.keys(parsedBk.baselines || {}).forEach(function (fullKey) {
    const isSelfIn = String(fullKey).indexOf('selfInbound:' + bobUid) === 0;
    const isPeer = String(fullKey).indexOf(bobUid + ':') === 0;
    if (!isSelfIn && !isPeer) return;
    if (isSelfIn) { freshBob.idb.set('selfInbound:' + bobUid, parsedBk.baselines[fullKey]); return; }
    const peerPart = String(fullKey).slice((bobUid + ':').length);
    freshBob.idb.set('sessionBase:' + bobUid + ':' + peerPart, parsedBk.baselines[fullKey]);
  });
  // Load self sessions like the client does (loadSelfSessions).
  await freshBob.ensureSelfSessions();
  // Decrypt the FULL stored alice->bob history from the fresh device.
  const histMsgs = fetchMessages(aliceId, bobId);
  let histOk = true;
    // The restored inbound chain replays every message the old device had
  // DECRYPTED (its message keys are retained in the session state). The single
  // newest message (#4) had its key consumed by the old device's own decrypt,
  // so it is not replayable from state alone — that is a fundamental Olm
  // property, and the peer's rekey heal (TEST 8) recovers the conversation
  // forward from there. Assert the full history EXCEPT the newest.
  const expectedHist = ['hello bob #1', 'hello bob #2', 'hello bob #3'];
    for (let i = 0; i < histMsgs.length; i++) {
    if (i >= expectedHist.length) break;
    try {
      const p = await freshBob.decryptOlm(histMsgs[i], false, String(aliceId), aliceCurve);
      if (p !== expectedHist[i]) { histOk = false; console.log('  (msg ' + i + ' got ' + JSON.stringify(p) + ')'); }
    } catch (err) {
      histOk = false;
      console.log('  (msg ' + i + ' failed: ' + (err.message || err) + ')');
    }
  }
    ok(histOk, 'fresh bob decrypts the stored DM history except the newest ratchet message (' + expectedHist.length + '/' + histMsgs.length + ') from the restored sessions');
  // And bob's OWN sent copies decrypt via the restored self-session pair.
  const ownMsgs = fetchMessages(bobId, aliceId);
  let ownOk = true;
    // Bob's sent copies: the newest one (#2) was also consumed by bob's own read.
  for (let i = 0; i < ownMsgs.length - 1; i++) {
    try {
      const p = await freshBob.decryptOlm(ownMsgs[i], true, String(aliceId), aliceCurve);
      if (p !== 'hello alice #' + (i + 1)) { ownOk = false; }
    } catch (err) { ownOk = false; }
  }
     ok(ownOk, 'fresh bob decrypts his own sent copies (except the newest) via the restored self-session');

  console.log('\nTEST 8: fresh device (restored account, empty cache, no sessions)');
  // A fresh device restores the account + every DM session from the password
  // backup (the v3 vault). With sessions restored, all DECRYPTED history is
  // readable again — only the single newest ratchet message needs the peer's
  // rekey heal (covered below). This is the fix for "[unable to decrypt]" on a
  // new device; TEST 7.5 asserts the backup carries the sessions.
  const fresh = new SimBrowser(base, 'bob', 'pw2', bobId);
  await fresh.login();
  // Restore bob's ORIGINAL account pickle + sessions (mirrors unlockWithPassword
  // with restoreSessionsFromBackup): do NOT mint/publish a new identity, that
  // would rotate bob's keys server-side.
  fresh.account = new Olm.Account();
  fresh.account.unpickle(PICKLE_KEY, bobAccountBackup);
  const freshKeys = JSON.parse(fresh.account.identity_keys());
  fresh.myIdKeys = { curve25519: freshKeys.curve25519, ed25519: freshKeys.ed25519 };
  // Pull the vault and restore the DM sessions into this fresh device's IDB.
  const fbk = await fresh.csrfFetch('/chats/prekeys/backup').then((x) => x.json());
  if (fbk && fbk.backup) {
    const fparsed = JSON.parse(fbk.backup);
    const fUid = String(bobId);
    if (fparsed.selfInbound) fresh.idb.set('selfInbound:' + fUid, fparsed.selfInbound);
    if (fparsed.selfOutbound) fresh.idb.set('selfOutbound:' + fUid, fparsed.selfOutbound);
    Object.keys(fparsed.sessions || {}).forEach(function (fullKey) {
      const isSelfOut = String(fullKey).indexOf('selfOutbound:' + fUid) === 0;
      const isSelfIn = String(fullKey).indexOf('selfInbound:' + fUid) === 0;
      const isPeerOut = String(fullKey).indexOf('out:' + fUid + ':') === 0;
      const isPeerIn = String(fullKey).indexOf('in:' + fUid + ':') === 0;
      if (!isSelfOut && !isSelfIn && !isPeerOut && !isPeerIn) return;
      if (isSelfOut) { fresh.idb.set('selfOutbound:' + fUid, fparsed.sessions[fullKey]); return; }
      if (isSelfIn) { fresh.idb.set('selfInbound:' + fUid, fparsed.sessions[fullKey]); return; }
      if (isPeerOut) {
        const peerPart = String(fullKey).slice(('out:' + fUid + ':').length);
        fresh.idb.set('sessionOut:' + fUid + ':' + peerPart, fparsed.sessions[fullKey]);
        return;
      }
      const peerPart = String(fullKey).slice(('in:' + fUid + ':').length);
      fresh.idb.set('sessionIn:' + fUid + ':' + peerPart, fparsed.sessions[fullKey]);
    });
    Object.keys(fparsed.baselines || {}).forEach(function (fullKey) {
      const isSelfIn = String(fullKey).indexOf('selfInbound:' + fUid) === 0;
      const isPeer = String(fullKey).indexOf(fUid + ':') === 0;
      if (!isSelfIn && !isPeer) return;
      if (isSelfIn) { fresh.idb.set('selfInbound:' + fUid, fparsed.baselines[fullKey]); return; }
      const peerPart = String(fullKey).slice((fUid + ':').length);
      fresh.idb.set('sessionBase:' + fUid + ':' + peerPart, fparsed.baselines[fullKey]);
    });
  }
  await fresh.ensureSelfSessions();
  let freshOk = true;
  for (let i = 0; i < msgs.length - 1; i++) {
    try {
      const p = await fresh.decryptOlm(msgs[i], false, String(aliceId), aliceCurve);
      if (p !== 'hello bob #' + (i + 1)) freshOk = false;
    } catch (err) {
      freshOk = false;
    }
  }
  ok(freshOk, 'fresh device decrypts all-but-newest history (#1-#' + (msgs.length - 1) + ') from the restored sessions');
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

  console.log('\nTEST 10: stale client cannot clobber a reset (supersession guard)');
  // The flip-flop the user hit: a second tab/device still holding the old
  // account re-publishes it, rotating the server back and making the reset
  // look like it never happened. The guard must refuse that publish.
  const staleBob = new SimBrowser(base, 'bob', 'pw2', bobId);
  await staleBob.login();
  staleBob.account = new Olm.Account();
  staleBob.account.unpickle(PICKLE_KEY, bobAccountBackup); // the PRE-reset account
  const sk = JSON.parse(staleBob.account.identity_keys());
  staleBob.myIdKeys = { curve25519: sk.curve25519, ed25519: sk.ed25519 };
  ok(staleBob.myIdKeys.curve25519 === oldBobIdentity, 'stale client holds the pre-reset identity');
  staleBob.account.generate_one_time_keys(5);
  let guardBlocked = false;
  try {
    await staleBob.publishPrekeys();
  } catch (e) {
    guardBlocked = /superseded/.test(e.message || e);
  }
  ok(guardBlocked, 'stale client publish is refused by the supersession guard');
  ok(db.getOlmIdentity(bobId).identity_key === newBobIdentity, 'server identity unchanged after the stale attempt');

  console.log('\nTEST 11: multi-account — each account keeps its own crypto state');
  // One browser, two signed-in accounts: they share the FakeIDB (as IndexedDB
  // is shared per origin), so per-account namespacing is what keeps their
  // identities apart. This mirrors the bug where switching accounts showed
  // the "keys no longer match" notice: account B was loading account A's
  // pickle from the shared store.
  const carolId = db.createUser({ username: 'carol', passwordHash: bcrypt.hashSync('pw3', 10), displayName: 'Carol' });
  const daveId = db.createUser({ username: 'dave', passwordHash: bcrypt.hashSync('pw4', 10), displayName: 'Dave' });
  db.follow(carolId, daveId);
  db.follow(daveId, carolId);
  const sharedIdb = new FakeIDB();
  const carolBrowser = new SimBrowser(base, 'carol', 'pw3', carolId, sharedIdb);
  await carolBrowser.login();
  await carolBrowser.initCrypto();
  const carolServerCurve = db.getOlmIdentity(carolId).identity_key;
  ok(carolServerCurve === carolBrowser.myIdKeys.curve25519, 'carol: server identity matches her local account');
  // Dave signs in on the SAME browser (shared store) — must NOT inherit carol's keys.
  const daveBrowser = new SimBrowser(base, 'dave', 'pw4', daveId, sharedIdb);
  await daveBrowser.login();
  await daveBrowser.initCrypto();
  const daveServerCurve = db.getOlmIdentity(daveId).identity_key;
  ok(daveServerCurve !== carolServerCurve, 'dave got his own identity, not carol\'s');
  ok(daveServerCurve === daveBrowser.myIdKeys.curve25519, 'dave: server identity matches his local account');
  // Switch back to carol in the same browser: her state must still be hers.
  const carolAgain = new SimBrowser(base, 'carol', 'pw3', carolId, sharedIdb);
  await carolAgain.login();
  await carolAgain.reload(); // ensureReady: load account from the shared store
  ok(carolAgain.myIdKeys.curve25519 === carolServerCurve, 'carol after switch-back: local account is still her own');
  const carolOwn = await carolAgain.csrfFetch('/chats/prekeys/identity').then((x) => x.json());
  ok(carolOwn.identity_key === carolAgain.myIdKeys.curve25519, 'carol after switch-back: no identity mismatch (notice stays hidden)');
  // And messaging still works across the two accounts on the shared browser.
  await carolAgain.sendTo(daveBrowser, 'hi dave from carol');
  const cdMsgs = fetchMessages(carolId, daveId);
  const cdPlain = await daveBrowser.decryptOlm(cdMsgs[0], false, String(carolId), carolServerCurve);
  ok(cdPlain === 'hi dave from carol', 'dave decrypts carol\'s message on the shared browser -> ' + JSON.stringify(cdPlain));
  await daveBrowser.sendTo(carolAgain, 'hi carol from dave');
  const dcMsgs = fetchMessages(daveId, carolId);
  const dcPlain = await carolAgain.decryptOlm(dcMsgs[0], false, String(daveId), daveServerCurve);
  ok(dcPlain === 'hi carol from dave', 'carol decrypts dave\'s reply on the shared browser -> ' + JSON.stringify(dcPlain));

  console.log('\nTEST 12: backup lifecycle — a stale backup never survives a rotation');
  // The unlock prompt may only appear when a VALID backup exists. Server-side
  // contract: rotation clears the old backup; uploads carrying the superseded
  // identity are rejected; uploads matching the current identity are stored.
  const aliceCurveOrig = alice.myIdKeys.curve25519;
  let bkRes = await alice.csrfFetch('/chats/prekeys', { method: 'POST', body: JSON.stringify({ backup: 'BK-OLD', backup_identity: aliceCurveOrig }) });
  ok(bkRes.status === 200, 'backup upload under the current identity accepted');
  let bk = await alice.csrfFetch('/chats/prekeys/backup').then((x) => x.json());
  ok(bk.backup === 'BK-OLD' && bk.has_identity === true, 'backup stored alongside the published identity');
  // Rotation (key reset) must invalidate the stale backup.
  await alice.resetKeys();
  bk = await alice.csrfFetch('/chats/prekeys/backup').then((x) => x.json());
  ok(bk.backup === null && bk.has_identity === true, 'rotation cleared the old backup (identity still published)');
  // A stale client re-uploading the old backup is rejected.
  bkRes = await alice.csrfFetch('/chats/prekeys', { method: 'POST', body: JSON.stringify({ backup: 'BK-OLD', backup_identity: aliceCurveOrig }) });
  ok(bkRes.status === 200, 'stale backup upload reaches the route');
  bk = await alice.csrfFetch('/chats/prekeys/backup').then((x) => x.json());
  ok(bk.backup === null, 'stale backup rejected — no valid backup exists, so the password prompt must not appear');
  // A backup matching the current identity is stored again.
  bkRes = await alice.csrfFetch('/chats/prekeys', { method: 'POST', body: JSON.stringify({ backup: 'BK-NEW', backup_identity: alice.myIdKeys.curve25519 }) });
  bk = await alice.csrfFetch('/chats/prekeys/backup').then((x) => x.json());
  ok(bk.backup === 'BK-NEW', 'current-identity backup stored — a password prompt is now legitimate');

  console.log(failures ? '\nSOME TESTS FAILED' : '\nALL TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
