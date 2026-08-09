'use strict';

const { DatabaseSync } = require('node:sqlite');
const { Store } = require('express-session');
const path = require('node:path');
const fs = require('node:fs');

const DB_PATH = process.env.EXTV_SESSION_DB_PATH || path.join(__dirname, '..', 'data', 'sessions.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )
`);
db.exec('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)');
// One row per (session, account) signed in on that device — survives server
// restarts because the session store is DB-backed. `active` marks the account
// currently acting as the session's userId (F1 multi-account).
db.exec(`
  CREATE TABLE IF NOT EXISTS account_sessions (
    session_id TEXT NOT NULL,
    user_id    INTEGER NOT NULL,
    active     INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, user_id)
  )
`);

const PURGE_INTERVAL = 900_000; // 15 min
let lastPurge = 0;

function purgeExpired() {
  const now = Date.now();
  if (now - lastPurge < PURGE_INTERVAL) return;
  lastPurge = now;
  const expired = db.prepare(`SELECT sid FROM sessions WHERE expires_at <= ?`).all(now);
  if (expired.length) {
    db.prepare(`DELETE FROM sessions WHERE expires_at <= ?`).run(now);
    const del = db.prepare(`DELETE FROM account_sessions WHERE session_id = ?`);
    for (const row of expired) del.run(row.sid);
  }
}

// Mirror the session's account list into the account_sessions table. Called on
// every session write, so login/logout/switch stay consistent even across
// restarts (the session row and its account rows are written together).
function syncAccountSessions(sid, session) {
  const ids = Array.isArray(session.accountIds) && session.accountIds.length > 0
    ? session.accountIds
    : (session.userId ? [session.userId] : []);
  const activeId = session.userId;
  db.prepare(`DELETE FROM account_sessions WHERE session_id = ?`).run(sid);
  if (ids.length === 0) return;
  const ins = db.prepare(`INSERT INTO account_sessions (session_id, user_id, active, created_at) VALUES (?,?,?,?)`);
  const now = Date.now();
  for (const userId of ids) {
    ins.run(sid, userId, userId === activeId ? 1 : 0, now);
  }
}

class SqliteStore extends Store {
  get(sid, cb) {
    try {
      purgeExpired();
      const row = db.prepare(`SELECT data, expires_at FROM sessions WHERE sid = ?`).get(sid);
      if (!row) return cb(null, null);
      if (row.expires_at <= Date.now()) {
        db.prepare(`DELETE FROM sessions WHERE sid = ?`).run(sid);
        return cb(null, null);
      }
      cb(null, JSON.parse(row.data));
    } catch (err) {
      console.error('Session store get error:', err);
      cb(err);
    }
  }

  set(sid, session, cb) {
    try {
      const expiresAt = session.cookie && session.cookie.maxAge
        ? Date.now() + session.cookie.maxAge
        : Date.now() + 86400000;
      const data = JSON.stringify(session);
      db.prepare(`
        INSERT INTO sessions (sid, data, expires_at) VALUES (?,?,?)
        ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at
      `).run(sid, data, expiresAt);
      syncAccountSessions(sid, session);
      cb(null);
    } catch (err) {
      console.error('Session store set error:', err);
      cb(err);
    }
  }

  destroy(sid, cb) {
    try {
      db.prepare(`DELETE FROM sessions WHERE sid = ?`).run(sid);
      db.prepare(`DELETE FROM account_sessions WHERE session_id = ?`).run(sid);
      cb(null);
    } catch (err) {
      cb(err);
    }
  }

  touch(sid, session, cb) {
    try {
      if (session.cookie && session.cookie.maxAge) {
        const expiresAt = Date.now() + session.cookie.maxAge;
        db.prepare(`UPDATE sessions SET expires_at = ? WHERE sid = ?`).run(expiresAt, sid);
      }
      cb(null);
    } catch (err) {
      cb(err);
    }
  }

  length(cb) {
    try {
      purgeExpired();
      const row = db.prepare(`SELECT COUNT(*) AS n FROM sessions`).get();
      cb(null, row.n);
    } catch (err) {
      cb(err);
    }
  }

  clear(cb) {
    try {
      db.prepare(`DELETE FROM sessions`).run();
      db.prepare(`DELETE FROM account_sessions`).run();
      cb(null);
    } catch (err) {
      cb(err);
    }
  }
}

// Read the persisted account list for a session (used by tests / diagnostics).
function listAccountSessions(sid) {
  return db.prepare(`SELECT user_id, active FROM account_sessions WHERE session_id = ? ORDER BY rowid`).all(sid);
}

module.exports = SqliteStore;
module.exports.listAccountSessions = listAccountSessions;
