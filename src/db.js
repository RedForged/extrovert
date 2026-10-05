'use strict';

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const DB_PATH = process.env.EXTV_DB_PATH || path.join(__dirname, '..', 'data', 'extrovert.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA busy_timeout = 5000;');
db.exec('PRAGMA foreign_keys = ON;');

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      display_name  TEXT NOT NULL,
      bio           TEXT NOT NULL DEFAULT '',
      created_at    INTEGER NOT NULL,
      theme         TEXT NOT NULL DEFAULT 'default',
      referral_code TEXT,
      referred_by  INTEGER REFERENCES users(id),
      referrer_ip   TEXT,
      is_admin     INTEGER NOT NULL DEFAULT 0,
      banned       INTEGER NOT NULL DEFAULT 0,
      avatar       TEXT
    );

    CREATE TABLE IF NOT EXISTS follows (
      follower_id INTEGER NOT NULL REFERENCES users(id),
      followee_id INTEGER NOT NULL REFERENCES users(id),
      created_at  INTEGER NOT NULL,
      PRIMARY KEY (follower_id, followee_id)
    );

    -- A follow that was triggered specifically by viewing a post.
    -- This is the "follow someone because of a post" signal: a BIG boost.
    CREATE TABLE IF NOT EXISTS follows_from_post (
      follower_id INTEGER NOT NULL REFERENCES users(id),
      followee_id INTEGER NOT NULL REFERENCES users(id),
      post_id     INTEGER NOT NULL REFERENCES posts(id),
      created_at  INTEGER NOT NULL,
      PRIMARY KEY (follower_id, followee_id, post_id)
    );

    CREATE TABLE IF NOT EXISTS posts (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       INTEGER NOT NULL REFERENCES users(id),
      type          TEXT NOT NULL CHECK(type IN ('text','photo','video','repost')),
      body          TEXT NOT NULL DEFAULT '',
      media_path    TEXT,
      repost_of_id  INTEGER REFERENCES posts(id),
      created_at    INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id);
    CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at);

    CREATE TABLE IF NOT EXISTS likes (
      user_id    INTEGER NOT NULL REFERENCES users(id),
      post_id    INTEGER NOT NULL REFERENCES posts(id),
      created_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, post_id)
    );

    CREATE TABLE IF NOT EXISTS comments (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id),
      post_id    INTEGER NOT NULL REFERENCES posts(id),
      body       TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS shares (
      user_id    INTEGER NOT NULL REFERENCES users(id),
      post_id    INTEGER NOT NULL REFERENCES posts(id),
      created_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, post_id)
    );

    CREATE TABLE IF NOT EXISTS profile_customization (
      user_id INTEGER PRIMARY KEY REFERENCES users(id),
      html    TEXT NOT NULL DEFAULT '',
      css     TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id),
      type       TEXT NOT NULL,
      actor_id   INTEGER NOT NULL REFERENCES users(id),
      post_id    INTEGER REFERENCES posts(id),
      read       INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, read, created_at);

    CREATE TABLE IF NOT EXISTS messages (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      from_id    INTEGER NOT NULL REFERENCES users(id),
      to_id      INTEGER NOT NULL REFERENCES users(id),
      body       TEXT NOT NULL,
      read       INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(from_id, to_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(to_id, read, created_at);

    CREATE TABLE IF NOT EXISTS user_public_keys (
      user_id    INTEGER PRIMARY KEY REFERENCES users(id),
      public_key TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS stickers (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id),
      file_path  TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS rooms (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      html        TEXT NOT NULL DEFAULT '',
      css         TEXT NOT NULL DEFAULT '',
      creator_id  INTEGER NOT NULL REFERENCES users(id),
      is_public   INTEGER NOT NULL DEFAULT 1,
      created_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS room_roles (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id     INTEGER NOT NULL REFERENCES rooms(id),
      name        TEXT NOT NULL,
      color       TEXT NOT NULL DEFAULT '#cccccc',
      permissions INTEGER NOT NULL DEFAULT 3,
      is_founder  INTEGER NOT NULL DEFAULT 0,
      position    INTEGER NOT NULL DEFAULT 0,
      created_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS room_members (
      room_id   INTEGER NOT NULL REFERENCES rooms(id),
      user_id   INTEGER NOT NULL REFERENCES users(id),
      role_id   INTEGER NOT NULL REFERENCES room_roles(id),
      joined_at INTEGER NOT NULL,
      PRIMARY KEY (room_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS room_channels (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id        INTEGER NOT NULL REFERENCES rooms(id),
      name           TEXT NOT NULL,
      view_role_ids  TEXT,
      write_role_ids TEXT,
      created_at     INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS room_messages (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      channel_id INTEGER NOT NULL REFERENCES room_channels(id),
      user_id    INTEGER NOT NULL REFERENCES users(id),
      body       TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_room_msg_channel ON room_messages(channel_id, created_at);

    CREATE TABLE IF NOT EXISTS reports (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      reporter_id      INTEGER NOT NULL REFERENCES users(id),
      reported_user_id INTEGER NOT NULL REFERENCES users(id),
      message_id       INTEGER NOT NULL,
      message_body     TEXT NOT NULL,
      channel_id       INTEGER NOT NULL,
      room_id          INTEGER NOT NULL,
      reason           TEXT NOT NULL,
      status           TEXT NOT NULL DEFAULT 'pending',
      created_at       INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS join_requests (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id    INTEGER NOT NULL REFERENCES rooms(id),
      user_id    INTEGER NOT NULL REFERENCES users(id),
      status     TEXT NOT NULL DEFAULT 'pending',
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS oauth_apps (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      name          TEXT NOT NULL,
      description   TEXT NOT NULL DEFAULT '',
      website       TEXT NOT NULL DEFAULT '',
      redirect_uris TEXT NOT NULL,
      client_id     TEXT UNIQUE NOT NULL,
      client_secret TEXT,
      scopes        TEXT NOT NULL DEFAULT 'read',
      owner_id      INTEGER REFERENCES users(id),
      created_at    INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_oauth_apps_client ON oauth_apps(client_id);
    CREATE INDEX IF NOT EXISTS idx_oauth_apps_owner ON oauth_apps(owner_id);

    CREATE TABLE IF NOT EXISTS oauth_codes (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      code        TEXT UNIQUE NOT NULL,
      app_id      INTEGER NOT NULL REFERENCES oauth_apps(id),
      user_id     INTEGER NOT NULL REFERENCES users(id),
      scopes      TEXT NOT NULL,
      nonce       TEXT,
      code_challenge        TEXT,
      code_challenge_method TEXT,
      redirect_uri TEXT NOT NULL,
      used        INTEGER NOT NULL DEFAULT 0,
      expires_at  INTEGER NOT NULL,
      created_at  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_oauth_codes_code ON oauth_codes(code);

    CREATE TABLE IF NOT EXISTS oauth_tokens (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      token        TEXT UNIQUE NOT NULL,
      refresh_token TEXT UNIQUE,
      app_id       INTEGER NOT NULL REFERENCES oauth_apps(id),
      user_id      INTEGER NOT NULL REFERENCES users(id),
      scopes       TEXT NOT NULL,
      expires_at   INTEGER,
      created_at   INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_oauth_tokens_token ON oauth_tokens(token);
    CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user ON oauth_tokens(user_id);

    CREATE TABLE IF NOT EXISTS media_attachments (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id),
      file_path  TEXT NOT NULL,
      mime_type  TEXT NOT NULL,
      file_size  INTEGER NOT NULL,
      width      INTEGER,
      height     INTEGER,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS idempotency_keys (
      key         TEXT PRIMARY KEY,
      response    TEXT NOT NULL,
      status_code INTEGER NOT NULL,
      created_at  INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      action     TEXT NOT NULL,
      actor_id   INTEGER REFERENCES users(id),
      details    TEXT,
      ip         TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action, created_at);

    CREATE TABLE IF NOT EXISTS edit_history (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_type TEXT NOT NULL,
      entity_id   INTEGER NOT NULL,
      old_body    TEXT NOT NULL,
      new_body    TEXT NOT NULL,
      edited_at   INTEGER NOT NULL,
      edited_by   INTEGER NOT NULL REFERENCES users(id)
    );
    CREATE INDEX IF NOT EXISTS idx_edit_history_entity ON edit_history(entity_type, entity_id);

    -- Server-wide announcement (singleton, id always 1).
    CREATE TABLE IF NOT EXISTS announcement (
      id         INTEGER PRIMARY KEY CHECK(id = 1),
      body       TEXT NOT NULL,
      author_id  INTEGER REFERENCES users(id),
      updated_at INTEGER NOT NULL
    );

    -- Email verification tokens (single active token per user, hashed at rest).
    CREATE TABLE IF NOT EXISTS email_verifications (
      user_id     INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      token_hash  TEXT NOT NULL,
      email       TEXT NOT NULL,
      created_at  INTEGER NOT NULL,
      expires_at  INTEGER NOT NULL,
      consumed_at INTEGER
    );

    -- Server-wide settings (key-value store).
    CREATE TABLE IF NOT EXISTS server_settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);
}

init();

// Push subscriptions for waking offline devices (web-push / FCM / APNs).
try { db.exec(`
  CREATE TABLE IF NOT EXISTS push_subscriptions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    platform   TEXT NOT NULL DEFAULT 'web',
    endpoint   TEXT NOT NULL,
    p256dh     TEXT,
    auth       TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE(user_id, platform, endpoint)
  );
`); } catch {}

// Migrations.
try { db.exec(`ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'default'`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN developer_mode INTEGER NOT NULL DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE messages ADD COLUMN key_for_sender TEXT`); } catch {}
try { db.exec(`ALTER TABLE messages ADD COLUMN key_for_recipient TEXT`); } catch {}
try { db.exec(`ALTER TABLE user_public_keys ADD COLUMN encrypted_private_key TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN referral_code TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN referred_by INTEGER REFERENCES users(id)`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN referrer_ip TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN avatar TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN email TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN email_verified_at INTEGER`); } catch {}
try { db.exec(`ALTER TABLE rooms ADD COLUMN is_public INTEGER NOT NULL DEFAULT 1`); } catch {}
try { db.exec(`ALTER TABLE room_channels ADD COLUMN type TEXT NOT NULL DEFAULT 'text'`); } catch {}
try { db.exec(`ALTER TABLE posts ADD COLUMN edited_at INTEGER`); } catch {}
try { db.exec(`ALTER TABLE comments ADD COLUMN edited_at INTEGER`); } catch {}
try { db.exec(`ALTER TABLE messages ADD COLUMN edited_at INTEGER`); } catch {}
try { db.exec(`ALTER TABLE room_messages ADD COLUMN edited_at INTEGER`); } catch {}
try { db.exec(`ALTER TABLE oauth_codes ADD COLUMN nonce TEXT`); } catch {}
try { db.exec(`ALTER TABLE oauth_tokens ADD COLUMN refresh_expires_at INTEGER`); } catch {}
// Refresh-token reuse detection: a rotated (superseded) refresh token is kept
// with revoked_at set instead of deleted, so replaying it is detectable.
try { db.exec(`ALTER TABLE oauth_tokens ADD COLUMN revoked_at INTEGER`); } catch {}
try { db.exec(`CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL REFERENCES users(id), reported_user_id INTEGER NOT NULL REFERENCES users(id), message_id INTEGER NOT NULL, message_body TEXT NOT NULL, channel_id INTEGER NOT NULL, room_id INTEGER NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL)`); } catch {}
// Private security reports from the responsible-disclosure form (/security).
// Visible only to admins — never rendered on public pages.
try { db.exec(`CREATE TABLE IF NOT EXISTS security_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_name TEXT,
  reporter_contact TEXT,
  summary TEXT NOT NULL,
  details TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at INTEGER NOT NULL,
  handled_at INTEGER,
  handled_by INTEGER REFERENCES users(id)
)`); } catch {}
try { db.exec(`CREATE TABLE IF NOT EXISTS join_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER NOT NULL REFERENCES rooms(id), user_id INTEGER NOT NULL REFERENCES users(id), status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL)`); } catch {}
// Two-factor authentication: TOTP secret is stored encrypted at rest
// (AES-256-GCM via TOTP_ENCRYPTION_KEY, see src/twofa.js). NULL = not enrolled.
try { db.exec(`ALTER TABLE users ADD COLUMN totp_secret TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN totp_confirmed_at INTEGER`); } catch {}
// One-time backup codes; only sha256$ hashes are stored, never plaintext.
try { db.exec(`
  CREATE TABLE IF NOT EXISTS recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    code_hash  TEXT NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL
  );
`); } catch {}
try { db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_codes_user_hash ON recovery_codes(user_id, code_hash)`); } catch {}
// WebAuthn passkeys. credential_id/public_key are base64url; counter guards
// against cloned authenticators.
try { db.exec(`
  CREATE TABLE IF NOT EXISTS passkeys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    credential_id TEXT UNIQUE NOT NULL,
    public_key    TEXT NOT NULL,
    counter       INTEGER NOT NULL DEFAULT 0,
    device_name   TEXT,
    transports    TEXT,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
  );
`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id)`); } catch {}
// "Remember this device" tokens that suppress the TOTP prompt on login.
// Only sha256$ hashes are stored.
try { db.exec(`
  CREATE TABLE IF NOT EXISTS trusted_devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    token_hash   TEXT UNIQUE NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_used_at INTEGER
  );
`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id)`); } catch {}
// Olm (Signal-style) end-to-end encryption: message protocol + sender-self ciphertext.
try { db.exec(`ALTER TABLE messages ADD COLUMN proto TEXT NOT NULL DEFAULT 'rsa'`); } catch {}
try { db.exec(`ALTER TABLE messages ADD COLUMN sender_ciphertext TEXT`); } catch {}
// Additional Security mode for DMs: per-user opt-in per conversation. Server-side
// deletion activates only once BOTH users have enabled it (mutual opt-in).
try { db.exec(`CREATE TABLE IF NOT EXISTS dm_security (
  user_id    INTEGER NOT NULL REFERENCES users(id),
  other_id   INTEGER NOT NULL REFERENCES users(id),
  enabled    INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, other_id)
)`); } catch {}
// Messages sent while the mode is active are flagged `secure` and deleted from
// the server once the sender AND the recipient have both acknowledged receipt
// (received_by_sender / received_by_recipient timestamps).
try { db.exec(`ALTER TABLE messages ADD COLUMN secure INTEGER NOT NULL DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE messages ADD COLUMN received_by_sender INTEGER`); } catch {}
try { db.exec(`ALTER TABLE messages ADD COLUMN received_by_recipient INTEGER`); } catch {}
try { db.exec(`ALTER TABLE room_messages ADD COLUMN proto TEXT NOT NULL DEFAULT 'mls'`); } catch {}
try { db.exec(`ALTER TABLE room_messages ADD COLUMN ciphertext TEXT`); } catch {}

// --- Pure MLS Migration & Cleanup: purge old non-MLS messages and drop legacy Olm/Megolm tables ---
try {
  db.exec(`
    DELETE FROM messages WHERE proto != 'mls' OR proto IS NULL;
    DELETE FROM room_messages WHERE proto != 'mls' OR proto IS NULL;
    DROP TABLE IF EXISTS olm_device_prekeys;
    DROP TABLE IF EXISTS olm_prekeys;
    DROP TABLE IF EXISTS olm_identity;
    DROP TABLE IF EXISTS user_devices;
    DROP TABLE IF EXISTS user_history_backup;
    DROP TABLE IF EXISTS dm_rekey_requests;
    DROP TABLE IF EXISTS room_group_sessions;
    DROP TABLE IF EXISTS room_group_session_keys;
    DROP TABLE IF EXISTS mls_traffic_stats;
    DROP TABLE IF EXISTS mls_migration_telemetry;
    DROP TABLE IF EXISTS mls_sunset_audit;
  `);
} catch (e) {
  console.error('Migration cleanup error:', e);
}

// --- MLS (RFC 9420) Delivery Service & Authentication Service ---
try { db.exec(`
  CREATE TABLE IF NOT EXISTS mls_devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       TEXT NOT NULL UNIQUE,
    device_name     TEXT NOT NULL,
    signing_key_pub TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    revoked_at      INTEGER DEFAULT NULL
  );
`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_mls_devices_user ON mls_devices(user_id, revoked_at)`); } catch {}

try { db.exec(`
  CREATE TABLE IF NOT EXISTS mls_keypackages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       TEXT NOT NULL,
    keypackage_ref  TEXT,
    keypackage_data TEXT NOT NULL,
    ciphersuite     INTEGER NOT NULL DEFAULT 1,
    not_before      INTEGER NOT NULL DEFAULT 0,
    not_after       INTEGER NOT NULL DEFAULT 2147483647,
    created_at      INTEGER NOT NULL,
    consumed_at     INTEGER DEFAULT NULL
  );
`); } catch {}
try { db.exec(`ALTER TABLE mls_keypackages ADD COLUMN keypackage_ref TEXT`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_mls_kp_available ON mls_keypackages(user_id, not_before, not_after, consumed_at)`); } catch {}
try { db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_mls_kp_unique ON mls_keypackages(device_id, keypackage_ref)`); } catch {}

try { db.exec(`
  CREATE TABLE IF NOT EXISTS mls_groups (
    group_id        TEXT PRIMARY KEY,
    epoch           INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
  );
`); } catch {}

try { db.exec(`
  CREATE TABLE IF NOT EXISTS mls_group_members (
    group_id     TEXT NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id    TEXT NOT NULL,
    leaf_index   INTEGER NOT NULL,
    role         TEXT NOT NULL DEFAULT 'member',
    joined_at    INTEGER NOT NULL,
    removed_at   INTEGER DEFAULT NULL,
    PRIMARY KEY (group_id, user_id, device_id)
  );
`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_group_members_active ON mls_group_members(group_id, removed_at)`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_user_active_groups ON mls_group_members(user_id, removed_at)`); } catch {}

try { db.exec(`
  CREATE TABLE IF NOT EXISTS mls_proposals (
    group_id      TEXT NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,
    epoch         INTEGER NOT NULL,
    proposal_ref  TEXT NOT NULL,
    sender_leaf   INTEGER NOT NULL,
    proposal_type INTEGER NOT NULL,
    proposal_data TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    consumed_at   INTEGER DEFAULT NULL,
    PRIMARY KEY (group_id, proposal_ref)
  );
`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_proposals_pending ON mls_proposals(group_id, epoch, consumed_at)`); } catch {}

try { db.exec(`
  CREATE TABLE IF NOT EXISTS mls_commits (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id     TEXT NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,
    epoch        INTEGER NOT NULL,
    commit_data  TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    UNIQUE(group_id, epoch)
  );
`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_mls_commits_epoch ON mls_commits(group_id, epoch)`); } catch {}

try { db.exec(`
  CREATE TABLE IF NOT EXISTS mls_welcomes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id        TEXT NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       TEXT NOT NULL,
    epoch           INTEGER NOT NULL,
    welcome_data    TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    fetched_at      INTEGER DEFAULT NULL,
    acked_at        INTEGER DEFAULT NULL
  );
`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_mls_welcomes_pending ON mls_welcomes(user_id, device_id, acked_at)`); } catch {}

try { db.exec(`
  CREATE TABLE IF NOT EXISTS mls_idempotency (
    group_id        TEXT NOT NULL REFERENCES mls_groups(group_id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    epoch           INTEGER NOT NULL,
    commit_hash     TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    PRIMARY KEY (group_id, idempotency_key)
  );
`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_mls_idempotency_exp ON mls_idempotency(expires_at)`); } catch {}

try { db.exec(`
  CREATE TABLE IF NOT EXISTS mls_credential_backups (
    user_id         INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    backup_data     TEXT NOT NULL,
    kek_salt        TEXT NOT NULL,
    updated_at      INTEGER NOT NULL
  );
`); } catch {}


// Fix stale referred_by links for users whose referrer no longer has a referral code.
db.prepare(`UPDATE users SET referred_by = NULL WHERE referred_by IS NOT NULL AND referred_by IN (SELECT id FROM users WHERE referral_code IS NULL)`).run();
// Ensure avatar paths have /uploads/ prefix for template rendering.
db.prepare(`UPDATE users SET avatar = '/uploads/' || avatar WHERE avatar IS NOT NULL AND avatar NOT LIKE '/uploads/%'`).run();

// OAuth secrets (bearer tokens, client secrets, authorization codes) are stored
// as SHA-256 hashes (see hashOAuthToken below). Migrate any rows written before
// hashing was introduced so existing credentials keep working. Exported so
// tests can exercise the legacy-row path.
function migrateOAuthTokenHashes() {
  try {
    const legacyRows = db.prepare(`SELECT id, token, refresh_token FROM oauth_tokens`).all();
    for (const r of legacyRows) {
      if (r.token && !String(r.token).startsWith('sha256$')) {
        db.prepare(`UPDATE oauth_tokens SET token = ? WHERE id = ?`).run(hashOAuthToken(r.token), r.id);
      }
      if (r.refresh_token && !String(r.refresh_token).startsWith('sha256$')) {
        db.prepare(`UPDATE oauth_tokens SET refresh_token = ? WHERE id = ?`).run(hashOAuthToken(r.refresh_token), r.id);
      }
    }
  } catch {}
  try {
    const apps = db.prepare(`SELECT id, client_secret FROM oauth_apps`).all();
    for (const a of apps) {
      if (a.client_secret && !String(a.client_secret).startsWith('sha256$')) {
        db.prepare(`UPDATE oauth_apps SET client_secret = ? WHERE id = ?`).run(hashOAuthToken(a.client_secret), a.id);
      }
    }
  } catch {}
  try {
    const codes = db.prepare(`SELECT id, code FROM oauth_codes`).all();
    for (const c of codes) {
      if (c.code && !String(c.code).startsWith('sha256$')) {
        db.prepare(`UPDATE oauth_codes SET code = ? WHERE id = ?`).run(hashOAuthToken(c.code), c.id);
      }
    }
  } catch {}
}
migrateOAuthTokenHashes();

// 1. Allow nullable owner_id on oauth_apps for dynamic client registration
try {
  const info = db.prepare(`PRAGMA table_info(oauth_apps)`).all();
  const ownerCol = info.find(c => c.name === 'owner_id');
  if (ownerCol && ownerCol.notnull === 1) {
    db.exec(`PRAGMA foreign_keys = OFF;`);
    db.exec(`
      CREATE TABLE oauth_apps_mig (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT NOT NULL,
        description   TEXT NOT NULL DEFAULT '',
        website       TEXT NOT NULL DEFAULT '',
        redirect_uris TEXT NOT NULL,
        client_id     TEXT UNIQUE NOT NULL,
        client_secret TEXT,
        scopes        TEXT NOT NULL DEFAULT 'read',
        owner_id      INTEGER REFERENCES users(id),
        created_at    INTEGER NOT NULL
      );
      INSERT INTO oauth_apps_mig SELECT id, name, description, website, redirect_uris, client_id, client_secret, scopes, owner_id, created_at FROM oauth_apps;
      DROP TABLE oauth_apps;
      ALTER TABLE oauth_apps_mig RENAME TO oauth_apps;
      CREATE INDEX IF NOT EXISTS idx_oauth_apps_client ON oauth_apps(client_id);
      CREATE INDEX IF NOT EXISTS idx_oauth_apps_owner ON oauth_apps(owner_id);
    `);
    db.exec(`PRAGMA foreign_keys = ON;`);
  }
} catch (e) {
  try { db.exec(`PRAGMA foreign_keys = ON;`); } catch {}
}

// 2. Personal Access Tokens table
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS personal_access_tokens (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      INTEGER NOT NULL REFERENCES users(id),
      name         TEXT NOT NULL,
      token_hash   TEXT UNIQUE NOT NULL,
      scopes       TEXT NOT NULL,
      last_used_at INTEGER,
      expires_at   INTEGER,
      created_at   INTEGER NOT NULL
    );
  `);
} catch (e) {}
try { db.exec(`ALTER TABLE personal_access_tokens ADD COLUMN token_prefix TEXT`); } catch (e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_pat_token ON personal_access_tokens(token_hash)`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_pat_user ON personal_access_tokens(user_id)`); } catch {}

// 3. Post follow-from tracking
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS post_referrals (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      follower_id  INTEGER NOT NULL REFERENCES users(id),
      followed_id  INTEGER NOT NULL REFERENCES users(id),
      post_id      INTEGER NOT NULL REFERENCES posts(id),
      created_at   INTEGER NOT NULL,
      UNIQUE(follower_id, followed_id, post_id)
    );
  `);
} catch (e) {}


// ---------- users ----------
function adminExists() {
  return db.prepare(`SELECT 1 FROM users WHERE is_admin = 1`).get() ? true : false;
}
function makeAdmin(userId) {
  db.prepare(`UPDATE users SET is_admin = 1 WHERE id = ?`).run(userId);
}

function createUser({ username, passwordHash, displayName, referredBy, referrerIp }) {
  const now = Date.now();
  const res = db.prepare(
    `INSERT INTO users (username, password_hash, display_name, created_at, referred_by, referrer_ip, is_admin) VALUES (?,?,?,?,?,?,0)`
  ).run(username, passwordHash, displayName, now, referredBy || null, referrerIp || null);
  return res.lastInsertRowid;
}

function getUserByUsername(username) {
  return db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
}

function getUserById(id) {
  return db.prepare(`SELECT * FROM users WHERE id = ?`).get(id);
}

function updateUserProfile(id, { displayName, bio }) {
  db.prepare(`UPDATE users SET display_name = ?, bio = ? WHERE id = ?`)
    .run(displayName, bio, id);
}

function setAvatar(id, avatarPath) {
  db.prepare(`UPDATE users SET avatar = ? WHERE id = ?`).run(avatarPath, id);
}

function getAvatar(id) {
  const row = db.prepare(`SELECT avatar FROM users WHERE id = ?`).get(id);
  return row ? row.avatar : null;
}

// ---------- follows ----------
function follow(followerId, followeeId) {
  if (followerId === followeeId) return;
  db.prepare(
    `INSERT OR IGNORE INTO follows (follower_id, followee_id, created_at) VALUES (?,?,?)`
  ).run(followerId, followeeId, Date.now());
  try { require('./feed').invalidateFeedCache(followerId); } catch {}
}

function unfollow(followerId, followeeId) {
  db.prepare(`DELETE FROM follows WHERE follower_id = ? AND followee_id = ?`)
    .run(followerId, followeeId);
  db.prepare(
    `DELETE FROM follows_from_post WHERE follower_id = ? AND followee_id = ?`
  ).run(followerId, followeeId);
  try { require('./feed').invalidateFeedCache(followerId); } catch {}
}

function isFollowing(followerId, followeeId) {
  const row = db.prepare(
    `SELECT 1 FROM follows WHERE follower_id = ? AND followee_id = ?`
  ).get(followerId, followeeId);
  return !!row;
}

function followingIds(userId) {
  const rows = db.prepare(
    `SELECT followee_id AS id FROM follows WHERE follower_id = ?`
  ).all(userId);
  return rows.map(r => r.id);
}

function countFollowers(userId) {
  return db.prepare(`SELECT COUNT(*) AS n FROM follows WHERE followee_id = ?`).get(userId).n;
}

function countFollowing(userId) {
  return db.prepare(`SELECT COUNT(*) AS n FROM follows WHERE follower_id = ?`).get(userId).n;
}

// Record that a follow happened because of a specific post (big boost source).
function recordFollowFromPost(followerId, followeeId, postId) {
  follow(followerId, followeeId);
  db.prepare(
    `INSERT OR IGNORE INTO follows_from_post (follower_id, followee_id, post_id, created_at)
     VALUES (?,?,?,?)`
  ).run(followerId, followeeId, postId, Date.now());
  try { require('./feed').invalidateFeedCache(followerId); } catch {}
}

// ---------- posts ----------
function createPost({ userId, type, body = '', mediaPath = null, repostOfId = null, createdAt }) {
  const now = createdAt || Date.now();
  const res = db.prepare(
    `INSERT INTO posts (user_id, type, body, media_path, repost_of_id, created_at)
     VALUES (?,?,?,?,?,?)`
  ).run(userId, type, body, mediaPath, repostOfId, now);
  return res.lastInsertRowid;
}

function getPostById(id) {
  return db.prepare(`SELECT * FROM posts WHERE id = ?`).get(id);
}

// Resolve a post, following one level of repost to its original.
function getDisplayPost(id) {
  const post = db.prepare(`SELECT * FROM posts WHERE id = ?`).get(id);
  if (!post) return null;
  if (post.type === 'repost' && post.repost_of_id) {
    const original = getDisplayPost(post.repost_of_id);
    return { post, original };
  }
  return { post, original: null };
}

function postsByUser(userId) {
  return db.prepare(
    `SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC`
  ).all(userId);
}

function countPostsByUser(userId) {
  const row = db.prepare(`SELECT COUNT(*) AS n FROM posts WHERE user_id = ?`).get(userId);
  return row.n;
}

// ---------- post deletion ----------
function deletePost(postId, userId) {
  const post = db.prepare(`SELECT * FROM posts WHERE id = ? AND user_id = ?`).get(postId, userId);
  if (!post) return false;
  // Cascade: remove related data for the effective (original) content.
  const effId = post.type === 'repost' && post.repost_of_id ? post.repost_of_id : post.id;
  db.prepare(`DELETE FROM likes WHERE post_id = ?`).run(effId);
  db.prepare(`DELETE FROM comments WHERE post_id = ?`).run(effId);
  db.prepare(`DELETE FROM shares WHERE post_id = ?`).run(effId);
  db.prepare(`DELETE FROM follows_from_post WHERE post_id = ?`).run(effId);
  db.prepare(`DELETE FROM notifications WHERE post_id = ?`).run(effId);
  // Delete reposts that point to this post.
  db.prepare(`DELETE FROM posts WHERE repost_of_id = ?`).run(post.id);
  // Delete the post itself.
  db.prepare(`DELETE FROM posts WHERE id = ?`).run(post.id);
  return true;
}

// ---------- batch counts (N+1 reduction) ----------
function batchPostCounts(postIds) {
  if (postIds.length === 0) return {};
  const ph = postIds.map(() => '?').join(',');
  const likes = db.prepare(`SELECT post_id, COUNT(*) AS n FROM likes WHERE post_id IN (${ph}) GROUP BY post_id`).all(...postIds);
  const shares = db.prepare(`SELECT post_id, COUNT(*) AS n FROM shares WHERE post_id IN (${ph}) GROUP BY post_id`).all(...postIds);
  const comments = db.prepare(`SELECT post_id, COUNT(*) AS n FROM comments WHERE post_id IN (${ph}) GROUP BY post_id`).all(...postIds);

  const likeMap = Object.fromEntries(likes.map(r => [r.post_id, r.n]));
  const shareMap = Object.fromEntries(shares.map(r => [r.post_id, r.n]));
  const commentMap = Object.fromEntries(comments.map(r => [r.post_id, r.n]));

  return { likeMap, shareMap, commentMap };
}

// ---------- likes ----------
function toggleLike(userId, postId) {
  const existing = db.prepare(
    `SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?`
  ).get(userId, postId);
  if (existing) {
    db.prepare(`DELETE FROM likes WHERE user_id = ? AND post_id = ?`).run(userId, postId);
    return false;
  }
  db.prepare(
    `INSERT INTO likes (user_id, post_id, created_at) VALUES (?,?,?)`
  ).run(userId, postId, Date.now());
  return true;
}

function hasLiked(userId, postId) {
  return !!db.prepare(
    `SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?`
  ).get(userId, postId);
}

// ---------- comments ----------
function addComment(userId, postId, body) {
  const now = Date.now();
  const res = db.prepare(
    `INSERT INTO comments (user_id, post_id, body, created_at) VALUES (?,?,?,?)`
  ).run(userId, postId, body, now);
  return res.lastInsertRowid;
}

function commentsForPost(postId) {
  return db.prepare(
    `SELECT c.*, u.username, u.display_name, u.avatar, u.bio AS user_bio, u.created_at AS user_created_at FROM comments c
     JOIN users u ON u.id = c.user_id
     WHERE c.post_id = ? ORDER BY c.created_at ASC`
  ).all(postId);
}

// ---------- edit history ----------
function editPost(postId, userId, newBody) {
  const post = db.prepare(`SELECT * FROM posts WHERE id = ? AND user_id = ?`).get(postId, userId);
  if (!post) return false;
  const now = Date.now();
  db.prepare(`INSERT INTO edit_history (entity_type, entity_id, old_body, new_body, edited_at, edited_by) VALUES (?,?,?,?,?,?)`)
    .run('post', postId, post.body, newBody, now, userId);
  db.prepare(`UPDATE posts SET body = ?, edited_at = ? WHERE id = ?`).run(newBody, now, postId);
  return true;
}

function deleteComment(commentId, userId) {
  const comment = db.prepare(`SELECT * FROM comments WHERE id = ? AND user_id = ?`).get(commentId, userId);
  if (!comment) return false;
  db.prepare(`DELETE FROM comments WHERE id = ?`).run(commentId);
  return true;
}

function editComment(commentId, userId, newBody) {
  const comment = db.prepare(`SELECT * FROM comments WHERE id = ? AND user_id = ?`).get(commentId, userId);
  if (!comment) return false;
  const now = Date.now();
  db.prepare(`INSERT INTO edit_history (entity_type, entity_id, old_body, new_body, edited_at, edited_by) VALUES (?,?,?,?,?,?)`)
    .run('comment', commentId, comment.body, newBody, now, userId);
  db.prepare(`UPDATE comments SET body = ?, edited_at = ? WHERE id = ?`).run(newBody, now, commentId);
  return true;
}

function editMessage(msgId, userId, newBody, keyForSender, keyForRecipient, proto, senderCiphertext) {
  const msg = db.prepare(`SELECT * FROM messages WHERE id = ? AND from_id = ?`).get(msgId, userId);
  if (!msg) return false;
  const now = Date.now();
  db.prepare(`INSERT INTO edit_history (entity_type, entity_id, old_body, new_body, edited_at, edited_by) VALUES (?,?,?,?,?,?)`)
    .run('message', msgId, msg.body, newBody, now, userId);
  db.prepare(`UPDATE messages SET body = ?, edited_at = ?, key_for_sender = COALESCE(?, key_for_sender), key_for_recipient = COALESCE(?, key_for_recipient), proto = COALESCE(?, proto), sender_ciphertext = COALESCE(?, sender_ciphertext) WHERE id = ?`).run(newBody, now, keyForSender || null, keyForRecipient || null, proto || null, senderCiphertext || null, msgId);
  return true;
}

function deleteMessage(msgId, userId) {
  const msg = db.prepare(`SELECT * FROM messages WHERE id = ? AND from_id = ?`).get(msgId, userId);
  if (!msg) return null;
  db.prepare(`DELETE FROM edit_history WHERE entity_type = 'message' AND entity_id = ?`).run(msgId);
  db.prepare(`DELETE FROM messages WHERE id = ?`).run(msgId);
  return msg;
}

function editRoomMessage(msgId, userId, newBody, proto, ciphertext, groupSessionId) {
  const msg = db.prepare(`SELECT * FROM room_messages WHERE id = ? AND user_id = ?`).get(msgId, userId);
  if (!msg) return false;
  const now = Date.now();
  db.prepare(`INSERT INTO edit_history (entity_type, entity_id, old_body, new_body, edited_at, edited_by) VALUES (?,?,?,?,?,?)`)
    .run('room_message', msgId, msg.body, newBody, now, userId);
  db.prepare(`UPDATE room_messages SET body = ?, proto = COALESCE(?, proto), ciphertext = COALESCE(?, ciphertext), group_session_id = COALESCE(?, group_session_id), edited_at = ? WHERE id = ?`).run(newBody, proto || null, ciphertext || null, groupSessionId || null, now, msgId);
  return true;
}

function getEditHistory(entityType, entityId) {
  return db.prepare(`
    SELECT eh.*, u.username, u.display_name
    FROM edit_history eh
    JOIN users u ON u.id = eh.edited_by
    WHERE eh.entity_type = ? AND eh.entity_id = ?
    ORDER BY eh.edited_at ASC
  `).all(entityType, entityId);
}

// ---------- shares ----------
function sharePost(userId, postId) {
  db.prepare(
    `INSERT OR IGNORE INTO shares (user_id, post_id, created_at) VALUES (?,?,?)`
  ).run(userId, postId, Date.now());
}

function hasShared(userId, postId) {
  return !!db.prepare(
    `SELECT 1 FROM shares WHERE user_id = ? AND post_id = ?`
  ).get(userId, postId);
}

// Has `userId` already reposted `originalId`? (prevents duplicate reposts)
function hasReposted(userId, originalId) {
  return !!db.prepare(
    `SELECT 1 FROM posts WHERE user_id = ? AND type = 'repost' AND repost_of_id = ?`
  ).get(userId, originalId);
}

// ---------- profile customization ----------
function getCustomization(userId) {
  return db.prepare(
    `SELECT * FROM profile_customization WHERE user_id = ?`
  ).get(userId) || { user_id: userId, html: '', css: '' };
}

function setCustomization(userId, html, css) {
  db.prepare(
    `INSERT INTO profile_customization (user_id, html, css) VALUES (?,?,?)
     ON CONFLICT(user_id) DO UPDATE SET html = excluded.html, css = excluded.css`
  ).run(userId, html, css);
}

// ---------- notifications ----------
const { notify } = require('./notif-broadcaster');

function createNotification({ userId, type, actorId, postId }) {
  if (userId === actorId && type !== 'security' && type !== 'login') return;
  const now = Date.now();
  const result = db.prepare(
    `INSERT INTO notifications (user_id, type, actor_id, post_id, created_at) VALUES (?,?,?,?,?)`
  ).run(userId, type, actorId, postId || null, now);
  const notif = { id: result.lastInsertRowid, type, actor_id: actorId, post_id: postId || null, created_at: now };
  notify(userId, notif);
}

function getNotifications(userId, limit = 50, cursor) {
  let sql, params;
  if (cursor) {
    sql = `
      SELECT n.*, u.username AS actor_username, u.display_name AS actor_name, u.avatar AS actor_avatar, u.bio AS actor_bio, u.created_at AS actor_created_at
      FROM notifications n
      JOIN users u ON u.id = n.actor_id
      WHERE n.user_id = ? AND n.id < ?
      ORDER BY n.id DESC
      LIMIT ?
    `;
    params = [userId, cursor, limit];
  } else {
    sql = `
      SELECT n.*, u.username AS actor_username, u.display_name AS actor_name, u.avatar AS actor_avatar, u.bio AS actor_bio, u.created_at AS actor_created_at
      FROM notifications n
      JOIN users u ON u.id = n.actor_id
      WHERE n.user_id = ?
      ORDER BY n.id DESC
      LIMIT ?
    `;
    params = [userId, limit];
  }
  return db.prepare(sql).all(...params);
}

function countUnreadNotifications(userId) {
  const row = db.prepare(
    `SELECT COUNT(*) AS n FROM notifications WHERE user_id = ? AND read = 0`
  ).get(userId);
  return row.n;
}

function markNotificationsRead(userId) {
  db.prepare(`UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0`).run(userId);
}

// ---------- push subscriptions ----------
function addPushSubscription({ userId, platform, endpoint, p256dh, auth }) {
  db.prepare(
    `INSERT INTO push_subscriptions (user_id, platform, endpoint, p256dh, auth, created_at)
     VALUES (?,?,?,?,?,?)
     ON CONFLICT(user_id, platform, endpoint) DO UPDATE SET p256dh=excluded.p256dh, auth=excluded.auth`
  ).run(userId, platform || 'web', endpoint, p256dh || null, auth || null, Date.now());
}

function getPushSubscriptions(userId) {
  return db.prepare(
    `SELECT id, platform, endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = ?`
  ).all(userId);
}

function removePushSubscription(userId, endpoint) {
  db.prepare(`DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?`).run(userId, endpoint);
}

function deletePushSubscriptionsByEndpoint(endpoint) {
  db.prepare(`DELETE FROM push_subscriptions WHERE endpoint = ?`).run(endpoint);
}

// ---------- user lists ----------
function getFollowers(userId) {
  return db.prepare(`
    SELECT u.id, u.username, u.display_name, u.avatar, u.bio, f.created_at AS followed_at
    FROM follows f
    JOIN users u ON u.id = f.follower_id
    WHERE f.followee_id = ?
    ORDER BY f.created_at DESC
  `).all(userId);
}

function getFollowing(userId) {
  return db.prepare(`
    SELECT u.id, u.username, u.display_name, u.avatar, u.bio, f.created_at AS followed_at
    FROM follows f
    JOIN users u ON u.id = f.followee_id
    WHERE f.follower_id = ?
    ORDER BY f.created_at DESC
  `).all(userId);
}

// ---------- mutual follow check ----------
function areMutualFollowers(aId, bId) {
  const row = db.prepare(`
    SELECT 1 FROM follows f1
    JOIN follows f2 ON f1.follower_id = f2.followee_id AND f1.followee_id = f2.follower_id
    WHERE f1.follower_id = ? AND f1.followee_id = ?
  `).get(aId, bId);
  return !!row;
}

// ---------- messages ----------
function sendMessage(fromId, toId, body, keyForSender, keyForRecipient, proto, senderCiphertext, secure = false) {
  const p = 'mls';
  const res = db.prepare(
    `INSERT INTO messages (from_id, to_id, body, created_at, key_for_sender, key_for_recipient, proto, sender_ciphertext, secure) VALUES (?,?,?,?,?,?,?,?,?)`
  ).run(fromId, toId, body, Date.now(), null, null, p, null, secure ? 1 : 0);
  return res.lastInsertRowid;
}

// ---------- Additional Security (server-side deletion after both received) ----------
// Per-user opt-in per conversation. The mode is ACTIVE for a conversation only
// when both users have enabled it (mutual opt-in), so a user whose client cannot
// store messages locally is never silently cut off from history.
function setDmSecurity(userId, otherId, enabled) {
  db.prepare(`
    INSERT INTO dm_security (user_id, other_id, enabled, updated_at)
    VALUES (?,?,?,?)
    ON CONFLICT(user_id, other_id) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
  `).run(userId, otherId, enabled ? 1 : 0, Date.now());
}

function getDmSecurity(userId, otherId) {
  const mine = db.prepare(`SELECT enabled FROM dm_security WHERE user_id = ? AND other_id = ?`).get(userId, otherId);
  const theirs = db.prepare(`SELECT enabled FROM dm_security WHERE user_id = ? AND other_id = ?`).get(otherId, userId);
  const m = !!mine && mine.enabled === 1;
  const t = !!theirs && theirs.enabled === 1;
  return { mine: m, theirs: t, active: m && t };
}

// Mark secure messages as received by the calling user (sender or recipient side
// depending on message direction), then delete any secure message that BOTH sides
// have now received. Only messages flagged secure=1 within this conversation pair
// are ever touched, so acks can never delete anything else.
function ackMessagesReceived(userId, otherId, ids) {
  // Cap per request: a huge id list would amplify into oversized IN clauses.
  const clean = [...new Set((ids || []).map(Number).filter(n => Number.isInteger(n) && n > 0))].slice(0, 200);
  if (!clean.length) return { acked: 0, deleted: 0 };
  const now = Date.now();
  const placeholders = clean.map(() => '?').join(',');
  db.prepare(`
    UPDATE messages SET received_by_sender = COALESCE(received_by_sender, ?)
    WHERE secure = 1 AND from_id = ? AND to_id = ? AND id IN (${placeholders})
  `).run(now, userId, otherId, ...clean);
  db.prepare(`
    UPDATE messages SET received_by_recipient = COALESCE(received_by_recipient, ?)
    WHERE secure = 1 AND to_id = ? AND from_id = ? AND id IN (${placeholders})
  `).run(now, userId, otherId, ...clean);
  const del = db.prepare(`
    DELETE FROM messages
    WHERE secure = 1 AND id IN (${placeholders})
      AND ((from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?))
      AND received_by_sender IS NOT NULL AND received_by_recipient IS NOT NULL
  `).run(...clean, userId, otherId, otherId, userId);
  return { acked: clean.length, deleted: del.changes };
}

function getConversations(userId) {
  return db.prepare(`
    WITH parts AS (
      SELECT DISTINCT
        CASE WHEN from_id = ? THEN to_id ELSE from_id END AS other_id
      FROM messages
      WHERE from_id = ? OR to_id = ?
    ),
    lasts AS (
      SELECT m.id AS last_id, m.from_id, m.to_id, m.body, m.proto, m.sender_ciphertext,
             m.key_for_sender, m.key_for_recipient, m.created_at,
             ROW_NUMBER() OVER (
               PARTITION BY CASE WHEN m.from_id = ? THEN m.to_id ELSE m.from_id END
               ORDER BY m.created_at DESC, m.id DESC
             ) AS rn
      FROM messages m
      WHERE m.from_id = ? OR m.to_id = ?
    )
    SELECT p.other_id AS id, u.username, u.display_name, u.avatar,
      l.last_id, l.from_id AS last_from, l.body AS last_message,
      l.proto AS last_proto, l.sender_ciphertext AS last_sender_ciphertext,
      l.key_for_sender AS last_key_for_sender, l.key_for_recipient AS last_key_for_recipient,
      l.created_at AS last_at,
      (SELECT COUNT(*) FROM messages m
       WHERE m.to_id = ? AND m.from_id = p.other_id AND m.read = 0) AS unread
    FROM parts p
    JOIN users u ON u.id = p.other_id
    LEFT JOIN lasts l ON l.rn = 1
      AND ((l.from_id = ? AND l.to_id = p.other_id) OR (l.from_id = p.other_id AND l.to_id = ?))
    ORDER BY l.created_at DESC
  `).all(userId, userId, userId, userId, userId, userId, userId, userId, userId);
}

// Newest N messages (older history via id cursor). Fetching the OLDEST N used to
// hide the recent end of any conversation longer than the page size.
function getMessages(userId, otherId, limit = 100, beforeId = null) {
  const where = `
    SELECT m.*, u.username, u.display_name
    FROM messages m
    JOIN users u ON u.id = m.from_id
    WHERE ((m.from_id = ? AND m.to_id = ?) OR (m.from_id = ? AND m.to_id = ?))
  `;
  if (beforeId) {
    return db.prepare(where + ` AND m.id < ? ORDER BY m.created_at DESC, m.id DESC LIMIT ?`)
      .all(userId, otherId, otherId, userId, beforeId, limit).reverse();
  }
  return db.prepare(where + ` ORDER BY m.created_at DESC, m.id DESC LIMIT ?`)
    .all(userId, otherId, otherId, userId, limit).reverse();
}

function countUnreadMessages(userId) {
  const row = db.prepare(
    `SELECT COUNT(*) AS n FROM messages WHERE to_id = ? AND read = 0`
  ).get(userId);
  return row.n;
}

function markConversationRead(userId, otherId) {
  db.prepare(
    `UPDATE messages SET read = 1 WHERE to_id = ? AND from_id = ? AND read = 0`
  ).run(userId, otherId);
}

// ---------- E2EE public keys ----------
function setPublicKey(userId, publicKey, encryptedPrivateKey) {
  db.prepare(`
    INSERT INTO user_public_keys (user_id, public_key, encrypted_private_key, created_at)
    VALUES (?,?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key, encrypted_private_key = COALESCE(excluded.encrypted_private_key, user_public_keys.encrypted_private_key), created_at = excluded.created_at
  `).run(userId, publicKey, encryptedPrivateKey || null, Date.now());
}
function getPublicKey(userId) {
  const row = db.prepare(`SELECT public_key FROM user_public_keys WHERE user_id = ?`).get(userId);
  return row ? row.public_key : null;
}
function getEncryptedPrivateKey(userId) {
  const row = db.prepare(`SELECT encrypted_private_key FROM user_public_keys WHERE user_id = ?`).get(userId);
  return row ? row.encrypted_private_key : null;
}

// ---------- Olm stubs (pure MLS mode) ----------
function setOlmIdentity() {}
function getOlmIdentity() { return null; }
function setOlmBackup() { return true; }
function addOlmPrekeys() {}
function countAvailablePrekeys() { return 0; }
function claimOlmPrekey() { return null; }
function peekOlmPrekey() { return null; }
function requestDmRekey() {}
function dmRekeyNeeded() { return false; }
function clearDmRekey() {}
function registerUserDevice() {}
function getUserDevices() { return []; }
function getUserDevice() { return null; }
function getSenderCurve() { return null; }
function touchUserDevice() {}
function deleteUserDevice() {}
function addDevicePrekeys() {}
function countAvailableDevicePrekeys() { return 0; }
function claimDevicePrekey() { return null; }
function peekDevicePrekey() { return null; }
function getAllDeviceBundlesForUser() { return []; }
function claimAllDevicePrekeysForUser() { return []; }
function setUserHistoryBackup() {}
function getUserHistoryBackup() { return null; }

// =============================================================================
// ---------- MLS (RFC 9420) Delivery Service & Authentication Service ---------
// =============================================================================

const MAX_MLS_DEVICES_PER_USER = 10;

function registerMlsDevice(userId, deviceId, deviceName, signingKeyPub) {
  const now = Date.now();
  const cleanId = String(deviceId || '').trim();
  const cleanName = String(deviceName || '').trim() || 'Default Device';
  const cleanKey = String(signingKeyPub || '').trim();
  if (!cleanId || !cleanKey) throw new Error('deviceId and signingKeyPub are required');

  const activeCount = db.prepare(`SELECT COUNT(*) AS count FROM mls_devices WHERE user_id = ? AND revoked_at IS NULL AND device_id != ?`).get(userId, cleanId);
  if (activeCount && activeCount.count >= MAX_MLS_DEVICES_PER_USER) {
    const err = new Error('Device quota exceeded (maximum ' + MAX_MLS_DEVICES_PER_USER + ' active devices). Please revoke an old device first.');
    err.code = 'QUOTA_EXCEEDED';
    throw err;
  }

  db.prepare(`
    INSERT INTO mls_devices (user_id, device_id, device_name, signing_key_pub, created_at, last_seen_at, revoked_at)
    VALUES (?, ?, ?, ?, ?, ?, NULL)
    ON CONFLICT(device_id) DO UPDATE SET
      user_id = excluded.user_id,
      device_name = excluded.device_name,
      signing_key_pub = excluded.signing_key_pub,
      last_seen_at = excluded.last_seen_at,
      revoked_at = NULL
  `).run(userId, cleanId, cleanName, cleanKey, now, now);

  return { device_id: cleanId, user_id: userId, device_name: cleanName, signing_key_pub: cleanKey };
}

function getMlsDevices(userId) {
  return db.prepare(`
    SELECT device_id, device_name, signing_key_pub, created_at, last_seen_at
    FROM mls_devices
    WHERE user_id = ? AND revoked_at IS NULL
    ORDER BY created_at ASC
  `).all(userId);
}

function getMlsDevice(userId, deviceId) {
  return db.prepare(`
    SELECT device_id, device_name, signing_key_pub, created_at, last_seen_at, revoked_at
    FROM mls_devices
    WHERE user_id = ? AND device_id = ?
  `).get(userId, String(deviceId)) || null;
}

function touchMlsDevice(userId, deviceId) {
  db.prepare(`UPDATE mls_devices SET last_seen_at = ? WHERE user_id = ? AND device_id = ?`).run(Date.now(), userId, String(deviceId));
}

function revokeMlsDevice(userId, deviceId) {
  const now = Date.now();
  db.prepare(`UPDATE mls_devices SET revoked_at = ? WHERE user_id = ? AND device_id = ?`).run(now, userId, String(deviceId));
  db.prepare(`UPDATE mls_keypackages SET consumed_at = ? WHERE user_id = ? AND device_id = ? AND consumed_at IS NULL`).run(now, userId, String(deviceId));
}

function saveMlsKeyPackages(userId, deviceId, packages) {
  const now = Date.now();
  const cleanDev = String(deviceId).trim();
  if (!Array.isArray(packages) || !packages.length) return 0;
  const insert = db.prepare(`
    INSERT OR IGNORE INTO mls_keypackages (user_id, device_id, keypackage_ref, keypackage_data, ciphersuite, not_before, not_after, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  db.exec('BEGIN IMMEDIATE');
  try {
    let savedCount = 0;
    for (const p of packages) {
      const data = typeof p === 'string' ? p : (p && (p.data || p.keypackage_data));
      const ref = (p && (p.keypackage_ref || p.ref)) ? String(p.keypackage_ref || p.ref).trim().toLowerCase() : null;
      const cs = (p && p.ciphersuite) || 1;
      const notBefore = (p && Number(p.not_before)) || 0;
      const notAfter = (p && Number(p.not_after)) || Math.floor((now + 90 * 86400000) / 1000);
      if (data) {
        const res = insert.run(userId, cleanDev, ref, String(data), cs, notBefore, notAfter, now);
        if (res.changes > 0) savedCount++;
      }
    }
    db.exec('COMMIT');
    return savedCount;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function getMlsKeyPackagesForUser(userId) {
  const devices = getMlsDevices(userId);
  const result = [];
  const nowSec = Math.floor(Date.now() / 1000);
  for (const dev of devices) {
    const kp = db.prepare(`
      SELECT id, device_id, keypackage_ref, keypackage_data, ciphersuite, not_before, not_after
      FROM mls_keypackages
      WHERE user_id = ? AND device_id = ? AND consumed_at IS NULL AND (? BETWEEN not_before AND not_after)
      ORDER BY id ASC LIMIT 1
    `).get(userId, dev.device_id, nowSec);
    if (kp) result.push(kp);
  }
  return result;
}

function consumeSpecificMlsKeyPackages(keypackageIds) {
  if (!Array.isArray(keypackageIds) || !keypackageIds.length) return [];
  const cleanIds = keypackageIds.map(Number).filter(n => Number.isInteger(n) && n > 0);
  if (!cleanIds.length) return [];
  const now = Date.now();
  const placeholders = cleanIds.map(() => '?').join(',');
  return db.prepare(`
    UPDATE mls_keypackages SET consumed_at = ?
    WHERE id IN (${placeholders}) AND consumed_at IS NULL
    RETURNING id, user_id, device_id
  `).all(now, ...cleanIds);
}

function claimMlsKeyPackage(userId, deviceId) {
  const now = Date.now();
  const nowSec = Math.floor(now / 1000);
  return db.prepare(`
    UPDATE mls_keypackages SET consumed_at = ?
    WHERE id = (
      SELECT id FROM mls_keypackages
      WHERE user_id = ? AND device_id = ? AND consumed_at IS NULL AND (? BETWEEN not_before AND not_after)
      ORDER BY id ASC LIMIT 1
    )
    RETURNING id, device_id, keypackage_ref, keypackage_data, ciphersuite
  `).get(now, userId, String(deviceId), nowSec) || null;
}

function claimUserMlsKeyPackages(userId) {
  const devices = getMlsDevices(userId);
  const result = [];
  for (const dev of devices) {
    const kp = claimMlsKeyPackage(userId, dev.device_id);
    if (kp) {
      result.push({
        device_id: dev.device_id,
        device_name: dev.device_name,
        keypackage_ref: kp.keypackage_ref,
        keypackage_data: kp.keypackage_data,
        ciphersuite: kp.ciphersuite
      });
    }
  }
  return result;
}

function getMlsKeyPackageStatus(userId, deviceId) {
  const nowSec = Math.floor(Date.now() / 1000);
  const r = db.prepare(`
    SELECT COUNT(*) AS count
    FROM mls_keypackages
    WHERE user_id = ? AND device_id = ? AND consumed_at IS NULL AND (? BETWEEN not_before AND not_after)
  `).get(userId, String(deviceId), nowSec);
  return r ? r.count : 0;
}

// Group Membership Management
function addMlsGroupMember(groupId, userId, deviceId, leafIndex = 0, role = 'member') {
  const now = Date.now();
  db.prepare(`
    INSERT INTO mls_group_members (group_id, user_id, device_id, leaf_index, role, joined_at, removed_at)
    VALUES (?, ?, ?, ?, ?, ?, NULL)
    ON CONFLICT(group_id, user_id, device_id) DO UPDATE SET
      leaf_index = excluded.leaf_index,
      role = excluded.role,
      removed_at = NULL
  `).run(String(groupId), userId, String(deviceId), Number(leafIndex) || 0, String(role || 'member'), now);
}

function removeMlsGroupMember(groupId, userId, deviceId) {
  db.prepare(`
    UPDATE mls_group_members SET removed_at = ?
    WHERE group_id = ? AND user_id = ? AND device_id = ? AND removed_at IS NULL
  `).run(Date.now(), String(groupId), userId, String(deviceId));
}

function getMlsGroupMembers(groupId) {
  return db.prepare(`
    SELECT user_id, device_id, leaf_index, role, joined_at
    FROM mls_group_members
    WHERE group_id = ? AND removed_at IS NULL
    ORDER BY leaf_index ASC
  `).all(String(groupId));
}

function isMlsGroupMember(groupId, userId, deviceId = null) {
  if (deviceId) {
    const row = db.prepare(`
      SELECT 1 FROM mls_group_members
      WHERE group_id = ? AND user_id = ? AND device_id = ? AND removed_at IS NULL
    `).get(String(groupId), userId, String(deviceId));
    return !!row;
  }
  const row = db.prepare(`
    SELECT 1 FROM mls_group_members
    WHERE group_id = ? AND user_id = ? AND removed_at IS NULL
  `).get(String(groupId), userId);
  return !!row;
}

function getUserMlsGroups(userId) {
  return db.prepare(`
    SELECT DISTINCT group_id
    FROM mls_group_members
    WHERE user_id = ? AND removed_at IS NULL
  `).all(userId).map(r => r.group_id);
}

// Standalone Public Proposals
function saveMlsProposal(groupId, epoch, proposalRef, senderLeaf, proposalType, proposalData) {
  const now = Date.now();
  db.prepare(`
    INSERT INTO mls_proposals (group_id, epoch, proposal_ref, sender_leaf, proposal_type, proposal_data, created_at, consumed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
    ON CONFLICT(group_id, proposal_ref) DO NOTHING
  `).run(String(groupId), Number(epoch), String(proposalRef), Number(senderLeaf), Number(proposalType), String(proposalData), now);
}

function getPendingMlsProposals(groupId, epoch) {
  return db.prepare(`
    SELECT proposal_ref, sender_leaf, proposal_type, proposal_data, created_at
    FROM mls_proposals
    WHERE group_id = ? AND epoch = ? AND consumed_at IS NULL
    ORDER BY created_at ASC
  `).all(String(groupId), Number(epoch));
}

function consumeMlsProposals(groupId, proposalRefs) {
  if (!Array.isArray(proposalRefs) || !proposalRefs.length) return 0;
  const now = Date.now();
  const placeholders = proposalRefs.map(() => '?').join(',');
  const res = db.prepare(`
    UPDATE mls_proposals SET consumed_at = ?
    WHERE group_id = ? AND proposal_ref IN (${placeholders}) AND consumed_at IS NULL
  `).run(now, String(groupId), ...proposalRefs);
  return res.changes;
}

function getMlsGroup(groupId) {
  const g = db.prepare(`SELECT * FROM mls_groups WHERE group_id = ?`).get(String(groupId));
  if (!g) return null;
  const members = getMlsGroupMembers(groupId);
  return {
    ...g,
    members,
    active_members: members.map(m => m.user_id)
  };
}

function initMlsGroup(groupId, initialEpoch, members = [], commitData = null, welcomes = [], idempotencyKey = null) {
  const now = Date.now();
  const gid = String(groupId).trim();
  const ep = Number(initialEpoch) || 0;

  // Support positional: initMlsGroup(gid, ep, members, commitData, welcomes, idemKey) or initMlsGroup(gid, ep, members, commitData, idemKey)
  let idemKey = idempotencyKey;
  let welc = Array.isArray(welcomes) ? welcomes : [];
  if (typeof welcomes === 'string') {
    idemKey = welcomes;
    welc = [];
  }

  if (idemKey) {
    const existingIdem = db.prepare(`
      SELECT epoch, commit_hash FROM mls_idempotency
      WHERE group_id = ? AND idempotency_key = ? AND expires_at > ?
    `).get(gid, String(idemKey), now);
    if (existingIdem) return { ok: true, group_id: gid, epoch: existingIdem.epoch };
  }

  db.exec('BEGIN IMMEDIATE');
  try {
    const existing = db.prepare(`SELECT epoch FROM mls_groups WHERE group_id = ?`).get(gid);
    if (existing) {
      const err = new Error('Group already exists');
      err.code = 'GROUP_EXISTS';
      err.epoch = existing.epoch;
      throw err;
    }

    const commitProvided = !!commitData;
    const activeEp = commitProvided ? ep + 1 : ep;

    db.prepare(`
      INSERT INTO mls_groups (group_id, epoch, created_at, updated_at)
      VALUES (?, ?, ?, ?)
    `).run(gid, activeEp, now, now);

    if (Array.isArray(members) && members.length) {
      const insertMember = db.prepare(`
        INSERT INTO mls_group_members (group_id, user_id, device_id, leaf_index, role, joined_at, removed_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(group_id, user_id, device_id) DO UPDATE SET
          leaf_index = excluded.leaf_index,
          role = excluded.role,
          removed_at = NULL
      `);
      for (const m of members) {
        if (m.user_id && m.device_id) {
          insertMember.run(gid, m.user_id, String(m.device_id), Number(m.leaf_index) || 0, String(m.role || 'member'), now);
        }
      }
    }

    let commitHash = '';
    if (commitData) {
      db.prepare(`
        INSERT INTO mls_commits (group_id, epoch, commit_data, created_at)
        VALUES (?, ?, ?, ?)
      `).run(gid, activeEp, String(commitData), now);
      commitHash = String(commitData).slice(0, 32);
    }

    if (welc.length) {
      const insertWelcome = db.prepare(`
        INSERT INTO mls_welcomes (group_id, user_id, device_id, epoch, welcome_data, created_at, fetched_at, acked_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
      `);
      for (const w of welc) {
        if (w.user_id && w.device_id && w.welcome_data) {
          insertWelcome.run(gid, w.user_id, String(w.device_id), activeEp, String(w.welcome_data), now);
        }
      }
    }

    const response = { ok: true, group_id: gid, epoch: activeEp };
    if (idemKey) {
      db.prepare(`
        INSERT INTO mls_idempotency (group_id, idempotency_key, epoch, commit_hash, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(group_id, idempotency_key) DO UPDATE SET
          epoch = excluded.epoch,
          commit_hash = excluded.commit_hash,
          expires_at = excluded.expires_at
      `).run(gid, String(idemKey), activeEp, commitHash, now, now + 86400000);
    }
    db.exec('COMMIT');
    return response;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function commitMlsGroup(groupId, expectedEpoch, commitData, welcomes = [], proposalsToConsume = [], membersToAdd = [], membersToRemove = [], idempotencyKey = null) {
  const now = Date.now();
  const gid = String(groupId).trim();
  const expEp = Number(expectedEpoch);

  let proposals = Array.isArray(proposalsToConsume) ? proposalsToConsume : [];
  let toAdd = Array.isArray(membersToAdd) ? membersToAdd : [];
  let toRemove = Array.isArray(membersToRemove) ? membersToRemove : [];
  let welc = Array.isArray(welcomes) ? welcomes : [];
  let idemKey = idempotencyKey;

  // Support positional idempotencyKey: commitMlsGroup(gid, ep, data, welcomes, idemKey)
  if (typeof proposalsToConsume === 'string') {
    idemKey = proposalsToConsume;
    proposals = [];
  } else if (typeof membersToAdd === 'string') {
    idemKey = membersToAdd;
    toAdd = [];
  }

  if (idemKey) {
    const existingIdem = db.prepare(`
      SELECT epoch, commit_hash FROM mls_idempotency
      WHERE group_id = ? AND idempotency_key = ? AND expires_at > ?
    `).get(gid, String(idemKey), now);
    if (existingIdem) return { ok: true, group_id: gid, new_epoch: existingIdem.epoch };
  }

  db.exec('BEGIN IMMEDIATE');
  try {
    const g = db.prepare(`SELECT epoch FROM mls_groups WHERE group_id = ?`).get(gid);
    if (!g) {
      const err = new Error('Group not found');
      err.code = 'GROUP_NOT_FOUND';
      throw err;
    }
    if (g.epoch !== expEp) {
      const err = new Error('Epoch conflict: expected ' + expEp + ' but server is at ' + g.epoch);
      err.code = 'EPOCH_CONFLICT';
      err.server_epoch = g.epoch;
      throw err;
    }

    const newEpoch = expEp + 1;
    db.prepare(`UPDATE mls_groups SET epoch = ?, updated_at = ? WHERE group_id = ? AND epoch = ?`).run(newEpoch, now, gid, expEp);

    let commitHash = '';
    if (commitData) {
      db.prepare(`
        INSERT INTO mls_commits (group_id, epoch, commit_data, created_at)
        VALUES (?, ?, ?, ?)
      `).run(gid, newEpoch, String(commitData), now);
      commitHash = String(commitData).slice(0, 32);
    }

    if (toAdd.length) {
      const insertMember = db.prepare(`
        INSERT INTO mls_group_members (group_id, user_id, device_id, leaf_index, role, joined_at, removed_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(group_id, user_id, device_id) DO UPDATE SET
          leaf_index = excluded.leaf_index,
          role = excluded.role,
          removed_at = NULL
      `);
      for (const m of toAdd) {
        if (m.user_id && m.device_id) {
          insertMember.run(gid, m.user_id, String(m.device_id), Number(m.leaf_index) || 0, String(m.role || 'member'), now);
        }
      }
    }

    if (toRemove.length) {
      const removeMember = db.prepare(`
        UPDATE mls_group_members SET removed_at = ?
        WHERE group_id = ? AND user_id = ? AND device_id = ? AND removed_at IS NULL
      `);
      for (const m of toRemove) {
        if (m.user_id && m.device_id) {
          removeMember.run(now, gid, m.user_id, String(m.device_id));
        }
      }
    }

    if (proposals.length) {
      consumeMlsProposals(gid, proposals);
    }

    if (welc.length) {
      const insertWelcome = db.prepare(`
        INSERT INTO mls_welcomes (group_id, user_id, device_id, epoch, welcome_data, created_at, fetched_at, acked_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
      `);
      for (const w of welc) {
        if (w.user_id && w.device_id && w.welcome_data) {
          insertWelcome.run(gid, w.user_id, String(w.device_id), newEpoch, String(w.welcome_data), now);
        }
      }
    }

    const response = { ok: true, group_id: gid, new_epoch: newEpoch };
    if (idemKey) {
      db.prepare(`
        INSERT INTO mls_idempotency (group_id, idempotency_key, epoch, commit_hash, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(group_id, idempotency_key) DO UPDATE SET
          epoch = excluded.epoch,
          commit_hash = excluded.commit_hash,
          expires_at = excluded.expires_at
      `).run(gid, String(idemKey), newEpoch, commitHash, now, now + 86400000);
    }
    db.exec('COMMIT');
    return response;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function getMlsCommits(groupId, sinceEpoch = -1) {
  return db.prepare(`
    SELECT epoch, commit_data, created_at
    FROM mls_commits
    WHERE group_id = ? AND epoch > ?
    ORDER BY epoch ASC
  `).all(String(groupId), Number(sinceEpoch));
}

function getMlsWelcomes(userId, deviceId) {
  const now = Date.now();
  const welcomes = db.prepare(`
    SELECT id, group_id, epoch, welcome_data, created_at, fetched_at
    FROM mls_welcomes
    WHERE user_id = ? AND device_id = ? AND acked_at IS NULL
    ORDER BY id ASC
  `).all(userId, String(deviceId));

  if (welcomes.length) {
    const ids = welcomes.map(w => w.id);
    const placeholders = ids.map(() => '?').join(',');
    db.prepare(`UPDATE mls_welcomes SET fetched_at = COALESCE(fetched_at, ?) WHERE id IN (${placeholders})`).run(now, ...ids);
  }

  return welcomes;
}

function ackMlsWelcome(welcomeId, userId, deviceId) {
  return db.prepare(`
    UPDATE mls_welcomes SET acked_at = ?
    WHERE id = ? AND user_id = ? AND device_id = ? AND acked_at IS NULL
  `).run(Date.now(), Number(welcomeId), userId, String(deviceId));
}

function saveMlsBackup(userId, backupData, salt) {
  const now = Date.now();
  db.prepare(`
    INSERT INTO mls_credential_backups (user_id, backup_data, kek_salt, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      backup_data = excluded.backup_data,
      kek_salt = excluded.kek_salt,
      updated_at = excluded.updated_at
  `).run(userId, String(backupData), String(salt), now);
}

function getMlsBackup(userId) {
  return db.prepare(`
    SELECT backup_data, kek_salt, updated_at
    FROM mls_credential_backups
    WHERE user_id = ?
  `).get(userId) || null;
}

function getHistoricalDmMessagesForMigration(userId, afterId = 0, limit = 50) {
  return db.prepare(`
    SELECT m.id, m.from_id, m.to_id, m.body, m.proto, m.sender_ciphertext, m.key_for_sender, m.key_for_recipient, m.created_at, m.edited_at, m.secure,
           u_from.username AS from_username, u_to.username AS to_username
    FROM messages m
    JOIN users u_from ON u_from.id = m.from_id
    JOIN users u_to ON u_to.id = m.to_id
    WHERE (m.from_id = ? OR m.to_id = ?)
      AND m.id > ?
      AND m.proto IN ('olm', 'rsa')
    ORDER BY m.id ASC
    LIMIT ?
  `).all(userId, userId, afterId, limit);
}

function getHistoricalRoomMessagesForMigration(userId, afterId = 0, limit = 50) {
  return db.prepare(`
    SELECT rm.id, rm.channel_id, rc.room_id, rm.user_id, rm.body, rm.proto, rm.ciphertext, rm.group_session_id, rm.created_at, rm.edited_at,
           u.username AS author_username
    FROM room_messages rm
    JOIN room_channels rc ON rc.id = rm.channel_id
    JOIN rooms r ON r.id = rc.room_id
    LEFT JOIN room_members mem ON mem.room_id = r.id AND mem.user_id = ?
    JOIN users u ON u.id = rm.user_id
    WHERE rm.id > ?
      AND rm.proto = 'megolm'
      AND (mem.user_id IS NOT NULL OR r.creator_id = ?)
    ORDER BY rm.id ASC
    LIMIT ?
  `).all(userId, afterId, userId, limit);
}

function recordMessageTraffic(proto) {
  if (!proto) return;
  const isMls = (proto === 'mls');
  const isLegacyE2ee = (proto === 'olm' || proto === 'megolm' || proto === 'rsa');
  if (!isMls && !isLegacyE2ee) return;

  const today = new Date().toISOString().slice(0, 10);
  const col = isMls ? 'proto_mls' : 'proto_legacy';
  db.prepare(`
    INSERT INTO mls_traffic_stats (date, proto_mls, proto_legacy)
    VALUES (?, ${isMls ? 1 : 0}, ${isLegacyE2ee ? 1 : 0})
    ON CONFLICT(date) DO UPDATE SET ${col} = ${col} + 1
  `).run(today);
}

function getLegacyTrafficSunsetStatus() {
  const rows = db.prepare(`
    SELECT date, proto_mls, proto_legacy
    FROM mls_traffic_stats
    ORDER BY date DESC
    LIMIT 30
  `).all();

  let consecutiveZeroDays = 0;
  for (const r of rows) {
    if (r.proto_legacy === 0 && r.proto_mls > 0) {
      consecutiveZeroDays++;
    } else {
      break;
    }
  }

  return {
    consecutive_zero_legacy_days: consecutiveZeroDays,
    sunset_eligible: (consecutiveZeroDays >= 30),
    recorded_days_count: rows.length,
    recent_history: rows
  };
}

function recordMigrationTelemetry(userId, hasCompletedFullScan, totalMigrated, unrecoverableBucket, blockedByPolicy) {
  const allowed = ['0', '1-10', '11-100', '100+'];
  const bucket = allowed.includes(unrecoverableBucket) ? unrecoverableBucket : '0';
  db.prepare(`
    INSERT INTO mls_migration_telemetry (user_id, has_completed_full_scan, total_migrated, unrecoverable_bucket, blocked_by_policy, reported_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      has_completed_full_scan = excluded.has_completed_full_scan,
      total_migrated = excluded.total_migrated,
      unrecoverable_bucket = excluded.unrecoverable_bucket,
      blocked_by_policy = excluded.blocked_by_policy,
      reported_at = excluded.reported_at
  `).run(userId, hasCompletedFullScan ? 1 : 0, totalMigrated || 0, bucket, blockedByPolicy ? 1 : 0, Date.now());
}

let lastAuditTs = 0;
function recordSunsetAudit(event, coveragePct, requiredCoveragePct, operatorName, migrationStartDate, sunsetCutoffDate, acknowledgedBy, operatorIp) {
  const now = Date.now();
  if (now - lastAuditTs < 5000) return;
  lastAuditTs = now;
  try {
    db.prepare(`
      INSERT INTO mls_sunset_audit (
        event, timestamp, coverage_pct, required_coverage_pct, operator_name, migration_start_date, sunset_cutoff_date, acknowledged_by, operator_ip
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      event,
      now,
      coveragePct != null ? coveragePct : 0,
      requiredCoveragePct != null ? requiredCoveragePct : 99,
      operatorName || 'unattributed',
      migrationStartDate || '',
      sunsetCutoffDate || '',
      acknowledgedBy || 'SYSTEM',
      operatorIp || '127.0.0.1'
    );
  } catch (_) {}
}

function getFleetMigrationSummary() {
  const totalUsersRow = db.prepare(`SELECT COUNT(*) AS total FROM users`).get();
  const totalUsers = totalUsersRow ? totalUsersRow.total : 0;

  const thirtyDaysAgo = Date.now() - (30 * 86400 * 1000);

  // Active users in last 30 days (sent or received in messages or room_messages)
  const activeUserRows = db.prepare(`
    SELECT DISTINCT user_id FROM (
      SELECT from_id AS user_id FROM messages WHERE created_at > ?
      UNION
      SELECT to_id AS user_id FROM messages WHERE created_at > ?
      UNION
      SELECT user_id FROM room_messages WHERE created_at > ?
    )
  `).all(thirtyDaysAgo, thirtyDaysAgo, thirtyDaysAgo);
  const activeUserIds = new Set(activeUserRows.map(r => r.user_id));
  const activeUsersTotal = activeUserIds.size;

  // Migrated signal: (1) hasCompletedFullScan reported via telemetry
  const telemetryScanRows = db.prepare(`
    SELECT user_id FROM mls_migration_telemetry WHERE has_completed_full_scan = 1
  `).all();
  const scanMigratedSet = new Set(telemetryScanRows.map(r => r.user_id));

  // (2) Server-side negative heuristic: has registered MLS devices AND 0 legacy messages in last 30d
  const mlsDeviceUsers = db.prepare(`SELECT DISTINCT user_id FROM mls_devices`).all();
  const mlsDeviceUserSet = new Set(mlsDeviceUsers.map(r => r.user_id));

  const legacyActiveUsers = db.prepare(`
    SELECT DISTINCT user_id FROM (
      SELECT from_id AS user_id FROM messages WHERE proto IN ('olm', 'megolm', 'rsa') AND created_at > ?
      UNION
      SELECT to_id AS user_id FROM messages WHERE proto IN ('olm', 'megolm', 'rsa') AND created_at > ?
      UNION
      SELECT user_id FROM room_messages WHERE proto IN ('olm', 'megolm') AND created_at > ?
    )
  `).all(thirtyDaysAgo, thirtyDaysAgo, thirtyDaysAgo);
  const legacyActiveSet = new Set(legacyActiveUsers.map(r => r.user_id));

  function isUserMigrated(uid) {
    return scanMigratedSet.has(uid) || (mlsDeviceUserSet.has(uid) && !legacyActiveSet.has(uid));
  }

  // Count active migrated users
  let activeMigratedCount = 0;
  for (const uid of activeUserIds) {
    if (isUserMigrated(uid)) activeMigratedCount++;
  }

  // Count registered migrated users
  const allUserRows = db.prepare(`SELECT id FROM users`).all();
  let registeredMigratedCount = 0;
  for (const u of allUserRows) {
    if (isUserMigrated(u.id)) registeredMigratedCount++;
  }

  const registeredCoveragePct = totalUsers > 0 ? Math.round((registeredMigratedCount / totalUsers) * 100) : 0;
  const activeCoveragePct = activeUsersTotal > 0
    ? Math.round((activeMigratedCount / activeUsersTotal) * 100)
    : (totalUsers > 0 ? registeredCoveragePct : 100);

  const blockedUsersRow = db.prepare(`
    SELECT COUNT(*) AS blocked FROM mls_migration_telemetry WHERE blocked_by_policy = 1
  `).get();
  const blockedUsers = blockedUsersRow ? blockedUsersRow.blocked : 0;

  const buckets = db.prepare(`
    SELECT unrecoverable_bucket, COUNT(*) AS count
    FROM mls_migration_telemetry
    GROUP BY unrecoverable_bucket
  `).all();

  const now = Date.now();
  const rolling7dTs = now - (7 * 86400 * 1000);
  const failureStats = db.prepare(`
    SELECT
      COUNT(*) AS total_reporters,
      SUM(CASE WHEN unrecoverable_bucket != '0' THEN 1 ELSE 0 END) AS reporters_with_failures,
      SUM(CASE WHEN reported_at >= ? THEN 1 ELSE 0 END) AS reporters_active_7d,
      SUM(CASE WHEN reported_at >= ? AND unrecoverable_bucket != '0' THEN 1 ELSE 0 END) AS failures_active_7d
    FROM mls_migration_telemetry
  `).get(rolling7dTs, rolling7dTs);

  const totalReporters = failureStats ? (failureStats.total_reporters || 0) : 0;
  const reportersWithFailures = failureStats ? (failureStats.reporters_with_failures || 0) : 0;
  const reportersActive7d = failureStats ? (failureStats.reporters_active_7d || 0) : 0;
  const failuresActive7d = failureStats ? (failureStats.failures_active_7d || 0) : 0;

  const pctUsersWithAnyFailuresAllTime = totalReporters > 0
    ? Math.round((reportersWithFailures / totalReporters) * 10000) / 100
    : 0;
  const pctActiveUsersWithFailures7d = reportersActive7d > 0
    ? Math.round((failuresActive7d / reportersActive7d) * 10000) / 100
    : 0;

  // 1. Traffic Sunset Sub-Criterion (30 consecutive zero legacy days)
  const sunsetStatus = getLegacyTrafficSunsetStatus();
  const trafficReady = Boolean(sunsetStatus.sunset_eligible);

  // 2. Fleet Migration Sub-Criterion (Configurable active users threshold, default 99%)
  const requiredCoveragePct = parseInt(process.env.MLS_REQUIRED_COVERAGE_PCT, 10) || 99;
  const fleetReady = (activeCoveragePct >= requiredCoveragePct);

  // 3. Time Window Sub-Criterion (180 days elapsed since migration launch)
  const launchDateStr = process.env.MLS_MIGRATION_START_DATE || '2026-10-05T00:00:00.000Z';
  const launchTs = new Date(launchDateStr).getTime();
  const cutoffDateStr = process.env.MLS_SUNSET_DATE || new Date(launchTs + (365 * 86400 * 1000)).toISOString();
  const elapsedDays = Math.max(0, Math.floor((Date.now() - launchTs) / (86400 * 1000)));
  const timeReady = (elapsedDays >= 180);

  // Force Sunset override check (requires both flag and explicit acknowledgment)
  const forceSunset = (process.env.MLS_FORCE_SUNSET === 'true' && process.env.MLS_FORCE_SUNSET_ACK === 'I_ACCEPT_DATA_LOSS');

  const allCriteriaMet = (trafficReady && fleetReady && timeReady) || forceSunset;

  return {
    traffic_sunset: {
      consecutive_zero_legacy_days: sunsetStatus.consecutive_zero_legacy_days,
      required_days: 30,
      ready: trafficReady
    },
    fleet_migration: {
      active_users_30d: activeUsersTotal,
      migrated_active_users: activeMigratedCount,
      active_users_coverage_pct: activeCoveragePct,
      required_coverage_pct: requiredCoveragePct,
      registered_users_total: totalUsers,
      registered_users_migrated: registeredMigratedCount,
      registered_users_coverage_pct: registeredCoveragePct,
      blocked_users: blockedUsers,
      ready: fleetReady,
      buckets: buckets,
      pct_active_users_with_failures_7d: pctActiveUsersWithFailures7d,
      pct_users_with_any_failures_7d: pctActiveUsersWithFailures7d, // backwards-compatible alias
      pct_users_with_any_failures_all_time: pctUsersWithAnyFailuresAllTime,
      reporters_active_7d: reportersActive7d,
      reporters_7d: reportersActive7d, // backwards-compatible alias for dashboards
      failures_active_7d: failuresActive7d,
      failures_7d: failuresActive7d, // backwards-compatible alias for dashboards
      all_time_reporters: totalReporters,
      all_time_users_with_failures: reportersWithFailures
    },
    time_window: {
      migration_start_date: launchDateStr,
      sunset_cutoff_date: cutoffDateStr,
      days_elapsed: elapsedDays,
      days_required: 180,
      ready: timeReady
    },
    all_criteria_met: allCriteriaMet,
    force_sunset_active: forceSunset
  };
}

function isLegacyE2eeEnabled(operatorIp) {
  if (process.env.E2EE_LEGACY_ENABLED === 'false') {
    const summary = getFleetMigrationSummary();
    if (summary.force_sunset_active) {
      const opName = process.env.MLS_FORCE_SUNSET_OPERATOR || 'unattributed';
      recordSunsetAudit(
        'force_sunset_engaged',
        summary.fleet_migration.active_users_coverage_pct,
        summary.fleet_migration.required_coverage_pct,
        opName,
        summary.time_window.migration_start_date,
        summary.time_window.sunset_cutoff_date,
        process.env.MLS_FORCE_SUNSET_ACK,
        operatorIp
      );
      return false;
    }
    if (!summary.all_criteria_met) {
      // Safety guard: criteria not met and not force sunset acknowledged -> keep legacy enabled
      return true;
    }
    return false;
  }
  return true;
}

// ---------- two-factor authentication (TOTP / recovery codes) ----------
function setTotpSecret(userId, encryptedSecret) {
  db.prepare(`UPDATE users SET totp_secret = ? WHERE id = ?`).run(encryptedSecret || null, userId);
}

function setTotpEnabled(userId, confirmedAt) {
  db.prepare(`UPDATE users SET totp_enabled = ?, totp_confirmed_at = ? WHERE id = ?`)
    .run(confirmedAt ? 1 : 0, confirmedAt || null, userId);
}

function replaceRecoveryCodes(userId, codeHashes, createdAt) {
  const now = createdAt || Date.now();
  db.exec('BEGIN');
  try {
    db.prepare(`DELETE FROM recovery_codes WHERE user_id = ?`).run(userId);
    const ins = db.prepare(`INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)`);
    for (const hash of codeHashes) ins.run(userId, hash, now);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function listRecoveryCodes(userId) {
  return db.prepare(`SELECT id, code_hash, used_at, created_at FROM recovery_codes WHERE user_id = ? ORDER BY id`).all(userId);
}

function countUnusedRecoveryCodes(userId) {
  const row = db.prepare(`SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`).get(userId);
  return row.n;
}

// Atomic single-use consume (cf. markOAuthCodeUsed): returns true when this
// exact unused hash was flipped to used by THIS call.
function consumeRecoveryCode(userId, codeHash) {
  const res = db.prepare(`UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`)
    .run(Date.now(), userId, codeHash);
  return res.changes > 0;
}

// ---------- passkeys (WebAuthn credentials) ----------
function createPasskey(p) {
  const now = Date.now();
  const res = db.prepare(`
    INSERT INTO passkeys (user_id, credential_id, public_key, counter, device_name, transports, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(p.userId, p.credentialId, p.publicKey, p.counter || 0, p.deviceName || null,
         p.transports ? JSON.stringify(p.transports) : null, now);
  return getPasskeyById(res.lastInsertRowid);
}

function getPasskeyById(id) {
  return db.prepare(`SELECT * FROM passkeys WHERE id = ?`).get(id);
}

// Global lookup: authentication happens before we know the user.
function getPasskeyByCredentialId(credentialId) {
  return db.prepare(`SELECT * FROM passkeys WHERE credential_id = ?`).get(String(credentialId));
}

function getPasskeysByUser(userId) {
  return db.prepare(`SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at DESC, id DESC`).all(userId);
}

function countPasskeys(userId) {
  const row = db.prepare(`SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?`).get(userId);
  return row.n;
}

function updatePasskeyCounter(id, counter) {
  db.prepare(`UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?`).run(counter, Date.now(), id);
}

function touchPasskey(id) {
  db.prepare(`UPDATE passkeys SET last_used_at = ? WHERE id = ?`).run(Date.now(), id);
}

function renamePasskey(id, userId, deviceName) {
  const res = db.prepare(`UPDATE passkeys SET device_name = ? WHERE id = ? AND user_id = ?`).run(deviceName, id, userId);
  return res.changes > 0;
}

function deletePasskey(id, userId) {
  const res = db.prepare(`DELETE FROM passkeys WHERE id = ? AND user_id = ?`).run(id, userId);
  return res.changes > 0;
}

// ---------- trusted devices ("remember this device" for 2FA) ----------
function addTrustedDevice(userId, tokenHash, expiresAt) {
  const now = Date.now();
  db.prepare(`INSERT INTO trusted_devices (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)`)
    .run(userId, tokenHash, now, expiresAt);
}

// Expired rows are treated as absent; non-expired reads refresh last_used_at.
function getTrustedDevice(tokenHash) {
  const row = db.prepare(`SELECT * FROM trusted_devices WHERE token_hash = ?`).get(tokenHash);
  if (!row) return null;
  if (row.expires_at <= Date.now()) {
    db.prepare(`DELETE FROM trusted_devices WHERE token_hash = ?`).run(tokenHash);
    return null;
  }
  db.prepare(`UPDATE trusted_devices SET last_used_at = ? WHERE id = ?`).run(Date.now(), row.id);
  return row;
}

function listTrustedDevices(userId) {
  return db.prepare(`SELECT * FROM trusted_devices WHERE user_id = ? ORDER BY created_at DESC, id DESC`).all(userId);
}

function deleteTrustedDevice(id, userId) {
  const res = db.prepare(`DELETE FROM trusted_devices WHERE id = ? AND user_id = ?`).run(id, userId);
  return res.changes > 0;
}

function deleteAllTrustedDevices(userId) {
  db.prepare(`DELETE FROM trusted_devices WHERE user_id = ?`).run(userId);
}

function pruneExpiredTrustedDevices() {
  db.prepare(`DELETE FROM trusted_devices WHERE expires_at <= ?`).run(Date.now());
}

// ---------- account deletion ----------
function deleteUser(userId) {
  // Remove every row referencing the user (FKs are enforced), in dependency
  // order, inside one transaction so a failure can't leave a half-deleted
  // account behind. Rooms the user created are deleted with all their content;
  // nullable references (announcement author, security-report handler) are
  // orphaned to NULL instead.
  db.exec('BEGIN');
  try {
    // Orphan any users this user referred.
    db.prepare(`UPDATE users SET referred_by = NULL WHERE referred_by = ?`).run(userId);
    // Delete posts-related data: collect all post IDs by this user.
    const postIds = db.prepare(`SELECT id FROM posts WHERE user_id = ?`).all(userId).map(r => r.id);
    for (const pid of postIds) {
      db.prepare(`DELETE FROM likes WHERE post_id = ?`).run(pid);
      db.prepare(`DELETE FROM comments WHERE post_id = ?`).run(pid);
      db.prepare(`DELETE FROM shares WHERE post_id = ?`).run(pid);
      db.prepare(`DELETE FROM follows_from_post WHERE post_id = ?`).run(pid);
      db.prepare(`DELETE FROM notifications WHERE post_id = ?`).run(pid);
      db.prepare(`DELETE FROM edit_history WHERE entity_type = 'post' AND entity_id = ?`).run(pid);
      db.prepare(`DELETE FROM posts WHERE repost_of_id = ?`).run(pid);
    }
    db.prepare(`DELETE FROM posts WHERE user_id = ?`).run(userId);
    // User activity.
    db.prepare(`DELETE FROM likes WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM comments WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM shares WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM follows WHERE follower_id = ? OR followee_id = ?`).run(userId, userId);
    db.prepare(`DELETE FROM follows_from_post WHERE follower_id = ? OR followee_id = ?`).run(userId, userId);
    db.prepare(`DELETE FROM notifications WHERE user_id = ? OR actor_id = ?`).run(userId, userId);
    db.prepare(`DELETE FROM messages WHERE from_id = ? OR to_id = ?`).run(userId, userId);
    db.prepare(`DELETE FROM profile_customization WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM user_public_keys WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM stickers WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM dm_security WHERE user_id = ? OR other_id = ?`).run(userId, userId);
    db.prepare(`DELETE FROM olm_identity WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM olm_prekeys WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM olm_device_prekeys WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM user_devices WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM user_history_backup WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM media_attachments WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM edit_history WHERE edited_by = ?`).run(userId);
    db.prepare(`DELETE FROM push_subscriptions WHERE user_id = ?`).run(userId);
    // Two-factor / passkey credentials.
    db.prepare(`DELETE FROM recovery_codes WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM passkeys WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM trusted_devices WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM audit_log WHERE actor_id = ?`).run(userId);
    db.prepare(`UPDATE announcement SET author_id = NULL WHERE author_id = ?`).run(userId);
    db.prepare(`UPDATE security_reports SET handled_by = NULL WHERE handled_by = ?`).run(userId);
    // OAuth: tokens and codes reference apps; delete children before the apps.
    db.prepare(`DELETE FROM oauth_codes WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM oauth_tokens WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM oauth_apps WHERE owner_id = ?`).run(userId);
    // Rooms this user created: delete the room and everything in it.
    const roomIds = db.prepare(`SELECT id FROM rooms WHERE creator_id = ?`).all(userId).map(r => r.id);
    for (const rid of roomIds) {
      const chanIds = db.prepare(`SELECT id FROM room_channels WHERE room_id = ?`).all(rid).map(r => r.id);
      for (const cid of chanIds) db.prepare(`DELETE FROM room_messages WHERE channel_id = ?`).run(cid);
      db.prepare(`DELETE FROM room_channels WHERE room_id = ?`).run(rid);
      db.prepare(`DELETE FROM room_members WHERE room_id = ?`).run(rid);
      db.prepare(`DELETE FROM room_roles WHERE room_id = ?`).run(rid);
      const gsIds = db.prepare(`SELECT id FROM room_group_sessions WHERE room_id = ?`).all(rid).map(r => r.id);
      for (const gid of gsIds) {
        db.prepare(`DELETE FROM room_group_session_keys WHERE session_id = ?`).run(gid);
        db.prepare(`DELETE FROM room_group_sessions WHERE id = ?`).run(gid);
      }
      db.prepare(`DELETE FROM reports WHERE room_id = ?`).run(rid);
      db.prepare(`DELETE FROM join_requests WHERE room_id = ?`).run(rid);
      db.prepare(`DELETE FROM rooms WHERE id = ?`).run(rid);
    }
    // Membership / messages in other users' rooms.
    db.prepare(`DELETE FROM room_members WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM room_messages WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM join_requests WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM room_group_sessions WHERE sender_id = ?`).run(userId);
    db.prepare(`DELETE FROM room_group_session_keys WHERE recipient_id = ?`).run(userId);
    // Reports involving this user (columns are NOT NULL — delete; the account is
    // gone so the moderation case is moot).
    db.prepare(`DELETE FROM reports WHERE reporter_id = ? OR reported_user_id = ?`).run(userId, userId);
    // Finally the user row.
    db.prepare(`DELETE FROM users WHERE id = ?`).run(userId);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

// ---------- admin ----------
function banUser(userId) {
  db.prepare(`UPDATE users SET banned = 1 WHERE id = ?`).run(userId);
}

function unbanUser(userId) {
  db.prepare(`UPDATE users SET banned = 0 WHERE id = ?`).run(userId);
}

function getAllUsers() {
  return db.prepare(`SELECT id, username, display_name, referral_code, created_at, is_admin, banned, (SELECT COUNT(*) FROM users WHERE referred_by = users.id) AS referral_count FROM users ORDER BY created_at ASC`).all();
}

function promoteUser(userId) {
  db.prepare(`UPDATE users SET is_admin = 1 WHERE id = ?`).run(userId);
}

function demoteUser(userId) {
  db.prepare(`UPDATE users SET is_admin = 0 WHERE id = ?`).run(userId);
}

function removeReferralBadge(userId) {
  db.prepare(`UPDATE users SET referred_by = NULL WHERE referred_by = ?`).run(userId);
  db.prepare(`UPDATE users SET referral_code = NULL WHERE id = ?`).run(userId);
}

// ---------- referrals ----------
function setReferralCode(userId, ip) {
  const existing = db.prepare(`SELECT referral_code FROM users WHERE id = ?`).get(userId);
  if (existing && existing.referral_code) {
    if (ip) db.prepare(`UPDATE users SET referrer_ip = ? WHERE id = ?`).run(ip, userId);
    return existing.referral_code;
  }
  let code;
  do {
    code = crypto.randomBytes(6).toString('base64url');
  } while (db.prepare(`SELECT 1 FROM users WHERE referral_code = ?`).get(code));
  db.prepare(`UPDATE users SET referral_code = ?, referrer_ip = ? WHERE id = ?`).run(code, ip || null, userId);
  return code;
}

function getUserByReferralCode(code) {
  return db.prepare(`SELECT * FROM users WHERE referral_code = ?`).get(code);
}

function getReferralCount(userId) {
  const row = db.prepare(`SELECT COUNT(*) AS n FROM users WHERE referred_by = ?`).get(userId);
  return row.n;
}

function getReferralCode(userId) {
  const row = db.prepare(`SELECT referral_code FROM users WHERE id = ?`).get(userId);
  return row ? row.referral_code : null;
}

function getReferrerIp(userId) {
  const row = db.prepare(`SELECT referrer_ip FROM users WHERE id = ?`).get(userId);
  return row ? row.referrer_ip : null;
}

// ---------- stickers ----------
function addSticker(userId, filePath) {
  const res = db.prepare(`INSERT INTO stickers (user_id, file_path, created_at) VALUES (?,?,?)`).run(userId, filePath, Date.now());
  return res.lastInsertRowid;
}

function getMyStickers(userId) {
  return db.prepare(`SELECT id, file_path FROM stickers WHERE user_id = ? ORDER BY created_at DESC`).all(userId);
}

function deleteSticker(id, userId) {
  const res = db.prepare(`DELETE FROM stickers WHERE id = ? AND user_id = ?`).run(id, userId);
  return res.changes > 0;
}

function getStickerById(id) {
  return db.prepare(`SELECT * FROM stickers WHERE id = ?`).get(id);
}

// ---------- rooms ----------
function createRoom(name, description, creatorId, isPublic = 1) {
  const now = Date.now();
  const res = db.prepare(`INSERT INTO rooms (name, description, creator_id, is_public, created_at) VALUES (?,?,?,?,?)`).run(name, description, creatorId, isPublic ? 1 : 0, now);
  const roomId = res.lastInsertRowid;
  const founderRole = db.prepare(`INSERT INTO room_roles (room_id, name, color, permissions, is_founder, position, created_at) VALUES (?,?,?,?,?,?,?)`).run(roomId, 'Founder', '#ffd700', 127, 1, 100, now);
  const memberRole = db.prepare(`INSERT INTO room_roles (room_id, name, color, permissions, is_founder, position, created_at) VALUES (?,?,?,?,?,?,?)`).run(roomId, 'Member', '#cccccc', 3, 0, 0, now);
  db.prepare(`INSERT INTO room_members (room_id, user_id, role_id, joined_at) VALUES (?,?,?,?)`).run(roomId, creatorId, founderRole.lastInsertRowid, now);
  db.prepare(`INSERT INTO room_channels (room_id, name, created_at) VALUES (?,?,?)`).run(roomId, 'general', now);
  return roomId;
}
function getRoom(id) { return db.prepare(`SELECT * FROM rooms WHERE id = ?`).get(id); }
function getRoomsForUser(userId) {
  return db.prepare(`SELECT r.* FROM rooms r INNER JOIN room_members m ON m.room_id = r.id WHERE m.user_id = ? ORDER BY r.name`).all(userId);
}
function getAvailableRooms(userId) {
  return db.prepare(`SELECT r.id, r.name, r.description, r.is_public, r.created_at, (SELECT COUNT(*) FROM room_members WHERE room_id = r.id) AS member_count FROM rooms r WHERE r.id NOT IN (SELECT room_id FROM room_members WHERE user_id = ?) ORDER BY r.is_public DESC, r.name`).all(userId);
}
function updateRoom(id, name, description, html, css, isPublic) {
  db.prepare(`UPDATE rooms SET name=?, description=?, html=?, css=?, is_public=? WHERE id=?`).run(name, description, html, css, isPublic !== undefined ? (isPublic ? 1 : 0) : undefined, id);
}
function deleteRoomMessage(msgId) {
  db.prepare(`DELETE FROM edit_history WHERE entity_type = 'room_message' AND entity_id = ?`).run(msgId);
  db.prepare(`DELETE FROM room_messages WHERE id = ?`).run(msgId);
}
function deleteRoom(id) {
  db.prepare(`DELETE FROM room_messages WHERE channel_id IN (SELECT id FROM room_channels WHERE room_id = ?)`).run(id);
  db.prepare(`DELETE FROM room_channels WHERE room_id = ?`).run(id);
  db.prepare(`DELETE FROM room_members WHERE room_id = ?`).run(id);
  db.prepare(`DELETE FROM room_roles WHERE room_id = ?`).run(id);
  db.prepare(`DELETE FROM rooms WHERE id = ?`).run(id);
}
function isRoomMember(roomId, userId) { return !!db.prepare(`SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?`).get(roomId, userId); }
function addRoomMember(roomId, userId, roleId) {
  if (!roleId) {
    const defaultRole = joinDefaultRole(roomId);
    roleId = defaultRole ? defaultRole.id : null;
  }
  db.prepare(`INSERT OR IGNORE INTO room_members (room_id, user_id, role_id, joined_at) VALUES (?,?,?,?)`).run(roomId, userId, roleId, Date.now());
}
function removeRoomMember(roomId, userId) {
  db.prepare(`DELETE FROM room_members WHERE room_id = ? AND user_id = ?`).run(roomId, userId);
  // Delete queued undelivered keys for former members in this room so superseded sessions are not blocked
  db.prepare(`
    DELETE FROM room_group_session_keys
    WHERE recipient_id = ?
      AND session_id IN (SELECT id FROM room_group_sessions WHERE room_id = ?)
  `).run(userId, roomId);
}
function getRoomMembers(roomId) {
  return db.prepare(`SELECT u.id AS user_id, u.username, u.display_name, u.avatar, m.role_id, m.joined_at FROM room_members m INNER JOIN users u ON u.id = m.user_id WHERE m.room_id = ? ORDER BY m.joined_at`).all(roomId);
}
function getUserRoomRole(roomId, userId) {
  return db.prepare(`SELECT r.* FROM room_roles r INNER JOIN room_members m ON m.role_id = r.id WHERE m.room_id = ? AND m.user_id = ?`).get(roomId, userId);
}
function countRoomMembers(roomId) {
  return db.prepare(`SELECT COUNT(*) AS n FROM room_members WHERE room_id = ?`).get(roomId).n;
}
function createRoomRole(roomId, name, color, permissions, position) {
  return db.prepare(`INSERT INTO room_roles (room_id, name, color, permissions, position, created_at) VALUES (?,?,?,?,?,?)`).run(roomId, name, color, permissions, position, Date.now()).lastInsertRowid;
}
function getRoomRole(id) { return db.prepare(`SELECT * FROM room_roles WHERE id = ?`).get(id); }
function getRoomRoles(roomId) {
  return db.prepare(`SELECT * FROM room_roles WHERE room_id = ? ORDER BY position DESC, created_at`).all(roomId);
}
function updateRoomRole(id, name, color, permissions) {
  db.prepare(`UPDATE room_roles SET name=?, color=?, permissions=? WHERE id=?`).run(name, color, permissions, id);
}
function deleteRoomRole(id) {
  const role = getRoomRole(id);
  if (role && role.is_founder) return false;
  db.prepare(`UPDATE room_members SET role_id = (SELECT id FROM room_roles WHERE room_id = (SELECT room_id FROM room_roles WHERE id = ?) AND is_founder = 0 LIMIT 1) WHERE role_id = ?`).run(id, id);
  db.prepare(`DELETE FROM room_roles WHERE id = ?`).run(id);
  return true;
}
function transferFounder(roomId, newOwnerId) {
  const founderRole = db.prepare(`SELECT id FROM room_roles WHERE room_id = ? AND is_founder = 1`).get(roomId);
  if (founderRole) db.prepare(`UPDATE room_members SET role_id = ? WHERE room_id = ? AND user_id = ?`).run(founderRole.id, roomId, newOwnerId);
}
function createRoomChannel(roomId, name, viewRoleIds, writeRoleIds, type) {
  type = type || 'text';
  return db.prepare(`INSERT INTO room_channels (room_id, name, view_role_ids, write_role_ids, type, created_at) VALUES (?,?,?,?,?,?)`).run(roomId, name, viewRoleIds || null, writeRoleIds || null, type, Date.now()).lastInsertRowid;
}
function getRoomChannel(id) { return db.prepare(`SELECT * FROM room_channels WHERE id = ?`).get(id); }
function getRoomChannels(roomId) {
  return db.prepare(`SELECT * FROM room_channels WHERE room_id = ? ORDER BY created_at`).all(roomId);
}
function updateRoomChannel(id, name, viewRoleIds, writeRoleIds) {
  db.prepare(`UPDATE room_channels SET name=?, view_role_ids=?, write_role_ids=? WHERE id=?`).run(name, viewRoleIds || null, writeRoleIds || null, id);
}
function deleteRoomChannel(id) {
  db.prepare(`DELETE FROM room_messages WHERE channel_id = ?`).run(id);
  db.prepare(`DELETE FROM room_channels WHERE id = ?`).run(id);
}
function getRoomMessages(channelId, beforeId) {
  if (beforeId) {
    return db.prepare(`SELECT m.id, m.body, m.proto, m.ciphertext, m.group_session_id, m.created_at, m.edited_at, u.id AS user_id, u.username, u.display_name, u.avatar FROM room_messages m INNER JOIN users u ON u.id = m.user_id WHERE m.channel_id = ? AND m.id < ? ORDER BY m.id DESC LIMIT 50`).all(channelId, beforeId);
  }
  return db.prepare(`SELECT m.id, m.body, m.proto, m.ciphertext, m.group_session_id, m.created_at, m.edited_at, u.id AS user_id, u.username, u.display_name, u.avatar FROM room_messages m INNER JOIN users u ON u.id = m.user_id WHERE m.channel_id = ? ORDER BY m.id DESC LIMIT 50`).all(channelId).reverse();
}
function sendRoomMessage(channelId, userId, body, proto, ciphertext, groupSessionId) {
  const p = 'mls';
  return db.prepare(`INSERT INTO room_messages (channel_id, user_id, body, proto, ciphertext, group_session_id, created_at) VALUES (?,?,?,?,?,?,?)`).run(channelId, userId, body, p, ciphertext || null, null, Date.now()).lastInsertRowid;
}

// ---------- Megolm stubs (pure MLS mode) ----------
function pruneSupersededRoomGroupSessions() {}
function publishRoomGroupSession() { return 'mls'; }
function getRoomGroupSession() { return null; }
function isRoomGroupSessionUsable() { return false; }
function saveRoomSessionKeys() { return 0; }
function ensureRoomSessionRecipient() {}
function getPendingRoomSessionKeys() { return []; }
function getPendingRoomSessionKeyForUserAndSession() { return null; }
function getRoomSessionKeyById() { return null; }
function markRoomSessionKeyDelivered() {}
function getRoomSessionRecipients() { return []; }
function getRoomSessionEmptyKeyRecipients() { return []; }
function getUserMediaUsage(userId) {
  return db.prepare(`SELECT COALESCE(SUM(file_size),0) AS n FROM media_attachments WHERE user_id = ?`).get(userId).n;
}
// ---------- retention pruning ----------
function pruneAuditLog() {
  return db.prepare(`DELETE FROM audit_log WHERE created_at < ?`).run(Date.now() - 90 * 86400000);
}
function pruneNotifications() {
  const now = Date.now();
  return db.prepare(`DELETE FROM notifications WHERE (read = 1 AND created_at < ?) OR created_at < ?`)
    .run(now - 30 * 86400000, now - 90 * 86400000);
}
function joinDefaultRole(roomId) {
  return db.prepare(`SELECT id FROM room_roles WHERE room_id = ? AND is_founder = 0 ORDER BY position DESC, id LIMIT 1`).get(roomId);
}
function hasRoomPermission(roomId, userId, permBit) {
  const role = getUserRoomRole(roomId, userId);
  return role && (role.permissions & permBit) === permBit;
}

// ---------- reports ----------
function createReport(reporterId, reportedUserId, messageId, messageBody, channelId, roomId, reason) {
  return db.prepare(`INSERT INTO reports (reporter_id, reported_user_id, message_id, message_body, channel_id, room_id, reason, status, created_at) VALUES (?,?,?,?,?,?,?,'pending',?)`).run(reporterId, reportedUserId, messageId, messageBody, channelId, roomId, reason, Date.now()).lastInsertRowid;
}
function getPendingReports() {
  return db.prepare(`SELECT r.*, rep.username AS reporter_username, rep.display_name AS reporter_name, u.username, u.display_name, rm.name AS room_name FROM reports r INNER JOIN users rep ON rep.id = r.reporter_id INNER JOIN users u ON u.id = r.reported_user_id INNER JOIN rooms rm ON rm.id = r.room_id WHERE r.status = 'pending' ORDER BY r.created_at DESC`).all();
}
function getReport(id) {
  return db.prepare(`SELECT r.*, rep.username AS reporter_username, rep.display_name AS reporter_name, u.username, u.display_name, u.avatar, rm.name AS room_name FROM reports r INNER JOIN users rep ON rep.id = r.reporter_id INNER JOIN users u ON u.id = r.reported_user_id INNER JOIN rooms rm ON rm.id = r.room_id WHERE r.id = ?`).get(id);
}
function resolveReport(id) {
  db.prepare(`UPDATE reports SET status = 'resolved' WHERE id = ?`).run(id);
}
function dismissReport(id) {  db.prepare(`UPDATE reports SET status = 'dismissed' WHERE id = ?`).run(id);
}

// ---------- security reports (private responsible-disclosure inbox) ----------
function createSecurityReport({ reporterName, reporterContact, summary, details }) {
  return db.prepare(`INSERT INTO security_reports (reporter_name, reporter_contact, summary, details, status, created_at) VALUES (?,?,?,?,'open',?)`)
    .run(reporterName || null, reporterContact || null, summary, details, Date.now()).lastInsertRowid;
}
function getSecurityReports() {
  return db.prepare(`SELECT s.*, h.username AS handled_by_username FROM security_reports s LEFT JOIN users h ON h.id = s.handled_by ORDER BY s.created_at DESC`).all();
}
function getPendingSecurityReports() {
  return db.prepare(`SELECT * FROM security_reports WHERE status = 'open' ORDER BY created_at DESC`).all();
}
function markSecurityReportHandled(id, adminId) {
  const res = db.prepare(`UPDATE security_reports SET status = 'handled', handled_at = ?, handled_by = ? WHERE id = ? AND status = 'open'`).run(Date.now(), adminId || null, id);
  return res.changes > 0;
}

// ---------- admin rooms ----------
function getAllRooms() {
  return db.prepare(`SELECT r.*, (SELECT COUNT(*) FROM room_members WHERE room_id = r.id) AS member_count, u.username AS creator_username FROM rooms r LEFT JOIN users u ON u.id = r.creator_id ORDER BY r.created_at DESC`).all();
}

// ---------- join requests ----------
function createJoinRequest(roomId, userId) {
  const existing = db.prepare(`SELECT id, status FROM join_requests WHERE room_id = ? AND user_id = ?`).get(roomId, userId);
  if (existing) return existing;
  return db.prepare(`INSERT INTO join_requests (room_id, user_id, status, created_at) VALUES (?,?,?,?)`).run(roomId, userId, 'pending', Date.now());
}
function getJoinRequests(roomId) {
  return db.prepare(`SELECT j.*, u.username, u.display_name, u.avatar FROM join_requests j INNER JOIN users u ON u.id = j.user_id WHERE j.room_id = ? AND j.status = 'pending' ORDER BY j.created_at ASC`).all(roomId);
}
function getJoinRequestById(id) {
  return db.prepare(`SELECT * FROM join_requests WHERE id = ?`).get(id) || null;
}
function approveJoinRequest(requestId) {
  const req = db.prepare(`SELECT * FROM join_requests WHERE id = ?`).get(requestId);
  if (!req || req.status !== 'pending') return null;
  db.prepare(`UPDATE join_requests SET status = 'approved' WHERE id = ?`).run(requestId);
  const defaultRole = db.prepare(`SELECT id FROM room_roles WHERE room_id = ? AND is_founder = 0 ORDER BY position DESC LIMIT 1`).get(req.room_id);
  if (defaultRole) addRoomMember(req.room_id, req.user_id, defaultRole.id);
  return true;
}
function rejectJoinRequest(requestId) {
  const req = db.prepare(`SELECT * FROM join_requests WHERE id = ?`).get(requestId);
  if (!req || req.status !== 'pending') return null;
  db.prepare(`UPDATE join_requests SET status = 'rejected' WHERE id = ?`).run(requestId);
  return true;
}
function hasPendingRequest(roomId, userId) {
  return !!db.prepare(`SELECT 1 FROM join_requests WHERE room_id = ? AND user_id = ? AND status = 'pending'`).get(roomId, userId);
}

// ---------- theme ----------
function getUserTheme(userId) {
  const row = db.prepare(`SELECT theme FROM users WHERE id = ?`).get(userId);
  if (!row) return 'dark';
  const t = row.theme;
  if (t === 'light' || t === 'dark') return t;
  return 'dark';
}

function setUserTheme(userId, theme) {
  db.prepare(`UPDATE users SET theme = ? WHERE id = ?`).run(theme, userId);
}

function getUserDeveloperMode(userId) {
  const row = db.prepare(`SELECT developer_mode FROM users WHERE id = ?`).get(userId);
  return !!(row && row.developer_mode);
}

function setUserDeveloperMode(userId, on) {
  db.prepare(`UPDATE users SET developer_mode = ? WHERE id = ?`).run(on ? 1 : 0, userId);
}

// ---------- OAuth Apps ----------
function createOAuthApp({ name, description, website, redirectUris, clientId, clientSecret, scopes, ownerId }) {
  const now = Date.now();
  const res = db.prepare(`
    INSERT INTO oauth_apps (name, description, website, redirect_uris, client_id, client_secret, scopes, owner_id, created_at)
    VALUES (?,?,?,?,?,?,?,?,?)
  `).run(name, description, website, redirectUris, clientId, clientSecret ? hashOAuthToken(clientSecret) : null, scopes, ownerId || null, now);
  return res.lastInsertRowid;
}

function getOAuthAppByClientId(clientId) {
  return db.prepare(`SELECT * FROM oauth_apps WHERE client_id = ?`).get(clientId);
}

function getOAuthAppById(id) {
  return db.prepare(`SELECT * FROM oauth_apps WHERE id = ?`).get(id);
}

function getOrCreateClientApp(clientName, ownerId = null) {
  const name = String(clientName || 'Extrovert Client').trim().slice(0, 100) || 'Extrovert Client';
  const existing = db.prepare(`SELECT * FROM oauth_apps WHERE name = ? AND (owner_id = ? OR owner_id IS NULL) LIMIT 1`).get(name, ownerId || null);
  if (existing) return existing;
  const clientId = 'ext_client_' + crypto.randomBytes(16).toString('hex');
  const clientSecret = crypto.randomBytes(32).toString('hex');
  const appId = createOAuthApp({
    name,
    description: 'Auto-provisioned client application',
    website: '',
    redirectUris: 'urn:ietf:wg:oauth:2.0:oob',
    clientId,
    clientSecret,
    scopes: 'read write follow notifications media.write read:direct write:direct profile admin',
    ownerId: ownerId || null,
  });
  return getOAuthAppById(appId);
}

function getOAuthAppsByOwner(ownerId) {
  return db.prepare(`SELECT * FROM oauth_apps WHERE owner_id = ? ORDER BY created_at DESC`).all(ownerId);
}

function getAuthorizedAppsForUser(userId) {
  return db.prepare(`
    SELECT DISTINCT a.id, a.name, a.website, a.client_id, a.scopes AS app_scopes,
           t.scopes AS token_scopes, t.created_at AS authorized_at
    FROM oauth_tokens t
    JOIN oauth_apps a ON a.id = t.app_id
    WHERE t.user_id = ?
    ORDER BY t.created_at DESC
  `).all(userId);
}

function deleteOAuthApp(id) {
  db.prepare(`DELETE FROM oauth_codes WHERE app_id = ?`).run(id);
  db.prepare(`DELETE FROM oauth_tokens WHERE app_id = ?`).run(id);
  db.prepare(`DELETE FROM oauth_apps WHERE id = ?`).run(id);
}

// ---------- OAuth codes (authorization code flow) ----------
function createOAuthCode(code, appId, userId, scopes, codeChallenge, codeChallengeMethod, redirectUri, nonce) {
  const now = Date.now();
  db.prepare(`
    INSERT INTO oauth_codes (code, app_id, user_id, scopes, nonce, code_challenge, code_challenge_method, redirect_uri, expires_at, created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)
  `).run(hashOAuthToken(code), appId, userId, scopes, nonce || null, codeChallenge || null, codeChallengeMethod || null, redirectUri, now + 600000, now);
}

function getOAuthCode(code) {
  return db.prepare(`SELECT * FROM oauth_codes WHERE code = ?`).get(hashOAuthToken(code));
}

function markOAuthCodeUsed(id) {
  // Atomic: only the first exchange wins (WHERE used = 0).
  return db.prepare(`UPDATE oauth_codes SET used = 1 WHERE id = ? AND used = 0`).run(id).changes > 0;
}

// ---------- OAuth2 tokens ----------
// ---------- OAuth tokens ----------
// Bearer tokens are high-value secrets; store only a SHA-256 hash so a leaked
// database dump cannot be replayed. Lookups hash the presented token first.
const TOKEN_HASH_PREFIX = 'sha256$';
function hashOAuthToken(token) {
  return TOKEN_HASH_PREFIX + crypto.createHash('sha256').update(String(token)).digest('hex');
}

function createOAuthToken(token, refreshToken, appId, userId, scopes, expiresAt) {
  const now = Date.now();
  const refreshExpiresAt = now + 90 * 24 * 60 * 60 * 1000; // 90 days
  db.prepare(`
    INSERT INTO oauth_tokens (token, refresh_token, app_id, user_id, scopes, expires_at, refresh_expires_at, created_at)
    VALUES (?,?,?,?,?,?,?,?)
  `).run(hashOAuthToken(token), refreshToken ? hashOAuthToken(refreshToken) : null, appId, userId, scopes, expiresAt || null, refreshExpiresAt, now);
}

function getOAuthToken(token) {
  return db.prepare(`SELECT * FROM oauth_tokens WHERE token = ? AND revoked_at IS NULL`).get(hashOAuthToken(token));
}

function getOAuthTokenByRefresh(refreshToken) {
  return db.prepare(`SELECT * FROM oauth_tokens WHERE refresh_token = ?`).get(hashOAuthToken(refreshToken));
}

function revokeOAuthToken(token) {
  db.prepare(`UPDATE oauth_tokens SET revoked_at = ? WHERE token = ? AND revoked_at IS NULL`).run(Date.now(), hashOAuthToken(token));
}

function revokeOAuthTokensForUser(userId, appId) {
  db.prepare(`DELETE FROM oauth_tokens WHERE user_id = ? AND app_id = ?`).run(userId, appId);
}

function revokeAllOAuthTokensForUser(userId) {
  db.prepare(`DELETE FROM oauth_tokens WHERE user_id = ?`).run(userId);
}

function rotateRefreshToken(oldRefreshToken, newToken, newRefreshToken, expiresAt) {
  const now = Date.now();
  const existing = db.prepare(`SELECT * FROM oauth_tokens WHERE refresh_token = ?`).get(hashOAuthToken(oldRefreshToken));
  if (!existing) return null;
  // Revoke (don't delete) the old row: a replay of the old refresh token
  // must be distinguishable from an invalid one so theft can be detected.
  db.prepare(`UPDATE oauth_tokens SET revoked_at = ? WHERE refresh_token = ?`).run(now, hashOAuthToken(oldRefreshToken));
  const refreshExpiresAt = now + 90 * 24 * 60 * 60 * 1000; // 90 days
  db.prepare(`
    INSERT INTO oauth_tokens (token, refresh_token, app_id, user_id, scopes, expires_at, refresh_expires_at, created_at)
    VALUES (?,?,?,?,?,?,?,?)
  `).run(hashOAuthToken(newToken), hashOAuthToken(newRefreshToken), existing.app_id, existing.user_id, existing.scopes, expiresAt || null, refreshExpiresAt, now);
  return existing;
}

// ---------- Personal Access Tokens ----------
function createPersonalAccessToken(userId, name, token, scopes, expiresAt = null) {
  const hash = hashOAuthToken(token);
  const prefix = token ? (token.slice(0, 15) + '...') : null;
  const now = Date.now();
  const res = db.prepare(`
    INSERT INTO personal_access_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(userId, name, hash, prefix, scopes, expiresAt, now);
  return res.lastInsertRowid;
}

function getPersonalAccessTokenByHash(tokenHash) {
  return db.prepare(`
    SELECT * FROM personal_access_tokens WHERE token_hash = ?
  `).get(tokenHash);
}

function touchPersonalAccessToken(id) {
  db.prepare(`UPDATE personal_access_tokens SET last_used_at = ? WHERE id = ?`).run(Date.now(), id);
}

function listPersonalAccessTokens(userId) {
  return db.prepare(`
    SELECT id, name, token_prefix, scopes, last_used_at, expires_at, created_at
    FROM personal_access_tokens
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).all(userId);
}

function deletePersonalAccessToken(id, userId) {
  const res = db.prepare(`DELETE FROM personal_access_tokens WHERE id = ? AND user_id = ?`).run(id, userId);
  return res.changes > 0;
}

// ---------- Active Sessions ----------
function listActiveSessionsForUser(userId) {
  return db.prepare(`
    SELECT t.id, t.created_at, t.expires_at, t.scopes, a.name AS client_name, a.website, a.client_id
    FROM oauth_tokens t
    LEFT JOIN oauth_apps a ON a.id = t.app_id
    WHERE t.user_id = ? AND t.revoked_at IS NULL
    ORDER BY t.created_at DESC
  `).all(userId);
}

function revokeSessionToken(tokenId, userId) {
  const res = db.prepare(`
    UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL
  `).run(Date.now(), tokenId, userId);
  return res.changes > 0;
}

// ---------- FoF Discovery ----------
function getSuggestedFoafUsers(userId, limit = 20) {
  const { friendIds, foafIds } = require('./network');
  const following = friendIds(userId);
  const foaf = [...foafIds(userId)];
  const suggestedIds = foaf.filter(id => !following.has(id) && id !== userId).slice(0, limit);
  if (!suggestedIds.length) return [];
  const placeholders = suggestedIds.map(() => '?').join(',');
  return db.prepare(`
    SELECT id, username, display_name, avatar, bio, created_at
    FROM users
    WHERE id IN (${placeholders}) AND banned = 0
  `).all(...suggestedIds);
}

// ---------- Media ----------
function createMediaAttachment(userId, filePath, mimeType, fileSize) {
  const now = Date.now();
  const res = db.prepare(`
    INSERT INTO media_attachments (user_id, file_path, mime_type, file_size, created_at)
    VALUES (?,?,?,?,?)
  `).run(userId, filePath, mimeType, fileSize, now);
  return res.lastInsertRowid;
}

function getMediaAttachment(id) {
  return db.prepare(`SELECT * FROM media_attachments WHERE id = ?`).get(id);
}

function getMediaAttachmentsByUser(userId) {
  return db.prepare(`SELECT * FROM media_attachments WHERE user_id = ? ORDER BY created_at DESC`).all(userId);
}

function updateMediaAttachmentDimensions(id, width, height) {
  db.prepare(`UPDATE media_attachments SET width = ?, height = ? WHERE id = ?`).run(width, height, id);
}

// ---------- Idempotency keys ----------
const IDEMPOTENCY_TTL = 24 * 60 * 60 * 1000; // 24h

function getIdempotencyKey(key) {
  const cutoff = Date.now() - IDEMPOTENCY_TTL;
  return db.prepare(`SELECT * FROM idempotency_keys WHERE key = ? AND created_at > ?`).get(key, cutoff);
}

function setIdempotencyKey(key, response, statusCode) {
  const now = Date.now();
  db.prepare(`INSERT OR IGNORE INTO idempotency_keys (key, response, status_code, created_at) VALUES (?,?,?,?)`)
    .run(key, response, statusCode, now);
  // Cleanup expired keys on write to prevent unbounded growth.
  const cutoff = now - IDEMPOTENCY_TTL;
  db.prepare(`DELETE FROM idempotency_keys WHERE created_at < ?`).run(cutoff);
}

// ---------- Search ----------
function searchUsers(query, opts = {}) {
  const limit = opts.limit || 20;
  const excludeId = opts.excludeId || 0;
  const like = `%${query}%`;
  const maxNameLen = Math.floor(query.length / 0.15);
  return db.prepare(`
    SELECT id, username, display_name, avatar, bio, created_at
    FROM users
    WHERE (
      (username LIKE ? AND LENGTH(username) <= ?)
      OR (display_name LIKE ? AND LENGTH(display_name) <= ?)
    )
    AND banned = 0
    AND id <> ?
    ORDER BY
      CASE WHEN username = ? THEN 0
           WHEN display_name = ? THEN 1
           WHEN username LIKE ? THEN 2
           ELSE 3
         END,
      username ASC
    LIMIT ?
  `).all(like, maxNameLen, like, maxNameLen, excludeId, query, query, `${query}%`, limit);
}

function searchPosts(query, viewerId, limit = 20) {
  const friendIds = db.prepare(`SELECT followee_id FROM follows WHERE follower_id = ?`).all(viewerId).map(r => r.followee_id);
  const ids = [viewerId, ...friendIds];
  const placeholders = ids.map(() => '?').join(',');
  const foafIds = db.prepare(`
    SELECT DISTINCT f2.followee_id AS id
    FROM follows f1
    JOIN follows f2 ON f2.follower_id = f1.followee_id
    WHERE f1.follower_id = ? AND f2.followee_id NOT IN (${placeholders})
  `).all(viewerId, ...ids).map(r => r.id);
  const allVisible = [...ids, ...foafIds];
  const visPlaceholders = allVisible.map(() => '?').join(',');
  return db.prepare(`
    SELECT p.id, p.type, p.body, p.media_path, p.created_at, p.user_id,
           u.username, u.display_name, u.avatar, u.bio AS user_bio,
           u.created_at AS user_created_at
    FROM posts p
    JOIN users u ON u.id = p.user_id
    WHERE p.user_id IN (${visPlaceholders})
      AND (p.body LIKE ? OR u.display_name LIKE ?)
    ORDER BY p.created_at DESC
    LIMIT ?
  `).all(...allVisible, `%${query}%`, `%${query}%`, limit);
}

// ---------- Audit log ----------
function auditLog(action, actorId, details, ip = null) {
  const now = Date.now();
  try {
    db.prepare(`INSERT INTO audit_log (action, actor_id, details, ip, created_at) VALUES (?,?,?,?,?)`)
      .run(action, actorId || null, details || '', ip || null, now);
  } catch {}
}

// ---------- Email (verification) ----------
// Email addresses are stored case-normalized (lowercased) but only when the
// user opted in; existence of a row's email is not surfaced to other users.
function normalizeEmail(email) {
  if (!email) return '';
  return String(email).trim().toLowerCase();
}

function isValidEmail(email) {
  const e = normalizeEmail(email);
  if (!e || e.length > 254) return false;
  // Practical mailbox pattern (not RFC-pedantic: no validation of the domain
  // itself, which the outbound SMTP session will fail on anyway).
  return /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(e);
}

function getUserByEmail(email) {
  if (!email) return null;
  return db.prepare(`SELECT * FROM users WHERE email = ? COLLATE NOCASE`).get(normalizeEmail(email)) || null;
}

function setUserEmail(userId, email) {
  const e = normalizeEmail(email);
  db.prepare(`UPDATE users SET email = ? WHERE id = ?`).run(e || null, userId);
}

function setUserEmailVerified(userId, email, verifiedAt) {
  const e = normalizeEmail(email);
  db.prepare(`UPDATE users SET email = ?, email_verified_at = ? WHERE id = ?`).run(e || null, verifiedAt || Date.now(), userId);
}

function clearUserEmail(userId) {
  db.prepare(`UPDATE users SET email = NULL, email_verified_at = NULL WHERE id = ?`).run(userId);
}

// One active verification per user; issuing a new one replaces the old row.
function saveEmailVerification({ userId, tokenHash, email, expiresAt }) {
  const now = Date.now();
  db.prepare(`
    INSERT INTO email_verifications (user_id, token_hash, email, created_at, expires_at) VALUES (?,?,?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET
      token_hash = excluded.token_hash,
      email = excluded.email,
      created_at = excluded.created_at,
      expires_at = excluded.expires_at,
      consumed_at = NULL
  `).run(userId, tokenHash, normalizeEmail(email), now, expiresAt);
}

function getEmailVerification(userId) {
  return db.prepare(`SELECT * FROM email_verifications WHERE user_id = ?`).get(userId) || null;
}

// Atomically consume a token so a single email can only verify once.
function consumeEmailVerification(userId, tokenHash) {
  const res = db.prepare(`
    UPDATE email_verifications
    SET consumed_at = ?
    WHERE user_id = ? AND token_hash = ? AND consumed_at IS NULL
  `).run(Date.now(), userId, tokenHash);
  return res.changes > 0;
}

function deleteEmailVerification(userId) {
  db.prepare(`DELETE FROM email_verifications WHERE user_id = ?`).run(userId);
}

// ---------- Server settings (singleton) ----------
function getSetting(key) {
  const row = db.prepare(`SELECT value FROM server_settings WHERE key = ?`).get(key);
  return row ? row.value : null;
}

function setSetting(key, value) {
  // null / undefined / empty string means "unset" — the caller falls back to
  // environment variables / built-in defaults.
  const v = value === null || value === undefined || String(value).trim() === '' ? null : String(value);
  if (v === null) {
    db.prepare(`DELETE FROM server_settings WHERE key = ?`).run(key);
    return;
  }
  db.prepare(`
    INSERT INTO server_settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(key, v);
}

// Email-verification enforcement policy for this instance.
// 'off'    — email verification disabled entirely.
// 'optional' — users may add/verify an email; nothing is gated.
// 'required' — unverified accounts are read-only (cannot create posts or
//              messages) until they verify an email address.
// Precedence: admin UI (DB) → EXTV_EMAIL_POLICY env → 'off'.
// The DB can hold an explicit 'off' too (admin chose it) — only a cleared
// row inherits from the environment.
function getEmailPolicy() {
  const v = getSetting('email_verification_policy');
  if (v === 'required' || v === 'optional' || v === 'off') return v;
  const env = process.env.EXTV_EMAIL_POLICY;
  return env === 'required' || env === 'optional' || env === 'off' ? env : 'off';
}

// '' or undefined clears the DB row so EXTV_EMAIL_POLICY / default applies
// again (matching how every other mail setting works). 'off'/'optional'/
// 'required' are stored as an explicit admin choice.
function setEmailPolicy(policy) {
  if (policy === 'required' || policy === 'optional' || policy === 'off') {
    setSetting('email_verification_policy', policy);
  } else {
    setSetting('email_verification_policy', null);
  }
}

function isEmailVerificationRequired() {
  return getEmailPolicy() === 'required';
}

function requireVerifiedEmail(user) {
  if (!isEmailVerificationRequired()) return false;
  if (!user) return false;
  // Admins are always exempt so a misconfiguration can't lock the owner out.
  if (user.is_admin) return false;
  return !user.email || !user.email_verified_at;
}

// ---------- Mail settings (admin-configurable; env vars are fallbacks) ----------
// Every key is stored under the `mail_` prefix in server_settings. A stored
// value takes precedence over the corresponding EXTV_MAIL_* environment
// variable; an "unset" row (NULL) means "use the env var / built-in default".
// This gives operators BOTH configuration surfaces: set defaults in Portainer
// at deploy time and/or change anything live from /admin/mail.
const MAIL_SETTING_KEYS = [
  'mode',            // 'auto' | 'capture'
  'relay',           // host:port SMTP relay override ('' = use MX)
  'from',            // From-header address
  'from_name',       // display name
  'bounce_from',     // RFC 5321 MAIL FROM
  'spf_ip',          // public IP of the sending server (fills the SPF record)
  'dkim_enabled',    // '1' | '0'
  'dkim_domain',     // signing domain
  'dkim_selector',   // DKIM selector
  'dkim_private_key',// PEM (secret — never read back for display)
  'starttls',        // 'opportunistic' | 'required' | 'off'
  'outbox_fallback', // '1' | '0'
  'timeout_ms',
  'max_attempts',
];

function getMailSettings() {
  const out = {};
  const rows = db.prepare(`SELECT key, value FROM server_settings WHERE key LIKE 'mail_%'`).all();
  for (const row of rows) out[row.key.replace(/^mail_/, '')] = row.value;
  return out;
}

// Accepts a plain object keyed WITHOUT the mail_ prefix; null/'' deletes.
function setMailSettings(partial) {
  for (const [k, v] of Object.entries(partial || {})) {
    if (!MAIL_SETTING_KEYS.includes(k)) continue;
    setSetting('mail_' + k, v);
  }
}

// ---------- Announcement (singleton) ----------
// JOINs the author's username/display_name so callers don't need a second lookup.
function getAnnouncement() {
  return db.prepare(`
    SELECT a.*, u.username AS author_username, u.display_name AS author_display_name
    FROM announcement a LEFT JOIN users u ON u.id = a.author_id
    WHERE a.id = 1
  `).get();
}

function setAnnouncement(body, authorId) {
  const trimmed = String(body || '').trim();
  if (!trimmed) throw new Error('Announcement body cannot be empty');
  db.prepare(`
    INSERT INTO announcement (id, body, author_id, updated_at) VALUES (1, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET body = excluded.body, author_id = excluded.author_id, updated_at = excluded.updated_at
  `).run(trimmed, authorId || null, Date.now());
  return getAnnouncement();
}

function clearAnnouncement() {
  db.prepare(`DELETE FROM announcement WHERE id = 1`).run();
}

module.exports = {
  db,
  // users
  createUser, getUserByUsername, getUserById, updateUserProfile,
  // follows
  follow, unfollow, isFollowing, followingIds, countFollowers, countFollowing, recordFollowFromPost,
  // posts
  createPost, getPostById, getDisplayPost, postsByUser, countPostsByUser, deletePost, deleteUser,
  // likes
  toggleLike, hasLiked,
  // batch
  batchPostCounts,
  // comments
  addComment, commentsForPost,
  // edit history
  editPost, editComment, editMessage, editRoomMessage, getEditHistory, deleteComment,
  // shares
  sharePost, hasShared, hasReposted,
  // customization
  getCustomization, setCustomization,
  // notifications
  createNotification, getNotifications, countUnreadNotifications, markNotificationsRead,
  // push subscriptions
  addPushSubscription, getPushSubscriptions, removePushSubscription, deletePushSubscriptionsByEndpoint,
  // user lists
  getFollowers, getFollowing,
  // mutual follow
  areMutualFollowers,
  // messages
  sendMessage, getConversations, getMessages, countUnreadMessages, markConversationRead, deleteMessage,
  // additional security (server-side deletion after both received)
  setDmSecurity, getDmSecurity, ackMessagesReceived,
  // E2EE
  setPublicKey, getPublicKey, getEncryptedPrivateKey,
  // Olm (Signal-style) E2EE
  setOlmIdentity, getOlmIdentity, setOlmBackup, addOlmPrekeys, countAvailablePrekeys, claimOlmPrekey, peekOlmPrekey, requestDmRekey, dmRekeyNeeded, clearDmRekey,
  // Multi-Device Olm E2EE & History Backup
  registerUserDevice, getUserDevices, getUserDevice, getSenderCurve, touchUserDevice, deleteUserDevice, addDevicePrekeys, countAvailableDevicePrekeys, claimDevicePrekey, peekDevicePrekey, getAllDeviceBundlesForUser, claimAllDevicePrekeysForUser, setUserHistoryBackup, getUserHistoryBackup,
  // admin
  adminExists, getAllUsers, promoteUser, demoteUser, removeReferralBadge, banUser, unbanUser,
  // referrals
  setReferralCode, getUserByReferralCode, getReferralCount, getReferralCode, getReferrerIp,
  // stickers
  addSticker, getMyStickers, deleteSticker, getStickerById,
  // personal access tokens
  createPersonalAccessToken, getPersonalAccessTokenByHash, touchPersonalAccessToken, listPersonalAccessTokens, deletePersonalAccessToken,
  // active sessions
  listActiveSessionsForUser, revokeSessionToken,
  // discovery
  getSuggestedFoafUsers,
  // avatar
  setAvatar, getAvatar,
  // email verification
  normalizeEmail, isValidEmail, getUserByEmail, setUserEmail, setUserEmailVerified, clearUserEmail,
  saveEmailVerification, getEmailVerification, consumeEmailVerification, deleteEmailVerification,
  getSetting, setSetting, getEmailPolicy, setEmailPolicy, isEmailVerificationRequired, requireVerifiedEmail,
  getMailSettings, setMailSettings, MAIL_SETTING_KEYS,
  // theme
  getUserTheme, setUserTheme, getUserDeveloperMode, setUserDeveloperMode,
  // two-factor authentication (TOTP / recovery codes / trusted devices)
  setTotpSecret, setTotpEnabled,
  replaceRecoveryCodes, listRecoveryCodes, countUnusedRecoveryCodes, consumeRecoveryCode,
  // passkeys (WebAuthn credentials)
  createPasskey, getPasskeyById, getPasskeyByCredentialId, getPasskeysByUser, countPasskeys,
  updatePasskeyCounter, touchPasskey, renamePasskey, deletePasskey,
  // trusted devices ("remember this device")
  addTrustedDevice, getTrustedDevice, listTrustedDevices, deleteTrustedDevice,
  deleteAllTrustedDevices, pruneExpiredTrustedDevices,
  // rooms
  createRoom, getRoom, getRoomsForUser, getAvailableRooms, updateRoom, deleteRoom,
  isRoomMember, addRoomMember, removeRoomMember, getRoomMembers, getUserRoomRole, countRoomMembers,
  getRoomMemberCount: countRoomMembers,
  createRoomRole, getRoomRole, getRoomRoles, updateRoomRole, deleteRoomRole, transferFounder,
  createRoomChannel, getRoomChannel, getRoomChannels, updateRoomChannel, deleteRoomChannel,
  getRoomMessages, sendRoomMessage, deleteRoomMessage, joinDefaultRole, hasRoomPermission,
  publishRoomGroupSession, getRoomGroupSession, isRoomGroupSessionUsable, pruneSupersededRoomGroupSessions, saveRoomSessionKeys, ensureRoomSessionRecipient, getPendingRoomSessionKeys, getPendingRoomSessionKeyForUserAndSession, getRoomSessionKeyById, markRoomSessionKeyDelivered, getRoomSessionRecipients, getRoomSessionEmptyKeyRecipients,
  // reports
  createReport, getPendingReports, getReport, resolveReport, dismissReport,
  // security reports (private responsible-disclosure inbox)
  createSecurityReport, getSecurityReports, getPendingSecurityReports, markSecurityReportHandled,
  // admin rooms
  getAllRooms,
  // join requests
  createJoinRequest, getJoinRequests, getJoinRequestById, approveJoinRequest, rejectJoinRequest, hasPendingRequest,
  // OAuth Apps
  createOAuthApp, getOAuthAppByClientId, getOAuthAppById, getOAuthAppsByOwner, getOrCreateClientApp,
  getAuthorizedAppsForUser, deleteOAuthApp,
  // OAuth codes
  createOAuthCode, getOAuthCode, markOAuthCodeUsed,
  // OAuth tokens
  createOAuthToken, getOAuthToken, getOAuthTokenByRefresh,
  revokeOAuthToken, revokeOAuthTokensForUser, revokeAllOAuthTokensForUser,
  rotateRefreshToken, migrateOAuthTokenHashes, hashOAuthToken,
  // media
  createMediaAttachment, getMediaAttachment, getMediaAttachmentsByUser, updateMediaAttachmentDimensions, getUserMediaUsage,
  // idempotency
  getIdempotencyKey, setIdempotencyKey,
  getUserMediaUsage, pruneAuditLog, pruneNotifications,
  searchUsers, searchPosts,
  // audit
  auditLog,
  // announcement (singleton, server-wide)
  getAnnouncement, setAnnouncement, clearAnnouncement,
  // MLS (RFC 9420) Delivery Service & Authentication Service
  registerMlsDevice, getMlsDevices, getMlsDevice, touchMlsDevice, revokeMlsDevice,
  saveMlsKeyPackages, getMlsKeyPackagesForUser, consumeSpecificMlsKeyPackages,
  claimMlsKeyPackage, claimUserMlsKeyPackages, getMlsKeyPackageStatus,
  addMlsGroupMember, removeMlsGroupMember, getMlsGroupMembers, isMlsGroupMember, getUserMlsGroups,
  saveMlsProposal, getPendingMlsProposals, consumeMlsProposals,
  getMlsGroup, initMlsGroup, commitMlsGroup, getMlsCommits,
  getMlsWelcomes, ackMlsWelcome,
  saveMlsBackup, getMlsBackup,
  getHistoricalDmMessagesForMigration, getHistoricalRoomMessagesForMigration,
  recordMessageTraffic, getLegacyTrafficSunsetStatus,
  recordMigrationTelemetry, getFleetMigrationSummary,
  recordSunsetAudit, isLegacyE2eeEnabled,
};
