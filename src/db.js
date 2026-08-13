'use strict';

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const DB_PATH = process.env.EXTV_DB_PATH || path.join(__dirname, '..', 'data', 'extrovert.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
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
      owner_id      INTEGER NOT NULL REFERENCES users(id),
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
try { db.exec(`ALTER TABLE rooms ADD COLUMN is_public INTEGER NOT NULL DEFAULT 1`); } catch {}
try { db.exec(`ALTER TABLE room_channels ADD COLUMN type TEXT NOT NULL DEFAULT 'text'`); } catch {}
try { db.exec(`ALTER TABLE posts ADD COLUMN edited_at INTEGER`); } catch {}
try { db.exec(`ALTER TABLE comments ADD COLUMN edited_at INTEGER`); } catch {}
try { db.exec(`ALTER TABLE messages ADD COLUMN edited_at INTEGER`); } catch {}
try { db.exec(`ALTER TABLE room_messages ADD COLUMN edited_at INTEGER`); } catch {}
try { db.exec(`ALTER TABLE oauth_codes ADD COLUMN nonce TEXT`); } catch {}
try { db.exec(`ALTER TABLE oauth_tokens ADD COLUMN refresh_expires_at INTEGER`); } catch {}
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
// Per-user Olm identity (public bundle material only; private halves live client-side).
try { db.exec(`
  CREATE TABLE IF NOT EXISTS olm_identity (
    user_id          INTEGER PRIMARY KEY REFERENCES users(id),
    identity_key     TEXT NOT NULL,
    ed25519_key      TEXT NOT NULL,
    fallback_key     TEXT,
    backup           TEXT,
    created_at       INTEGER NOT NULL,
    rotated_at       INTEGER
  );
`); } catch {}
try { db.exec(`ALTER TABLE olm_identity ADD COLUMN backup TEXT`); } catch {}
// One-time prekeys (Curve25519 publics only). Claimed (used=1) on bundle fetch.
try { db.exec(`
  CREATE TABLE IF NOT EXISTS olm_prekeys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    key_id      TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
  );
`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_olm_prekeys_user ON olm_prekeys(user_id, used)`); } catch {}

// --- Megolm (group) room encryption ---
// room_messages: protocol column + Megolm ciphertext + which group session encrypted it.
try { db.exec(`ALTER TABLE room_messages ADD COLUMN proto TEXT NOT NULL DEFAULT 'plain'`); } catch {}
try { db.exec(`ALTER TABLE room_messages ADD COLUMN ciphertext TEXT`); } catch {}
try { db.exec(`ALTER TABLE room_messages ADD COLUMN group_session_id TEXT`); } catch {}
// One active Megolm session per (room, sender). Private half lives client-side.
try { db.exec(`
  CREATE TABLE IF NOT EXISTS room_group_sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id    INTEGER NOT NULL REFERENCES rooms(id),
    sender_id  INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL,
    UNIQUE(room_id, sender_id)
  );
`); } catch {}
// Pending encrypted session keys awaiting delivery to each recipient.
// encrypted_key is the Megolm session key wrapped in the recipient's 1:1 Olm session.
try { db.exec(`
  CREATE TABLE IF NOT EXISTS room_group_session_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER NOT NULL REFERENCES room_group_sessions(id),
    recipient_id  INTEGER NOT NULL REFERENCES users(id),
    encrypted_key TEXT NOT NULL,
    delivered     INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
  );
`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_room_gs_keys_recipient ON room_group_session_keys(recipient_id, delivered)`); } catch {}
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
  if (userId === actorId) return;
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
  const res = db.prepare(
    `INSERT INTO messages (from_id, to_id, body, created_at, key_for_sender, key_for_recipient, proto, sender_ciphertext, secure) VALUES (?,?,?,?,?,?,?,?,?)`
  ).run(fromId, toId, body, Date.now(), keyForSender || null, keyForRecipient || null, proto || 'rsa', senderCiphertext || null, secure ? 1 : 0);
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
      SELECT m.from_id, m.to_id, m.body, m.proto, m.sender_ciphertext,
             m.key_for_sender, m.key_for_recipient, m.created_at,
             ROW_NUMBER() OVER (
               PARTITION BY CASE WHEN m.from_id = ? THEN m.to_id ELSE m.from_id END
               ORDER BY m.created_at DESC, m.id DESC
             ) AS rn
      FROM messages m
      WHERE m.from_id = ? OR m.to_id = ?
    )
    SELECT p.other_id AS id, u.username, u.display_name, u.avatar,
      l.from_id AS last_from, l.body AS last_message,
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

function getMessages(userId, otherId, limit = 100) {
  return db.prepare(`
    SELECT m.*, u.username, u.display_name
    FROM messages m
    JOIN users u ON u.id = m.from_id
    WHERE (m.from_id = ? AND m.to_id = ?)
       OR (m.from_id = ? AND m.to_id = ?)
    ORDER BY m.created_at ASC
    LIMIT ?
  `).all(userId, otherId, otherId, userId, limit);
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

// ---------- Olm (Signal-style) identity + prekeys ----------
function setOlmIdentity(userId, identityKey, ed25519Key, fallbackKey) {
  db.prepare(`
    INSERT INTO olm_identity (user_id, identity_key, ed25519_key, fallback_key, created_at, rotated_at)
    VALUES (?,?,?,?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET identity_key = excluded.identity_key, ed25519_key = excluded.ed25519_key, fallback_key = excluded.fallback_key, rotated_at = excluded.rotated_at
  `).run(userId, identityKey, ed25519Key, fallbackKey || null, Date.now(), Date.now());
}

function getOlmIdentity(userId) {
  return db.prepare(`SELECT identity_key, ed25519_key, fallback_key, backup FROM olm_identity WHERE user_id = ?`).get(userId) || null;
}

function setOlmBackup(userId, backup) {
  db.prepare(`UPDATE olm_identity SET backup = ? WHERE user_id = ?`).run(backup || null, userId);
}

function addOlmPrekeys(userId, prekeys) {
  // prekeys: [{ id, public_key }]
  const now = Date.now();
  const stmt = db.prepare(`INSERT INTO olm_prekeys (user_id, key_id, public_key, used, created_at) VALUES (?,?,?,?,?)`);
  for (const k of prekeys) stmt.run(userId, String(k.id), String(k.public_key), 0, now);
}

function countAvailablePrekeys(userId) {
  const row = db.prepare(`SELECT COUNT(*) AS n FROM olm_prekeys WHERE user_id = ? AND used = 0`).get(userId);
  return row ? row.n : 0;
}

// Atomically claim one unused one-time prekey for a recipient bundle.
function claimOlmPrekey(userId) {
  const row = db.prepare(`SELECT id, key_id, public_key FROM olm_prekeys WHERE user_id = ? AND used = 0 ORDER BY id ASC LIMIT 1`).get(userId);
  if (!row) return null;
  db.prepare(`UPDATE olm_prekeys SET used = 1 WHERE id = ?`).run(row.id);
  return { id: row.key_id, public_key: row.public_key };
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
    db.prepare(`DELETE FROM media_attachments WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM edit_history WHERE edited_by = ?`).run(userId);
    db.prepare(`DELETE FROM push_subscriptions WHERE user_id = ?`).run(userId);
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
  db.prepare(`INSERT INTO stickers (user_id, file_path, created_at) VALUES (?,?,?)`).run(userId, filePath, Date.now());
  return filePath;
}

function getMyStickers(userId) {
  return db.prepare(`SELECT id, file_path FROM stickers WHERE user_id = ? ORDER BY created_at DESC`).all(userId);
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
  db.prepare(`INSERT OR IGNORE INTO room_members (room_id, user_id, role_id, joined_at) VALUES (?,?,?,?)`).run(roomId, userId, roleId, Date.now());
}
function removeRoomMember(roomId, userId) {
  db.prepare(`DELETE FROM room_members WHERE room_id = ? AND user_id = ?`).run(roomId, userId);
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
  return db.prepare(`INSERT INTO room_messages (channel_id, user_id, body, proto, ciphertext, group_session_id, created_at) VALUES (?,?,?,?,?,?,?)`).run(channelId, userId, body, proto || 'plain', ciphertext || null, groupSessionId || null, Date.now()).lastInsertRowid;
}

// ---------- Megolm room group sessions ----------
// rotate=true deletes the existing (room, sender) session so a fresh id is issued.
function publishRoomGroupSession(roomId, senderId, rotate) {
  if (rotate) {
    const existing = db.prepare(`SELECT id FROM room_group_sessions WHERE room_id = ? AND sender_id = ?`).get(roomId, senderId);
    if (existing) {
      db.prepare(`DELETE FROM room_group_session_keys WHERE session_id = ?`).run(existing.id);
      db.prepare(`DELETE FROM room_group_sessions WHERE id = ?`).run(existing.id);
    }
  }
  db.prepare(`INSERT OR IGNORE INTO room_group_sessions (room_id, sender_id, created_at) VALUES (?,?,?)`).run(roomId, senderId, Date.now());
  const row = db.prepare(`SELECT id FROM room_group_sessions WHERE room_id = ? AND sender_id = ?`).get(roomId, senderId);
  return row.id;
}
function getRoomGroupSession(roomId, senderId) {
  return db.prepare(`SELECT id FROM room_group_sessions WHERE room_id = ? AND sender_id = ?`).get(roomId, senderId) || null;
}
// Upsert: re-sharing replaces the key and re-queues delivery.
function saveRoomSessionKeys(sessionId, recipientId, encryptedKey) {
  const existing = db.prepare(`SELECT id FROM room_group_session_keys WHERE session_id = ? AND recipient_id = ?`).get(sessionId, recipientId);
  if (existing) {
    db.prepare(`UPDATE room_group_session_keys SET encrypted_key = ?, delivered = 0, created_at = ? WHERE id = ?`).run(encryptedKey, Date.now(), existing.id);
  } else {
    db.prepare(`INSERT INTO room_group_session_keys (session_id, recipient_id, encrypted_key, created_at) VALUES (?,?,?,?)`).run(sessionId, recipientId, encryptedKey, Date.now());
  }
}
// Cover a member even when no real key could be produced (no E2EE setup yet),
// so the sender doesn't rotate on every visit for that member.
function ensureRoomSessionRecipient(sessionId, recipientId) {
  const existing = db.prepare(`SELECT id FROM room_group_session_keys WHERE session_id = ? AND recipient_id = ?`).get(sessionId, recipientId);
  if (!existing) {
    db.prepare(`INSERT INTO room_group_session_keys (session_id, recipient_id, encrypted_key, created_at) VALUES (?,?,?,?)`).run(sessionId, recipientId, '', Date.now());
  }
}
function getPendingRoomSessionKeys(userId) {
  return db.prepare(`
    SELECT k.id AS key_id, k.encrypted_key, gs.id AS session_id, gs.room_id, gs.sender_id
    FROM room_group_session_keys k
    JOIN room_group_sessions gs ON gs.id = k.session_id
    WHERE k.recipient_id = ? AND k.delivered = 0 AND k.encrypted_key <> ''
  `).all(userId);
}
function markRoomSessionKeyDelivered(keyId) {
  db.prepare(`UPDATE room_group_session_keys SET delivered = 1 WHERE id = ?`).run(keyId);
}
// Everyone ever given (or targeted for) a key for this session.
function getRoomSessionRecipients(sessionId) {
  return db.prepare(`SELECT DISTINCT recipient_id FROM room_group_session_keys WHERE session_id = ?`).all(sessionId).map(r => r.recipient_id);
}
// Members who are covered but have no real key yet — the sender should re-share.
function getRoomSessionEmptyKeyRecipients(sessionId) {
  return db.prepare(`SELECT DISTINCT recipient_id FROM room_group_session_keys WHERE session_id = ? AND encrypted_key = ''`).all(sessionId).map(r => r.recipient_id);
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
  `).run(name, description, website, redirectUris, clientId, clientSecret ? hashOAuthToken(clientSecret) : null, scopes, ownerId, now);
  return res.lastInsertRowid;
}

function getOAuthAppByClientId(clientId) {
  return db.prepare(`SELECT * FROM oauth_apps WHERE client_id = ?`).get(clientId);
}

function getOAuthAppById(id) {
  return db.prepare(`SELECT * FROM oauth_apps WHERE id = ?`).get(id);
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
  return db.prepare(`SELECT * FROM oauth_tokens WHERE token = ?`).get(hashOAuthToken(token));
}

function getOAuthTokenByRefresh(refreshToken) {
  return db.prepare(`SELECT * FROM oauth_tokens WHERE refresh_token = ?`).get(hashOAuthToken(refreshToken));
}

function revokeOAuthToken(token) {
  db.prepare(`DELETE FROM oauth_tokens WHERE token = ?`).run(hashOAuthToken(token));
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
  db.prepare(`DELETE FROM oauth_tokens WHERE refresh_token = ?`).run(hashOAuthToken(oldRefreshToken));
  const refreshExpiresAt = now + 90 * 24 * 60 * 60 * 1000; // 90 days
  db.prepare(`
    INSERT INTO oauth_tokens (token, refresh_token, app_id, user_id, scopes, expires_at, refresh_expires_at, created_at)
    VALUES (?,?,?,?,?,?,?,?)
  `).run(hashOAuthToken(newToken), hashOAuthToken(newRefreshToken), existing.app_id, existing.user_id, existing.scopes, expiresAt || null, refreshExpiresAt, now);
  return existing;
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
function auditLog(action, actorId, details) {
  const now = Date.now();
  try {
    db.prepare(`INSERT INTO audit_log (action, actor_id, details, ip, created_at) VALUES (?,?,?,?,?)`)
      .run(action, actorId || null, details || '', null, now);
  } catch {}
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
  setOlmIdentity, getOlmIdentity, setOlmBackup, addOlmPrekeys, countAvailablePrekeys, claimOlmPrekey,
  // admin
  adminExists, getAllUsers, promoteUser, removeReferralBadge, banUser, unbanUser,
  // referrals
  setReferralCode, getUserByReferralCode, getReferralCount, getReferralCode, getReferrerIp,
  // stickers
  addSticker, getMyStickers,
  // avatar
  setAvatar, getAvatar,
  // theme
  getUserTheme, setUserTheme, getUserDeveloperMode, setUserDeveloperMode,
  // rooms
  createRoom, getRoom, getRoomsForUser, getAvailableRooms, updateRoom, deleteRoom,
  isRoomMember, addRoomMember, removeRoomMember, getRoomMembers, getUserRoomRole, countRoomMembers,
  createRoomRole, getRoomRole, getRoomRoles, updateRoomRole, deleteRoomRole, transferFounder,
  createRoomChannel, getRoomChannel, getRoomChannels, updateRoomChannel, deleteRoomChannel,
  getRoomMessages, sendRoomMessage, deleteRoomMessage, joinDefaultRole, hasRoomPermission,
  publishRoomGroupSession, getRoomGroupSession, saveRoomSessionKeys, ensureRoomSessionRecipient, getPendingRoomSessionKeys, markRoomSessionKeyDelivered, getRoomSessionRecipients, getRoomSessionEmptyKeyRecipients,
  // reports
  createReport, getPendingReports, getReport, resolveReport, dismissReport,
  // security reports (private responsible-disclosure inbox)
  createSecurityReport, getSecurityReports, getPendingSecurityReports, markSecurityReportHandled,
  // admin rooms
  getAllRooms,
  // join requests
  createJoinRequest, getJoinRequests, approveJoinRequest, rejectJoinRequest, hasPendingRequest,
  // OAuth Apps
  createOAuthApp, getOAuthAppByClientId, getOAuthAppById, getOAuthAppsByOwner,
  getAuthorizedAppsForUser, deleteOAuthApp,
  // OAuth codes
  createOAuthCode, getOAuthCode, markOAuthCodeUsed,
  // OAuth tokens
  createOAuthToken, getOAuthToken, getOAuthTokenByRefresh,
  revokeOAuthToken, revokeOAuthTokensForUser, revokeAllOAuthTokensForUser,
  rotateRefreshToken, migrateOAuthTokenHashes, hashOAuthToken,
  // media
  createMediaAttachment, getMediaAttachment, getMediaAttachmentsByUser, updateMediaAttachmentDimensions,
  // idempotency
  getIdempotencyKey, setIdempotencyKey,
  // search
  searchUsers, searchPosts,
  // audit
  auditLog,
  // announcement (singleton, server-wide)
  getAnnouncement, setAnnouncement, clearAnnouncement,
};
