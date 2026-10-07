'use strict';

// Drive: the single storage pipeline for user uploads.
//
// Files live under data/drive with server-generated names; the accounting lives
// in the user_files table (src/db.js). The user's Drive quota is the only limit
// that matters here — the per-request ceiling below is a denial-of-service
// guard, not a product limit.

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const multer = require('multer');
const db = require('./db');

const DRIVE_DIR = db.FILE_ROOTS.drive;
fs.mkdirSync(DRIVE_DIR, { recursive: true });

// Extensions a browser is allowed to interpret. Anything else is stored with no
// extension, so it can only ever be served as an opaque download — this is what
// keeps .html/.svg/.js out of the storage tree (asserted by scripts/asvs-test.js).
const SAFE_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.avif',
  '.mp4', '.webm', '.mov', '.mkv', '.avi',
  '.mp3', '.ogg', '.oga', '.wav', '.m4a', '.flac',
  '.pdf', '.txt', '.md', '.csv', '.rtf', '.odt', '.ods', '.odp', '.docx', '.xlsx', '.pptx',
  '.zip', '.gz', '.tar', '.7z', '.rar',
]);

// Safety ceiling for a single request's body. The quota check below is what
// actually refuses uploads; this just bounds the worst case.
const MAX_REQUEST_BYTES = 512 * 1024 * 1024;

// A multipart body carries boundaries and part headers on top of the file.
const MULTIPART_OVERHEAD = 64 * 1024;

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, DRIVE_DIR),
    filename: (req, file, cb) => {
      // Sealed blobs get no extension at all: the server shouldn't be able to
      // tell an image from a PDF. The client learns the type from the message.
      const sealed = String((req.query && req.query.sealed) || '') === '1';
      const original = path.extname(file.originalname || '').toLowerCase();
      const ext = !sealed && SAFE_EXTENSIONS.has(original) ? original : '';
      cb(null, crypto.randomBytes(16).toString('hex') + ext);
    },
  }),
  limits: { fileSize: MAX_REQUEST_BYTES, files: 1 },
});

function userIdOf(req, res) {
  const user = (res && res.locals && res.locals.currentUser) || req.apiUser || null;
  return user ? user.id : null;
}

function wantsJson(req) {
  if (req.xhr) return true;
  if (req.path && req.path.startsWith('/api/')) return true;
  return String(req.get('accept') || '').includes('json');
}

function fmt(bytes) {
  const n = Number(bytes) || 0;
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(n >= 10 * 1024 * 1024 ? 0 : 1) + ' MB';
  if (n >= 1024) return Math.round(n / 1024) + ' KB';
  return n + ' B';
}

function quotaState(userId) {
  const quota = db.getDriveQuotaBytes();
  const used = db.getUserFileUsage(userId);
  return { used, quota, remaining: Math.max(0, quota - used) };
}

function fullMessage(state) {
  if (state.used >= state.quota) return 'Your Drive is full. Delete something to free space.';
  return `Not enough Drive space: ${fmt(state.remaining)} left of ${fmt(state.quota)}.`;
}

function rejectFull(req, res, state) {
  const message = fullMessage(state);
  if (wantsJson(req)) {
    return res.status(413).json({
      error: 'StorageQuotaExceeded',
      message,
      used: state.used,
      quota: state.quota,
      remaining: state.remaining,
    });
  }
  return res.status(413).send(message);
}

// Cheap refusal before the body is read, using the declared length.
function quotaGuard() {
  return (req, res, next) => {
    const userId = userIdOf(req, res);
    if (!userId) return next();
    const declared = Number(req.headers['content-length']);
    if (!Number.isFinite(declared)) return next();
    const state = quotaState(userId);
    if (declared > state.remaining + MULTIPART_OVERHEAD) return rejectFull(req, res, state);
    next();
  };
}

// multer with readable errors instead of a generic 500.
function single(field) {
  const mw = upload.single(field);
  return (req, res, next) => {
    mw(req, res, (err) => {
      if (!err) return next();
      const message = err.code === 'LIMIT_FILE_SIZE'
        ? 'That file is too large to upload.'
        : 'Upload failed.';
      if (wantsJson(req)) return res.status(413).json({ error: 'UploadFailed', message });
      return res.status(413).send(message);
    });
  };
}

// Removes a staged file (used on every error path after multer ran).
function discardUpload(req) {
  if (req.file && req.file.path) {
    try { fs.unlinkSync(req.file.path); } catch (e) { /* already gone */ }
  }
}

// Post-parse: enforce the quota, then register the file. Returns
// { ok: true, url, size, used, quota } or { ok: false, exceeded, state }.
function acceptUpload(req, res, opts = {}) {
  const userId = opts.userId || userIdOf(req, res);
  const file = req.file;
  if (!file) return { ok: false, noFile: true };

  const state = quotaState(userId);
  if (state.used + file.size > state.quota) {
    discardUpload(req);
    return { ok: false, exceeded: true, state };
  }

  const name = path.basename(file.path);
  const sealed = !!opts.sealed;
  db.createUserFile({
    userId,
    kind: opts.kind || 'drive',
    root: 'drive',
    path: name,
    // A sealed blob is opaque ciphertext: the original name and type only ever
    // travel inside the end-to-end encrypted message.
    mime: sealed ? null : (file.mimetype || null),
    size: file.size,
    sealed,
    name: sealed ? null : (file.originalname || null),
  });

  return {
    ok: true,
    url: '/drive/f/' + name,
    name,
    size: file.size,
    used: state.used + file.size,
    quota: state.quota,
  };
}

module.exports = {
  DRIVE_DIR,
  SAFE_EXTENSIONS,
  MAX_REQUEST_BYTES,
  upload,
  single,
  quotaGuard,
  quotaState,
  acceptUpload,
  discardUpload,
  rejectFull,
  fullMessage,
  userIdOf,
  wantsJson,
  fmt,
};
