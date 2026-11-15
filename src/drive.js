'use strict';

// Drive: the single storage pipeline for user uploads.
//
// Files live under data/drive with server-generated names; the accounting lives
// in the user_files table (src/db.js). When a user connects their own Nextcloud
// (settings → Drive), new uploads are staged here and immediately moved there —
// the row records backend='nextcloud' and the Drive quota stops applying. The
// per-request ceiling below is a denial-of-service guard for local storage, not
// a product limit.

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const multer = require('multer');
const db = require('./db');
const nextcloud = require('./nextcloud');

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
  // Web fonts, so profiles can ship their own (served with the font MIME type).
  '.woff2', '.woff', '.ttf', '.otf', '.ttc',
]);

// Extensions we accept as a profile font.
const FONT_EXTENSIONS = new Set(['.woff2', '.woff', '.ttf', '.otf', '.ttc']);

// A font file has to actually be one: browsers parse these with a font engine,
// so we only accept known container signatures.
const FONT_SIGNATURES = [
  Buffer.from([0x77, 0x4f, 0x46, 0x32]), // wOF2
  Buffer.from([0x77, 0x4f, 0x46, 0x46]), // wOFF
  Buffer.from([0x4f, 0x54, 0x54, 0x4f]), // OTTO (CFF/OpenType)
  Buffer.from([0x00, 0x01, 0x00, 0x00]), // TrueType
  Buffer.from([0x74, 0x72, 0x75, 0x65]), // true (Apple)
  Buffer.from([0x74, 0x74, 0x63, 0x66]), // ttcf (collection)
];

function isFontFile(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const head = Buffer.alloc(4);
    fs.readSync(fd, head, 0, 4, 0);
    fs.closeSync(fd);
    return FONT_SIGNATURES.some((sig) => head.equals(sig));
  } catch (e) {
    return false;
  }
}

// Fonts are small; keep one from eating the whole quota in a single request.
const MAX_FONT_BYTES = 8 * 1024 * 1024;

// Browsers run downloaded fonts through the OpenType Sanitizer before the OS
// font engine sees them. We do the same on the way in, so a malformed font is
// re-serialized (or rejected) instead of being stored as-is. Override the path
// with EXTV_OTS_SANITIZE; when the binary is missing we fall back to the
// signature/extension checks and warn once.
const OTS_BIN = process.env.EXTV_OTS_SANITIZE || 'ots-sanitize';
const OTS_TIMEOUT_MS = 20000;
let otsWarned = false;

// Validates and re-serializes a font in place.
//   { ok: true, size }                 — replaced with the sanitized output
//   { ok: false, reason: 'invalid' }   — the sanitizer rejected it
//   { ok: false, reason: 'missing' }   — ots-sanitize isn't installed
//   { ok: false, reason: 'failed', detail }
function sanitizeFontFile(filePath) {
  const outPath = filePath + '.ots';
  return new Promise((resolve) => {
    let child;
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(killTimer);
      resolve(result);
    };
    const killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (e) { /* already gone */ }
      try { fs.unlinkSync(outPath); } catch (e) { /* nothing written */ }
      finish({ ok: false, reason: 'failed', detail: 'sanitizer timed out' });
    }, OTS_TIMEOUT_MS);

    try {
      child = spawn(OTS_BIN, ['--quiet', filePath, outPath], { stdio: 'ignore' });
    } catch (e) {
      return finish({ ok: false, reason: 'missing' });
    }

    child.on('error', (err) => {
      const missing = err && err.code === 'ENOENT';
      finish({ ok: false, reason: missing ? 'missing' : 'failed', detail: String((err && err.message) || err) });
    });

    child.on('close', (code) => {
      if (code !== 0) {
        try { fs.unlinkSync(outPath); } catch (e) { /* nothing written */ }
        return finish({ ok: false, reason: 'invalid' });
      }
      try {
        const size = fs.statSync(outPath).size;
        if (!size) throw new Error('empty output');
        fs.renameSync(outPath, filePath);
        finish({ ok: true, size });
      } catch (e) {
        try { fs.unlinkSync(outPath); } catch (e2) { /* nothing written */ }
        finish({ ok: false, reason: 'failed', detail: String(e.message || e) });
      }
    });
  });
}

function warnOtsMissingOnce() {
  if (otsWarned) return;
  otsWarned = true;
  console.warn('[Drive] ots-sanitize not found — fonts are stored without re-serialization. Install opentype-sanitizer (or set EXTV_OTS_SANITIZE).');
}

// Safety ceiling for a single request's body. The quota check below is what
// actually refuses uploads; this just bounds the worst case.
const MAX_REQUEST_BYTES = 512 * 1024 * 1024;

// A multipart body carries boundaries and part headers on top of the file.
const MULTIPART_OVERHEAD = 64 * 1024;

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, DRIVE_DIR),
  filename: (req, file, cb) => {
    // Sealed blobs get no extension at all: the server shouldn't be able to
    // tell an image from a PDF. The client learns the type from the message.
    const sealed = String((req.query && req.query.sealed) || '') === '1';
    const original = path.extname(file.originalname || '').toLowerCase();
    const ext = !sealed && SAFE_EXTENSIONS.has(original) ? original : '';
    cb(null, crypto.randomBytes(16).toString('hex') + ext);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_REQUEST_BYTES, files: 1 },
});

// Same staging, no size ceiling: when a user's own Nextcloud stores the file,
// this server is only a pass-through and the Drive quota does not apply. The
// copy is removed from local disk as soon as it is uploaded.
const uploadToBackend = multer({
  storage,
  limits: { files: 1 },
});

function userIdOf(req, res) {
  const user = (res && res.locals && res.locals.currentUser) || req.apiUser || null;
  return user ? user.id : null;
}

function wantsJson(req) {
  if (req.xhr) return true;
  if ((req.originalUrl || req.path || '').startsWith('/api/')) return true;
  return String(req.get('accept') || '').includes('json');
}

function fmt(bytes) {
  const n = Number(bytes) || 0;
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(n >= 10 * 1024 * 1024 ? 0 : 1) + ' MB';
  if (n >= 1024) return Math.round(n / 1024) + ' KB';
  return n + ' B';
}

// Usage for a user. `localUsed` is what the quota is about; remote bytes live
// in the user's Nextcloud and are only reported. `unlimited` means a flat
// per-user limit does not apply to the Drive any more.
function quotaState(userId) {
  const quota = db.getDriveQuotaBytes();
  const used = db.getUserFileUsage(userId);
  const localUsed = db.getLocalUserFileUsage(userId);
  const backend = db.getActiveNextcloud(userId);
  return {
    used,
    localUsed,
    remoteUsed: Math.max(0, used - localUsed),
    quota,
    remaining: Math.max(0, quota - localUsed),
    unlimited: !!backend,
    backend: backend ? 'nextcloud' : 'local',
  };
}

function fullMessage(state) {
  if (state.localUsed >= state.quota) return 'Your Drive is full. Delete something to free space.';
  return `Not enough Drive space: ${fmt(state.remaining)} left of ${fmt(state.quota)}.`;
}

function rejectFull(req, res, state) {
  const message = fullMessage(state);
  if (wantsJson(req)) {
    return res.status(413).json({
      error: 'StorageQuotaExceeded',
      message,
      used: state.localUsed,
      quota: state.quota,
      remaining: state.remaining,
    });
  }
  return res.status(413).send(message);
}

// Quota is checked against disk-backed usage plus in-flight multipart requests.
// A per-process reservation prevents two concurrent uploads from each passing
// the same "remaining" check before either one creates its user_files row.
const uploadReservations = new Map(); // userId -> Map<token, reserved bytes>

function reservedBytes(userId, excludeToken) {
  const rows = uploadReservations.get(Number(userId));
  if (!rows) return 0;
  let total = 0;
  for (const [token, bytes] of rows) {
    if (token !== excludeToken) total += Number(bytes) || 0;
  }
  return total;
}

function releaseUploadReservation(req) {
  const reservation = req && req.uploadReservation;
  if (!reservation || reservation.released) return;
  reservation.released = true;
  const rows = uploadReservations.get(reservation.userId);
  if (!rows) return;
  rows.delete(reservation.token);
  if (rows.size === 0) uploadReservations.delete(reservation.userId);
}

function reserveUpload(req, res, userId, bytes) {
  const uid = Number(userId);
  const token = crypto.randomUUID();
  if (!uploadReservations.has(uid)) uploadReservations.set(uid, new Map());
  uploadReservations.get(uid).set(token, bytes);
  req.uploadReservation = { userId: uid, token, bytes, released: false };
  const release = () => releaseUploadReservation(req);
  res.once('finish', release);
  res.once('close', release);
}

function uploadFits(req, size, userIdOverride, opts = {}) {
  const userId = Number(userIdOverride || userIdOf(req));
  if (!Number.isInteger(userId) || userId <= 0) return { ok: false, unauthenticated: true };
  const bytes = Number(size);
  if (!Number.isFinite(bytes) || bytes < 0) return { ok: false, invalidSize: true, state: quotaState(userId) };
  const state = quotaState(userId);
  // Bytes that end up in the user's Nextcloud do not consume local space.
  if (opts.remote) return { ok: true, state };
  const ownToken = req.uploadReservation ? req.uploadReservation.token : null;
  if (state.localUsed + reservedBytes(userId, ownToken) + bytes > state.quota) {
    return { ok: false, exceeded: true, state };
  }
  return { ok: true, state };
}

// Cheap refusal before the body is read, using the declared length.
// `opts.remote` marks routes that store in the user's own backend: those skip
// both the quota and the local request ceiling. `opts.localOnly` forces local
// storage even when a backend is configured (profile fonts are served from
// disk, so they can never live remotely).
function quotaGuard(opts = {}) {
  return (req, res, next) => {
    // Non-multipart requests never reach a disk storage engine; their normal
    // body parser limit already applies.
    if (!req.is('multipart/form-data')) return next();
    const userId = userIdOf(req, res);
    if (!userId) {
      if (wantsJson(req)) return res.status(401).json({ error: 'Unauthorized' });
      return res.status(401).send('Not logged in');
    }
    // A connected Nextcloud is the store: no quota, no per-request ceiling.
    if (opts.remote && !opts.localOnly) {
      const backend = db.getActiveNextcloud(userId);
      if (backend) {
        req.driveBackend = backend;
        return next();
      }
    }
    const declared = Number(req.headers['content-length']);
    if (req.headers['content-length'] === undefined || !Number.isFinite(declared) || declared < 0) {
      const message = 'A finite Content-Length header is required for multipart uploads.';
      if (wantsJson(req)) return res.status(411).json({ error: 'LengthRequired', message });
      return res.status(411).send(message);
    }
    const maxBytes = Number(opts.maxBytes) > 0 ? Number(opts.maxBytes) : MAX_REQUEST_BYTES;
    if (declared > maxBytes + MULTIPART_OVERHEAD) {
      const message = 'That file is too large to upload.';
      if (wantsJson(req)) return res.status(413).json({ error: 'UploadFailed', message });
      return res.status(413).send(message);
    }
    const state = quotaState(userId);
    if (state.localUsed + reservedBytes(userId) + Math.max(0, declared - MULTIPART_OVERHEAD) > state.quota) {
      return rejectFull(req, res, state);
    }
    reserveUpload(req, res, userId, declared);
    next();
  };
}

// multer with readable errors instead of a generic 500. Routes that store in a
// user's Nextcloud use the instance without the local per-request ceiling.
function single(field) {
  const local = upload.single(field);
  const remote = uploadToBackend.single(field);
  return (req, res, next) => {
    const mw = req.driveBackend ? remote : local;
    mw(req, res, (err) => {
      if (!err) return next();
      discardUpload(req);
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
  releaseUploadReservation(req);
}

// Post-parse: enforce the quota, then register the file. When the user has a
// Nextcloud backend the staged copy is uploaded there first and deleted from
// local disk. Returns
// { ok: true, url, size, used, quota, backend } or { ok: false, exceeded, state }
// or { ok: false, storageFailed, message, state }.
async function acceptUpload(req, res, opts = {}) {
  const userId = opts.userId || userIdOf(req, res);
  const file = req.file;
  if (!file) return { ok: false, noFile: true };

  const backend = req.driveBackend || null;
  const fit = uploadFits(req, file.size, userId, { remote: !!backend });
  if (!fit.ok) {
    discardUpload(req);
    return { ok: false, exceeded: !!fit.exceeded, state: fit.state };
  }
  const state = fit.state;

  const name = path.basename(file.path);
  const sealed = !!opts.sealed;
  let remotePath = null;
  if (backend) {
    remotePath = nextcloud.remotePathFor(name);
    try {
      await nextcloud.ensureDir(backend);
      await nextcloud.uploadFile(backend, remotePath, file.path);
    } catch (err) {
      console.error('[Drive] Nextcloud upload failed:', nextcloud.errorMessage(err));
      discardUpload(req);
      return {
        ok: false,
        storageFailed: true,
        state,
        message: 'Could not save the file to your Nextcloud (' + nextcloud.errorMessage(err) + ').',
      };
    }
    // The remote copy is the real one now; the staged file is just a temp.
    try { fs.unlinkSync(file.path); } catch (e) { /* already gone */ }
  }

  try {
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
      backend: backend ? 'nextcloud' : 'local',
      remotePath,
    });
  } catch (err) {
    if (backend) {
      try {
        await nextcloud.deleteFile(backend, remotePath);
      } catch (e) { /* best effort */ }
    }
    discardUpload(req);
    return { ok: false, registrationFailed: true, state };
  }
  releaseUploadReservation(req);

  return {
    ok: true,
    url: '/drive/f/' + name,
    name,
    size: file.size,
    used: state.used + file.size,
    quota: state.quota,
    backend: backend ? 'nextcloud' : 'local',
  };
}

module.exports = {
  DRIVE_DIR,
  SAFE_EXTENSIONS,
  FONT_EXTENSIONS,
  MAX_FONT_BYTES,
  MAX_REQUEST_BYTES,
  isFontFile,
  sanitizeFontFile,
  warnOtsMissingOnce,
  upload,
  single,
  quotaGuard,
  uploadFits,
  releaseUploadReservation,
  quotaState,
  acceptUpload,
  discardUpload,
  rejectFull,
  fullMessage,
  userIdOf,
  wantsJson,
  fmt,
};
