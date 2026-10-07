'use strict';

const express = require('express');
const db = require('../db');
const drive = require('../drive');

const router = express.Router();

function requireUser(req, res, next) {
  if (!res.locals.currentUser) return res.redirect('/login');
  next();
}

function csrfOk(req) {
  const token = req.body._csrf || req.headers['x-csrf-token'];
  return !!token && token === req.session.csrfToken;
}

// Where a stored file is served from, and whether this page owns it.
function describe(file) {
  const owned = file.root === 'drive';
  const url = owned
    ? '/drive/f/' + file.path
    : (file.root === 'api-uploads' ? '/api-uploads/' + file.path : '/uploads/' + file.path);
  return {
    id: file.id,
    kind: file.kind,
    sealed: !!file.sealed,
    name: file.name,
    mime: file.mime,
    size: file.size,
    created_at: file.created_at,
    url,
    owned,
    usedByPost: owned ? db.countPostsUsingMedia(url) : 0,
  };
}

router.use(requireUser);

// The Drive.
router.get('/', (req, res) => {
  const user = res.locals.currentUser;
  const usage = drive.quotaState(user.id);
  const files = db.getUserFiles(user.id).map(describe);
  res.render('drive', {
    usage,
    files,
    usedPercent: usage.quota ? Math.min(100, Math.round((usage.used / usage.quota) * 100)) : 0,
    fmt: drive.fmt,
  });
});

// Usage, for the upload pickers in chats and the composer.
router.get('/usage', (req, res) => {
  res.json(drive.quotaState(res.locals.currentUser.id));
});

// Upload. Plaintext (the Drive itself); chat attachments seal client-side first
// and post `?sealed=1`, which stores the blob with no extension and no metadata.
// Multipart bodies can't be CSRF-checked by the global middleware (it runs
// before multer), so this route validates the token itself — same as the other
// multipart endpoints.
router.post('/upload', drive.quotaGuard(), drive.single('file'), (req, res) => {
  const user = res.locals.currentUser;
  if (!csrfOk(req)) {
    drive.discardUpload(req);
    return res.status(403).send('CSRF validation failed');
  }
  const sealed = String(req.query.sealed || '') === '1';
  const result = drive.acceptUpload(req, res, { kind: sealed ? 'chat' : 'drive', sealed, userId: user.id });
  if (!result.ok) {
    if (result.exceeded) return drive.rejectFull(req, res, result.state);
    return res.status(400).send('No file was uploaded.');
  }
  if (drive.wantsJson(req)) {
    return res.json({ url: result.url, size: result.size, used: result.used, quota: result.quota, sealed });
  }
  res.redirect('/drive');
});

// Delete one of the user's own Drive files.
router.post('/:id/delete', (req, res) => {
  const user = res.locals.currentUser;
  if (!csrfOk(req)) return res.status(403).send('CSRF validation failed');
  const file = db.getUserFileById(Number(req.params.id));
  if (!file || file.user_id !== user.id || file.root !== 'drive') {
    return res.status(404).send('File not found.');
  }
  const url = '/drive/f/' + file.path;
  // A post still showing this image would break silently, so make the user
  // delete the post instead (which refunds the space anyway).
  if (db.countPostsUsingMedia(url) > 0) {
    return res.status(409).send('This file is used by a post. Delete the post to free its space.');
  }
  db.removeStoredFile('drive', file.path);
  res.redirect('/drive');
});

module.exports = router;
