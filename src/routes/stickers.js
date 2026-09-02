'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const sharp = require('sharp');
const { addSticker, getMyStickers } = require('../db');

const router = express.Router();

const STICKER_DIR = path.join(__dirname, '..', '..', 'uploads', 'stickers');
fs.mkdirSync(STICKER_DIR, { recursive: true });

const ALLOWED = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'];

const storage = multer.diskStorage({
  destination: STICKER_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const name = crypto.randomBytes(12).toString('hex') + ext;
    cb(null, name);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, ALLOWED.includes(ext));
  },
});

router.get('/mine', (req, res) => {
  if (!res.locals.currentUser) return res.status(401).json([]);
  res.json(getMyStickers(res.locals.currentUser.id));
});

router.post('/upload', (req, res) => {
  if (!res.locals.currentUser) return res.status(401).send('Not logged in');
  // Multipart bodies bypass the global CSRF middleware, and the token is a
  // form field inside the multipart body, so validation must happen AFTER
  // multer parses the request (upload.single below populates req.body).
  upload.single('sticker')(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).send('Sticker must be under 500 KB.');
      return res.status(400).send('Invalid file.');
    }
    if (!req.file) return res.status(400).send('No file uploaded.');
    const token = (req.body && req.body._csrf) || req.get('X-CSRF-Token');
    if (!token || token !== req.session.csrfToken) {
      try { fs.unlink(req.file.path, () => {}); } catch {}
      return res.status(403).send('CSRF validation failed');
    }
    // Auto-compress if over 250 KB and not a GIF.
    const fullPath = req.file.path;
    const ext = path.extname(req.file.originalname).toLowerCase();
    const stat = fs.statSync(fullPath);
    if (stat.size > 250 * 1024 && ext !== '.gif') {
      try {
        const img = sharp(fullPath);
        const meta = await img.metadata();
        let compressed;
        if (meta.format === 'jpeg') compressed = await img.jpeg({ quality: 70 }).toBuffer();
        else if (meta.format === 'png') compressed = await img.png({ quality: 70 }).toBuffer();
        else if (meta.format === 'webp') compressed = await img.webp({ quality: 70 }).toBuffer();
        if (compressed && compressed.length < stat.size) {
          fs.writeFileSync(fullPath, compressed);
        }
      } catch (err) {
        // Compression blew up mid-flight: drop the temp original rather than
        // leaving stale oversize files behind.
        try { fs.unlink(fullPath, () => {}); } catch {}
        return res.status(400).send('Invalid file.');
      }
    }

    const filePath = '/uploads/stickers/' + req.file.filename;
    addSticker(res.locals.currentUser.id, filePath);
    res.redirect('/stickers/manage');
  });
});

router.get('/manage', (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const stickers = getMyStickers(res.locals.currentUser.id);
  res.render('stickers', { stickers });
});

router.post('/add', (req, res) => {
  if (!res.locals.currentUser) return res.status(401).send('Not logged in');
  const filePath = String(req.body.path || '').trim();
  if (!filePath.startsWith('/uploads/stickers/')) return res.status(400).send('Invalid sticker.');
  // Don't duplicate.
  const existing = getMyStickers(res.locals.currentUser.id).filter(s => s.file_path === filePath);
  if (existing.length === 0) {
    addSticker(res.locals.currentUser.id, filePath);
  }
  res.json({ ok: true });
});

module.exports = router;
