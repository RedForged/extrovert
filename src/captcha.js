'use strict';

// Self-hosted image captcha for /register (anti-bot).
//
// Fully inside the Extrovert instance/image: no third-party service, no
// external requests, no API keys. The server renders a distorted-text SVG
// (the svg-captcha generator, a regular npm dependency) and the client types the characters — a
// plain terminal/scripted client has no way to read the image, so mass
// registration via curl/POST is stopped outright.
//
// The challenge is random per request, bound to the session, short-lived
// (5 minutes) and SINGLE-USE: it is consumed on every registration attempt,
// successful or not, so an answer can never be replayed and every
// username-enumeration attempt costs a fresh challenge.
//
// NOTE: this is anti-spam, not a security boundary. It stops scripted bots
// (curl, mass-signup tools) that don't read images — a terminal cannot pass.
// A bot with OCR — or that extracts the bundled font and matches the rendered
// glyph paths — can still solve it, as with any fixed-font image captcha.
// Only a managed behavioral service would go further, and that would require
// external JS — excluded by this project's self-hosting constraint.

const crypto = require('node:crypto');
const svgCaptcha = require('svg-captcha');

const TTL_MS = 5 * 60 * 1000;
const LENGTH = 6; // characters in the image
// Drop easily-confused characters (0/O, 1/l/I) so humans make fewer mistakes.
const IGNORE_CHARS = '0oO1ilI';

// Render a fresh challenge bound to this session. Returns the SVG body to
// serve as image/svg+xml; the expected answer (lowercased) + expiry live in
// req.session.captcha.
function generate(req) {
  const cap = svgCaptcha.create({
    size: LENGTH,
    ignoreChars: IGNORE_CHARS,
    noise: 3,
    color: true,
    background: '#f2efe8',
    width: 160,
    height: 56,
  });
  req.session.captcha = {
    text: cap.text.toLowerCase(),
    expiresAt: Date.now() + TTL_MS,
  };
  return cap.data;
}

function verify(req, body) {
  const data = req.session.captcha;
  delete req.session.captcha; // single-use: consumed whether or not it verifies
  if (!data) {
    return { ok: false, error: 'Captcha verification failed — reload the page and try again.' };
  }
  if (Date.now() > data.expiresAt) {
    return { ok: false, error: 'Captcha expired — reload the page and try again.' };
  }
  const answer = String((body && body.captcha) || '').toLowerCase();
  if (answer.length < LENGTH || answer.length > 16) {
    return { ok: false, error: 'Captcha verification failed — please try again.' };
  }
  // Constant-time compare. Buffers are compared RAW; a length mismatch bails
  // BEFORE timingSafeEqual, which throws on unequal lengths — that throw must
  // never reach the async route handler, or one unauthenticated request (e.g.
  // a multibyte answer that is 6 code units but >6 UTF-8 bytes) crashes the
  // whole process.
  const a = Buffer.from(answer, 'utf8');
  const b = Buffer.from(data.text, 'utf8');
  if (a.length !== b.length) {
    return { ok: false, error: 'Captcha verification failed — please try again.' };
  }
  if (!crypto.timingSafeEqual(a, b)) {
    return { ok: false, error: 'Captcha verification failed — please try again.' };
  }
  return { ok: true };
}

module.exports = { TTL_MS, LENGTH, generate, verify };
