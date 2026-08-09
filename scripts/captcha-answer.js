'use strict';
// CLI helper for the bash smoke scripts: print the register captcha answer for
// a session id. Reads the session DB directly (dev/tooling only — the answer
// is server-side state that remote clients never see; they only get the SVG).
// Usage: node scripts/captcha-answer.js <sid>

const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const sid = process.argv[2];
if (!sid) {
  console.error('usage: node scripts/captcha-answer.js <sid>');
  process.exit(2);
}
const dbPath = process.env.EXTV_SESSION_DB_PATH || path.join(__dirname, '..', 'data', 'sessions.db');
const db = new DatabaseSync(dbPath);
const row = db.prepare('SELECT data FROM sessions WHERE sid = ?').get(sid);
if (!row) {
  console.error('session not found');
  process.exit(1);
}
const sess = JSON.parse(row.data);
if (!sess.captcha) {
  console.error('no captcha in session');
  process.exit(1);
}
console.log(sess.captcha.text);
