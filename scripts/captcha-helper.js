'use strict';
// Test helper for the self-hosted image captcha (register anti-bot).
// The expected answer lives in the SERVER-SIDE session store; tests read it
// from the DB the way an operator could. Remote attackers cannot — they only
// receive the SVG image, which is the whole point.
const SessionStore = require('../src/session-store');
const store = new SessionStore();

// Strip the signed-cookie envelope from a raw cookie VALUE
// (s%3A<sid>.<signature> -> sid).
function sidFromCookie(value) {
  const v = decodeURIComponent(value);
  return v.replace(/^s:/, '').split('.')[0];
}

// The captcha answer for a session (null when the image was never fetched).
function captchaAnswer(sid) {
  return new Promise((resolve, reject) => {
    store.get(sid, (err, sess) => {
      if (err) return reject(err);
      resolve(sess && sess.captcha ? sess.captcha.text : null);
    });
  });
}

module.exports = { sidFromCookie, captchaAnswer };
