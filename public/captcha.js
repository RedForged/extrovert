// Self-hosted proof-of-work captcha widget (register page).
// Finds `number` such that sha256(challenge + salt + number) starts with
// `difficulty` hex zeroes, then writes it into the hidden `captcha_number`
// field and enables the submit button. Pure-JS SHA-256 (no crypto.subtle) so
// it works on plain-HTTP instances where WebCrypto is unavailable.
//
// The page embeds the challenge as data-* attributes on #captcha; if that
// challenge is stale/expired the widget re-fetches one from /register/captcha.
(function () {
  'use strict';

  // ---- SHA-256 (pure JS; input is ASCII: challenge+salt are hex, number decimal) ----
  var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256Hex(str) {
    var msg = [];
    for (var i = 0; i < str.length; i++) msg.push(str.charCodeAt(i) & 0xff);
    var bitLen = msg.length * 8;
    msg.push(0x80);
    while (msg.length % 64 !== 56) msg.push(0);
    // 64-bit big-endian length; our inputs are far below 2^32 bytes so the
    // high word is zero and only the low 32 bits need writing.
    msg.push(0, 0, 0, 0, (bitLen >>> 24) & 0xff, (bitLen >>> 16) & 0xff, (bitLen >>> 8) & 0xff, bitLen & 0xff);

    var w = new Array(64);
    var h0 = H[0], h1 = H[1], h2 = H[2], h3 = H[3], h4 = H[4], h5 = H[5], h6 = H[6], h7 = H[7];
    for (var off = 0; off < msg.length; off += 64) {
      for (var j = 0; j < 16; j++) {
        w[j] = (msg[off + j * 4] << 24) | (msg[off + j * 4 + 1] << 16) | (msg[off + j * 4 + 2] << 8) | msg[off + j * 4 + 3];
      }
      for (j = 16; j < 64; j++) {
        var s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
        var s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
      }
      var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (j = 0; j < 64; j++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[j] + w[j]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    return [h0, h1, h2, h3, h4, h5, h6, h7]
      .map(function (x) { return ('00000000' + (x >>> 0).toString(16)).slice(-8); })
      .join('');
  }

  // Promise resolving to the first `number` (0..maxnumber) that solves the
  // proof, batching work so the UI thread stays responsive.
  function solve(challenge, salt, maxnumber, diff) {
    var target = new Array(diff + 1).join('0');
    return new Promise(function (resolve, reject) {
      var number = 0;
      var BATCH = 2048;
      (function step() {
        var end = Math.min(number + BATCH, maxnumber + 1);
        for (; number < end; number++) {
          if (sha256Hex(challenge + salt + number).startsWith(target)) { resolve(number); return; }
        }
        if (number > maxnumber) { reject(new Error('no proof found')); return; }
        setTimeout(step, 0); // yield to the event loop between batches
      })();
    });
  }

  function init() {
    var root = document.getElementById('captcha');
    if (!root) return;
    var input = document.getElementById('captcha-number');
    var status = document.getElementById('captcha-status');
    var submit = document.getElementById('register-submit');
    var attempts = 0;

    function setStatus(msg, state) {
      status.textContent = msg;
      status.className = 'captcha-status' + (state ? ' ' + state : '');
    }

    async function run(challenge, salt, maxnumber, diff) {
      setStatus('Solving captcha\u2026', 'busy');
      try {
        var number = await solve(challenge, salt, maxnumber, diff);
        input.value = String(number);
        setStatus('Human verified \u2713', 'ok');
        if (submit) submit.disabled = false;
        root.setAttribute('data-solved', '1');
      } catch (e) {
        if (attempts++ < 2) {
          // Stale/expired inline challenge — fetch a fresh one and retry.
          try {
            var r = await fetch('/register/captcha');
            var fresh = await r.json();
            return run(fresh.challenge, fresh.salt, fresh.maxnumber, fresh.difficulty);
          } catch (e2) {
            setStatus('Could not verify \u2014 please reload the page.', 'err');
          }
        } else {
          setStatus('Could not verify \u2014 please reload the page.', 'err');
        }
      }
    }

    run(root.dataset.challenge, root.dataset.salt, Number(root.dataset.maxnumber), Number(root.dataset.difficulty));
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }

  // Node-visible exports for the test suite (sha256Hex must match node:crypto).
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { sha256Hex: sha256Hex, solve: solve };
  }
})();
