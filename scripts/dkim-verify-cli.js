'use strict';
// Independent RFC 6376 DKIM verifier — a fresh implementation used ONLY to
// prove that mailer.js's signatures are valid (the same checks a receiving
// server / dkimverify / SpamAssassin performs). Not used by the app itself.
//
// Usage: node scripts/dkim-verify-cli.js <file.eml>
const fs = require('node:fs');
const crypto = require('node:crypto');

function relaxedBody(body) {
  const s = String(body)
    .replace(/[ \t]+\r?\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\r?\n/g, '\r\n');
  return s.replace(/(?:\r\n)+$/g, '');
}

function relaxedHeader(name, value) {
  return name.toLowerCase() + ':' + String(value)
    .replace(/\r?\n\s+/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim();
}

function parseSignatureHeader(rawValue) {
  // Unfold first: the header may span multiple lines.
  const unfolded = rawValue.replace(/\r?\n\s+/g, ' ').trim();
  const tags = {};
  // Split on ';' outside quotes (base64 b= has no semicolons, so a simple
  // split is safe here).
  for (const part of unfolded.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const k = part.slice(0, eq).trim().toLowerCase();
    const v = part.slice(eq + 1).trim();
    tags[k] = v;
  }
  return tags;
}

function verifyEml(eml) {
  // Normalize to LF, split, then re-join with CRLF so line endings can't
  // corrupt the body canonicalization.
  const lines = eml.replace(/\r\n/g, '\n').split('\n').map(l => l.replace(/\r$/, ''));
  // Split headers from body.
  const headerLines = [];
  let i = 0;
  for (; i < lines.length; i++) {
    if (lines[i] === '') break;
    headerLines.push(lines[i]);
  }
  const body = lines.slice(i + 1).join('\r\n');

  // Reconstruct header map (folded lines joined). Keep raw values.
  const headers = [];
  let cur = null;
  for (const line of headerLines) {
    if (/^[ \t]/.test(line)) {
      if (cur) cur.value += ' ' + line.trim();
    } else {
      if (cur) headers.push(cur);
      const idx = line.indexOf(':');
      cur = { name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() };
    }
  }
  if (cur) headers.push(cur);

  const dkim = headers.filter(h => h.name.toLowerCase() === 'dkim-signature');
  if (!dkim.length) return { status: 'FAIL', reason: 'no DKIM-Signature' };

  const results = [];
  for (const h of dkim) {
    const sig = parseSignatureHeader(h.value);
    const required = ['v', 'a', 'd', 's', 'h', 'bh'];
    const missing = required.filter(k => !(k in sig));
    if (missing.length) { results.push({ status: 'PERMFAIL', reason: 'missing tags: ' + missing }); continue; }
    if (sig.a !== 'rsa-sha256') { results.push({ status: 'PERMFAIL', reason: 'algo ' + sig.a }); continue; }

    // 1. body hash check
    const bhCalc = crypto.createHash('sha256').update(relaxedBody(body)).digest('base64');
    if (bhCalc !== sig.bh) {
      results.push({ status: 'PERMFAIL', reason: `body hash mismatch (calc=${bhCalc.slice(0,20)}…, hdr=${sig.bh.slice(0,20)}…)` });
      continue;
    }

    // 2. header list + signature verification
    const sigList = sig.h.split(':').map(s => s.trim().toLowerCase());
    const wanted = new Set(sigList);
    // The DKIM-Signature header itself is signed with b= empty.
    const sigHeaderRaw = 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=' + sig.d + '; s=' + sig.s +
      '; h=' + sig.h + '; bh=' + sig.bh + '; b=';
    const toSign = [];
    const multi = {};
    for (const hh of headers) {
      const n = hh.name.toLowerCase();
      if (wanted.has(n)) (multi[n] = multi[n] || []).push(hh);
    }
    for (const n of sigList) {
      const list = multi[n];
      if (!list || !list.length) { results.push({ status: 'PERMFAIL', reason: 'missing signed header ' + n }); break; }
      // last instance of each header (RFC 6376 §5.4.2)
      const hh = list[list.length - 1];
      toSign.push(relaxedHeader(n, hh.value));
    }
    if (results.length && results[results.length - 1].status === 'PERMFAIL') continue;
    toSign.push(relaxedHeader('dkim-signature', sigHeaderRaw));

    // 3. verify with public key derived from the signer's private key
    const pem = fs.readFileSync(require.resolve('../data/mail-keys/dkim-private.pem'), 'utf8');
    const pub = crypto.createPublicKey(pem);
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(toSign.join('\r\n') + '\r\n');
    const ok = verifier.verify(pub, sig.b, 'base64');
    results.push({ status: ok ? 'PASS' : 'FAIL', domain: sig.d, selector: sig.s, signedHeaders: sig.h, c: sig.c });
  }
  return results;
}

const file = process.argv[2];
if (!file) { console.error('usage: node dkim-verify-cli.js <file.eml>'); process.exit(2); }
const eml = fs.readFileSync(file, 'utf8');
const res = verifyEml(eml);
for (const r of res) console.log(r.status.padEnd(8), r.reason || `domain=${r.domain} selector=${r.selector} h=${r.signedHeaders} c=${r.c}`);
process.exit(res.every(r => r.status === 'PASS') ? 0 : 1);