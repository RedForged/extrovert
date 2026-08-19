'use strict';

// ---------------------------------------------------------------------------
// Extrovert's built-in micro mail server.
//
// Sends verification email WITHOUT any external email service:
//   * a small RFC 5321 SMTP client that speaks directly to the recipient's
//     mail exchanger (resolving MX records itself),
//   * opportunistic STARTTLS (RFC 3207) so messages are encrypted whenever
//     the receiving server supports it,
//   * DKIM signing (RFC 6376) and DMARC alignment so the mail is
//     authenticatable — required to avoid the spam folder,
//   * a local SMTP catcher (the "mail server" for development/testing) so the
//     whole flow runs with zero external services. It is NOT auto-started:
//     dev/test tooling calls startCatcher() explicitly (the app itself
//     delivers via MX or the configured relay),
//   * and a filesystem outbox fallback that writes every message (full
//     headers + body) to data/outbox/<message-id>.eml when no mail server can
//     be reached — nothing is silently dropped, and the .eml files can be
//     piped into spam-filter tooling for local verification.
//
// Deliverability reality check (documented in docs/mail.md): a self-hosted
// mail sender can only get to the inbox if the operator publishes the usual
// DNS records (MX, DKIM, SPF, DMARC, rDNS/PTR) — the protocol machinery here
// (DKIM signing, correct MIME, DMARC alignment) is the software half; the DNS
// half is configuration, and `EXTV_MAIL_MODE=capture` is the recommended
// default until that DNS is in place.
// ---------------------------------------------------------------------------

const net = require('node:net');
const tls = require('node:tls');
const dns = require('node:dns').promises;
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');

const DATA_DIR = path.join(__dirname, '..', 'data');
const OUTBOX_DIR = path.join(DATA_DIR, 'outbox');
const KEYS_DIR = path.join(DATA_DIR, 'mail-keys');

// ---------------------------------------------------------------------------
// Configuration
//
// Every setting resolves as: admin-UI DB value (server_settings.mail_*) —
// if set → environment variable (EXTV_MAIL_*, set e.g. in Portainer) → built-in
// default. Admins can therefore either deploy-time-configure via env vars or
// change anything live from /admin/mail without a restart. `reloadConfig()`
// is called before each send so a settings change applies immediately.
// ---------------------------------------------------------------------------

const ENV_DEFAULTS = {
  mode: 'auto',
  relay: null,
  timeoutMs: 15000,
  maxAttempts: 3,
  retryBaseMs: 30000,
  outboxFallback: true,
  // From defaults to noreply@<instance-domain> derived from the site URL
  // (see derivedFromAddress below); this is only the last-resort fallback.
  from: 'noreply@extrovert.local',
  fromName: 'Extrovert',
  catchDomain: 'extrovert.test',
  dkimEnabled: true,
  dkimSelector: 'extrovert',
  dkimDomain: '',
  bounceFrom: '',
  starttls: 'opportunistic',
  logLevel: 'info',
};

// Cache of the last resolved config — refreshed on every send.
let CFG = resolveConfig();

// Read a value with the documented precedence:
//   stored[dbKey] (if set) → process.env[envName] (if set) → fallback.
function pick(stored, dbKey, envName, fallback) {
  const s = stored[dbKey];
  if (s !== undefined && s !== null && s !== '') return s;
  const e = process.env[envName];
  if (e !== undefined && e !== null && e !== '') return e;
  return fallback;
}

// Derive the mail From domain from the instance's public URL (the OIDC
// issuer, e.g. https://extrovert.redforged.eu → extrovert.redforged.eu) so a
// fresh install works with zero mail config: noreply@<your-domain>. No IP
// needed — the domain is all SMTP receivers care about. Falls back to
// extrovert.local when no issuer is configured or it isn't a real public
// hostname. Only trusts OIDC_ISSUER when explicitly set in the environment —
// the module's built-in default is the author's production URL and must never
// leak into From addresses or verification links.
function derivedFromDomain() {
  try {
    const issuer = process.env.OIDC_ISSUER;
    if (!issuer || !/^https?:\/\//.test(issuer)) return '';
    const host = new URL(issuer).hostname || '';
    // Reject non-sendable names: localhost, .local/.test/.invalid/.example
    // TLDs, any IP literal (v4 or v6, incl. RFC1918 ranges), or an empty host.
    if (!host) return '';
    const lower = host.toLowerCase();
    if (lower === 'localhost') return '';
    // URL.hostname keeps IPv6 brackets ([::1]); isIP wants the bare address.
    const bare = lower.startsWith('[') && lower.endsWith(']') ? lower.slice(1, -1) : lower;
    if (require('node:net').isIP(bare)) return '';
    if (/\.(local|test|invalid|example|internal|home\.arpa)$/i.test(lower)) return '';
    // Trailing-dot FQDNs and single-label names (e.g. "intranet") are not
    // public sendable domains either.
    if (lower.endsWith('.') || !lower.includes('.')) return '';
    return lower;
  } catch {
    return '';
  }
}

function derivedFromAddress() {
  const domain = derivedFromDomain();
  return domain ? `noreply@${domain}` : 'noreply@extrovert.local';
}

// Merge DB-backed settings + env + defaults into the runtime CFG shape.
// `stored` comes from db.getMailSettings() (loaded lazily so a change in the
// admin UI applies without a restart). Returns a fresh object each call.
function resolveConfig(stored) {
  const s = stored || {};
  const bool = (v, def) => (v === '1' || v === 'true' ? true : v === '0' || v === 'false' ? false : def);
  const num = (v, def) => {
    const n = parseInt(v, 10);
    return Number.isFinite(n) && n > 0 ? n : def;
  };
  const from = pick(s, 'from', 'EXTV_MAIL_FROM', derivedFromAddress());
  const modeRaw = pick(s, 'mode', 'EXTV_MAIL_MODE', ENV_DEFAULTS.mode);
  const starttlsRaw = pick(s, 'starttls', 'EXTV_MAIL_STARTTLS', ENV_DEFAULTS.starttls);
  return {
    // 'auto' (default): try the real SMTP client; if the destination MX or
    // connection fails and outbox fallback is on, write a .eml to
    // data/outbox/ instead. 'capture': always write .eml (never touch the
    // network). Used by dev/test. Anything else from env/DB falls back to
    // 'auto'.
    mode: modeRaw === 'capture' ? 'capture' : 'auto',
    // SMTP relay override — when set, all messages go to this host instead of
    // the recipient's MX. E.g. EXTV_MAIL_RELAY=127.0.0.1:2525 → the catcher.
    relay: pick(s, 'relay', 'EXTV_MAIL_RELAY', '') || null,
    timeoutMs: num(pick(s, 'timeout_ms', 'EXTV_MAIL_TIMEOUT_MS', ENV_DEFAULTS.timeoutMs), ENV_DEFAULTS.timeoutMs),
    maxAttempts: num(pick(s, 'max_attempts', 'EXTV_MAIL_MAX_ATTEMPTS', ENV_DEFAULTS.maxAttempts), ENV_DEFAULTS.maxAttempts),
    retryBaseMs: num(pick(s, null, 'EXTV_MAIL_RETRY_BASE_MS', ENV_DEFAULTS.retryBaseMs), ENV_DEFAULTS.retryBaseMs),
    outboxFallback: bool(pick(s, 'outbox_fallback', 'EXTV_MAIL_OUTBOX_FALLBACK', ENV_DEFAULTS.outboxFallback ? '1' : '0'), ENV_DEFAULTS.outboxFallback),
    // From-header address. Must be a real address on the sending domain so
    // DKIM/SPF/DMARC alignment can succeed. Defaults to noreply@<your-domain>
    // derived from the instance URL.
    from,
    fromName: pick(s, 'from_name', 'EXTV_MAIL_FROM_NAME', ENV_DEFAULTS.fromName),
    // Suffix for the in-process catcher's addresses (RFC 2606 .test TLD is
    // guaranteed non-resolvable, so it can never collide with a real box).
    catchDomain: ENV_DEFAULTS.catchDomain,
    dkim: {
      enabled: bool(pick(s, 'dkim_enabled', 'EXTV_MAIL_DKIM', ENV_DEFAULTS.dkimEnabled ? '1' : '0'), ENV_DEFAULTS.dkimEnabled),
      selector: pick(s, 'dkim_selector', 'EXTV_MAIL_DKIM_SELECTOR', ENV_DEFAULTS.dkimSelector),
      // DKIM signing domain defaults to the From domain when not configured —
      // which itself defaults to the instance domain. Perfect DMARC alignment.
      domain: pick(s, 'dkim_domain', 'EXTV_MAIL_DKIM_DOMAIN', domainOf(from) || derivedFromDomain() || ''),
      // The private key is a secret: it may come from the admin UI (stored in
      // the DB as mail_dkim_private_key) or the environment
      // (EXTV_MAIL_DKIM_PRIVATE_KEY). It is never read back for display.
      privateKeyPem: s.dkim_private_key || process.env.EXTV_MAIL_DKIM_PRIVATE_KEY || '',
    },
    // Administrative contact for DMARC/bounce records (RFC 5321 MAIL FROM).
    bounceFrom: pick(s, 'bounce_from', 'EXTV_MAIL_BOUNCE_FROM', ENV_DEFAULTS.bounceFrom),
    // Public IP of the mail-sending server — fills the ip4: mechanism in the
    // SPF record the admin publishes. Validated to be a real IPv4/IPv6.
    spfIp: (() => {
      const raw = String(pick(s, 'spf_ip', 'EXTV_MAIL_SPF_IP', '') || '').trim();
      return net.isIP(raw) ? raw : '';
    })(),
    // STARTTLS security level: 'opportunistic' | 'required' | 'off'.
    // Anything else from env/DB falls back to 'opportunistic'.
    starttls: starttlsRaw === 'off' || starttlsRaw === 'required' ? starttlsRaw : 'opportunistic',
    logLevel: pick(s, null, 'EXTV_MAIL_LOG', ENV_DEFAULTS.logLevel),
  };
}

// Refresh the cached config from the database (admin UI changes apply without
// a restart). Called before each sendMail; also exported for tests.
function reloadConfig() {
  try {
    const db = require('./db');
    const stored = db.getMailSettings ? db.getMailSettings() : {};
    CFG = resolveConfig(stored);
  } catch (err) {
    // db unavailable (e.g. early unit tests) — keep env/default resolution.
    CFG = resolveConfig({});
  }
  return CFG;
}

function log(level, msg) {
  if (CFG.logLevel === 'silent') return;
  const order = { error: 1, info: 2, debug: 3 };
  if (order[level] > order[CFG.logLevel || 'info']) return;
  console.log(`[mailer] ${msg}`);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function normalizeDomain(host) {
  return String(host || '').trim().toLowerCase().replace(/\.$/, '');
}

// Extract the domain from an email address (lowercased, punycode untouched).
function domainOf(email) {
  const at = String(email).lastIndexOf('@');
  return at === -1 ? '' : normalizeDomain(email.slice(at + 1));
}

// Basic sanity check; the SMTP session will be the real gatekeeper.
function isEmailish(s) {
  return typeof s === 'string' && /^[^@\s]+@[^@\s]+$/.test(s.trim());
}

function sanitizeHeaderValue(s) {
  return String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').trim();
}

function formatDate(ts) {
  return new Date(ts || Date.now()).toUTCString().replace('GMT', '+0000');
}

// ---------------------------------------------------------------------------
// DKIM key handling
// ---------------------------------------------------------------------------

function ensureDkimKey() {
  if (CFG.dkim.privateKeyPem) return;
  try {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
    const file = path.join(KEYS_DIR, 'dkim-private.pem');
    if (!fs.existsSync(file)) {
      // RSA-2048 — the minimum accepted by most receivers.
      const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      fs.writeFileSync(file, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      fs.writeFileSync(path.join(KEYS_DIR, 'dkim-public.pem'),
        publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
      log('info', 'Generated DKIM keypair in ' + file);
    }
    CFG.dkim.privateKeyPem = fs.readFileSync(file, 'utf8');
  } catch (err) {
    log('error', 'Could not set up DKIM key: ' + err.message);
  }
}

// The DNS TXT record an operator must publish to make DKIM verify:
//   <selector>._domainkey.<domain> TXT "v=DKIM1; k=rsa; p=<base64>"
function dkimPublicKeyRecord() {
  try {
    ensureDkimKey();
    if (!CFG.dkim.privateKeyPem) return null;
    const pub = crypto.createPublicKey(CFG.dkim.privateKeyPem);
    const der = pub.export({ type: 'spki', format: 'der' });
    // Walk the SPKI structure to the inner RSAPublicKey (RFC 5280:
    // SEQUENCE { algorithm SEQUENCE, BIT STRING { RSAPublicKey } }). The
    // DKIM 'p=' tag MUST be the DER RSAPublicKey itself (RFC 6376 §3.6.1) —
    // NOT the whole SPKI, which strict verifiers reject.
    let offset = 0;
    const readLen = () => {
      let l = der[offset]; offset += 1;
      if ((l & 0x80) === 0x80) {
        const n = l & 0x7f;
        l = 0;
        for (let i = 0; i < n; i++) { l = l * 256 + der[offset]; offset += 1; }
      }
      return l;
    };
    const expect = (tag) => {
      const t = der[offset]; offset += 1;
      if (t !== tag) throw new Error('unexpected DER tag 0x' + t.toString(16));
      return readLen();
    };
    expect(0x30);                      // SPKI SEQUENCE
    // NOTE: do NOT write `offset += expect(...)` — compound assignment reads
    // the LHS value before the RHS runs, so the increments inside the walker
    // would be lost. Two statements on purpose.
    const algLen = expect(0x30);       // algorithm SEQUENCE (OID + NULL)
    offset += algLen;                  // skip its content
    expect(0x03);                      // BIT STRING
    offset += 1;                       // unused-bits byte
    const pk = der.subarray(offset);
    // Sanity: RSAPublicKey is SEQUENCE { INTEGER modulus, INTEGER exponent } —
    // pk = 30 <len> 02 <len> <modulus> ...
    if (pk[0] !== 0x30 || pk[4] !== 0x02) throw new Error('RSAPublicKey parse failed');
    return pk.toString('base64');
  } catch (err) {
    log('error', 'DKIM public key export failed: ' + err.message);
    return null;
  }
}

function dkimTxtRecord() {
  const p = dkimPublicKeyRecord();
  if (!p) return null;
  return `v=DKIM1; k=rsa; p=${p}`;
}

// ---------------------------------------------------------------------------
// RFC 5322 MIME message builder
// ---------------------------------------------------------------------------

function foldHeader(name, value) {
  // Fold long headers at a sane width (RFC 5322). Continuation lines MUST
  // start with a space (or tab) — trimming them would turn the folded header
  // into a broken message and break every parser downstream.
  const max = 76;
  const words = String(value).split(' ');
  const lines = [];
  let cur = name + ':';
  for (const w of words) {
    if ((cur + ' ' + w).length > max && cur !== name + ':') {
      lines.push(cur);
      cur = ' ' + w;
    } else {
      cur += ' ' + w;
    }
  }
  lines.push(cur);
  return lines.join('\r\n');
}

// RFC 2047 encoded-word for non-ASCII header values (subjects). ASCII-only
// values pass through untouched, which keeps 8bit headers out of the wire.
function encodeHeaderValue(value) {
  const s = String(value == null ? '' : value);
  if (/^[\x20-\x7e]*$/.test(s)) return s;
  const bytes = Buffer.from(s, 'utf8');
  const q = bytes
    .map((b) => (b >= 0x20 && b <= 0x7e && b !== 0x3f && b !== 0x3d && b !== 0x5f ? String.fromCharCode(b) : '=' + b.toString(16).toUpperCase().padStart(2, '0')))
    .join('');
  return '=?UTF-8?Q?' + q + '?=';
}

function base64wrap(s, width = 76) {
  const out = [];
  for (let i = 0; i < s.length; i += width) out.push(s.slice(i, i + width));
  return out.join('\r\n');
}

// Build a multipart/alternative message (plain text + HTML).
function buildMessage({ to, subject, text, html, messageId }) {
  const boundary = '----=_extrovert_' + crypto.randomBytes(16).toString('hex');
  const fromAddr = CFG.from;
  const fromDisplay = sanitizeHeaderValue(CFG.fromName);
  const fromHeader = fromDisplay && fromDisplay.toLowerCase() !== fromAddr
    ? `${fromDisplay} <${fromAddr}>` : fromAddr;

  const headers = [];
  headers.push(foldHeader('From', fromHeader));
  headers.push(foldHeader('To', sanitizeHeaderValue(to)));
  headers.push('Reply-To: ' + fromAddr);
  headers.push('Subject: ' + encodeHeaderValue(sanitizeHeaderValue(subject)));
  headers.push('Date: ' + formatDate(Date.now()));
  headers.push('Message-ID: <' + messageId + '>');
  headers.push('MIME-Version: 1.0');
  headers.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);
  headers.push('Content-Transfer-Encoding: 7bit');

  const plain = `This is a multipart message in MIME format.`;
  const parts = [];
  parts.push(`--${boundary}`);
  parts.push('Content-Type: text/plain; charset=UTF-8');
  parts.push('Content-Transfer-Encoding: 7bit');
  parts.push('');
  parts.push(text);
  parts.push(`--${boundary}`);
  parts.push('Content-Type: text/html; charset=UTF-8');
  parts.push('Content-Transfer-Encoding: 7bit');
  parts.push('');
  parts.push(html || `<html><body>${text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>')}</body></html>`);
  parts.push(`--${boundary}--`);
  parts.push('');

  return {
    headers: headers.join('\r\n'),
    body: parts.join('\r\n'),
  };
}

// ---------------------------------------------------------------------------
// DKIM signing (RFC 6376)
// ---------------------------------------------------------------------------

// Relaxed canonicalization for the body (RFC 6376 §3.4.3): strip all
// trailing empty lines, then reduce sequences of WSP between words to a
// single space.
function canonicalizeBodyRelaxed(body) {
  const s = String(body)
    .replace(/[ \t]+\r?\n/g, '\n')       // strip trailing WSP per line
    .replace(/[ \t]+/g, ' ')             // collapse internal WSP runs
    .replace(/\r?\n/g, '\r\n');
  return s.replace(/(?:\r\n)+$/g, '');   // ignore ALL trailing empty lines
}

function canonicalizeHeaderRelaxed(name, value) {
  return name.toLowerCase() + ':' + String(value).replace(/\r?\n\s+/g, ' ').replace(/[ \t]+/g, ' ').trim();
}

// Sign the already-built message (RFC 6376). `messageId` must match the
// Message-ID header; the header values are read back from the message itself.
function signDkim({ messageId, headers, body }) {
  if (!CFG.dkim.enabled) return headers;
  ensureDkimKey();
  if (!CFG.dkim.privateKeyPem) return headers;

  const domain = CFG.dkim.domain || domainOf(CFG.from);
  if (!domain) return headers;

  const signedHeaders = [
    'from', 'to', 'subject', 'date', 'message-id',
  ];

  // Digest of the canonicalized body, used in the signature's b=.
  const bodyHash = crypto.createHash('sha256')
    .update(canonicalizeBodyRelaxed(body), 'utf8')
    .digest('base64');

  // Build the signature header value with an empty b= first, then sign the
  // canonicalized form of the signed headers + the signature header itself.
  const sigHeaderName = 'DKIM-Signature';
  const sigBase = [
    'v=1',
    `a=rsa-sha256`,
    `c=relaxed/relaxed`,
    `d=${domain}`,
    `s=${CFG.dkim.selector}`,
    `h=${signedHeaders.join(':')}`,
    'bh=' + bodyHash,
    'b=',
  ].join('; ');

  const headerLines = headers.split('\r\n');
  const headerMap = {};
  for (const line of headerLines) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const name = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    headerMap[name] = headerMap[name] === undefined ? value : headerMap[name] + ' ' + value;
  }

  const toSign = [];
  for (const h of signedHeaders) {
    if (headerMap[h] !== undefined) toSign.push(canonicalizeHeaderRelaxed(h, headerMap[h]));
  }
  toSign.push(canonicalizeHeaderRelaxed(sigHeaderName, sigBase));

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(toSign.join('\r\n') + '\r\n');
  const signature = signer.sign(CFG.dkim.privateKeyPem, 'base64');

  return headers + '\r\n' + foldHeader(sigHeaderName, sigBase.replace('b=', 'b=' + signature));
}

// ---------------------------------------------------------------------------
// Outbound SMTP client (RFC 5321) — speaks directly to the recipient's MX
// ---------------------------------------------------------------------------

class SmtpError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'SmtpError';
    this.code = code;
  }
}

// Refresh the banner (used for both raw and TLS sockets) with proper
// listener cleanup so repeated calls don't accumulate handlers.
function smtpExchange(socket, timeoutMs) {
  let buffer = '';
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      clearTimeout(timer);
      fn(arg);
    };
    const timer = setTimeout(() => finish(reject, new SmtpError('SMTP read timeout')), timeoutMs);
    function onData(chunk) {
      if (settled) return;
      buffer += chunk.toString('utf8');
      if (buffer.length > 65536) { finish(reject, new SmtpError('SMTP response too long')); return; }
      const lines = buffer.split('\r\n');
      buffer = lines.pop();
      const complete = lines;
      const finalLine = complete[complete.length - 1];
      if (finalLine && /^\d{3} /.test(finalLine)) {
        finish(resolve, complete);
      }
    }
    function onError(e) { finish(reject, new SmtpError('SMTP connection error: ' + e.message)); }
    function onClose() { finish(reject, new SmtpError('SMTP connection closed')); }
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  });
}

function writeLine(socket, line) {
  return new Promise((resolve, reject) => {
    socket.write(line + '\r\n', (err) => (err ? reject(new SmtpError('SMTP write failed: ' + err.message)) : resolve()));
  });
}

async function smtpCommand(socket, cmd, expectCodes, timeoutMs) {
  await writeLine(socket, cmd);
  const replies = await smtpExchange(socket, timeoutMs);
  const last = replies[replies.length - 1];
  const code = parseInt(last.slice(0, 3), 10);
  if (!expectCodes.includes(code)) {
    throw new SmtpError(`SMTP ${cmd.split(' ')[0]} rejected with ${last}`, code);
  }
  return replies;
}

// Upgrade an existing connection to TLS (STARTTLS, RFC 3207). After this the
// caller must switch to the returned TLSSocket — it is a drop-in Duplex.
function upgradeToTls(rawSocket, host, timeoutMs, { required }) {
  return new Promise((resolve, reject) => {
    // servername must be a DNS name — Node forbids IP literals there.
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
    const opts = {
      socket: rawSocket,
      rejectUnauthorized: false, // opportunistic — we still verify nothing; see docs
    };
    if (!isIp) opts.servername = host;
    const tlsSocket = tls.connect(opts);
    const timer = setTimeout(() => {
      tlsSocket.destroy();
      reject(new SmtpError('STARTTLS handshake timeout'));
    }, timeoutMs);
    tlsSocket.once('secureConnect', () => {
      clearTimeout(timer);
      // Silence the socket's noise after success — the caller owns it now.
      tlsSocket.on('error', () => {});
      resolve(tlsSocket);
    });
    tlsSocket.once('error', (e) => {
      clearTimeout(timer);
      reject(new SmtpError('STARTTLS handshake failed: ' + e.message + (required ? '' : ' (continuing without TLS)')));
    });
  });
}

// One full message delivery to a single host:port (the MX or relay).
async function deliverToHost({ host, port, to, message, messageId, heloName }) {
  const rawSocket = net.connect({ host, port });
  let sock = rawSocket;
  const timeoutMs = CFG.timeoutMs;
  try {
    const banner = await smtpExchange(sock, timeoutMs);
    const bannerCode = parseInt(banner[0].slice(0, 3), 10);
    if (bannerCode !== 220) throw new SmtpError('Banner not 220: ' + banner[0], bannerCode);

    await smtpCommand(sock, 'EHLO ' + heloName, [250], timeoutMs);

    // STARTTLS (RFC 3207) — opportunistic by default.
    if (CFG.starttls !== 'off') {
      let upgraded = false;
      try {
        await smtpCommand(sock, 'STARTTLS', [220], timeoutMs);
        // From here the TLS socket owns the raw stream; keep a no-op error
        // guard on the raw socket so a late error can't crash the process if
        // we ever need to fall back to plaintext on it.
        rawSocket.on('error', () => {});
        sock.removeAllListeners();
        sock = await upgradeToTls(rawSocket, host, timeoutMs, { required: CFG.starttls === 'required' });
        upgraded = true;
        await smtpCommand(sock, 'EHLO ' + heloName, [250], timeoutMs);
      } catch (err) {
        if (CFG.starttls === 'required' || upgraded) throw err;
        // opportunistic: continue unencrypted (the retry loop handles hosts
        // that don't play nice after a half-baked TLS negotiation)
        log('debug', `STARTTLS unavailable (${err.message}); continuing plaintext`);
      }
    }

    const fromAddr = CFG.bounceFrom || CFG.from;
    await smtpCommand(sock, 'MAIL FROM:<' + fromAddr + '>', [250], timeoutMs);
    await smtpCommand(sock, 'RCPT TO:<' + to + '>', [250, 251], timeoutMs);
    await smtpCommand(sock, 'DATA', [354], timeoutMs);
    // Dot-stuffing (RFC 5321 §4.5.2): a line beginning with '.' gets an
    // extra '.' so the transmission terminator is unambiguous.
    await writeLine(sock, message.split('\r\n').map(l => l.startsWith('.') ? '.' + l : l).join('\r\n'));
    await writeLine(sock, '.');
    const done = await smtpExchange(sock, timeoutMs);
    const doneCode = parseInt(done[done.length - 1].slice(0, 3), 10);
    if (doneCode !== 250) throw new SmtpError('DATA not accepted: ' + done[done.length - 1], doneCode);
    await writeLine(sock, 'QUIT');
    sock.end();
    log('info', `Sent ${messageId} to <${to}> via ${host}:${port}`);
  } catch (err) {
    try { sock.destroy(); } catch {}
    throw err;
  }
}

// Resolve the MX hosts for a domain, falling back to the domain's own A
// record when no MX exists (RFC 5321 §5.1).
async function mxHosts(domain) {
  try {
    const mx = await dns.resolveMx(domain);
    if (mx.length) {
      return mx
        .sort((a, b) => a.priority - b.priority)
        .map(r => ({ host: r.exchange.replace(/\.$/, ''), port: 25 }));
    }
  } catch { /* no MX → fall through */ }
  return [{ host: domain, port: 25 }];
}

// ---------------------------------------------------------------------------
// Delivery orchestration
// ---------------------------------------------------------------------------

function ensureOutbox() {
  try { fs.mkdirSync(OUTBOX_DIR, { recursive: true }); } catch {}
}

// Write the full message (headers + body) to data/outbox as a .eml file.
// These are complete RFC 5322 messages, so they can be piped into
// spamassassin -t / dkimverify etc. for local deliverability testing without
// any external service. `force` bypasses the outbox_fallback flag: capture
// mode IS the delivery mechanism, so disabling the fallback must not also
// silence capture mode.
function writeOutbox(eml, messageId, force = false) {
  if (!force && !CFG.outboxFallback) return false;
  ensureOutbox();
  const file = path.join(OUTBOX_DIR, messageId + '.eml');
  try {
    fs.writeFileSync(file, eml, { mode: 0o600 });
    log('info', `Wrote ${file} (outbox fallback / capture mode)`);
    return true;
  } catch (err) {
    log('error', 'Failed to write outbox file: ' + err.message);
    return false;
  }
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// Parse a relay setting that may be "host:port", "host", "[::1]:port" or
// "[::1]" (IPv6 literals must be bracketed to carry a port).
function parseRelay(relay) {
  let host = String(relay || '').trim();
  let port = 25;
  const bracketed = host.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) {
    host = bracketed[1];
    if (bracketed[2]) port = parseInt(bracketed[2], 10);
  } else {
    const idx = host.lastIndexOf(':');
    // Only split host:port when there's exactly one colon (no IPv6 literal).
    if (idx !== -1 && host.indexOf(':') === idx) {
      port = parseInt(host.slice(idx + 1), 10);
      host = host.slice(0, idx);
    }
  }
  return { host: host || '127.0.0.1', port: Number.isFinite(port) && port > 0 ? port : 25 };
}

/**
 * Send an email. Returns { ok: true, messageId } or { ok: false, error }.
 *
 * Modes:
 *  - 'capture': never touches the network; always writes the .eml to
 *    data/outbox (outbox_fallback is ignored — capture IS the delivery), and
 *    if EXTV_MAIL_RELAY points at a loopback catcher started via
 *    startCatcher(), messages can also be "received" for round-trip tests.
 *  - 'auto' with EXTV_MAIL_RELAY set → deliver to that relay (retries with
 *    backoff); on final failure the outbox fallback captures the message.
 *  - 'auto' without relay → resolve MX and deliver; same fallback.
 */
async function sendMail({ to, subject, text, html, template }) {
  // Live config: admin-UI DB overrides env overrides defaults. A settings
  // change in /admin/mail applies to the very next send.
  reloadConfig();
  if (!isEmailish(to)) {
    return { ok: false, error: 'Invalid recipient address', messageId: null };
  }

  let messageId;
  try {
    messageId = crypto.randomBytes(16).toString('hex') + '@' + sanitizeHeaderValue(domainOf(CFG.from) || 'extrovert.local');
  } catch {
    messageId = crypto.randomBytes(16).toString('hex') + '@extrovert.local';
  }

  const { headers: h0, body } = buildMessage({ to, subject, text, html, messageId });
  const headers = signDkim({ messageId, headers: h0, body });
  const eml = headers + '\r\n\r\n' + body + '\r\n';

  log('debug', `Sending ${messageId} -> ${to} (mode=${CFG.mode}, relay=${CFG.relay || 'MX'})`);

  // Capture mode: never send over the network.
  if (CFG.mode === 'capture') {
    // Always write in capture mode — the outbox IS the delivery here, so the
    // outbox_fallback flag (meant for auto-mode failure) doesn't apply.
    const wrote = writeOutbox(eml, messageId, true);
    return { ok: wrote, messageId, captured: true, eml };
  }

  // Resolve the destination.
  let targets = [];
  try {
    if (CFG.relay) {
      targets = [parseRelay(CFG.relay)];
    } else {
      targets = await mxHosts(domainOf(to));
      log('debug', `MX for ${domainOf(to)}: ${targets.map(t => t.host + ':' + t.port).join(', ')}`);
    }
  } catch (err) {
    const wrote = writeOutbox(eml, messageId);
    return { ok: wrote, error: 'MX resolution failed: ' + err.message, messageId, captured: wrote };
  }

  if (targets.length === 0) {
    const wrote = writeOutbox(eml, messageId);
    return { ok: wrote, error: 'No mail exchanger found', messageId, captured: wrote };
  }

  const heloName = domainOf(CFG.from) || 'extrovert.local';
  let lastError = null;
  for (let attempt = 1; attempt <= CFG.maxAttempts; attempt++) {
    for (const target of targets) {
      try {
        await deliverToHost({ host: target.host, port: target.port, to, message: eml, messageId, heloName });
        return { ok: true, messageId };
      } catch (err) {
        lastError = err;
        log('error', `Delivery attempt ${attempt} to ${target.host}:${target.port} failed: ${err.message}`);
      }
    }
    if (attempt < CFG.maxAttempts) {
      const delay = CFG.retryBaseMs * attempt;
      log('debug', `Retrying in ${Math.round(delay / 1000)}s`);
      await sleep(delay);
    }
  }

  // Final failure: capture so the mail isn't lost silently.
  const wrote = writeOutbox(eml, messageId);
  return { ok: wrote, error: lastError ? lastError.message : 'Delivery failed', messageId, captured: wrote };
}

// ---------------------------------------------------------------------------
// In-process local SMTP catcher — the "micro mail server" for dev/test.
// Listens on 127.0.0.1, accepts the standard SMTP verbs, and records what it
// receives so tests (and operators on localhost) can assert on it.
// ---------------------------------------------------------------------------

const caughtMessages = [];

function resetCatcher() { caughtMessages.length = 0; }
function getCaughtMessages() { return caughtMessages.slice(); }

function startCatcher(port = 2525) {
  if (CFG.mode !== 'capture' && CFG.mode !== 'auto') {
    return Promise.resolve(null);
  }
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.setEncoding('utf8');
      let buffer = '';
      let inData = false;
      let current = null;
      let session = {};

      const send = (line) => socket.write(line + '\r\n');
      const reset = () => { buffer = ''; inData = false; current = null; };

      send(CFG.mode === 'capture'
        ? '220 extrovert-local ESMTP catcher ready (capture mode — no external service contacted)'
        : '220 extrovert-local ESMTP ready');

      socket.on('data', (chunk) => {
        buffer += chunk;
        const lines = buffer.split('\r\n');
        buffer = lines.pop();
        for (const line of lines) {
          if (inData) {
            if (line === '.') {
              // End of DATA — store the message.
              const msg = session.dataLines ? session.dataLines.join('\r\n') : '';
              caughtMessages.push({
                from: session.mailFrom || null,
                to: (session.rcptTo || []).slice(),
                data: msg + (buffer ? '\r\n' + buffer : ''),
                receivedAt: Date.now(),
              });
              reset();
              send('250 2.0.0 Ok: queued');
            } else {
              (session.dataLines = session.dataLines || []).push(line);
            }
            continue;
          }
          const cmd = line.trim();
          if (!cmd) continue;
          const [verb, ...rest] = cmd.split(' ');
          switch (verb.toUpperCase()) {
            case 'EHLO': case 'HELO':
              (session.helo = rest.join(' '));
              send('250-extrovert-catcher');
              send('250-PIPELINING');
              send('250-8BITMIME');
              send('250 STARTTLS');
              break;
            case 'MAIL':
              session.mailFrom = cmd.slice(cmd.indexOf(':') + 1).trim();
              send('250 2.1.0 Ok');
              break;
            case 'RCPT':
              (session.rcptTo = session.rcptTo || []).push(cmd.slice(cmd.indexOf(':') + 1).trim());
              send('250 2.1.5 Ok');
              break;
            case 'DATA':
              inData = true;
              session.dataLines = [];
              send('354 End data with <CR><LF>.<CR><LF>');
              break;
            case 'QUIT':
              send('221 2.0.0 Bye');
              socket.end();
              break;
            case 'RSET': reset(); send('250 2.0.0 Ok'); break;
            case 'NOOP': send('250 2.0.0 Ok'); break;
            default:
              send('502 5.5.1 Command not implemented: ' + verb);
          }
        }
      });
      socket.on('error', () => {});
    });

    server.on('error', reject);
    // Bind to all interfaces (like the app) but only enough to be useful.
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

// ---------------------------------------------------------------------------
// DMARC / policy endpoint
//
// The DNS TXT record at `_dmarc.<domain>` is what receiving servers actually
// check — the HTTP endpoint below is a convenience for operators without DNS
// control to learn what record they must publish, and a handy /dmarc route
// (like a "well-known" for mail policy). It never substitutes for the DNS
// record; the delivered mail itself is unaffected either way.
// ---------------------------------------------------------------------------

function dmarcRecord(domain, contact) {
  reloadConfig();
  const d = domain || CFG.dkim.domain || domainOf(CFG.from) || 'example.com';
  const c = contact || CFG.bounceFrom || CFG.from;
  // p=quarantine is the sanest default for an instance that verifies email:
  // unauthenticated mail from the domain lands in spam rather than being
  // outright rejected, so real users still get their verification link.
  return `v=DMARC1; p=quarantine; adkim=s; aspf=s; rua=mailto:${c}; fo=1`;
}

// Is a domain a real, publishable public name? The built-in fallback
// (extrovert.local) and other RFC 2606/6761 reserved names are NOT — records
// for them are useless and would be actively harmful to publish.
function isPublicDomain(domain) {
  const lower = String(domain || '').trim().toLowerCase();
  if (!lower || !lower.includes('.')) return false;
  if (/\.(local|test|invalid|example|internal)$/.test(lower)) return false;
  if (lower === 'localhost' || net.isIP(lower)) return false;
  return true;
}

// The instance's real public host from the incoming request — used when the
// effective config domain is the non-public fallback (e.g. fresh install
// without OIDC_ISSUER), so the admin panel can still show usable records.
function requestDomain(req) {
  if (!req || !req.headers) return '';
  const raw = req.headers['x-forwarded-host'] || req.headers.host || (req.get && req.get('host')) || '';
  const h = String(raw).split(',')[0].split(':')[0].trim().toLowerCase();
  return isPublicDomain(h) ? h : '';
}

// DNS records the operator must publish for DKIM/DMARC authentication to
// work — surfaced in the admin mail panel as copy-paste TXT snippets.
// `req` is optional; when present and the configured domain is the non-public
// fallback, the records are derived from the request's real host instead.
function dnsRecords(req) {
  reloadConfig();
  const cfgDomain = CFG.dkim.domain || domainOf(CFG.from);
  const domain = isPublicDomain(cfgDomain) ? cfgDomain : requestDomain(req);
  const isFallback = !isPublicDomain(domain);
  // The DMARC rua must be a real address; if the From is on the fallback
  // domain, point it at the derived public domain instead.
  const contact = isPublicDomain(cfgDomain) ? (CFG.bounceFrom || CFG.from) : `noreply@${domain}`;
  const dkim = dkimTxtRecord();
  // The SPF value needs the sending server's public IP. It cannot be derived
  // from the request (that's the admin's browser); the admin sets it in the
  // panel, otherwise the placeholder stays and the record must be completed
  // by hand. IPv6 is fine as ip6:.
  const spf = domain
    ? (CFG.spfIp
      ? `v=spf1 mx a ip${net.isIP(CFG.spfIp) === 6 ? '6' : '4'}:${CFG.spfIp} -all`
      : `v=spf1 mx a ip4:<your-server-ip> -all`)
    : null;
  return {
    dkim,
    dmarc: dmarcRecord(domain || 'example.com', contact),
    spf,
    selector: CFG.dkim.selector,
    domain: domain || '',
    isFallback,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

module.exports = {
  CFG,
  reloadConfig,
  resolveConfig,
  sendMail,
  startCatcher,
  resetCatcher,
  getCaughtMessages,
  dmarcRecord,
  dkimTxtRecord,
  dkimPublicKeyRecord,
  dnsRecords,
};