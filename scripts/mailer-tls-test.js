'use strict';
// Exercised via CLI: starts a real STARTTLS SMTP server (self-signed cert)
// and delivers through the mailer's SMTP client, proving the TLS-upgrade path.
const tls = require('node:tls');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.EXTV_MAIL_MODE = 'auto';
process.env.EXTV_MAIL_OUTBOX_FALLBACK = 'false';
process.env.EXTV_MAIL_LOG = 'info';
process.env.EXTV_MAIL_STARTTLS = 'required'; // force the TLS path

const mailer = require('../src/mailer');

(async () => {
  // Self-signed cert for the fake MX. Node's crypto cannot generate X.509
  // certificates, so openssl is required (present on CI and every practical
  // deployment); bail out with a clear message instead of a broken fallback.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'extro-tls-'));
  const keyFile = path.join(dir, 'key.pem');
  const certFile = path.join(dir, 'cert.pem');
  let opensslPath = null;
  try {
    opensslPath = require('node:child_process').execSync('command -v openssl', { encoding: 'utf8' }).trim() || null;
  } catch {}
  if (!opensslPath) {
    console.error('TLS TEST: openssl not found on PATH — cannot generate a self-signed cert; skipping the TLS path.');
    process.exit(2);
  }
  require('node:child_process').execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout ${keyFile} -out ${certFile} -days 1 -nodes -subj "/CN=localhost" 2>/dev/null`,
    { stdio: 'ignore' }
  );

  const received = [];
  const server = net.createServer((raw) => {
    let session = {};
    let tlsSock = null;
    let tlsActive = false;
    const send = (s) => (tlsSock ? tlsSock.write(s + '\r\n') : raw.write(s + '\r\n'));
    send('220 fake-mx ESMTP');

    const handle = (line) => {
      const [verb, ...rest] = line.trim().split(' ');
      switch (verb.toUpperCase()) {
        case 'EHLO': send('250-fake-mx'); send('250-STARTTLS'); send('250 8BITMIME'); break;
        case 'STARTTLS':
          send('220 Go ahead');
          raw.pause();                     // stop flowing raw bytes
          raw.removeAllListeners('data');  // TLS owns the stream from here
          tlsActive = true;
          // Server side of STARTTLS: TLSSocket with isServer, NOT tls.connect.
          tlsSock = new tls.TLSSocket(raw, {
            isServer: true,
            secureContext: tls.createSecureContext({ key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) }),
          });
          tlsSock.on('error', () => {});
          tlsSock.setEncoding('utf8');
          let tbuf = '';
          tlsSock.on('data', (td) => {
            if (!tlsSock.encrypted || !tlsActive) return;
            tbuf += td;
            const tl = tbuf.split('\r\n');
            tbuf = tl.pop();
            for (const l of tl) { if (l.trim()) handle(l); }
          });
          break;
        case 'MAIL': session.from = rest.join(' '); send('250 OK'); break;
        case 'RCPT': (session.to = session.to || []).push(rest.join(' ')); send('250 OK'); break;
        case 'DATA': session.data = []; send('354 go'); break;
        case 'QUIT': send('221 bye'); (tlsSock || raw).end(); break;
        default:
          if (session.data !== undefined) {
            if (line === '.') { received.push({ from: session.from, to: session.to, data: session.data.join('\r\n') }); session = {}; send('250 queued'); }
            else session.data.push(line);
          } else send('250 OK');
      }
    };

    let buffer = '';
    raw.on('data', (d) => {
      if (tlsActive) return;               // defensive — TLS path handles it
      buffer += d;
      const lines = buffer.split('\r\n');
      buffer = lines.pop();
      for (const l of lines) { if (l.trim()) handle(l); }
    });
  });

  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  const port = server.address().port;
  process.env.EXTV_MAIL_RELAY = `127.0.0.1:${port}`;
  delete require.cache[require.resolve('../src/mailer')];
  const m2 = require('../src/mailer');

  const r = await m2.sendMail({ to: 'x@example.com', subject: 'TLS test', text: 'over the wire', html: '<p>tls</p>' });
  console.log('send result:', JSON.stringify({ ok: r.ok, error: r.error || null, captured: r.captured || false }));
  await new Promise((res) => setTimeout(res, 200));
  console.log('received count:', received.length);
  if (received.length) console.log('received from:', received[0].from, 'to:', received[0].to);
  server.close();
  await new Promise((res) => setTimeout(res, 100));
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(r.ok && received.length === 1 ? 0 : 1);
})().catch((e) => { console.error('TLS TEST ERROR:', e); process.exit(1); });