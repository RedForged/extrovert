'use strict';
// Starts a real STARTTLS SMTP server and exercises both transport modes:
// unauthenticated direct-style TLS, and authenticated relay TLS with CA and
// hostname verification. Also proves credentials are refused without a relay.
const tls = require('node:tls');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'extro-tls-'));
const keyFile = path.join(dir, 'key.pem');
const certFile = path.join(dir, 'cert.pem');
const configFile = path.join(dir, 'openssl.cnf');
const dbFile = path.join(dir, 'mailer.db');

process.env.EXTV_DB_PATH = dbFile;
process.env.EXTV_MAIL_MODE = 'auto';
process.env.EXTV_MAIL_OUTBOX_FALLBACK = 'false';
process.env.EXTV_MAIL_LOG = 'silent';
process.env.EXTV_MAIL_STARTTLS = 'required';
process.env.EXTV_MAIL_MAX_ATTEMPTS = '1';

const { DatabaseSync } = require('node:sqlite');
const seedDb = new DatabaseSync(dbFile);
seedDb.exec('CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT)');
seedDb.close();

const mailer = require('../src/mailer');

function fail(message) {
  console.error('TLS TEST FAILED:', message);
  process.exit(1);
}

function generateCertificate() {
  fs.writeFileSync(configFile, [
    '[req]',
    'prompt = no',
    'distinguished_name = dn',
    'x509_extensions = v3',
    '[dn]',
    'CN = localhost',
    '[v3]',
    'subjectAltName = DNS:localhost',
    '',
  ].join('\n'));
  const result = spawnSync(process.env.OPENSSL_BIN || 'openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', keyFile, '-out', certFile, '-days', '1', '-config', configFile,
  ], { stdio: 'ignore' });
  return result.status === 0 && fs.existsSync(keyFile) && fs.existsSync(certFile);
}

if (!generateCertificate()) {
  console.error('TLS TEST: openssl could not generate a test certificate; skipping.');
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(2);
}

const received = [];
let authCommands = 0;
let authSuccesses = 0;

const server = net.createServer((raw) => {
  let session = {};
  let tlsSock = null;
  let tlsActive = false;
  let authStep = null;
  const send = (s) => (tlsSock ? tlsSock.write(s + '\r\n') : raw.write(s + '\r\n'));
  send('220 fake-mx ESMTP');

  const handle = (line) => {
    if (authStep === 'username') {
      session.authUser = Buffer.from(line, 'base64').toString('utf8');
      authStep = 'password';
      send('334 UGFzc3dvcmQ6');
      return;
    }
    if (authStep === 'password') {
      session.authPassword = Buffer.from(line, 'base64').toString('utf8');
      authStep = null;
      authSuccesses++;
      send('235 2.7.0 Authentication successful');
      return;
    }

    const [verb, ...rest] = line.trim().split(' ');
    switch (verb.toUpperCase()) {
      case 'EHLO':
        send('250-fake-mx');
        send('250-STARTTLS');
        send('250-AUTH LOGIN');
        send('250 8BITMIME');
        break;
      case 'AUTH':
        authCommands++;
        if (String(rest[0] || '').toUpperCase() === 'LOGIN') {
          authStep = 'username';
          send('334 VXNlcm5hbWU6');
        } else {
          send('504 Unsupported authentication mechanism');
        }
        break;
      case 'STARTTLS':
        send('220 Go ahead');
        raw.pause();
        raw.removeAllListeners('data');
        tlsActive = true;
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
          const lines = tbuf.split('\r\n');
          tbuf = lines.pop();
          for (const l of lines) { if (l.trim()) handle(l); }
        });
        break;
      case 'MAIL': session.from = rest.join(' '); send('250 OK'); break;
      case 'RCPT': (session.to = session.to || []).push(rest.join(' ')); send('250 OK'); break;
      case 'DATA': session.data = []; send('354 go'); break;
      case 'QUIT': send('221 bye'); (tlsSock || raw).end(); break;
      default:
        if (session.data !== undefined) {
          if (line === '.') {
            received.push({
              from: session.from,
              to: session.to,
              authUser: session.authUser || null,
              data: session.data.join('\r\n'),
            });
            session = {};
            send('250 queued');
          } else {
            session.data.push(line);
          }
        } else {
          send('250 OK');
        }
    }
  };

  let buffer = '';
  raw.on('data', (d) => {
    if (tlsActive) return;
    buffer += d;
    const lines = buffer.split('\r\n');
    buffer = lines.pop();
    for (const l of lines) { if (l.trim()) handle(l); }
  });
});

(async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  // Credentials without an explicit relay must fail before any connection.
  process.env.EXTV_MAIL_USERNAME = 'relay-user';
  process.env.EXTV_MAIL_PASSWORD = 'relay-password';
  const noRelay = await mailer.sendMail({ to: 'x@example.com', subject: 'No relay', text: 'blocked' });
  if (noRelay.ok || !/credentials require an explicit relay/i.test(noRelay.error || '')) {
    fail('credentials without a relay were not rejected');
  }
  if (received.length !== 0) fail('credentials without a relay reached the network');

  process.env.EXTV_MAIL_RELAY = `localhost:${port}`;

  // Unauthenticated relay delivery remains opportunistic and never sends AUTH.
  delete process.env.EXTV_MAIL_USERNAME;
  delete process.env.EXTV_MAIL_PASSWORD;
  const plain = await mailer.sendMail({ to: 'x@example.com', subject: 'TLS test', text: 'over the wire' });
  if (!plain.ok) fail('unauthenticated STARTTLS delivery failed: ' + (plain.error || 'unknown'));
  if (authCommands !== 0) fail('unauthenticated delivery sent AUTH');
  if (received.length !== 1) fail('unauthenticated delivery did not arrive');

  // Authenticated relay delivery verifies the certificate against the supplied
  // CA, validates the hostname, then sends AUTH LOGIN.
  process.env.EXTV_MAIL_USERNAME = 'relay-user';
  process.env.EXTV_MAIL_PASSWORD = 'relay-password';
  process.env.EXTV_MAIL_TLS_CA = certFile;
  const authenticated = await mailer.sendMail({ to: 'x@example.com', subject: 'AUTH test', text: 'authenticated' });
  if (!authenticated.ok) fail('authenticated verified-TLS delivery failed: ' + (authenticated.error || 'unknown'));
  if (authCommands !== 1 || authSuccesses !== 1) fail('authenticated relay did not receive exactly one successful AUTH');
  if (received.length !== 2 || received[1].authUser !== 'relay-user') fail('authenticated message was not recorded correctly');

  // A certificate failure must abort before AUTH and before DATA.
  delete process.env.EXTV_MAIL_TLS_CA;
  const rejected = await mailer.sendMail({ to: 'x@example.com', subject: 'Bad cert', text: 'must fail' });
  if (rejected.ok) fail('self-signed relay was accepted without a trusted CA');
  if (authCommands !== 1 || authSuccesses !== 1) fail('certificate failure sent credentials');
  if (received.length !== 2) fail('certificate failure delivered a message');

  server.close();
  await new Promise((resolve) => setTimeout(resolve, 100));
  fs.rmSync(dir, { recursive: true, force: true });
  console.log('Mailer TLS/authentication tests passed');
})().catch((error) => {
  console.error('TLS TEST ERROR:', error);
  try { server.close(); } catch {}
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(1);
});
