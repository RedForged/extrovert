'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const KEY_FILE = path.join(DATA_DIR, 'oidc-keys.json');
const ISSUER = process.env.OIDC_ISSUER || 'https://extrovert.redforged.eu';

let keyPair = null;
let previousKeys = [];

function loadOrGenerateKeys() {
  if (keyPair) return keyPair;

  // Allow loading private key directly from env var (overrides file).
  const envPrivateKey = process.env.OIDC_PRIVATE_KEY;
  if (envPrivateKey) {
    const kid = process.env.OIDC_KID || crypto.randomBytes(8).toString('hex');
    keyPair = {
      publicKey: crypto.createPublicKey(envPrivateKey),
      privateKey: crypto.createPrivateKey(envPrivateKey),
      kid,
    };
    return keyPair;
  }

  try {
    if (fs.existsSync(KEY_FILE)) {
      const raw = fs.readFileSync(KEY_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      keyPair = {
        publicKey: crypto.createPublicKey(parsed.publicKeyPem),
        privateKey: crypto.createPrivateKey(parsed.privateKeyPem),
        kid: parsed.kid,
      };
      // Restore previously-rotated keys so verification still works across
      // restarts (otherwise tokens signed before the last rotation could no
      // longer be validated after a server restart).
      if (Array.isArray(parsed.previousKeys)) {
        previousKeys = parsed.previousKeys
          .filter(k => k && k.kid && k.jwk)
          .slice(-2);
      }
      return keyPair;
    }
  } catch {}

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const kid = crypto.randomBytes(8).toString('hex');
  const keyData = {
    kid,
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    previousKeys: [],
    generatedAt: Date.now(),
  };

  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(KEY_FILE, JSON.stringify(keyData, null, 2), 'utf8');
  try { fs.chmodSync(KEY_FILE, 0o600); } catch {}

  keyPair = {
    publicKey: crypto.createPublicKey(publicKey),
    privateKey: crypto.createPrivateKey(privateKey),
    kid,
  };
  return keyPair;
}

function saveKeyFile(publicKey, privateKey, kid) {
  const keyData = {
    kid,
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    // Persist the rollover set: without this a restart would silently drop the
    // verification keys for every id_token signed before the last rotation.
    previousKeys: previousKeys.slice(-2),
    generatedAt: Date.now(),
  };
  fs.writeFileSync(KEY_FILE, JSON.stringify(keyData, null, 2), 'utf8');
  try { fs.chmodSync(KEY_FILE, 0o600); } catch {}
}

function getJwks() {
  const { publicKey, kid } = loadOrGenerateKeys();
  const jwk = publicKey.export({ format: 'jwk' });
  const keys = [{
    kty: jwk.kty,
    kid,
    use: 'sig',
    alg: 'RS256',
    n: jwk.n,
    e: jwk.e,
  }];
  // Include previous keys for verification during rotation
  for (const pk of previousKeys) {
    keys.push({
      kty: pk.jwk.kty,
      kid: pk.kid,
      use: 'sig',
      alg: 'RS256',
      n: pk.jwk.n,
      e: pk.jwk.e,
    });
  }
  return { keys };
}

function rotateKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const oldPair = loadOrGenerateKeys();
  if (oldPair) {
    // Keep the old key for verification during rollover
    const oldJwk = oldPair.publicKey.export({ format: 'jwk' });
    previousKeys.push({ kid: oldPair.kid, jwk: oldJwk });
    // Keep at most 2 previous keys
    if (previousKeys.length > 2) previousKeys.shift();
  }

  const kid = crypto.randomBytes(8).toString('hex');
  saveKeyFile(publicKey, privateKey, kid);

  keyPair = {
    publicKey: crypto.createPublicKey(publicKey),
    privateKey: crypto.createPrivateKey(privateKey),
    kid,
  };
  return keyPair;
}

function signIdToken(payload) {
  const { privateKey, kid } = loadOrGenerateKeys();
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid,
  };

  const now = Math.floor(Date.now() / 1000);
  const tokenPayload = {
    iss: ISSUER,
    iat: now,
    exp: now + 3600,
    ...payload,
  };

  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const headerB64 = b64(header);
  const payloadB64 = b64(tokenPayload);
  const signature = crypto.sign('RSA-SHA256', Buffer.from(`${headerB64}.${payloadB64}`), privateKey);
  const signatureB64 = signature.toString('base64url');

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

module.exports = { loadOrGenerateKeys, getJwks, signIdToken, rotateKeys, ISSUER };
