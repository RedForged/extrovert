'use strict';

const express = require('express');
const crypto = require('node:crypto');
const multer = require('multer');
const path = require('node:path');
const fs = require('node:fs');
const { Buffer } = require('node:buffer');
const sharp = require('sharp');
const db = require('../db');
const { canView } = require('../network');
const feed = require('../feed');
const { requireApiAuth, clientAppAuth, generateToken, VALID_SCOPES } = require('../api-auth');
const { signIdToken, ISSUER } = require('../oidc');
const { getAccountIds } = require('../accounts');
const bcrypt = require('bcryptjs');
const { sanitizeProfileHTML, sanitizeCSS } = require('../sanitize');
const { getOnlineUsers, getUserPresence, sendDmEvent, cancelPendingCallByToken, broadcastGatewayEvent, getGatewayLatestSeq, updateUserRoomSubscriptions, pushRoomSessionKeyToRecipient } = require('../webrtc-signaling');
const { onNotification } = require('../notif-broadcaster');
const dm = require('../dm');
const { getVapidPublicKey, validatePushEndpoint } = require('../push');
const { renderMarkdown } = require('../markdown');
const twofa = require('../twofa');
const webauthn = require('../webauthn');
const captcha = require('../captcha');
const sessionStore = require('../session-store');

const router = express.Router();

// ----- helpers -----
const UPLOAD_DIR = path.join(__dirname, '..', '..', 'uploads');
const API_UPLOAD_DIR = path.join(__dirname, '..', '..', 'data', 'api-uploads');
fs.mkdirSync(API_UPLOAD_DIR, { recursive: true });

const ALLOWED_EXT = new Set(['.jpg','.jpeg','.png','.gif','.webp','.mp4','.webm','.mov']);

const upload = multer({
  storage: multer.diskStorage({
    destination: API_UPLOAD_DIR,
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomBytes(16).toString('hex') + (ALLOWED_EXT.has(ext) ? ext : ''));
    },
  }),
  limits: { fileSize: 60 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXT.has(ext)) return cb(null, false);
    if (!file.mimetype.startsWith('image/') && !file.mimetype.startsWith('video/')) return cb(null, false);
    cb(null, true);
  },
});

const STICKER_DIR = path.join(__dirname, '..', '..', 'uploads', 'stickers');
fs.mkdirSync(STICKER_DIR, { recursive: true });

const ALLOWED_STICKER_EXT = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp']);
const stickerUpload = multer({
  storage: multer.diskStorage({
    destination: STICKER_DIR,
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomBytes(12).toString('hex') + (ALLOWED_STICKER_EXT.has(ext) ? ext : '.png'));
    },
  }),
  limits: { fileSize: 500 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, ALLOWED_STICKER_EXT.has(ext));
  },
});

function responseEnvelope(res, data, opts = {}) {
  const body = { data };
  if (opts.pagination) body.pagination = opts.pagination;
  res.json(body);
}

function errorResponse(res, status, title, detail, type = 'about:blank') {
  res.status(status).json({
    type,
    title,
    status,
    detail,
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Policy gate for write interactions: on 'required' instances, unverified
// accounts are read-only (can't like/comment/reblog via the API either).
function requireVerifiedApiWrite(req, res, next) {
  if (db.requireVerifiedEmail(req.apiUser)) {
    return errorResponse(res, 403, 'Forbidden',
      'Email verification required before interacting. Use PATCH /api/v1/accounts/email to set and verify an address.');
  }
  next();
}

// F2.5 — does this session still owe a second factor for `userId`? True when
// the account has TOTP enabled and this browser has neither a trusted-device
// cookie nor a recorded second-factor pass for it. The pass is per-account
// (bound to whichever account the code will be issued FOR), so a stolen
// session can't mint tokens for another signed-in 2FA account via the picker.
function needsSecondFactor(req, userId) {
  if (req.session.secondFactorPassed === userId) return false;
  const { hasTrustedDevice } = require('./auth');
  return !hasTrustedDevice(req, userId);
}

function makeCursor(items, key = 'id') {
  if (!items || items.length === 0) return null;
  return Buffer.from(JSON.stringify({ [key]: items[items.length - 1][key] })).toString('base64url');
}

function decodeCursor(cursor) {
  try {
    return JSON.parse(Buffer.from(cursor, 'base64url').toString());
  } catch {
    return null;
  }
}

function serializeAccount(user, currentUserId) {
  const isSelf = currentUserId ? currentUserId === user.id : false;
  const custom = db.getCustomization(user.id);
  return {
    id: String(user.id),
    username: user.username,
    display_name: user.display_name,
    avatar: user.avatar || null,
    bio: user.bio || '',
    created_at: user.created_at,
    statuses_count: db.countPostsByUser(user.id),
    followers_count: db.countFollowers(user.id),
    following_count: db.countFollowing(user.id),
    is_following: currentUserId ? db.isFollowing(currentUserId, user.id) : false,
    is_self: isSelf,
    is_bot: !!user.is_bot,
    html: (custom && custom.html) || '',
    css: (custom && custom.css) || '',
    // Email info is only ever exposed to the account owner (never in public
    // profiles), matching how Mastodon-style APIs gate account details.
    email_verified: isSelf ? !!user.email_verified_at : null,
    email_required: isSelf ? db.isEmailVerificationRequired() : null,
  };
}

function serializePost(post, author, currentUserId) {
  const interactId = post.type === 'repost' && post.repost_of_id
    ? db.getPostById(post.repost_of_id)
    : post;
  const targetId = interactId ? interactId.id : post.id;
  const bodyText = post.body || '';
  return {
    id: String(post.id),
    type: post.type,
    body: bodyText,
    content: bodyText,
    content_html: renderMarkdown(bodyText),
    media_path: post.media_path || null,
    created_at: post.created_at,
    edited_at: post.edited_at || null,
    account: author ? serializeAccount(author, currentUserId) : null,
    likes_count: db.db.prepare(`SELECT COUNT(*) FROM likes WHERE post_id = ?`).get(targetId)['COUNT(*)'],
    shares_count: db.db.prepare(`SELECT COUNT(*) FROM shares WHERE post_id = ?`).get(targetId)['COUNT(*)'],
    comments_count: db.db.prepare(`SELECT COUNT(*) FROM comments WHERE post_id = ?`).get(targetId)['COUNT(*)'],
    liked: currentUserId ? db.hasLiked(currentUserId, targetId) : false,
    shared: currentUserId ? db.hasShared(currentUserId, targetId) : false,
    repost_of_id: post.repost_of_id ? String(post.repost_of_id) : null,
    is_own: currentUserId ? currentUserId === post.user_id : false,
  };
}

// ======== Client Ergonomics & Device Pairing ========

function getIceServersConfig() {
  let iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (process.env.EXTV_ICE_SERVERS) {
    try {
      iceServers = JSON.parse(process.env.EXTV_ICE_SERVERS);
    } catch {}
  } else if (process.env.EXTV_STUN_SERVER) {
    iceServers = [{ urls: process.env.EXTV_STUN_SERVER }];
  }
  return iceServers;
}

const devicePairingCodes = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of devicePairingCodes) {
    if (v.expiresAt <= now) devicePairingCodes.delete(k);
  }
}, 60000).unref();

function requireAuthOrSession(scope = 'write') {
  return (req, res, next) => {
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      return requireApiAuth(scope)(req, res, next);
    }
    if (req.session && req.session.userId) {
      const user = db.getUserById(req.session.userId);
      if (user && !user.banned) {
        req.apiUser = user;
        req.apiToken = { user_id: user.id, scopes: 'read write profile' };
        return next();
      }
    }
    return requireApiAuth(scope)(req, res, next);
  };
}

// Generate a short-lived device pairing code (for QR code or manual entry)
router.post('/auth/pair/init', requireAuthOrSession('write'), express.json(), (req, res) => {
  const code = 'EXT-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const ttlMs = 5 * 60 * 1000; // 5 minutes
  const expiresAt = Date.now() + ttlMs;

  const requested = String((req.body && req.body.scopes) || '').trim();
  const scopes = requested.split(/\s+/).filter(s => VALID_SCOPES.has(s)).join(' ');

  devicePairingCodes.set(code, {
    userId: req.apiUser.id,
    expiresAt,
    scopes,
  });

  const baseUrl = `${req.protocol}://${req.get('host')}`;
  res.status(201).json({
    data: {
      code,
      expires_in: 300,
      expires_at: expiresAt,
      pairing_url: `${baseUrl}/pair?code=${code}`,
    },
  });
});

// Exchange a pairing code for a permanent Personal Access Token
router.post('/auth/pair/claim', express.json(), (req, res) => {
  const { code, client_name } = req.body || {};
  if (!code || typeof code !== 'string') {
    return errorResponse(res, 400, 'Bad Request', 'code is required.');
  }

  const cleanCode = code.trim().toUpperCase();
  const pairing = devicePairingCodes.get(cleanCode);
  if (!pairing || pairing.expiresAt < Date.now()) {
    devicePairingCodes.delete(cleanCode);
    return errorResponse(res, 404, 'Not Found', 'Pairing code is invalid or has expired.');
  }

  devicePairingCodes.delete(cleanCode); // single-use token

  const user = db.getUserById(pairing.userId);
  if (!user || user.banned) {
    return errorResponse(res, 403, 'Forbidden', 'User account is not accessible.');
  }

  const appName = String(client_name || 'Paired Device').trim().slice(0, 100);
  const rawToken = 'ext_pat_' + crypto.randomBytes(32).toString('hex');
  const validScopes = pairing.scopes ||
    'read write follow notifications media.write read:direct write:direct profile';
  db.createPersonalAccessToken(user.id, appName, rawToken, validScopes, null);

  db.auditLog('device_paired', user.id, `Paired new device: ${appName}`);

  res.status(200).json({
    token: rawToken,
    token_type: 'Bearer',
    data: {
      token: rawToken,
      token_type: 'Bearer',
      scopes: validScopes.split(' '),
      user: serializeAccount(user, user.id),
    },
  });
});

// ======== API Authentication & Registration (Password, TOTP, Passkeys, Captcha) ========

function enforceHttpsInProduction(req, res, next) {
  // req.secure is only true when TLS reaches Express directly or the fronting
  // proxy is trusted (TRUST_PROXY). Accept the standard edge-proxy header too,
  // so TLS-terminating deployments (Nginx Proxy Manager, Caddy, …) keep
  // working even when trust proxy is misconfigured.
  const forwardedProto = (req.get('x-forwarded-proto') || '').split(',')[0].trim();
  if (process.env.NODE_ENV === 'production' && !req.secure && forwardedProto !== 'https') {
    return errorResponse(res, 403, 'Forbidden', 'HTTPS is required in production.');
  }
  next();
}


const loginLockouts = new Map(); // `${username}:${ip}` -> { count: number, lockedUntil: number, lastAttempt: number }
const globalUserFailures = new Map(); // username -> { count: number, lastAttempt: number }

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of loginLockouts) {
    if (v.lastAttempt < now - 3600000 && (!v.lockedUntil || v.lockedUntil < now)) {
      loginLockouts.delete(k);
    }
  }
  for (const [k, v] of globalUserFailures) {
    if (v.lastAttempt < now - 3600000) {
      globalUserFailures.delete(k);
    }
  }
}, 60000).unref();

function getLockoutKey(username, ip) {
  return `${String(username || '').trim().toLowerCase()}:${String(ip || '').trim() || 'unknown'}`;
}

function checkLoginLockout(username, ip) {
  const key = getLockoutKey(username, ip);
  const state = loginLockouts.get(key);
  if (!state) return { locked: false, retryAfter: 0 };
  const now = Date.now();
  if (state.lockedUntil && state.lockedUntil > now) {
    const retryAfter = Math.ceil((state.lockedUntil - now) / 1000);
    return { locked: true, retryAfter };
  }
  return { locked: false, retryAfter: 0 };
}

function recordFailedLogin(username, ip) {
  const key = getLockoutKey(username, ip);
  const userKey = String(username || '').trim().toLowerCase();
  const now = Date.now();
  const maxAttempts = Number(process.env.EXTV_LOGIN_LOCKOUT_ATTEMPTS) || 5;
  const state = loginLockouts.get(key) || { count: 0, lockedUntil: 0, lastAttempt: now };
  state.count += 1;
  state.lastAttempt = now;
  if (state.count >= maxAttempts) {
    const backoffMinutes = Math.min(15, Math.pow(2, state.count - maxAttempts));
    state.lockedUntil = now + backoffMinutes * 60 * 1000;
  }
  loginLockouts.set(key, state);

  const global = globalUserFailures.get(userKey) || { count: 0, lastAttempt: now };
  global.count += 1;
  global.lastAttempt = now;
  globalUserFailures.set(userKey, global);
}

function resetFailedLogin(username, ip) {
  const key = getLockoutKey(username, ip);
  loginLockouts.delete(key);
}

async function applySoftDelayIfNeeded(username) {
  const userKey = String(username || '').trim().toLowerCase();
  const global = globalUserFailures.get(userKey);
  if (global && global.count >= 3) {
    const delayMs = Math.min(1500, (global.count - 2) * 200);
    await new Promise(r => setTimeout(r, delayMs));
  }
}

const DUMMY_BCRYPT_HASH = '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ123456';

function verifySecondFactor(user, code) {
  const trimmed = String(code || '').trim();
  if (!trimmed) return false;
  try {
    if (/^\d{6}$/.test(trimmed.replace(/\s+/g, ''))) {
      return twofa.verifyTotp(twofa.decryptSecret(user.totp_secret), trimmed);
    }
    return db.consumeRecoveryCode(user.id, twofa.hashRecoveryCode(trimmed));
  } catch (err) {
    console.error('api second-factor verify error:', err.message);
    return false;
  }
}

const totpChallenges = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of totpChallenges) {
    if (v.expiresAt <= now) totpChallenges.delete(k);
  }
}, 60000).unref();

function issueOAuthTokensForUser(user, clientName, scopes, req) {
  const app = db.getOrCreateClientApp(clientName, user.id);
  const accessToken = 'ext_oat_' + crypto.randomBytes(32).toString('hex');
  const refreshToken = 'ext_rt_' + crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 86400 * 1000;
  const validScopes = scopes || 'read write follow notifications media.write read:direct write:direct profile';
  db.createOAuthToken(accessToken, refreshToken, app.id, user.id, validScopes, expiresAt);

  try {
    db.createNotification({
      userId: user.id,
      type: 'security',
      actorId: user.id,
    });
  } catch (err) {
    console.error('createNotification security error:', err);
  }

  const userAgent = (req.headers && req.headers['user-agent']) || 'Unknown Client';
  db.auditLog('api_login_success', user.id, `App: "${app.name}", UA: "${userAgent.slice(0, 80)}"`, req.ip);

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    scope: validScopes,
    created_at: Math.floor(Date.now() / 1000),
    expires_in: 86400,
    refresh_token: refreshToken,
    client_id: app.client_id,
    user: {
      id: String(user.id),
      username: user.username,
      display_name: user.display_name,
    },
  };
}

// 1. Password login endpoint
router.post('/auth/login', enforceHttpsInProduction, express.json(), async (req, res) => {
  if (process.env.EXTV_API_PASSWORD_LOGIN === 'off') {
    return errorResponse(res, 403, 'Forbidden', 'API password login is disabled on this server.');
  }

  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const clientName = String((req.body && req.body.client_name) || '').trim();
  const requestedScopes = String((req.body && req.body.scopes) || '').trim();
  const validScopes = requestedScopes.split(/\s+/).filter(s => VALID_SCOPES.has(s)).join(' ') ||
    'read write follow notifications media.write read:direct write:direct profile';

  if (!username || !password) {
    return errorResponse(res, 400, 'Bad Request', 'username and password are required.');
  }

  const lockout = checkLoginLockout(username, req.ip);
  if (lockout.locked) {
    res.set('Retry-After', String(lockout.retryAfter));
    return errorResponse(res, 429, 'Too Many Requests', `Account temporarily locked due to too many failed attempts. Try again in ${lockout.retryAfter} seconds.`);
  }

  const user = db.getUserByUsername(username);
  const userAgent = (req.headers && req.headers['user-agent']) || 'Unknown Client';

  if (!user) {
    bcrypt.compareSync(password, DUMMY_BCRYPT_HASH);
    recordFailedLogin(username, req.ip);
    await applySoftDelayIfNeeded(username);
    db.auditLog('api_login_failed', null, `Unknown user "${username.slice(0, 30)}", UA: "${userAgent.slice(0, 80)}"`, req.ip);
    return errorResponse(res, 401, 'Unauthorized', 'Invalid username or password.');
  }

  if (user.banned) {
    bcrypt.compareSync(password, user.password_hash || DUMMY_BCRYPT_HASH);
    recordFailedLogin(username, req.ip);
    await applySoftDelayIfNeeded(username);
    db.auditLog('api_login_failed', user.id, `Banned user "${user.username}", UA: "${userAgent.slice(0, 80)}"`, req.ip);
    return errorResponse(res, 401, 'Unauthorized', 'Invalid username or password.');
  }

  const passwordOk = bcrypt.compareSync(password, user.password_hash);
  if (!passwordOk) {
    recordFailedLogin(username, req.ip);
    await applySoftDelayIfNeeded(username);
    db.auditLog('api_login_failed', user.id, `Bad password for "${user.username}", UA: "${userAgent.slice(0, 80)}"`, req.ip);
    return errorResponse(res, 401, 'Unauthorized', 'Invalid username or password.');
  }

  resetFailedLogin(username, req.ip);

  if (user.totp_enabled) {
    const challengeToken = 'ext_totp_' + crypto.randomBytes(32).toString('hex');
    totpChallenges.set(challengeToken, {
      userId: user.id,
      clientName: clientName || 'Extrovert Client',
      scopes: validScopes,
      attempts: 0,
      expiresAt: Date.now() + 300 * 1000,
    });
    return res.json({
      totp_required: true,
      challenge_token: challengeToken,
      expires_in: 300,
    });
  }

  const tokens = issueOAuthTokensForUser(user, clientName, validScopes, req);
  return res.json(tokens);
});

// 2. TOTP second factor completion
router.post('/auth/login/totp', enforceHttpsInProduction, express.json(), (req, res) => {
  const challengeToken = String((req.body && req.body.challenge_token) || '').trim();
  const code = String((req.body && req.body.code) || '').trim();
  if (!challengeToken || !code) {
    return errorResponse(res, 400, 'Bad Request', 'challenge_token and code are required.');
  }

  const challenge = totpChallenges.get(challengeToken);
  if (!challenge || challenge.expiresAt < Date.now()) {
    totpChallenges.delete(challengeToken);
    return errorResponse(res, 400, 'Bad Request', 'Challenge is invalid or has expired.');
  }

  challenge.attempts += 1;
  if (challenge.attempts > 5) {
    totpChallenges.delete(challengeToken);
    db.auditLog('api_totp_lockout', challenge.userId, 'Too many failed 2FA attempts', req.ip);
    return errorResponse(res, 429, 'Too Many Requests', 'Too many failed verification attempts. Please log in again.');
  }

  const user = db.getUserById(challenge.userId);
  if (!user || user.banned) {
    totpChallenges.delete(challengeToken);
    return errorResponse(res, 401, 'Unauthorized', 'Invalid username or password.');
  }

  const ok = verifySecondFactor(user, code);
  if (!ok) {
    db.auditLog('api_totp_failed', user.id, `Failed 2FA code (attempt ${challenge.attempts}/5)`, req.ip);
    return errorResponse(res, 401, 'Unauthorized', 'Invalid verification code.');
  }

  totpChallenges.delete(challengeToken);
  resetFailedLogin(user.username, req.ip);

  const tokens = issueOAuthTokensForUser(user, challenge.clientName, challenge.scopes, req);
  return res.json(tokens);
});

// Passkey Ceremony over API
const passkeyApiChallenges = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of passkeyApiChallenges) {
    if (v.expiresAt <= now) passkeyApiChallenges.delete(k);
  }
}, 60000).unref();

router.post('/auth/passkey/options', enforceHttpsInProduction, express.json(), async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  let allowCredentials = [];
  let user = null;
  if (username) {
    user = db.getUserByUsername(username);
    if (user) {
      allowCredentials = db.getPasskeysByUser(user.id).map(p => ({
        id: p.credential_id,
        transports: p.transports ? JSON.parse(p.transports) : undefined,
      }));
      if (allowCredentials.length === 0) {
        return errorResponse(res, 400, 'Bad Request', 'No passkeys are registered for that account.');
      }
    }
  }

  const { rpID } = webauthn.rpInfo(req);
  const options = await webauthn.authenticationOptions({ rpID, allowCredentials });
  const challengeToken = 'ext_pk_' + crypto.randomBytes(32).toString('hex');
  passkeyApiChallenges.set(challengeToken, {
    challenge: options.challenge,
    userId: user ? user.id : null,
    expiresAt: Date.now() + 300 * 1000,
  });

  res.json({
    challenge_token: challengeToken,
    options,
    expires_in: 300,
  });
});

router.post('/auth/passkey/verify', enforceHttpsInProduction, express.json(), async (req, res) => {
  const challengeToken = String((req.body && req.body.challenge_token) || '').trim();
  const response = req.body && req.body.response;
  const clientName = String((req.body && req.body.client_name) || '').trim();
  const requestedScopes = String((req.body && req.body.scopes) || '').trim();
  const validScopes = requestedScopes.split(/\s+/).filter(s => VALID_SCOPES.has(s)).join(' ') ||
    'read write follow notifications media.write read:direct write:direct profile';

  if (!challengeToken || !response) {
    return errorResponse(res, 400, 'Bad Request', 'challenge_token and response are required.');
  }

  const challengeData = passkeyApiChallenges.get(challengeToken);
  passkeyApiChallenges.delete(challengeToken);
  if (!challengeData || challengeData.expiresAt < Date.now()) {
    return errorResponse(res, 400, 'Bad Request', 'Passkey challenge is invalid or has expired.');
  }

  const credentialId = response && response.id;
  if (!credentialId) return errorResponse(res, 400, 'Bad Request', 'Invalid authentication response.');

  const stored = db.getPasskeyByCredentialId(credentialId);
  if (!stored) {
    db.auditLog('api_passkey_login_failed', null, 'Unknown passkey credential', req.ip);
    return errorResponse(res, 401, 'Unauthorized', 'Invalid credentials.');
  }

  const user = db.getUserById(stored.user_id);
  if (!user || user.banned) {
    db.auditLog('api_passkey_login_failed', stored.user_id, 'Banned or deleted user', req.ip);
    return errorResponse(res, 401, 'Unauthorized', 'Invalid credentials.');
  }

  const { rpID, origin } = webauthn.rpInfo(req);
  let verification;
  try {
    verification = await webauthn.verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeData.challenge,
      expectedOrigin: origin,
      expectedRPID: [rpID],
      requireUserVerification: false,
      credential: {
        id: stored.credential_id,
        publicKey: Buffer.from(stored.public_key, 'base64url'),
        counter: stored.counter,
        transports: stored.transports ? JSON.parse(stored.transports) : undefined,
      },
    });
  } catch (err) {
    db.auditLog('api_passkey_login_failed', user.id, `Verification error: ${err.message}`, req.ip);
    return errorResponse(res, 401, 'Unauthorized', 'Invalid passkey assertion.');
  }

  if (!verification || !verification.verified) {
    db.auditLog('api_passkey_login_failed', user.id, 'Assertion not verified', req.ip);
    return errorResponse(res, 401, 'Unauthorized', 'Invalid passkey assertion.');
  }

  const newCount = verification.authenticationInfo.newCounter;
  if (newCount > 0 && newCount <= stored.counter) {
    db.auditLog('api_passkey_login_failed', user.id, 'Stale signature counter', req.ip);
    return errorResponse(res, 401, 'Unauthorized', 'Invalid passkey assertion.');
  }

  db.updatePasskeyCounter(stored.id, newCount);
  const tokens = issueOAuthTokensForUser(user, clientName, validScopes, req);
  res.json(tokens);
});

// Captcha & Registration over API
router.get('/auth/captcha', (req, res) => {
  const cap = captcha.generateApiCaptcha();
  res.json({
    data: {
      captcha_token: cap.token,
      captcha_svg: cap.svg,
      expires_in: cap.expires_in,
    },
  });
});

router.post('/auth/register', enforceHttpsInProduction, express.json(), (req, res) => {
  const { captcha_token, captcha_answer, username, password, display_name, email, client_name } = req.body || {};
  const cap = captcha.verifyApiCaptcha(captcha_token, captcha_answer);
  if (!cap.ok) {
    return errorResponse(res, 400, 'Bad Request', cap.error);
  }

  const cleanUsername = String(username || '').trim();
  const cleanPassword = String(password || '');
  const cleanDisplayName = String(display_name || '').trim() || cleanUsername;
  const cleanEmail = String(email || '').trim();

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(cleanUsername)) {
    return errorResponse(res, 400, 'Bad Request', 'Username must be 3-20 letters, numbers, or underscores.');
  }
  if (cleanPassword.length < 12 || Buffer.byteLength(cleanPassword, 'utf8') > 72) {
    return errorResponse(res, 400, 'Bad Request', 'Password must be at least 12 characters and at most 72 bytes.');
  }

  const emailRequired = db.isEmailVerificationRequired();
  if (cleanEmail) {
    if (!db.isValidEmail(cleanEmail)) {
      return errorResponse(res, 400, 'Bad Request', 'Invalid email address.');
    }
    if (db.getUserByEmail(cleanEmail)) {
      return errorResponse(res, 409, 'Conflict', 'That email address cannot be used.');
    }
  } else if (emailRequired) {
    return errorResponse(res, 400, 'Bad Request', 'This server requires a verified email address to register.');
  }

  if (db.getUserByUsername(cleanUsername)) {
    return errorResponse(res, 409, 'Conflict', 'That username is already taken.');
  }

  const hash = bcrypt.hashSync(cleanPassword, 10);
  const userId = db.createUser({
    username: cleanUsername,
    passwordHash: hash,
    displayName: cleanDisplayName,
    referredBy: null,
    referrerIp: req.ip,
  });

  if (cleanEmail) {
    db.setUserEmail(userId, cleanEmail);
    try {
      require('../email-verify').sendVerificationEmail({ userId, to: cleanEmail, req }).catch(err => {
        console.error('api register email error:', err && err.message);
      });
    } catch {}
  }

  const user = db.getUserById(userId);
  const validScopes = 'read write follow notifications media.write read:direct write:direct profile';
  const tokens = issueOAuthTokensForUser(user, client_name || 'Extrovert Client', validScopes, req);
  db.auditLog('api_register_success', userId, 'User registered via API', req.ip);

  res.status(201).json({
    data: {
      user: serializeAccount(user, userId),
      tokens,
    },
  });
});

// Single round-trip state bootstrap for native and third-party clients
router.get('/client/bootstrap', requireApiAuth('read'), (req, res) => {
  const userId = req.apiUser.id;

  // 1. Current user
  const account = serializeAccount(req.apiUser, userId);

  // 2. Unread notifications
  const unreadCount = db.countUnreadNotifications ? db.countUnreadNotifications(userId) : 0;

  // 3. Gateway sequence
  const initialSeq = getGatewayLatestSeq();

  // 4. Joined rooms with channels, members count, user role, and latest messages
  const userRooms = db.getRoomsForUser(userId) || [];
  const rooms = userRooms.map(r => {
    const channels = db.getRoomChannels(r.id) || [];
    const defaultChan = channels.find(c => c.name === 'general') || channels[0];
    let latestMessages = [];
    if (defaultChan) {
      const msgs = db.getRoomMessages(defaultChan.id) || [];
      latestMessages = msgs.slice(-25).map(m => ({
        id: String(m.id),
        room_id: String(r.id),
        channel_id: String(defaultChan.id),
        user_id: String(m.user_id),
        author: {
          id: String(m.user_id),
          username: m.username,
          display_name: m.display_name,
          avatar: m.avatar || null,
        },
        proto: m.proto,
        body: m.body || '',
        ciphertext: m.ciphertext || null,
        group_session_id: m.group_session_id || null,
        created_at: m.created_at,
        edited_at: m.edited_at || null,
      }));
    }
    const role = db.getUserRoomRole(r.id, userId);
    return {
      id: String(r.id),
      name: r.name,
      description: r.description || '',
      is_public: !!r.is_public,
      created_at: r.created_at,
      member_count: db.getRoomMemberCount(r.id),
      role: role ? { id: role.id, name: role.name, permissions: role.permissions, is_founder: !!role.is_founder } : null,
      channels: channels.map(c => ({
        id: String(c.id),
        room_id: String(c.room_id),
        name: c.name,
        type: c.type || 'text',
        created_at: c.created_at,
      })),
      latest_messages: latestMessages,
    };
  });

  // 5. Initial home timeline
  let timeline = [];
  try {
    const feedResult = feed.buildFeed(userId);
    const items = (feedResult.items || []).slice(0, 20);
    const postIds = items.map(i => i.interactId || i.id).filter(Boolean);
    const counts = db.batchPostCounts(postIds);
    timeline = items.map(item => {
      const post = db.getPostById(item.id);
      if (!post) return null;
      const author = db.getUserById(post.user_id);
      const targetId = item.interactId || post.id;
      return {
        id: String(post.id),
        type: post.type,
        body: post.body || '',
        content: post.body || '',
        content_html: renderMarkdown(post.body || ''),
        media_path: post.media_path || null,
        created_at: post.created_at,
        edited_at: post.edited_at || null,
        account: author ? serializeAccount(author, userId) : null,
        likes_count: counts.likeMap[targetId] || 0,
        shares_count: counts.shareMap[targetId] || 0,
        comments_count: counts.commentMap[targetId] || 0,
        liked: !!db.hasLiked(userId, targetId),
        shared: !!db.hasShared(userId, targetId),
        repost_of_id: post.repost_of_id ? String(post.repost_of_id) : null,
        is_own: post.user_id === userId,
      };
    }).filter(Boolean);
  } catch (err) {
    console.error('Bootstrap timeline error:', err);
  }

  // 6. ICE servers
  const iceServers = getIceServersConfig();

  // 7. E2EE status & prekey count
  const otkCount = db.countAvailablePrekeys ? db.countAvailablePrekeys(userId) : 0;

  responseEnvelope(res, {
    user: account,
    unread_notifications: unreadCount,
    initial_seq: initialSeq,
    rooms,
    timeline,
    ice_servers: iceServers,
    e2ee: {
      otk_count: otkCount,
      otk_low: otkCount < 10,
      has_prekeys: otkCount > 0,
    },
    server: {
      name: process.env.INSTANCE_NAME || 'Extrovert',
      version: '1.0.0',
      max_post_length: 5000,
      max_media_size: 60 * 1024 * 1024,
      e2ee_supported: true,
      realtime_gateway_url: '/ws',
    },
  });
});

// ======== OAuth & App endpoints ========

// Dynamic Client Registration (RFC 7591 / Mastodon compatible)
router.post('/apps', express.json(), express.urlencoded({ extended: true }), (req, res) => {
  const clientName = String(req.body.client_name || req.body.name || '').trim();
  if (!clientName || clientName.length > 100) {
    return errorResponse(res, 400, 'Bad Request', 'client_name is required (max 100 chars).');
  }

  let redirectUris = req.body.redirect_uris;
  if (!redirectUris) redirectUris = 'urn:ietf:wg:oauth:2.0:oob';
  const uris = Array.isArray(redirectUris) ? redirectUris.map(String) : String(redirectUris).split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  if (!uris.length) {
    return errorResponse(res, 400, 'Bad Request', 'redirect_uris is required.');
  }

  const cleanUris = [];
  for (const u of uris) {
    if (u === 'urn:ietf:wg:oauth:2.0:oob') {
      cleanUris.push(u);
      continue;
    }
    let parsed;
    try { parsed = new URL(u); } catch { return errorResponse(res, 400, 'Bad Request', `Invalid redirect URI: ${u}`); }
    const proto = parsed.protocol.toLowerCase();
    if (['javascript:', 'data:', 'vbscript:', 'file:'].includes(proto)) {
      return errorResponse(res, 400, 'Bad Request', 'Disallowed redirect URI scheme.');
    }
    if (parsed.username || parsed.password) {
      return errorResponse(res, 400, 'Bad Request', 'Embedded credentials in redirect URI not allowed.');
    }
    cleanUris.push(u);
  }

  const website = String(req.body.website || '').trim().slice(0, 200);
  const requestedScopes = String(req.body.scopes || 'read write follow notifications media.write read:direct write:direct profile').trim();
  const validScopes = requestedScopes.split(/\s+/).filter(s => VALID_SCOPES.has(s)).join(' ') || 'read';

  const clientId = 'ext_client_' + crypto.randomBytes(16).toString('hex');
  const clientSecret = crypto.randomBytes(32).toString('hex');
  const ownerId = (req.session && req.session.userId) ? req.session.userId : null;

  const appId = db.createOAuthApp({
    name: clientName,
    description: String(req.body.description || 'Dynamically registered application').trim().slice(0, 500),
    website,
    redirectUris: cleanUris.join('\n'),
    clientId,
    clientSecret,
    scopes: validScopes,
    ownerId,
  });

  const appData = {
    id: String(appId),
    name: clientName,
    website: website || null,
    redirect_uri: cleanUris[0],
    redirect_uris: cleanUris,
    client_id: clientId,
    client_secret: clientSecret,
    scopes: validScopes,
    vapid_key: getVapidPublicKey() || null,
  };

  res.status(201).json({
    ...appData,
    data: appData,
  });
});

// Register a new OAuth app
router.post('/oauth/apps', (req, res) => {
  const { name, description, website, redirect_uris, scopes } = req.body;
  if (!name || !redirect_uris) {
    return errorResponse(res, 400, 'Bad Request', 'name and redirect_uris are required.');
  }
  if (String(name).length > 100) {
    return errorResponse(res, 400, 'Bad Request', 'name must be 100 characters or fewer.');
  }

  if (!req.session.userId) {
    return errorResponse(res, 401, 'Unauthorized', 'You must be logged in to register an app.');
  }

  const validScopes = scopes
    ? scopes.split(' ').filter(s => VALID_SCOPES.has(s)).join(' ')
    : 'read';

  // redirect_uris must be absolute http(s) URLs without embedded credentials —
  // anything else (javascript:, data:, file:) could later turn the consent
  // redirect into an open redirect or scheme injection.
  const uris = Array.isArray(redirect_uris) ? redirect_uris.map(String) : [String(redirect_uris)];
  const cleanUris = [];
  for (const u of uris) {
    let parsed;
    try { parsed = new URL(u); } catch { return errorResponse(res, 400, 'Bad Request', 'redirect_uris must be absolute http(s) URLs.'); }
    if ((parsed.protocol !== 'https:' && parsed.protocol !== 'http:') || parsed.username || parsed.password) {
      return errorResponse(res, 400, 'Bad Request', 'redirect_uris must be absolute http(s) URLs without credentials.');
    }
    cleanUris.push(u);
  }
  if (website) {
    let w;
    try { w = new URL(website); } catch { return errorResponse(res, 400, 'Bad Request', 'website must be an http(s) URL.'); }
    if (w.protocol !== 'https:' && w.protocol !== 'http:') {
      return errorResponse(res, 400, 'Bad Request', 'website must be an http(s) URL.');
    }
  }

  const clientId = crypto.randomBytes(24).toString('hex');
  const clientSecret = crypto.randomBytes(32).toString('hex');

  const id = db.createOAuthApp({
    name,
    description: description || '',
    website: website || '',
    redirectUris: cleanUris.join(','),
    clientId,
    clientSecret,
    scopes: validScopes,
    ownerId: req.session.userId,
  });

  db.auditLog('oauth_app_created', req.session.userId, `App "${name}" (client_id: ${clientId})`);

  res.status(201).json({
    data: {
      id: String(id),
      name,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uris: cleanUris,
      scopes: validScopes,
      website: website || '',
    },
  });
});

// List user's registered apps
router.get('/oauth/apps', (req, res) => {
  if (!req.session.userId) {
    return errorResponse(res, 401, 'Unauthorized', 'You must be logged in.');
  }
  const apps = db.getOAuthAppsByOwner(req.session.userId);
  responseEnvelope(res, apps.map(a => ({
    id: String(a.id),
    name: a.name,
    client_id: a.client_id,
    redirect_uris: a.redirect_uris.split(','),
    scopes: a.scopes,
    website: a.website || '',
    created_at: a.created_at,
  })));
});

// OAuth authorize endpoint (user-facing, renders consent page)
router.get('/oauth/authorize', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login?next=' + encodeURIComponent('/api/v1/oauth/authorize?' + new URLSearchParams(req.query).toString()));
  }

  const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method, nonce } = req.query;

  if (response_type !== 'code') {
    return errorResponse(res, 400, 'Bad Request', 'Only response_type=code is supported (Authorization Code flow).');
  }

  const app = db.getOAuthAppByClientId(client_id);
  if (!app) {
    return errorResponse(res, 401, 'Invalid Client', 'Unknown client_id.');
  }

  const allowedUris = app.redirect_uris.split(',');
  if (!redirect_uri || !allowedUris.includes(redirect_uri)) {
    return errorResponse(res, 400, 'Bad Request', 'redirect_uri does not match registered URIs.');
  }
  let parsedRedirect;
  try { parsedRedirect = new URL(redirect_uri); } catch {
    return errorResponse(res, 400, 'Bad Request', 'redirect_uri is not a valid absolute URL.');
  }
  if (parsedRedirect.protocol !== 'https:' && parsedRedirect.protocol !== 'http:') {
    return errorResponse(res, 400, 'Bad Request', 'redirect_uri must be an http(s) URL.');
  }
  if (code_challenge && code_challenge_method && code_challenge_method !== 'S256') {
    return errorResponse(res, 400, 'Bad Request', 'Only the S256 code_challenge_method is supported.');
  }

  // Requested scopes are capped by the scopes the client registered (least
  // privilege): an app registered for 'read' can never ask for 'write'.
  const requestedScopes = scope || app.scopes;
  const appScopes = new Set(app.scopes.split(' '));
  const validScopes = requestedScopes.split(' ').filter(s => VALID_SCOPES.has(s) && appScopes.has(s)).join(' ');
  if (!validScopes) {
    return errorResponse(res, 400, 'Bad Request', 'None of the requested scopes are granted to this client.');
  }

  // F1 multi-account: when several accounts are signed in on this device, the
  // consent page embeds an account picker so the user chooses WHICH account
  // authorizes the app. The picker only changes which account — the consent
  // approval step below stays mandatory.
  const accountIds = getAccountIds(req);
  const signedInAccounts = accountIds.map(id => db.getUserById(id)).filter(Boolean);
  const oauthNextUrl = '/api/v1/oauth/authorize?' + new URLSearchParams(req.query).toString();

  // F2.5: an OAuth authorization from a device that isn't trusted for this
  // account must complete the same second-factor step the login flow uses
  // before consent is shown — OAuth tokens grant API access, so minting one
  // from a merely password-authenticated session would bypass 2FA.
  const activeUser = db.getUserById(req.session.userId);
  if (activeUser && activeUser.totp_enabled && needsSecondFactor(req, activeUser.id)) {
    if (!req.session.csrfToken) {
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return res.render('oauth-second-factor', {
      app,
      redirect_uri,
      state,
      scopes: validScopes,
      code_challenge,
      code_challenge_method,
      nonce,
      csrfToken: req.session.csrfToken,
      signedInAccounts,
      activeId: req.session.userId,
    });
  }

  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }

  res.render('oauth-authorize', {
    app,
    redirect_uri,
    state,
    scopes: validScopes,
    code_challenge,
    code_challenge_method,
    nonce,
    csrfToken: req.session.csrfToken,
    signedInAccounts,
    activeId: req.session.userId,
    addAccountUrl: '/login?add=1&next=' + encodeURIComponent(oauthNextUrl),
  });
});

// OAuth authorize consent POST. Session-cookie state-changing endpoint, so the
// CSRF token IS enforced here (the global /api/* CSRF skip does not apply).
router.post('/oauth/authorize', (req, res) => {
  if (!req.session.userId) {
    return errorResponse(res, 401, 'Unauthorized', 'Not logged in.');
  }
  if (!req.session.csrfToken || req.body._csrf !== req.session.csrfToken) {
    return errorResponse(res, 403, 'Bad Request', 'CSRF token missing or invalid. Re-open the authorization request.');
  }

  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, nonce, approve, account_id } = req.body;

  const app = db.getOAuthAppByClientId(client_id);
  if (!app) return errorResponse(res, 401, 'Invalid Client', 'Unknown client_id.');

  // Never trust the body's redirect_uri — it must exactly match a registered
  // URI. (The consent page re-sends the GET-validated value, but re-check here
  // so a tampered form cannot redirect the code to an attacker's site.)
  if (!redirect_uri || !app.redirect_uris.split(',').includes(redirect_uri)) {
    return errorResponse(res, 400, 'Bad Request', 'redirect_uri does not match registered URIs.');
  }

  // F2.5 second factor, step 2: this is the INTERSTITIAL SUBMISSION (its form
  // always carries the totp_code field and never an approve flag). Verify the
  // code for the target account, record the per-account pass, and bounce back
  // to the GET so the CONSENT page renders next — factor first, consent second.
  if (req.body.totp_code !== undefined) {
    let factorUserId = req.session.userId;
    if (account_id !== undefined && account_id !== '') {
      const parsed = Number(account_id);
      if (!Number.isInteger(parsed) || !getAccountIds(req).includes(parsed)) {
        return errorResponse(res, 400, 'Bad Request', 'Selected account is not signed in on this device.');
      }
      factorUserId = parsed;
    }
    const factorUser = db.getUserById(factorUserId);
    const relayFields = {
      app, redirect_uri, state, scopes: req.body.scope || app.scopes,
      code_challenge, code_challenge_method, nonce,
      signedInAccounts: getAccountIds(req).map(id => db.getUserById(id)).filter(Boolean),
      activeId: factorUserId,
    };
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    relayFields.csrfToken = req.session.csrfToken;

    const overAttempts = (req.session.secondFactorAttempts || 0) >= 5;
    const codeInput = String(req.body.totp_code || '').trim();
    if (overAttempts) {
      return errorResponse(res, 429, 'Too Many Requests',
        'Too many invalid codes. Re-open the authorization request from the application.');
    }
    if (!codeInput || !factorUser || !factorUser.totp_enabled || !auth.verifySecondFactor(factorUser, codeInput)) {
      req.session.secondFactorAttempts = (req.session.secondFactorAttempts || 0) + 1;
      db.auditLog('2fa_verify_failed', factorUserId, 'oauth_authorize');
      relayFields.error = 'Invalid code.';
      return res.render('oauth-second-factor', relayFields);
    }
    delete req.session.secondFactorAttempts;
    req.session.secondFactorPassed = factorUserId;
    const getParams = new URLSearchParams({
      client_id,
      response_type: 'code',
      redirect_uri,
      scope: req.body.scope || '',
    });
    if (state) getParams.set('state', state);
    if (code_challenge) getParams.set('code_challenge', code_challenge);
    if (code_challenge_method) getParams.set('code_challenge_method', code_challenge_method);
    if (nonce) getParams.set('nonce', nonce);
    if (account_id !== undefined && account_id !== '') getParams.set('account_id', account_id);
    return res.redirect('/api/v1/oauth/authorize?' + getParams.toString());
  }

  if (approve !== 'yes') {
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('error', 'access_denied');
    if (state) redirectUrl.searchParams.set('state', state);
    return res.redirect(redirectUrl.toString());
  }

  // F1 multi-account: the consent POST carries the account chosen on the
  // consent page. It must be one of the accounts signed in on this device —
  // the picker never lets a client bypass consent, it only chooses WHICH
  // account the code is bound to (nonce rides along on the same code row).
  let userId = req.session.userId;
  if (account_id !== undefined && account_id !== '') {
    const parsed = Number(account_id);
    if (!Number.isInteger(parsed) || !getAccountIds(req).includes(parsed)) {
      return errorResponse(res, 400, 'Bad Request', 'Selected account is not signed in on this device.');
    }
    userId = parsed;
  }

  // F2.5 second factor, step 1: consent was given (approve=yes) but the target
  // account hasn't passed a factor challenge on this device — demand the code
  // instead of issuing anything (tampered form, or trusted-device cookie that
  // expired between GET and POST).
  const factorUser = db.getUserById(userId);
  if (factorUser && factorUser.totp_enabled && needsSecondFactor(req, userId)) {
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    return res.render('oauth-second-factor', {
      app, redirect_uri, state, scopes: req.body.scope || app.scopes,
      code_challenge, code_challenge_method, nonce,
      csrfToken: req.session.csrfToken,
      signedInAccounts: getAccountIds(req).map(id => db.getUserById(id)).filter(Boolean),
      activeId: userId,
    });
  }

  // Cap requested scopes by what the client registered (least privilege).
  const requestedScopes = scope || app.scopes;
  const appScopes = new Set(app.scopes.split(' '));
  const validScopes = requestedScopes.split(' ').filter(s => VALID_SCOPES.has(s) && appScopes.has(s)).join(' ');
  if (!validScopes) {
    return errorResponse(res, 400, 'Bad Request', 'None of the requested scopes are granted to this client.');
  }
  if (code_challenge && code_challenge_method && code_challenge_method !== 'S256') {
    return errorResponse(res, 400, 'Bad Request', 'Only the S256 code_challenge_method is supported.');
  }

  const code = crypto.randomBytes(32).toString('hex');

  db.createOAuthCode(code, app.id, userId, validScopes, code_challenge || null, code_challenge_method || null, redirect_uri, nonce || null);

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);

  db.auditLog('oauth_code_issued', userId, `App "${app.name}" scopes: ${validScopes}`);

  // Loopback redirect targets (native apps' http://localhost:PORT/callback)
  // are unreachable from MOBILE browsers: they silently refuse to navigate to
  // localhost, so the 302 would land on the consent page with nothing visible
  // and the app never receives the code. Instead render a same-origin page
  // that (a) tries the loopback redirect automatically (works on desktop and
  // browsers that allow it) and (b) shows the authorization code for manual
  // copy-paste into the app (works on every browser). The code is single-use
  // server-side, so displaying it is safe.
  const loopbackHosts = new Set(['localhost', '127.0.0.1', '::1']);
  if (loopbackHosts.has(redirectUrl.hostname)) {
    const dest = escapeHtml(redirectUrl.toString());
    const theCode = escapeHtml(code);
    res.set('Cache-Control', 'no-store');
    return res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="0; url=${dest}">
<title>Authorization Successful — Introvert</title>
<style>
  body{background:#0c0e12;color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .card{background:#151821;border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:28px;max-width:460px;width:90%;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.5)}
  h2{margin:0 0 8px;font-size:19px;color:#38bdf8}
  p{font-size:13px;color:#94a3b8;margin:0 0 14px;line-height:1.5}
  code{display:block;background:#0a0d12;border:1px solid rgba(56,189,248,0.35);color:#7dd3fc;border-radius:10px;padding:12px 14px;font-size:13px;word-break:break-all;user-select:all;-webkit-user-select:all;margin:0 0 14px;font-family:ui-monospace,Menlo,Consolas,monospace}
  a{color:#38bdf8}
</style></head>
<body><div class="card">
  <h2>Authorization Successful</h2>
  <p>Introvert is connecting automatically. If it doesn't open on its own, <strong>copy the code below</strong> and paste it into the app:</p>
  <code>${theCode}</code>
  <p><a href="${dest}">Open Introvert</a> · <a href="https://extrovert.redforged.eu">Extrovert</a></p>
</div></body></html>`);
  }

  res.redirect(redirectUrl.toString());
});

// Token exchange (authorization code -> access token)
router.post('/oauth/token', clientAppAuth, (req, res) => {
  const { grant_type, code, code_verifier, redirect_uri, refresh_token } = req.body;
  const app = req.oauthApp;

  if (grant_type === 'authorization_code') {
    if (!code) return errorResponse(res, 400, 'Bad Request', 'code is required for authorization_code grant.');

    const authCode = db.getOAuthCode(code);
    if (!authCode || authCode.used || Date.now() > authCode.expires_at) {
      return errorResponse(res, 400, 'Bad Request', 'Invalid, expired, or already used authorization code.');
    }

    if (authCode.app_id !== app.id) {
      return errorResponse(res, 400, 'Bad Request', 'Code was issued to a different client.');
    }

    if (authCode.redirect_uri !== redirect_uri) {
      return errorResponse(res, 400, 'Bad Request', 'redirect_uri mismatch.');
    }

    // S256 only — 'plain' leaks the verifier into logs/URLs and must not be
    // supported. Redeeming a code requires either a valid client_secret (a
    // wrong one was already rejected by clientAppAuth) or PKCE — a leaked
    // authorization code alone must never be redeemable.
    if (authCode.code_challenge_method && authCode.code_challenge_method !== 'S256') {
      return errorResponse(res, 400, 'Bad Request', 'Only the S256 code_challenge_method is supported.');
    }
    const authenticatedBySecret = !!(req.body.client_secret && app.client_secret);
    if (!authenticatedBySecret && !authCode.code_challenge) {
      return errorResponse(res, 400, 'Bad Request', 'A valid client_secret or PKCE (code_challenge / code_verifier) is required to redeem this code.');
    }
    if (authCode.code_challenge) {
      if (!code_verifier) {
        return errorResponse(res, 400, 'Bad Request', 'code_verifier is required (PKCE).');
      }
      const challenge = crypto.createHash('sha256').update(code_verifier).digest('base64url');
      if (challenge !== authCode.code_challenge) {
        return errorResponse(res, 400, 'Bad Request', 'code_verifier does not match code_challenge.');
      }
    }

    // Atomically mark the code used; a second concurrent exchange loses.
    if (!db.markOAuthCodeUsed(authCode.id)) {
      return errorResponse(res, 400, 'Bad Request', 'Invalid, expired, or already used authorization code.');
    }

    const accessToken = generateToken();
    const refreshToken = generateToken();
    const expiresAt = Date.now() + 86400000; // 24h

    db.createOAuthToken(accessToken, refreshToken, app.id, authCode.user_id, authCode.scopes, expiresAt);
    db.auditLog('oauth_token_issued', authCode.user_id, `App "${app.name}"`);

    const tokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      scope: authCode.scopes,
      created_at: Math.floor(Date.now() / 1000),
      expires_in: 86400,
      refresh_token: refreshToken,
    };

    const scopesSet = new Set(authCode.scopes.split(' '));
    if (scopesSet.has('openid')) {
      const user = db.getUserById(authCode.user_id);
      const idTokenPayload = {
        sub: String(authCode.user_id),
        aud: app.client_id,
        auth_time: Math.floor(Date.now() / 1000),
      };
      if (authCode.nonce) idTokenPayload.nonce = authCode.nonce;
      if (scopesSet.has('profile')) {
        idTokenPayload.preferred_username = user.username;
        idTokenPayload.name = user.display_name;
        if (user.avatar) idTokenPayload.picture = `${ISSUER}${user.avatar}`;
      }
      // `email` scope (OIDC spec): the claims are omitted entirely when the
      // account has no address stored. email_verified lets relying parties
      // decide whether to trust the address.
      if (scopesSet.has('email')) {
        // Always a strict JSON boolean (Headscale & other clients unmarshal
        // it into a Go bool — a missing claim would silently read false).
        idTokenPayload.email_verified = !!user.email_verified_at;
        if (user.email) idTokenPayload.email = user.email;
      }
      tokenResponse.id_token = signIdToken(idTokenPayload);
    }

    return res.json(tokenResponse);
  }

  if (grant_type === 'refresh_token') {
    if (!refresh_token) return errorResponse(res, 400, 'Bad Request', 'refresh_token is required.');

    const existing = db.getOAuthTokenByRefresh(refresh_token);
    if (!existing) {
      return errorResponse(res, 400, 'Bad Request', 'Invalid or already revoked refresh token.');
    }
    if (existing.revoked_at) {
      // A previously rotated refresh token is being replayed — treat it as
      // token theft (RFC 6749 BCP) and kill every token for this user.
      db.revokeAllOAuthTokensForUser(existing.user_id);
      db.auditLog('oauth_refresh_reuse', existing.user_id, `App "${app.name}"`);
      return errorResponse(res, 401, 'Unauthorized', 'Refresh token reuse detected; all tokens have been revoked.');
    }
    if (existing.app_id !== app.id) {
      // Refresh tokens are bound to the client they were issued to; another
      // registered client must not be able to mint tokens with them.
      return errorResponse(res, 400, 'Bad Request', 'Refresh token was issued to a different client.');
    }
    if (existing.refresh_expires_at && Date.now() > existing.refresh_expires_at) {
      return errorResponse(res, 400, 'Bad Request', 'Refresh token has expired.');
    }

    const newToken = generateToken();
    const newRefreshToken = generateToken();
    const expiresAt = Date.now() + 86400000;

    db.rotateRefreshToken(refresh_token, newToken, newRefreshToken, expiresAt);
    db.auditLog('oauth_token_refreshed', existing.user_id, `App "${app.name}"`);

    return res.json({
      access_token: newToken,
      token_type: 'Bearer',
      scope: existing.scopes,
      created_at: Math.floor(Date.now() / 1000),
      expires_in: 86400,
      refresh_token: newRefreshToken,
    });
  }

  return errorResponse(res, 400, 'Bad Request', `Unsupported grant_type: ${grant_type}.`);
});

// Token revocation
router.post('/oauth/revoke', (req, res) => {
  const { token, client_id } = req.body;
  if (!token) return errorResponse(res, 400, 'Bad Request', 'token is required.');

  const tokenRecord = db.getOAuthToken(token);
  if (tokenRecord) {
    db.revokeOAuthToken(token);
    db.auditLog('oauth_token_revoked', tokenRecord.user_id, `App id: ${tokenRecord.app_id}`);
  }
  // Always return OK to prevent token enumeration
  res.json({ ok: true });
});

// List authorized apps for the current session user
router.get('/oauth/authorized_apps', (req, res) => {
  if (!req.session.userId) {
    return errorResponse(res, 401, 'Unauthorized', 'You must be logged in.');
  }
  const apps = db.getAuthorizedAppsForUser(req.session.userId);
  responseEnvelope(res, apps.map(a => ({
    id: String(a.id),
    name: a.name,
    website: a.website || '',
    client_id: a.client_id,
    scopes: a.token_scopes,
    authorized_at: a.authorized_at,
  })));
});

// Revoke specific app's access for current user
router.post('/oauth/authorized_apps/:appId/revoke', (req, res) => {
  if (!req.session.userId) return errorResponse(res, 401, 'Unauthorized', 'Not logged in.');
  const appId = parseInt(req.params.appId, 10);
  db.revokeOAuthTokensForUser(req.session.userId, appId);
  db.auditLog('oauth_app_access_revoked', req.session.userId, `App id: ${appId}`);
  res.json({ ok: true });
});

// OIDC UserInfo endpoint
router.get('/oauth/userinfo', requireApiAuth('openid'), (req, res) => {
  const scopesSet = new Set(req.apiToken.scopes.split(' '));
  const user = req.apiUser;
  const info = {
    sub: String(user.id),
  };
  if (scopesSet.has('profile')) {
    info.preferred_username = user.username;
    info.name = user.display_name;
    if (user.avatar) info.picture = `${ISSUER}${user.avatar}`;
  }
  // `email` scope (OIDC spec): omitted when the account has no address.
  if (scopesSet.has('email')) {
    // Strict JSON boolean even without an email — see id_token note.
    info.email_verified = !!user.email_verified_at;
    if (user.email) info.email = user.email;
  }
  res.json(info);
});

// Avatar upload dir
const AVATAR_DIR = path.join(__dirname, '..', '..', 'uploads', 'avatars');
fs.mkdirSync(AVATAR_DIR, { recursive: true });

const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: AVATAR_DIR,
    filename: (req, file, cb) => {
      cb(null, crypto.randomBytes(12).toString('hex') + '.jpg');
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(null, false);
    cb(null, true);
  },
});

// ======== Accounts ========

router.get('/accounts/verify_credentials', requireApiAuth('read'), (req, res) => {
  responseEnvelope(res, serializeAccount(req.apiUser, req.apiUser.id));
});

router.patch('/accounts/update_credentials', requireApiAuth('profile'), (req, res) => {
  const { display_name, bio, theme, html, css } = req.body || {};
  if (display_name !== undefined) req.apiUser.display_name = String(display_name).trim().slice(0, 100);
  if (bio !== undefined) req.apiUser.bio = String(bio).trim().slice(0, 500);
  if (theme !== undefined && ['light', 'dark', 'default'].includes(theme)) {
    req.apiUser.theme = theme;
    db.setUserTheme(req.apiUser.id, theme);
  }
  db.updateUserProfile(req.apiUser.id, { displayName: req.apiUser.display_name, bio: req.apiUser.bio });

  if (html !== undefined || css !== undefined) {
    const existing = db.getCustomization(req.apiUser.id);
    const rawHtml = html !== undefined ? String(html).slice(0, 20000) : existing.html;
    const rawCss = css !== undefined ? String(css).slice(0, 10000) : existing.css;
    const cleanHtml = sanitizeProfileHTML(rawHtml);
    const cleanCss = sanitizeCSS(rawCss);
    db.setCustomization(req.apiUser.id, cleanHtml, cleanCss);
  }

  db.auditLog('profile_updated', req.apiUser.id, 'Updated via API', req.ip);
  responseEnvelope(res, serializeAccount(req.apiUser, req.apiUser.id));
});

// Update the account's email address (sends a verification link) — owner only.
// Mirrors the web /settings/email route: blocked entirely when the server has
// email verification switched off.
router.patch('/accounts/email', requireApiAuth('profile'), (req, res) => {
  if (db.getEmailPolicy() === 'off') {
    return errorResponse(res, 400, 'Bad Request', 'Email verification is disabled on this server.');
  }
  const { email } = req.body || {};
  if (typeof email !== 'string') {
    return errorResponse(res, 400, 'Bad Request', 'email is required.');
  }
  const addr = email.trim();
  if (!db.isValidEmail(addr)) {
    return errorResponse(res, 400, 'Bad Request', 'Invalid email address.');
  }
  const existing = db.getUserByEmail(addr);
  if (existing && existing.id !== req.apiUser.id) {
    return errorResponse(res, 409, 'Conflict', 'That email address is already in use.');
  }
  db.clearUserEmail(req.apiUser.id);
  db.setUserEmail(req.apiUser.id, addr);
  db.deleteEmailVerification(req.apiUser.id);
  // Fire-and-forget the verification email; the API returns immediately.
  require('../email-verify').sendVerificationEmail({ userId: req.apiUser.id, to: addr, req })
    .catch((e) => console.error('api accounts/email: send failed', e && e.message));
  db.auditLog('email_updated', req.apiUser.id, 'Email changed via API');
  const u = db.getUserById(req.apiUser.id);
  responseEnvelope(res, { ...serializeAccount(u, u.id), email: u.email, verification_sent: true });
});

// Avatar upload via API
router.post('/accounts/avatar', requireApiAuth('profile'), avatarUpload.single('avatar'), async (req, res) => {
  if (!req.file) return errorResponse(res, 400, 'Bad Request', 'No file uploaded. Use multipart/form-data with field "avatar".');

  const inputPath = req.file.path;
  const outputName = crypto.randomBytes(12).toString('hex') + '.jpg';
  const outputPath = path.join(AVATAR_DIR, outputName);

  try {
    await sharp(inputPath).resize(200, 200, { fit: 'cover', position: 'center' }).jpeg({ quality: 85 }).toFile(outputPath);
    fs.unlinkSync(inputPath);
    db.setAvatar(req.apiUser.id, '/uploads/avatars/' + outputName);
  } catch (e) {
    try { fs.unlinkSync(inputPath); } catch {}
    return errorResponse(res, 400, 'Bad Request', 'Failed to process image.');
  }

  db.auditLog('avatar_updated', req.apiUser.id, 'Updated via API');
  responseEnvelope(res, serializeAccount(db.getUserById(req.apiUser.id), req.apiUser.id));
});

// List personal access tokens
router.get('/accounts/tokens', requireApiAuth('profile'), (req, res) => {
  const tokens = db.listPersonalAccessTokens(req.apiUser.id);
  responseEnvelope(res, tokens.map(t => ({
    id: String(t.id),
    name: t.name,
    token_prefix: t.token_prefix,
    scopes: t.scopes,
    last_used_at: t.last_used_at,
    expires_at: t.expires_at,
    created_at: t.created_at,
  })));
});

// Create personal access token
router.post('/accounts/tokens', requireApiAuth('profile'), express.json(), (req, res) => {
  const name = String(req.body.name || '').trim();
  if (!name || name.length > 100) {
    return errorResponse(res, 400, 'Bad Request', 'name is required (max 100 chars).');
  }
  const scopes = String(req.body.scopes || 'read write follow notifications media.write read:direct write:direct profile').trim();
  const validScopes = scopes.split(/\s+/).filter(s => VALID_SCOPES.has(s)).join(' ') || 'read';
  const rawToken = 'ext_pat_' + crypto.randomBytes(32).toString('hex');
  const days = req.body.expires_in_days ? Number(req.body.expires_in_days) : null;
  const expiresAt = days && days > 0 ? Date.now() + days * 86400000 : null;

  const id = db.createPersonalAccessToken(req.apiUser.id, name, rawToken, validScopes, expiresAt);
  res.status(201).json({
    data: {
      id: String(id),
      name,
      token: rawToken,
      scopes: validScopes,
      expires_at: expiresAt,
      created_at: Date.now(),
    }
  });
});

// Delete personal access token
router.delete('/accounts/tokens/:id', requireApiAuth('profile'), (req, res) => {
  const ok = db.deletePersonalAccessToken(Number(req.params.id), req.apiUser.id);
  if (!ok) return errorResponse(res, 404, 'Not Found', 'Token not found.');
  responseEnvelope(res, { ok: true });
});

// List authorized sessions
router.get('/accounts/sessions', requireApiAuth('profile'), (req, res) => {
  const sessions = db.listActiveSessionsForUser(req.apiUser.id);
  responseEnvelope(res, sessions.map(s => ({
    id: String(s.id),
    client_name: s.client_name || 'Personal Access Token / Unknown',
    client_id: s.client_id,
    website: s.website || null,
    scopes: s.scopes,
    created_at: s.created_at,
    expires_at: s.expires_at,
  })));
});

// Revoke a session token
router.delete('/accounts/sessions/:id', requireApiAuth('profile'), (req, res) => {
  const ok = db.revokeSessionToken(Number(req.params.id), req.apiUser.id);
  if (!ok) return errorResponse(res, 404, 'Not Found', 'Session not found.');
  responseEnvelope(res, { ok: true });
});

// Delete own account
router.delete('/accounts/me', requireApiAuth('profile'), express.json(), (req, res) => {
  const password = String(req.body.password || '');
  if (!password) return errorResponse(res, 400, 'Bad Request', 'password confirmation is required.');
  if (!bcrypt.compareSync(password, req.apiUser.password_hash)) {
    return errorResponse(res, 403, 'Forbidden', 'Incorrect password.');
  }
  db.deleteUser(req.apiUser.id);
  responseEnvelope(res, { ok: true });
});


router.get('/accounts/relationships', requireApiAuth('read'), (req, res) => {
  const ids = String(req.query.id || '').split(',').map(Number).filter(Boolean);
  const results = ids.map(id => ({
    id: String(id),
    following: db.isFollowing(req.apiUser.id, id),
    followed_by: db.isFollowing(id, req.apiUser.id),
  }));
  responseEnvelope(res, results);
});

router.get('/accounts/:id', requireApiAuth('read'), (req, res) => {
  const user = db.getUserById(parseInt(req.params.id, 10));
  if (!user) return errorResponse(res, 404, 'Not Found', 'Account not found.');
  responseEnvelope(res, serializeAccount(user, req.apiUser.id));
});

router.get('/accounts/:id/statuses', requireApiAuth('read'), (req, res) => {
  const user = db.getUserById(parseInt(req.params.id, 10));
  if (!user) return errorResponse(res, 404, 'Not Found', 'Account not found.');
  if (!canView(req.apiUser.id, user.id)) return errorResponse(res, 404, 'Not Found', 'Account not found.');

  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 40);
  const cursor = req.query.cursor ? decodeCursor(req.query.cursor) : null;

  let posts;
  if (cursor) {
    posts = db.db.prepare(`
      SELECT * FROM posts WHERE user_id = ? AND id < ? ORDER BY id DESC LIMIT ?
    `).all(user.id, cursor.id, limit);
  } else {
    posts = db.db.prepare(`
      SELECT * FROM posts WHERE user_id = ? ORDER BY id DESC LIMIT ?
    `).all(user.id, limit);
  }

  responseEnvelope(res, posts.map(p => serializePost(p, user, req.apiUser.id)), {
    pagination: {
      next: makeCursor(posts),
    },
  });
});

router.get('/accounts/:id/followers', requireApiAuth('read'), (req, res) => {
  const user = db.getUserById(parseInt(req.params.id, 10));
  if (!user) return errorResponse(res, 404, 'Not Found', 'Account not found.');

  const followers = db.getFollowers(user.id);
  responseEnvelope(res, followers.map(f => serializeAccount(f, req.apiUser.id)));
});

router.get('/accounts/:id/following', requireApiAuth('read'), (req, res) => {
  const user = db.getUserById(parseInt(req.params.id, 10));
  if (!user) return errorResponse(res, 404, 'Not Found', 'Account not found.');

  const following = db.getFollowing(user.id);
  responseEnvelope(res, following.map(f => serializeAccount(f, req.apiUser.id)));
});

// ======== Follows ========

router.post('/accounts/:id/follow', requireApiAuth('follow'), (req, res) => {
  const target = db.getUserById(parseInt(req.params.id, 10));
  if (!target) return errorResponse(res, 404, 'Not Found', 'Account not found.');
  if (target.id === req.apiUser.id) return errorResponse(res, 400, 'Bad Request', 'Cannot follow yourself.');

  db.follow(req.apiUser.id, target.id);
  db.createNotification({ userId: target.id, type: 'follow', actorId: req.apiUser.id });
  db.auditLog('follow', req.apiUser.id, `Followed user ${target.id}`);
  responseEnvelope(res, serializeAccount(target, req.apiUser.id));
});

router.post('/accounts/:id/unfollow', requireApiAuth('follow'), (req, res) => {
  const target = db.getUserById(parseInt(req.params.id, 10));
  if (!target) return errorResponse(res, 404, 'Not Found', 'Account not found.');

  db.unfollow(req.apiUser.id, target.id);
  db.auditLog('unfollow', req.apiUser.id, `Unfollowed user ${target.id}`);
  responseEnvelope(res, serializeAccount(target, req.apiUser.id));
});

// ======== Statuses ========

router.post('/statuses', requireApiAuth('write'), upload.single('media'), (req, res) => {
  // Policy gate: 'required' instances block posting until the email is verified.
  if (db.requireVerifiedEmail(req.apiUser)) {
    return errorResponse(res, 403, 'Forbidden', 'Email verification required before posting. Use PATCH /api/v1/accounts/email to set and verify an address.');
  }
  const idempotencyKey = req.headers['idempotency-key'];
  if (idempotencyKey) {
    const cached = db.getIdempotencyKey(idempotencyKey);
    if (cached) {
      return res.status(cached.status_code).set('X-Idempotency-Replayed', 'true')
        .json(JSON.parse(cached.response));
    }
  }

  const postType = req.body.type || 'text';
  const postBody = req.body.body !== undefined ? req.body.body : req.body.status;
  const repost_of_id = req.body.repost_of_id;
  let mediaPath = null;

  if ((postType === 'photo' || postType === 'video') && req.file) {
    mediaPath = '/api-uploads/' + req.file.filename;
  }

  if (postType === 'text' && !postBody) return errorResponse(res, 400, 'Bad Request', 'body is required for text posts.');
  if (postType === 'repost') {
    if (!repost_of_id) return errorResponse(res, 400, 'Bad Request', 'repost_of_id is required for repost type.');
    const original = db.getPostById(parseInt(repost_of_id, 10));
    if (!original) return errorResponse(res, 404, 'Not Found', 'Original post not found.');
    if (!canView(req.apiUser.id, original.user_id)) return errorResponse(res, 404, 'Not Found', 'Original post not found.');
    if (db.hasReposted(req.apiUser.id, original.id)) return errorResponse(res, 409, 'Conflict', 'Already reposted this post.');
  }

  const postId = db.createPost({
    userId: req.apiUser.id,
    type: postType,
    body: String(postBody || '').trim().slice(0, 5000),
    mediaPath,
    repostOfId: repost_of_id ? parseInt(repost_of_id, 10) : null,
  });

  const post = db.getPostById(postId);
  const author = db.getUserById(post.user_id);
  db.notifyMentions(post.body, req.apiUser.id, postId);

  const response = serializePost(post, author, req.apiUser.id);
  const clientId = req.body.client_id || req.body.nonce || req.body.client_tx_id;
  if (clientId) response.client_id = String(clientId);

  const envelope = { data: response };
  if (idempotencyKey) {
    db.setIdempotencyKey(idempotencyKey, JSON.stringify(envelope), 201);
  }

  db.auditLog('post_created', req.apiUser.id, `Post ${postId} type: ${postType}`);
  broadcastGatewayEvent('timeline:home', 'post_create', response);
  res.status(201).json(envelope);
});

router.get('/statuses/:id', requireApiAuth('read'), (req, res) => {
  const post = db.getPostById(parseInt(req.params.id, 10));
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');

  const author = db.getUserById(post.user_id);
  if (!author) return errorResponse(res, 404, 'Not Found', 'Author not found.');
  if (!canView(req.apiUser.id, author.id)) return errorResponse(res, 404, 'Not Found', 'Post not found.');

  responseEnvelope(res, serializePost(post, author, req.apiUser.id));
});

router.patch('/statuses/:id', requireApiAuth('write'), requireVerifiedApiWrite, express.json(), (req, res) => {
  const post = db.getPostById(parseInt(req.params.id, 10));
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');
  if (post.user_id !== req.apiUser.id) return errorResponse(res, 403, 'Forbidden', 'You can only edit your own posts.');
  const inputBody = req.body.body !== undefined ? req.body.body : req.body.status;
  const body = String(inputBody || '').trim();
  if (!body) return errorResponse(res, 400, 'Bad Request', 'body is required.');
  if (body.length > 5000) return errorResponse(res, 400, 'Bad Request', 'body must be 5000 characters or fewer.');

  const ok = db.editPost(post.id, req.apiUser.id, body);
  if (!ok) return errorResponse(res, 404, 'Not Found', 'Post not found or not yours.');

  const updated = db.getPostById(post.id);
  const author = db.getUserById(updated.user_id);
  const serialized = serializePost(updated, author, req.apiUser.id);
  broadcastGatewayEvent('timeline:home', 'post_update', serialized);
  responseEnvelope(res, serialized);
});

router.get('/statuses/:id/history', requireApiAuth('read'), (req, res) => {
  const post = db.getPostById(parseInt(req.params.id, 10));
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');
  const author = db.getUserById(post.user_id);
  if (!author || !canView(req.apiUser.id, author.id)) return errorResponse(res, 404, 'Not Found', 'Post not found.');

  const history = db.getEditHistory('post', post.id);
  responseEnvelope(res, history.map(h => ({
    id: String(h.id),
    entity_id: String(h.entity_id),
    body: h.old_body,
    old_body: h.old_body,
    edited_at: h.edited_at,
  })));
});

router.delete('/statuses/:id', requireApiAuth('write'), (req, res) => {
  const post = db.getPostById(parseInt(req.params.id, 10));
  const deleted = db.deletePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!deleted) return errorResponse(res, 404, 'Not Found', 'Post not found or not yours.');
  if (post && post.media_path && post.media_path.startsWith('/uploads/')) {
    fs.unlink(path.join(__dirname, '..', '..', post.media_path), () => {});
  }
  db.auditLog('post_deleted', req.apiUser.id, `Post ${req.params.id}`);
  broadcastGatewayEvent('timeline:home', 'post_delete', { id: String(req.params.id) });
  res.json({ data: { ok: true } });
});

router.post('/statuses/:id/follow_from', requireApiAuth('follow'), (req, res) => {
  const post = resolveVisiblePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');
  if (post.user_id === req.apiUser.id) return errorResponse(res, 400, 'Bad Request', 'Cannot follow from your own post.');

  db.recordFollowFromPost(req.apiUser.id, post.user_id, post.id);
  responseEnvelope(res, { ok: true });
});

router.post('/statuses/:id/favourite', requireApiAuth('write'), requireVerifiedApiWrite, (req, res) => {
  const post = resolveVisiblePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');

  const liked = db.toggleLike(req.apiUser.id, post.id);
  if (liked && post.user_id !== req.apiUser.id) {
    db.createNotification({ userId: post.user_id, type: 'like', actorId: req.apiUser.id, postId: post.id });
  }
  db.auditLog('like_toggle', req.apiUser.id, `Post ${post.id} liked: ${liked}`);

  const author = db.getUserById(post.user_id);
  responseEnvelope(res, serializePost(post, author, req.apiUser.id));
});

router.post('/statuses/:id/unfavourite', requireApiAuth('write'), (req, res) => {
  const post = resolveVisiblePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');

  db.db.prepare(`DELETE FROM likes WHERE user_id = ? AND post_id = ?`).run(req.apiUser.id, post.id);

  const author = db.getUserById(post.user_id);
  responseEnvelope(res, serializePost(post, author, req.apiUser.id));
});

router.post('/statuses/:id/reblog', requireApiAuth('write'), requireVerifiedApiWrite, (req, res) => {
  const post = resolveVisiblePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');
  if (post.user_id === req.apiUser.id) return errorResponse(res, 400, 'Bad Request', 'Cannot repost your own post.');

  if (!db.hasReposted(req.apiUser.id, post.id)) {
    db.createPost({ userId: req.apiUser.id, type: 'repost', repostOfId: post.id });
    db.createNotification({ userId: post.user_id, type: 'share', actorId: req.apiUser.id, postId: post.id });
  }

  const author = db.getUserById(post.user_id);
  responseEnvelope(res, serializePost(post, author, req.apiUser.id));
});

router.get('/statuses/:id/context', requireApiAuth('read'), (req, res) => {
  const post = resolveVisiblePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');

  const comments = db.commentsForPost(post.id);
  res.json({
    data: {
      ancestors: [],
      descendants: comments.map(c => ({
        id: String(c.id),
        body: c.body,
        created_at: c.created_at,
        edited_at: c.edited_at || null,
        account: serializeAccount({ id: c.user_id, username: c.username, display_name: c.display_name, avatar: c.avatar, bio: c.user_bio || '', created_at: c.user_created_at }, req.apiUser.id),
      })),
    },
  });
});

// Comment on a post (same behavior as the web form).
router.post(['/statuses/:id/comment', '/statuses/:id/comments'], requireApiAuth('write'), requireVerifiedApiWrite, (req, res) => {
  const post = resolveVisiblePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');
  const body = String(req.body.body || '').trim();
  if (!body) return errorResponse(res, 400, 'Bad Request', 'body is required.');
  const commentId = db.addComment(req.apiUser.id, post.id, body.slice(0, 1000));
  db.notifyMentions(body, req.apiUser.id, post.id);
  if (post.user_id !== req.apiUser.id) {
    db.createNotification({ userId: post.user_id, type: 'comment', actorId: req.apiUser.id, postId: post.id });
  }
  const c = db.db.prepare(
    `SELECT c.*, u.username, u.display_name, u.avatar, u.created_at AS user_created_at
     FROM comments c JOIN users u ON u.id = c.user_id WHERE c.id = ?`
  ).get(commentId);

  const clientId = req.body.client_id || req.body.nonce || req.body.client_tx_id;
  const commentData = {
    id: String(c.id),
    post_id: String(post.id),
    body: c.body,
    created_at: c.created_at,
    edited_at: c.edited_at || null,
    account: serializeAccount({ id: c.user_id, username: c.username, display_name: c.display_name, avatar: c.avatar, bio: c.user_bio || '', created_at: c.user_created_at }, req.apiUser.id),
  };
  if (clientId) commentData.client_id = String(clientId);

  broadcastGatewayEvent('timeline:home', 'comment_create', commentData);
  responseEnvelope(res, commentData);
});

router.patch('/statuses/:id/comments/:cid', requireApiAuth('write'), requireVerifiedApiWrite, express.json(), (req, res) => {
  const post = resolveVisiblePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');
  const body = String(req.body.body || '').trim().slice(0, 1000);
  if (!body) return errorResponse(res, 400, 'Bad Request', 'body is required.');
  const ok = db.editComment(parseInt(req.params.cid, 10), req.apiUser.id, body);
  if (!ok) return errorResponse(res, 404, 'Not Found', 'Comment not found or not yours.');
  const c = db.db.prepare(
    `SELECT c.*, u.username, u.display_name, u.avatar, u.created_at AS user_created_at
     FROM comments c JOIN users u ON u.id = c.user_id WHERE c.id = ?`
  ).get(parseInt(req.params.cid, 10));
  responseEnvelope(res, {
    id: String(c.id),
    body: c.body,
    created_at: c.created_at,
    edited_at: c.edited_at || null,
    account: serializeAccount({ id: c.user_id, username: c.username, display_name: c.display_name, avatar: c.avatar, bio: c.user_bio || '', created_at: c.user_created_at }, req.apiUser.id),
  });
});

router.delete('/statuses/:id/comments/:cid', requireApiAuth('write'), (req, res) => {
  const post = resolveVisiblePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');
  const ok = db.deleteComment(parseInt(req.params.cid, 10), req.apiUser.id);
  if (!ok) return errorResponse(res, 404, 'Not Found', 'Comment not found or not yours.');
  responseEnvelope(res, { ok: true });
});

router.get('/statuses/:id/favourited_by', requireApiAuth('read'), (req, res) => {
  const post = resolveVisiblePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');

  const likers = db.db.prepare(`
    SELECT u.id, u.username, u.display_name, u.avatar, u.bio, u.created_at
    FROM likes l JOIN users u ON u.id = l.user_id
    WHERE l.post_id = ? ORDER BY l.created_at DESC
  `).all(post.id);

  responseEnvelope(res, likers.map(u => serializeAccount(u, req.apiUser.id)));
});

router.get('/statuses/:id/reblogged_by', requireApiAuth('read'), (req, res) => {
  const post = resolveVisiblePost(parseInt(req.params.id, 10), req.apiUser.id);
  if (!post) return errorResponse(res, 404, 'Not Found', 'Post not found.');

  const reposters = db.db.prepare(`
    SELECT u.id, u.username, u.display_name, u.avatar, u.bio, u.created_at
    FROM posts p JOIN users u ON u.id = p.user_id
    WHERE p.type = 'repost' AND p.repost_of_id = ? ORDER BY p.created_at DESC
  `).all(post.id);

  responseEnvelope(res, reposters.map(u => serializeAccount(u, req.apiUser.id)));
});

function resolveVisiblePost(postId, userId) {
  const post = db.getPostById(postId);
  if (!post) return null;
  const content = post.type === 'repost' && post.repost_of_id
    ? db.getPostById(post.repost_of_id) || post
    : post;
  if (!canView(userId, content.user_id)) return null;
  return content;
}

// ======== Timelines ========

// Mentions-only feed (planned.md F5.4) — cheap, high value for bots.
router.get('/timelines/mentions', requireApiAuth('read'), (req, res) => {
  const posts = db.getMentionsFeed(req.apiUser.id, parseInt(req.query.limit, 10) || 40);
  responseEnvelope(res, posts.map((p) => serializePost(p, {
    id: p.user_id,
    username: p.username,
    display_name: p.display_name,
    avatar: p.avatar,
    bio: p.user_bio || '',
    created_at: p.user_created_at,
  }, req.apiUser.id)));
});

router.get('/timelines/home', requireApiAuth('read'), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 40);
  const cursor = req.query.cursor ? decodeCursor(req.query.cursor) : null;

  const feedResult = feed.buildFeed(req.apiUser.id);

  let items = feedResult.items;
  if (cursor) {
    const cursorIndex = items.findIndex(i => i.id === cursor.id || i.postId === cursor.id);
    if (cursorIndex !== -1) {
      items = items.slice(cursorIndex + 1);
    }
  }
  items = items.slice(0, limit);

  // Batch-fetch counts for all posts in the page
  const postIds = items.map(i => i.interactId || i.id).filter(Boolean);
  const counts = db.batchPostCounts(postIds);

  const results = items.map(item => {
    const post = db.getPostById(item.id);
    if (!post) return null;
    const author = db.getUserById(post.user_id);
    const targetId = item.interactId || post.id;
    return {
      id: String(post.id),
      type: post.type,
      body: post.body || '',
      media_path: post.media_path || null,
      created_at: post.created_at,
      account: author ? serializeAccount(author, req.apiUser.id) : null,
      likes_count: counts.likeMap[targetId] || 0,
      shares_count: counts.shareMap[targetId] || 0,
      comments_count: counts.commentMap[targetId] || 0,
      liked: req.apiUser.id ? db.hasLiked(req.apiUser.id, targetId) : false,
      shared: req.apiUser.id ? db.hasShared(req.apiUser.id, targetId) : false,
      repost_of_id: post.repost_of_id ? String(post.repost_of_id) : null,
      is_own: req.apiUser.id ? req.apiUser.id === post.user_id : false,
    };
  }).filter(Boolean);

  responseEnvelope(res, results, {
    pagination: {
      next: items.length >= limit ? Buffer.from(JSON.stringify({ id: items[items.length - 1].id })).toString('base64url') : null,
    },
  });
});

router.get('/timelines/public', (req, res) => {
  errorResponse(res, 403, 'Forbidden', 'Extrovert does not have a public timeline. Content is network-bound.');
});

// ======== Notifications ========

router.get('/notifications', requireApiAuth('notifications'), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 40);
  const cursor = req.query.cursor ? decodeCursor(req.query.cursor) : null;
  const notifications = db.getNotifications(req.apiUser.id, limit, cursor ? cursor.id : null);

  responseEnvelope(res, notifications.map(n => ({
    id: String(n.id),
    type: n.type,
    created_at: n.created_at,
    read: !!n.read,
    account: serializeAccount({ id: n.actor_id, username: n.actor_username, display_name: n.actor_name, avatar: n.actor_avatar, bio: n.actor_bio || '', created_at: n.actor_created_at }, req.apiUser.id),
    post_id: n.post_id ? String(n.post_id) : null,
  })), {
    pagination: {
      next: makeCursor(notifications),
    },
  });
});

router.post('/notifications/clear', requireApiAuth('notifications'), (req, res) => {
  db.markNotificationsRead(req.apiUser.id);
  res.json({ data: { ok: true } });
});

router.get('/notifications/unread_count', requireApiAuth('notifications'), (req, res) => {
  const count = db.countUnreadNotifications(req.apiUser.id);
  responseEnvelope(res, { count });
});

// SSE notification stream
router.get('/notifications/stream', requireApiAuth('notifications'), (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  res.write('event: connected\ndata: {}\n\n');

  const heartbeat = setInterval(() => {
    res.write(': heartbeat\n\n');
  }, 15000);

  const unsubscribe = onNotification(req.apiUser.id, (notif) => {
    res.write(`event: notification\ndata: ${JSON.stringify(notif)}\n\n`);
  });

  req.on('close', () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
});

// ======== Bots (planned.md F5) ========

// Discord-style: any user creates and owns their bots; admins manage all.
const BOT_LIMIT_PER_USER = Number(process.env.EXTV_BOT_LIMIT_PER_USER) || 10;

function botOwnedByCaller(req, bot) {
  return !!bot && (bot.bot_owner_id === req.apiUser.id || !!req.apiUser.is_admin);
}

// Create a bot account owned by the caller + its first long-lived token. The
// raw token is returned exactly once — only its hash is stored.
router.post('/bots', requireApiAuth('write'), (req, res) => {
  const username = String(req.body.username || '').trim();
  const displayName = String(req.body.display_name || '').trim() || username;
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return errorResponse(res, 400, 'Bad Request', 'username must be 3-20 letters, numbers, or underscores.');
  }
  if (db.countBotsByOwner(req.apiUser.id) >= BOT_LIMIT_PER_USER) {
    return errorResponse(res, 403, 'Forbidden', `Bot limit reached (${BOT_LIMIT_PER_USER}).`);
  }
  if (db.getUserByUsername('%' + username)) return errorResponse(res, 409, 'Conflict', 'That bot name is taken.');
  const botId = db.createBotUser({ username, displayName, ownerId: req.apiUser.id });
  const token = db.generateBotTokenValue();
  const tokenId = db.createBotToken(botId, 'default', token);
  db.auditLog('bot_created', req.apiUser.id, `Bot @${username} (token ${tokenId})`);
  res.status(201).json({
    data: {
      account: serializeAccount(db.getUserById(botId), req.apiUser.id),
      token,
      token_id: String(tokenId),
    },
  });
});

// List your bots (admins see every bot).
router.get('/bots', requireApiAuth('read'), (req, res) => {
  const bots = req.apiUser.is_admin ? db.getAllBots() : db.getBotsByOwner(req.apiUser.id);
  responseEnvelope(res, bots.map((b) => serializeAccount(b, req.apiUser.id)));
});

// Issue an additional long-lived token for a bot you own.
router.post('/bots/:id/tokens', requireApiAuth('write'), (req, res) => {
  const bot = db.getUserById(parseInt(req.params.id, 10));
  if (!bot || !bot.is_bot) return errorResponse(res, 404, 'Not Found', 'Bot not found.');
  if (!botOwnedByCaller(req, bot)) return errorResponse(res, 403, 'Forbidden', 'Not your bot.');
  const token = db.generateBotTokenValue();
  const tokenId = db.createBotToken(bot.id, String(req.body.name || 'default').slice(0, 60), token);
  db.auditLog('bot_token_issued', req.apiUser.id, `Bot @${bot.username} token ${tokenId}`);
  res.status(201).json({ data: { token, token_id: String(tokenId) } });
});

// List a bot's tokens (prefixes only, never the secrets).
router.get('/bots/:id/tokens', requireApiAuth('read'), (req, res) => {
  const bot = db.getUserById(parseInt(req.params.id, 10));
  if (!bot || !bot.is_bot) return errorResponse(res, 404, 'Not Found', 'Bot not found.');
  if (!botOwnedByCaller(req, bot)) return errorResponse(res, 403, 'Forbidden', 'Not your bot.');
  responseEnvelope(res, db.listBotTokens(bot.id).map((t) => ({
    id: String(t.id),
    name: t.name,
    token_prefix: t.token_prefix,
    created_at: t.created_at,
    revoked_at: t.revoked_at,
  })));
});

// Revoke a bot token.
router.delete('/bots/:id/tokens/:tokenId', requireApiAuth('write'), (req, res) => {
  const bot = db.getUserById(parseInt(req.params.id, 10));
  if (!bot || !bot.is_bot) return errorResponse(res, 404, 'Not Found', 'Bot not found.');
  if (!botOwnedByCaller(req, bot)) return errorResponse(res, 403, 'Forbidden', 'Not your bot.');
  const r = db.revokeBotToken(bot.id, parseInt(req.params.tokenId, 10));
  if (!r.changes) return errorResponse(res, 404, 'Not Found', 'Token not found or already revoked.');
  db.auditLog('bot_token_revoked', req.apiUser.id, `Bot @${bot.username} token ${req.params.tokenId}`);
  responseEnvelope(res, { ok: true });
});

// Delete a bot you own (admins: any bot). Tokens, webhook and content go with it.
router.delete('/bots/:id', requireApiAuth('write'), (req, res) => {
  const bot = db.getUserById(parseInt(req.params.id, 10));
  if (!bot || !bot.is_bot) return errorResponse(res, 404, 'Not Found', 'Bot not found.');
  if (!botOwnedByCaller(req, bot)) return errorResponse(res, 403, 'Forbidden', 'Not your bot.');
  db.deleteBot(bot.id);
  db.auditLog('bot_deleted', req.apiUser.id, `Bot @${bot.username}`);
  responseEnvelope(res, { ok: true });
});

// Bot self-service: register a webhook endpoint. The HMAC secret is returned
// exactly once; rotate it with /bots/webhook/rotate if it leaks.
router.post('/bots/webhook', requireApiAuth('write'), (req, res) => {
  if (!req.apiUser.is_bot) return errorResponse(res, 403, 'Forbidden', 'Bot accounts only.');
  const url = String(req.body.url || '').trim();
  if (!/^https?:\/\/.+/i.test(url) || url.length > 500) {
    return errorResponse(res, 400, 'Bad Request', 'url must be a valid http(s) URL.');
  }
  const secret = db.generateBotWebhookSecret();
  db.setBotWebhook(req.apiUser.id, url, secret);
  db.auditLog('bot_webhook_set', req.apiUser.id, url);
  responseEnvelope(res, {
    url,
    secret,
    signature: 'X-Webhook-Signature: hex(HMAC-SHA256(secret, raw_body))',
  });
});

// Bot self-service: rotate the webhook signing secret.
router.post('/bots/webhook/rotate', requireApiAuth('write'), (req, res) => {
  if (!req.apiUser.is_bot) return errorResponse(res, 403, 'Forbidden', 'Bot accounts only.');
  const secret = db.rotateBotWebhookSecret(req.apiUser.id);
  if (!secret) return errorResponse(res, 404, 'Not Found', 'No webhook registered.');
  db.auditLog('bot_webhook_rotated', req.apiUser.id, 'secret rotated');
  responseEnvelope(res, { secret });
});

// Own identity — works for bots and humans alike.
router.get('/bot/me', requireApiAuth('read'), (req, res) => {
  responseEnvelope(res, serializeAccount(req.apiUser, req.apiUser.id));
});

// ======== Media ========

router.post('/media', requireApiAuth('media.write'), upload.single('file'), async (req, res) => {
  if (!req.file) return errorResponse(res, 400, 'Bad Request', 'No file uploaded. Use multipart/form-data with field "file".');

  // Per-account disk quota: reject uploads that would exceed 2 GiB of
  // stored media so a single account can't grow uploads/ without bound.
  const MEDIA_QUOTA_BYTES = 2 * 1024 * 1024 * 1024;
  const existing = db.getUserMediaUsage(req.apiUser.id);
  if (existing + req.file.size > MEDIA_QUOTA_BYTES) {
    try { fs.unlink(req.file.path, () => {}); } catch {}
    return errorResponse(res, 413, 'Payload Too Large', 'Media storage quota exceeded (2 GiB per account).');
  }

  const mimeType = req.file.mimetype;
  const fileSize = req.file.size;
  const filePath = req.file.filename;

  const id = db.createMediaAttachment(req.apiUser.id, filePath, mimeType, fileSize);

  // Read image dimensions with sharp (skip for video).
  if (mimeType.startsWith('image/')) {
    try {
      const metadata = await sharp(req.file.path).metadata();
      if (metadata.width && metadata.height) {
        db.updateMediaAttachmentDimensions(id, metadata.width, metadata.height);
      }
    } catch {}
  }

  db.auditLog('media_uploaded', req.apiUser.id, `Media ${id} (${mimeType}, ${fileSize} bytes)`);

  const media = db.getMediaAttachment(id);

  res.status(201).json({
    data: {
      id: String(id),
      url: `/api-uploads/${filePath}`,
      mime_type: mimeType,
      file_size: fileSize,
      width: media.width,
      height: media.height,
      created_at: Date.now(),
    },
  });
});

router.get('/media/:id', requireApiAuth('read'), (req, res) => {
  const media = db.getMediaAttachment(parseInt(req.params.id, 10));
  if (!media) return errorResponse(res, 404, 'Not Found', 'Media not found.');
  if (media.user_id !== req.apiUser.id) return errorResponse(res, 403, 'Forbidden', 'You do not have access to this media.');

  res.json({
    data: {
      id: String(media.id),
      url: `/api-uploads/${media.file_path}`,
      mime_type: media.mime_type,
      file_size: media.file_size,
      width: media.width,
      height: media.height,
      created_at: media.created_at,
    },
  });
});

// ======== Search ========

router.get('/search', requireApiAuth('read'), (req, res) => {
  const { q, type, limit } = req.query;
  if (!q || String(q).trim().length === 0) return errorResponse(res, 400, 'Bad Request', 'Query parameter "q" is required.');

  const query = String(q).trim();
  const maxResults = Math.min(parseInt(limit, 10) || 20, 40);

  if (type === 'accounts') {
    const users = db.searchUsers(query, { limit: maxResults });
    return responseEnvelope(res, users.map(u => serializeAccount(u, req.apiUser.id)));
  }

  if (type === 'statuses') {
    const posts = db.searchPosts(query, req.apiUser.id, maxResults);
    return responseEnvelope(res, posts.map(p => {
      const author = { id: p.user_id, username: p.username, display_name: p.display_name, avatar: p.avatar, bio: p.user_bio || '', created_at: p.user_created_at };
      return serializePost(p, author, req.apiUser.id);
    }));
  }

  // Default: return both
  const users = db.searchUsers(query, { limit: maxResults });
  const posts = db.searchPosts(query, req.apiUser.id, maxResults);

  responseEnvelope(res, {
    accounts: users.map(u => serializeAccount(u, req.apiUser.id)),
    statuses: posts.map(p => {
      const author = { id: p.user_id, username: p.username, display_name: p.display_name, avatar: p.avatar, bio: p.user_bio || '', created_at: p.user_created_at };
      return serializePost(p, author, req.apiUser.id);
    }),
  });
});

// ----- Calls / Presence -----

router.get('/calls/presence', requireApiAuth(), (req, res) => {
  const users = getOnlineUsers(req.apiUser.id);
  responseEnvelope(res, users);
});

router.get('/calls/presence/:username', requireApiAuth(), (req, res) => {
  // Presence is only visible to mutual followers (matches the list endpoint
  // and WS presence broadcasts); everyone else sees a plain-offline response.
  const other = db.getUserByUsername(req.params.username);
  if (!other || !db.areMutualFollowers(req.apiUser.id, other.id)) {
    return res.json({ online: false, in_call: false });
  }
  const presence = getUserPresence(req.params.username);
  res.json(presence);
});

// ======== Push subscriptions (native/mobile + PWA) ========

router.get('/push/vapid-public', requireApiAuth(), (req, res) => {
  const key = getVapidPublicKey();
  if (!key) return res.status(404).json({ error: 'Push not configured' });
  res.json({ data: { publicKey: key } });
});

router.post('/push/subscribe', requireApiAuth(), async (req, res) => {
  const { platform: rawPlatform, endpoint, p256dh, auth: pushAuth } = req.body || {};
  if (!endpoint) return res.status(400).json({ error: 'endpoint is required' });
  const platform = String(rawPlatform || 'web');
  if (!['web', 'fcm', 'apns', 'ws'].includes(platform)) return res.status(400).json({ error: 'unsupported platform' });
  const check = await validatePushEndpoint(endpoint, platform);
  if (!check.ok) return res.status(400).json({ error: check.reason });
  db.addPushSubscription({
    userId: req.apiUser.id,
    platform,
    endpoint: String(endpoint).trim(),
    p256dh,
    auth: pushAuth,
  });
  res.json({ data: { ok: true } });
});

router.post('/push/unsubscribe', requireApiAuth(), (req, res) => {
  const { endpoint } = req.body || {};
  if (!endpoint) return res.status(400).json({ error: 'endpoint is required' });
  db.removePushSubscription(req.apiUser.id, String(endpoint).trim());
  res.json({ data: { ok: true } });
});

// ======== Rooms ========

const ROOM_PERM = { VIEW: 1, WRITE: 2, MANAGE_CHANNELS: 4, MANAGE_ROLES: 8, MANAGE_MESSAGES: 16, MANAGE_MEMBERS: 32, MANAGE_ROOM: 64 };

router.get('/rooms', requireApiAuth('read'), (req, res) => {
  const myRooms = db.getRoomsForUser(req.apiUser.id);
  const result = myRooms.map(r => ({
    id: String(r.id),
    name: r.name,
    description: r.description || '',
    is_public: !!r.is_public,
    member_count: db.countRoomMembers(r.id),
    is_member: true,
  }));
  responseEnvelope(res, result);
});

// Create room
router.post('/rooms', requireApiAuth('write'), requireVerifiedApiWrite, express.json(), (req, res) => {
  const name = String(req.body.name || '').trim();
  if (!name || name.length > 100) return errorResponse(res, 400, 'Bad Request', 'name is required (max 100 chars).');
  const description = String(req.body.description || '').trim().slice(0, 500);
  const isPublic = req.body.is_public !== false && req.body.is_public !== 'false' && req.body.is_public !== 0;

  const roomId = db.createRoom(name, description, req.apiUser.id, isPublic);
  if (req.body.html || req.body.css) {
    db.updateRoom(roomId, name, description, sanitizeProfileHTML(req.body.html || ''), sanitizeCSS(req.body.css || ''), isPublic);
  }
  const room = db.getRoom(roomId);
  res.status(201).json({
    data: {
      id: String(room.id),
      name: room.name,
      description: room.description || '',
      is_public: !!room.is_public,
      html: room.html || '',
      css: room.css || '',
      is_member: true,
      member_count: 1,
    }
  });
});

// Update room
router.patch('/rooms/:id', requireApiAuth('write'), express.json(), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_ROOM)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission to manage this room.');
  }

  const name = req.body.name !== undefined ? String(req.body.name).trim().slice(0, 100) : room.name;
  if (!name) return errorResponse(res, 400, 'Bad Request', 'name cannot be empty.');
  const description = req.body.description !== undefined ? String(req.body.description).trim().slice(0, 500) : room.description;
  const inputHtml = req.body.html !== undefined ? req.body.html : req.body.custom_html;
  const inputCss = req.body.css !== undefined ? req.body.css : req.body.custom_css;
  const html = inputHtml !== undefined ? sanitizeProfileHTML(inputHtml) : (room.html || '');
  const css = inputCss !== undefined ? sanitizeCSS(inputCss) : (room.css || '');
  const isPublic = req.body.is_public !== undefined ? (req.body.is_public !== false && req.body.is_public !== 'false' && req.body.is_public !== 0) : !!room.is_public;

  db.updateRoom(room.id, name, description, html, css, isPublic);
  const updated = db.getRoom(room.id);
  responseEnvelope(res, {
    id: String(updated.id),
    name: updated.name,
    description: updated.description || '',
    html: updated.html || '',
    css: updated.css || '',
    is_public: !!updated.is_public,
  });
});

// Delete room
router.delete('/rooms/:id', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  const role = db.getUserRoomRole(room.id, req.apiUser.id);
  if (!req.apiUser.is_admin && (!role || !role.is_founder)) {
    return errorResponse(res, 403, 'Forbidden', 'Only the founder can delete this room.');
  }

  db.deleteRoom(room.id);
  responseEnvelope(res, { ok: true });
});

// Join room
router.post('/rooms/:id/join', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (db.isRoomMember(room.id, req.apiUser.id)) {
    return responseEnvelope(res, { ok: true, already_member: true });
  }
  if (!room.is_public && !req.apiUser.is_admin) {
    return errorResponse(res, 403, 'Forbidden', 'This room is private.');
  }

  const defaultRole = db.joinDefaultRole(room.id);
  if (defaultRole) db.addRoomMember(room.id, req.apiUser.id, defaultRole.id);
  updateUserRoomSubscriptions(req.apiUser.id, room.id, 'join');
  broadcastGatewayEvent(`room:${room.id}`, 'member_join', {
    room_id: String(room.id),
    user_id: String(req.apiUser.id),
    username: req.apiUser.username,
    display_name: req.apiUser.display_name,
  });
  responseEnvelope(res, { ok: true, status: 'joined' });
});

// Leave room
router.post('/rooms/:id/leave', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  const role = db.getUserRoomRole(room.id, req.apiUser.id);
  if (!role) return errorResponse(res, 400, 'Bad Request', 'Not a member of this room.');

  if (role.is_founder) {
    const members = db.getRoomMembers(room.id);
    const others = members.filter(m => m.user_id !== req.apiUser.id);
    if (others.length === 0) {
      db.deleteRoom(room.id);
      return responseEnvelope(res, { ok: true, room_deleted: true });
    }
    return errorResponse(res, 400, 'Bad Request', 'Founder must transfer ownership before leaving.');
  }

  db.removeRoomMember(room.id, req.apiUser.id);
  updateUserRoomSubscriptions(req.apiUser.id, room.id, 'leave');
  broadcastGatewayEvent(`room:${room.id}`, 'member_leave', {
    room_id: String(room.id),
    user_id: String(req.apiUser.id),
    username: req.apiUser.username,
  });
  responseEnvelope(res, { ok: true });
});

// Create channel
router.post('/rooms/:id/channels', requireApiAuth('write'), express.json(), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_CHANNELS)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission to manage channels.');
  }
  const name = String(req.body.name || '').trim();
  if (!name || name.length > 50) return errorResponse(res, 400, 'Bad Request', 'name is required (max 50 chars).');
  const type = String(req.body.type || 'text').trim() === 'voice' ? 'voice' : 'text';
  const viewRoles = Array.isArray(req.body.view_roles) ? JSON.stringify(req.body.view_roles.map(Number)) : null;
  const writeRoles = Array.isArray(req.body.write_roles) ? JSON.stringify(req.body.write_roles.map(Number)) : null;

  const cid = db.createRoomChannel(room.id, name, viewRoles, writeRoles, type);
  res.status(201).json({
    data: {
      id: String(cid),
      room_id: String(room.id),
      name,
      type,
    }
  });
});

// Update channel
router.patch('/rooms/:id/channels/:cid', requireApiAuth('write'), express.json(), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_CHANNELS)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission to manage channels.');
  }
  const channel = db.getRoomChannel(parseInt(req.params.cid, 10));
  if (!channel || channel.room_id !== room.id) return errorResponse(res, 404, 'Not Found', 'Channel not found.');

  const name = req.body.name !== undefined ? String(req.body.name).trim().slice(0, 50) : channel.name;
  if (!name) return errorResponse(res, 400, 'Bad Request', 'name cannot be empty.');
  const viewRoles = req.body.view_roles !== undefined ? (Array.isArray(req.body.view_roles) ? JSON.stringify(req.body.view_roles.map(Number)) : null) : channel.view_role_ids;
  const writeRoles = req.body.write_roles !== undefined ? (Array.isArray(req.body.write_roles) ? JSON.stringify(req.body.write_roles.map(Number)) : null) : channel.write_role_ids;
  const type = req.body.type !== undefined ? (String(req.body.type).trim() === 'voice' ? 'voice' : 'text') : channel.type;

  db.updateRoomChannel(channel.id, name, viewRoles, writeRoles, type);
  responseEnvelope(res, {
    id: String(channel.id),
    room_id: String(room.id),
    name,
    type,
  });
});

// Delete channel
router.delete('/rooms/:id/channels/:cid', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_CHANNELS)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission to manage channels.');
  }
  const channel = db.getRoomChannel(parseInt(req.params.cid, 10));
  if (!channel || channel.room_id !== room.id) return errorResponse(res, 404, 'Not Found', 'Channel not found.');

  db.deleteRoomChannel(channel.id);
  responseEnvelope(res, { ok: true });
});

// List room roles
router.get('/rooms/:id/roles', requireApiAuth('read'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  const roles = db.getRoomRoles(room.id);
  responseEnvelope(res, roles.map(r => ({
    id: String(r.id),
    name: r.name,
    color: r.color,
    permissions: r.permissions,
    is_founder: !!r.is_founder,
    position: r.position,
  })));
});

// Create role
router.post('/rooms/:id/roles', requireApiAuth('write'), express.json(), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_ROLES)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission to manage roles.');
  }
  const name = String(req.body.name || '').trim();
  if (!name || name.length > 50) return errorResponse(res, 400, 'Bad Request', 'name is required (max 50 chars).');
  const color = /^#[0-9a-fA-F]{6}$/.test(String(req.body.color || '').trim()) ? String(req.body.color).trim() : '#cccccc';
  const permissions = Number(req.body.permissions) || 0;

  const rid = db.createRoomRole(room.id, name, color, permissions, 0);
  res.status(201).json({
    data: {
      id: String(rid),
      name,
      color,
      permissions,
      is_founder: false,
    }
  });
});

// Update role
router.patch('/rooms/:id/roles/:rid', requireApiAuth('write'), express.json(), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_ROLES)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission to manage roles.');
  }
  const role = db.getRoomRole(parseInt(req.params.rid, 10));
  if (!role || role.room_id !== room.id) return errorResponse(res, 404, 'Not Found', 'Role not found.');
  if (role.is_founder) return errorResponse(res, 400, 'Bad Request', 'Cannot edit founder role.');

  const name = req.body.name !== undefined ? String(req.body.name).trim().slice(0, 50) : role.name;
  if (!name) return errorResponse(res, 400, 'Bad Request', 'name cannot be empty.');
  const color = req.body.color !== undefined && /^#[0-9a-fA-F]{6}$/.test(String(req.body.color).trim()) ? String(req.body.color).trim() : role.color;
  const permissions = req.body.permissions !== undefined ? Number(req.body.permissions) : role.permissions;

  db.updateRoomRole(role.id, name, color, permissions);
  responseEnvelope(res, {
    id: String(role.id),
    name,
    color,
    permissions,
    is_founder: false,
  });
});

// Delete role
router.delete('/rooms/:id/roles/:rid', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_ROLES)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission to manage roles.');
  }
  const role = db.getRoomRole(parseInt(req.params.rid, 10));
  if (!role || role.room_id !== room.id) return errorResponse(res, 404, 'Not Found', 'Role not found.');
  if (!db.deleteRoomRole(role.id)) return errorResponse(res, 400, 'Bad Request', 'Cannot delete founder role.');
  responseEnvelope(res, { ok: true });
});

// Assign role to member
router.post('/rooms/:id/members/:uid/roles', requireApiAuth('write'), express.json(), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_MEMBERS)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission to manage members.');
  }
  const roleId = Number(req.body.role_id);
  const targetUser = db.getUserById(parseInt(req.params.uid, 10));
  if (!targetUser) return errorResponse(res, 404, 'Not Found', 'User not found.');
  const targetRole = db.getRoomRole(roleId);
  if (!targetRole || targetRole.room_id !== room.id) return errorResponse(res, 404, 'Not Found', 'Role not found.');
  if (targetRole.is_founder) return errorResponse(res, 400, 'Bad Request', 'Cannot assign founder role.');
  const currentMemberRole = db.getUserRoomRole(room.id, targetUser.id);
  if (currentMemberRole && currentMemberRole.is_founder) return errorResponse(res, 400, 'Bad Request', 'Cannot change founder role.');

  db.db.prepare(`UPDATE room_members SET role_id = ? WHERE room_id = ? AND user_id = ?`).run(roleId, room.id, targetUser.id);
  responseEnvelope(res, { ok: true });
});

// Kick member
router.post('/rooms/:id/members/:uid/kick', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_MEMBERS)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission to manage members.');
  }
  const targetUser = db.getUserById(parseInt(req.params.uid, 10));
  if (!targetUser) return errorResponse(res, 404, 'Not Found', 'User not found.');
  const currentMemberRole = db.getUserRoomRole(room.id, targetUser.id);
  if (currentMemberRole && currentMemberRole.is_founder) return errorResponse(res, 400, 'Bad Request', 'Cannot kick founder.');

  db.removeRoomMember(room.id, targetUser.id);
  broadcastGatewayEvent(`room:${room.id}`, 'member_leave', {
    room_id: String(room.id),
    user_id: String(targetUser.id),
    username: targetUser.username,
  });
  responseEnvelope(res, { ok: true });
});

// Transfer founder
router.post('/rooms/:id/transfer', requireApiAuth('write'), express.json(), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  const myRole = db.getUserRoomRole(room.id, req.apiUser.id);
  if (!myRole || !myRole.is_founder) return errorResponse(res, 403, 'Forbidden', 'Only founder can transfer ownership.');
  const newOwnerId = Number(req.body.user_id);
  if (!newOwnerId) return errorResponse(res, 400, 'Bad Request', 'user_id is required.');
  if (!db.isRoomMember(room.id, newOwnerId)) return errorResponse(res, 400, 'Bad Request', 'Target user is not a member.');

  db.transferFounder(room.id, newOwnerId);
  const defaultRole = db.joinDefaultRole(room.id);
  if (defaultRole) {
    db.db.prepare(`UPDATE room_members SET role_id = ? WHERE room_id = ? AND user_id = ?`).run(defaultRole.id, room.id, req.apiUser.id);
  }
  responseEnvelope(res, { ok: true });
});

// List join requests
router.get('/rooms/:id/requests', requireApiAuth('read'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_MEMBERS)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission.');
  }
  const requests = db.getJoinRequests(room.id);
  responseEnvelope(res, requests.map(r => ({
    id: String(r.id),
    user_id: String(r.user_id),
    username: r.username,
    display_name: r.display_name,
    avatar: r.avatar,
    created_at: r.created_at,
  })));
});

// Approve join request
router.post('/rooms/:id/requests/:reqId/approve', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_MEMBERS)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission.');
  }
  const jreq = db.getJoinRequestById(parseInt(req.params.reqId, 10));
  if (!jreq || jreq.room_id !== room.id) return errorResponse(res, 404, 'Not Found', 'Request not found.');

  db.approveJoinRequest(jreq.id);
  broadcastGatewayEvent(`room:${room.id}`, 'member_join', {
    room_id: String(room.id),
    user_id: String(jreq.user_id),
    username: jreq.username,
  });
  responseEnvelope(res, { ok: true });
});

// Reject join request
router.post('/rooms/:id/requests/:reqId/reject', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_MEMBERS)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission.');
  }
  const jreq = db.getJoinRequestById(parseInt(req.params.reqId, 10));
  if (!jreq || jreq.room_id !== room.id) return errorResponse(res, 404, 'Not Found', 'Request not found.');

  db.rejectJoinRequest(jreq.id);
  responseEnvelope(res, { ok: true });
});

// Invite user
router.post('/rooms/:id/invite', requireApiAuth('write'), express.json(), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.hasRoomPermission(room.id, req.apiUser.id, ROOM_PERM.MANAGE_MEMBERS)) {
    return errorResponse(res, 403, 'Forbidden', 'No permission.');
  }
  const username = String(req.body.username || '').trim().toLowerCase();
  if (!username) return errorResponse(res, 400, 'Bad Request', 'username is required.');
  const target = db.getUserByUsername(username);
  if (!target) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (db.isRoomMember(room.id, target.id)) return errorResponse(res, 409, 'Conflict', 'Already a member.');

  const defaultRole = db.joinDefaultRole(room.id);
  if (defaultRole) db.addRoomMember(room.id, target.id, defaultRole.id);
  broadcastGatewayEvent(`room:${room.id}`, 'member_join', {
    room_id: String(room.id),
    user_id: String(target.id),
    username: target.username,
  });
  responseEnvelope(res, { ok: true });
});

router.get('/rooms/:id', requireApiAuth('read'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  const isMember = db.isRoomMember(room.id, req.apiUser.id);
  if (!room.is_public && !isMember && !req.apiUser.is_admin) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!isMember && !req.apiUser.is_admin) {
    // Public room, non-member: limited profile only — no member roster,
    // no channels, no custom html/css.
    return responseEnvelope(res, {
      id: String(room.id),
      name: room.name,
      description: room.description || '',
      is_public: true,
      is_member: false,
      member_count: db.countRoomMembers(room.id),
    });
  }
  const channels = db.getRoomChannels(room.id).map(c => ({
    id: String(c.id),
    name: c.name,
    type: c.type || 'text',
  }));
  const members = db.getRoomMembers(room.id).map(m => ({
    id: String(m.user_id),
    username: m.username,
    display_name: m.display_name,
    avatar: m.avatar || null,
  }));
  responseEnvelope(res, {
    id: String(room.id),
    name: room.name,
    description: room.description || '',
    html: room.html || '',
    css: room.css || '',
    is_public: !!room.is_public,
    is_member: isMember,
    channels,
    members,
  });
});

router.get('/rooms/:id/channels/:cid/messages', requireApiAuth('read'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id)) return errorResponse(res, 403, 'Forbidden', 'Not a member.');
  const channel = db.getRoomChannel(parseInt(req.params.cid, 10));
  if (!channel || channel.room_id !== room.id) return errorResponse(res, 404, 'Not Found', 'Channel not found.');
  // Per-channel view restriction — mirrors the web route's semantics: a null
  // or unparseable view_role_ids column means open to all members.
  const role = db.getUserRoomRole(room.id, req.apiUser.id);
  if (channel.view_role_ids) {
    try {
      const viewRoles = JSON.parse(channel.view_role_ids);
      if (Array.isArray(viewRoles) && !viewRoles.includes(role.id)) return errorResponse(res, 403, 'Forbidden', 'No view permission.');
    } catch {}
  }

  const cursor = req.query.cursor ? parseInt(req.query.cursor, 10) : null;

  const messages = db.getRoomMessages(channel.id, cursor);
  const next = messages.length >= 50 ? String(messages[messages.length - 1].id) : null;

  responseEnvelope(res, {
    messages: messages.map(m => ({
      id: String(m.id),
      user_id: String(m.user_id),
      username: m.username,
      display_name: m.display_name,
      avatar: m.avatar || null,
      body: m.body,
      proto: m.proto,
      ciphertext: m.ciphertext,
      group_session_id: m.group_session_id,
      created_at: m.created_at,
      edited_at: m.edited_at || null,
    })),
    next,
  });
});

router.post('/rooms/:id/channels/:cid/messages', requireApiAuth('write'), requireVerifiedApiWrite, (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id)) return errorResponse(res, 403, 'Forbidden', 'Not a member.');
  const channel = db.getRoomChannel(parseInt(req.params.cid, 10));
  if (!channel || channel.room_id !== room.id) return errorResponse(res, 404, 'Not Found', 'Channel not found.');

  // Per-channel write restriction — mirrors the web route's semantics: a null
  // or unparseable write_role_ids column means open to all members.
  const role = db.getUserRoomRole(room.id, req.apiUser.id);
  if (channel.write_role_ids) {
    try {
      const writeRoles = JSON.parse(channel.write_role_ids);
      if (Array.isArray(writeRoles) && !writeRoles.includes(role.id)) return errorResponse(res, 403, 'Forbidden', 'No write permission.');
    } catch {}
  }

  const body = String(req.body.body || '').trim();
  const rawProto = String(req.body.proto || '').trim();
  const ciphertextRaw = String(req.body.ciphertext || '').trim();
  const isSticker = body.startsWith('/uploads/stickers/');
  if (!isSticker) {
    if (!ciphertextRaw) return errorResponse(res, 400, 'Bad Request', 'ciphertext is required.');
    if (ciphertextRaw.length > 20000) {
      return errorResponse(res, 400, 'Bad Request', 'Message is too long.');
    }
    if (rawProto !== 'mls') {
      return errorResponse(res, 426, 'Upgrade Required', 'LegacyProtocolRetired: Extrovert has upgraded to MLS encryption (RFC 9420). Please refresh your client.');
    }
  }
  const ciphertext = ciphertextRaw || null;

  const msgId = db.sendRoomMessage(channel.id, req.apiUser.id, isSticker ? body : '', 'mls', ciphertext, null);

  const clientId = req.body.client_id || req.body.nonce || req.body.client_tx_id;
  const msgData = {
    id: String(msgId),
    room_id: String(room.id),
    channel_id: String(channel.id),
    user_id: String(req.apiUser.id),
    author: {
      id: String(req.apiUser.id),
      username: req.apiUser.username,
      display_name: req.apiUser.display_name,
    },
    proto: isSticker ? 'plain' : proto,
    body: isSticker ? body : '',
    ciphertext: isSticker ? null : ciphertext,
    group_session_id: isSticker ? null : groupSessionId,
    created_at: new Date().toISOString(),
  };
  if (clientId) msgData.client_id = String(clientId);
  broadcastGatewayEvent('room:' + room.id, 'message_create', msgData);

  res.status(201).json({ data: msgData });
});

router.delete('/rooms/:id/channels/:cid/messages/:mid', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id) && !req.apiUser.is_admin) return errorResponse(res, 403, 'Forbidden', 'Not a member.');
  const channel = db.getRoomChannel(parseInt(req.params.cid, 10));
  if (!channel || channel.room_id !== room.id) return errorResponse(res, 404, 'Not Found', 'Channel not found.');
  // Per-channel view restriction — mirrors the web route's semantics.
  const deleterRole = db.getUserRoomRole(room.id, req.apiUser.id);
  if (channel.view_role_ids) {
    try {
      const viewRoles = JSON.parse(channel.view_role_ids);
      if (Array.isArray(viewRoles) && !viewRoles.includes(deleterRole.id)) return errorResponse(res, 403, 'Forbidden', 'No view permission.');
    } catch {}
  }
  const msgId = parseInt(req.params.mid, 10);
  const msgs = db.getRoomMessages(channel.id);
  const msg = msgs.find(m => m.id === msgId);
  if (!msg) return errorResponse(res, 404, 'Not Found', 'Message not found.');
  const canDeleteOwn = msg.user_id === req.apiUser.id;
  const canModerate = db.hasRoomPermission(room.id, req.apiUser.id, 16); // 16 = PERM.MANAGE_MESSAGES
  if (!canDeleteOwn && !canModerate && !req.apiUser.is_admin) return errorResponse(res, 403, 'Forbidden', 'No permission.');
  db.deleteRoomMessage(msgId);
  db.auditLog('room_message_deleted', req.apiUser.id, `Room ${room.id} Message ${msgId}`);
  broadcastGatewayEvent('room:' + room.id, 'message_delete', {
    id: String(msgId),
    room_id: String(room.id),
    channel_id: String(channel.id),
  });
  res.json({ data: { ok: true } });
});

// Publish / refresh the caller's Megolm group session for a room + encrypted keys.
router.post('/rooms/:id/session', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id)) return errorResponse(res, 403, 'Forbidden', 'Not a member.');
  const keys = Array.isArray(req.body.keys) ? req.body.keys : [];
  const memberIds = Array.isArray(req.body.member_ids) ? req.body.member_ids.map(Number) : [];
  const rotate = req.body.rotate === true || req.body.rotate === 'true';
  const senderDeviceId = String(req.body.sender_device_id || '').trim().slice(0, 100);
  const sessionId = db.publishRoomGroupSession(room.id, req.apiUser.id, senderDeviceId, rotate);
  const roomMembers = new Set(db.getRoomMembers(room.id).map(m => m.user_id));
  for (const k of keys) {
    const rid = Number(k.recipient_id);
    const ek = String(k.encrypted_key || '').trim();
    if (!rid || !ek || ek.length > 200000) continue;
    if (!roomMembers.has(rid)) continue;
    const keyId = db.saveRoomSessionKeys(sessionId, rid, ek);
    pushRoomSessionKeyToRecipient(rid, {
      key_id: keyId,
      session_id: sessionId,
      room_id: String(room.id),
      sender_id: String(req.apiUser.id),
      sender_username: req.apiUser.username,
      encrypted_key: ek,
    });
  }
  for (const mid of memberIds) {
    if (roomMembers.has(mid)) db.ensureRoomSessionRecipient(sessionId, mid);
  }
  responseEnvelope(res, { session_id: sessionId });
});

// Unified Room Session Sync: atomically distribute new keys, fetch incoming pending keys,
// acknowledge delivered keys, and identify unkeyed room members in one round-trip.
router.post('/rooms/:id/session/sync', requireApiAuth('write'), express.json(), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id)) return errorResponse(res, 403, 'Forbidden', 'Not a member.');

  const rotate = req.body.rotate === true || req.body.rotate === 'true';
  const senderDeviceId = String(req.body.sender_device_id || '').trim().slice(0, 100);

  // 1. Process incoming ACKs
  const ackKeyIds = Array.isArray(req.body.ack_key_ids) ? req.body.ack_key_ids.map(Number) : [];
  for (const id of ackKeyIds) {
    const key = db.getRoomSessionKeyById(id);
    if (key && key.recipient_id === req.apiUser.id && key.room_id === room.id) {
      db.markRoomSessionKeyDelivered(id);
    }
  }

  // 2. Resolve caller's active outbound session
  let sessionId = null;
  if (rotate) {
    sessionId = db.publishRoomGroupSession(room.id, req.apiUser.id, senderDeviceId, true);
  } else {
    const existing = db.getRoomGroupSession(room.id, req.apiUser.id, senderDeviceId);
    if (existing) {
      sessionId = existing.id;
    } else {
      sessionId = db.publishRoomGroupSession(room.id, req.apiUser.id, senderDeviceId, false);
    }
  }

  // 3. Save new encrypted keys published by caller and push in realtime
  const keys = Array.isArray(req.body.keys) ? req.body.keys : [];
  const memberIds = Array.isArray(req.body.member_ids) ? req.body.member_ids.map(Number) : [];
  const roomMembers = new Set(db.getRoomMembers(room.id).map(m => m.user_id));
  for (const k of keys) {
    const rid = Number(k.recipient_id);
    const ek = String(k.encrypted_key || '').trim();
    if (!rid || !ek || ek.length > 200000) continue;
    if (!roomMembers.has(rid)) continue;
    const keyId = db.saveRoomSessionKeys(sessionId, rid, ek);
    pushRoomSessionKeyToRecipient(rid, {
      key_id: keyId,
      session_id: sessionId,
      room_id: String(room.id),
      sender_id: String(req.apiUser.id),
      sender_username: req.apiUser.username,
      encrypted_key: ek,
    });
  }
  for (const mid of memberIds) {
    if (roomMembers.has(mid)) db.ensureRoomSessionRecipient(sessionId, mid);
  }

  // 4. Fetch caller's pending keys for this room
  const pendingKeys = db.getPendingRoomSessionKeys(req.apiUser.id)
    .filter(k => k.room_id === room.id)
    .map(k => ({
      key_id: k.key_id,
      session_id: k.session_id,
      room_id: String(k.room_id),
      sender_id: String(k.sender_id),
      encrypted_key: k.encrypted_key,
    }));

  // 5. Compute missing members who need the caller's active session key
  const recipients = new Set(db.getRoomSessionRecipients(sessionId));
  const emptyRecipients = new Set(db.getRoomSessionEmptyKeyRecipients(sessionId));
  const allMembers = db.getRoomMembers(room.id);
  const missingMembers = [];
  for (const m of allMembers) {
    if (m.user_id === req.apiUser.id) continue;
    if (!recipients.has(m.user_id) || emptyRecipients.has(m.user_id)) {
      missingMembers.push({
        id: String(m.user_id),
        username: m.username,
        display_name: m.display_name,
      });
    }
  }

  responseEnvelope(res, {
    room_id: String(room.id),
    active_session_id: sessionId,
    pending_keys: pendingKeys,
    missing_members: missingMembers,
    recipients_count: Math.max(0, recipients.size - emptyRecipients.size),
  });
});

// Pending Megolm session keys for the caller.
router.get('/rooms/:id/session/keys', requireApiAuth('read'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id)) return errorResponse(res, 403, 'Forbidden', 'Not a member.');
  const keys = db.getPendingRoomSessionKeys(req.apiUser.id)
    .filter(k => k.room_id === room.id)
    .map(k => ({
      key_id: k.key_id, session_id: k.session_id, room_id: k.room_id, sender_id: k.sender_id, encrypted_key: k.encrypted_key,
    }));
  responseEnvelope(res, { keys });
});

// Mark delivered session keys as received.
router.post('/rooms/:id/session/keys/delivered', requireApiAuth('write'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id)) return errorResponse(res, 403, 'Forbidden', 'Not a member.');
  const ids = Array.isArray(req.body.key_ids) ? req.body.key_ids.map(Number) : [];
  // Only keys actually addressed to this caller in THIS room may be marked
  // delivered; silently skip everything else (unknown ids behave the same).
  for (const id of ids) {
    const key = db.getRoomSessionKeyById(id);
    if (key && key.recipient_id === req.apiUser.id && key.room_id === room.id) {
      db.markRoomSessionKeyDelivered(id);
    }
  }
  responseEnvelope(res, { ok: true });
});

// Which members hold the caller's session keys.
router.get('/rooms/:id/session/status', requireApiAuth('read'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id)) return errorResponse(res, 403, 'Forbidden', 'Not a member.');
  const deviceId = String(req.query.device_id || '').trim().slice(0, 100);
  const gs = db.getRoomGroupSession(room.id, req.apiUser.id, deviceId);
  if (!gs) return responseEnvelope(res, { session_id: null, recipients: [], empty_keys_for: [] });
  responseEnvelope(res, { session_id: gs.id, recipients: db.getRoomSessionRecipients(gs.id), empty_keys_for: db.getRoomSessionEmptyKeyRecipients(gs.id) });
});

// Batch prekey bundles for room members (optionally filtered by members missing active session key)
router.get('/rooms/:id/bundles', requireApiAuth('read'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id)) return errorResponse(res, 403, 'Forbidden', 'Not a member.');

  const missingForSession = String(req.query.missing_for_session || '').trim();
  let existingRecipients = new Set();
  if (missingForSession) {
    existingRecipients = new Set(db.getRoomSessionRecipients(missingForSession));
    const emptyKeys = new Set(db.getRoomSessionEmptyKeyRecipients(missingForSession));
    for (const emptyId of emptyKeys) {
      existingRecipients.delete(emptyId);
    }
  }

  const claim = req.query.claim === '1' || req.query.claim === 'true';
  const bundlesFor = claim ? db.claimAllDevicePrekeysForUser : db.getAllDeviceBundlesForUser;
  const members = db.getRoomMembers(room.id);
  const bundles = [];

  for (const m of members) {
    if (m.user_id === req.apiUser.id) continue;
    if (missingForSession && existingRecipients.has(m.user_id)) continue;

    const recipientDevices = bundlesFor(m.user_id);
    if (!recipientDevices || !recipientDevices.length) continue;
    const primary = recipientDevices[0];
    const otk = typeof primary.one_time_key === 'object' && primary.one_time_key ? primary.one_time_key.public_key : primary.one_time_key;
    const otkid = typeof primary.one_time_key === 'object' && primary.one_time_key ? primary.one_time_key.id : primary.one_time_key_id;
    bundles.push({
      user_id: String(m.user_id),
      username: m.username,
      display_name: m.display_name,
      identity_key: primary.identity_key,
      one_time_key: otk,
      one_time_key_id: otkid,
      identity_keys: primary.identity_keys,
      device_id: primary.device_id,
      devices: recipientDevices,
    });
  }

  responseEnvelope(res, {
    room_id: String(room.id),
    total_members: members.length,
    returned_bundles: bundles.length,
    bundles,
  });
});

// Room-scoped prekey bundle (no mutual-follower requirement). READ-ONLY: the
// one_time_key is an unclaimed preview (?claim=1 keeps the legacy behavior).
router.get('/rooms/:id/bundle/:username', requireApiAuth('read'), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id)) return errorResponse(res, 403, 'Forbidden', 'Not a member.');
  const other = db.getUserByUsername(req.params.username);
  if (!other) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (!db.isRoomMember(room.id, other.id)) return errorResponse(res, 403, 'Forbidden', 'Target is not a member.');
  const bundlesFor = req.query.claim === '1' ? db.claimAllDevicePrekeysForUser : db.getAllDeviceBundlesForUser;
  const recipientDevices = bundlesFor(other.id);
  const primary = recipientDevices[0] || null;
  if (!primary) return errorResponse(res, 404, 'Not Found', 'Target has no encryption keys.');
  responseEnvelope(res, {
    devices: recipientDevices,
    identity_key: primary.identity_key,
    ed25519_key: primary.ed25519_key,
    fallback_key: primary.fallback_key,
    one_time_key: primary.one_time_key
  });
});

// Claim one one-time prekey per listed device of a room member (session-key
// wrapping establishes a new 1:1 session).
router.post('/rooms/:id/claim/:username', requireApiAuth('write'), express.json(), (req, res) => {
  const room = db.getRoom(parseInt(req.params.id, 10));
  if (!room) return errorResponse(res, 404, 'Not Found', 'Room not found.');
  if (!db.isRoomMember(room.id, req.apiUser.id)) return errorResponse(res, 403, 'Forbidden', 'Not a member.');
  const other = db.getUserByUsername(req.params.username);
  if (!other) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (!db.isRoomMember(room.id, other.id)) return errorResponse(res, 403, 'Forbidden', 'Target is not a member.');
  const deviceIds = Array.isArray(req.body.device_ids)
    ? [...new Set(req.body.device_ids.map(x => String(x || '').trim()).filter(Boolean))].slice(0, 50)
    : null;
  const devices = deviceIds ? db.claimAllDevicePrekeysForUser(other.id, deviceIds) : [];
  responseEnvelope(res, { devices });
});

// ======== Announcement ========

// Server-wide announcement (if one is set) — shown as a banner in clients.
router.get('/announcement', requireApiAuth('read'), (req, res) => {
  const a = db.getAnnouncement();
  if (!a || !a.body) return responseEnvelope(res, null);
  responseEnvelope(res, {
    body: a.body,
    author_display_name: a.author_display_name,
    author_username: a.author_username,
    updated_at: a.updated_at || null,
  });
});

// ======== Direct Messages (E2E) ========

// List conversations
router.get('/conversations', requireApiAuth('read:direct'), (req, res) => {
  const conversations = dm.getConversations(req.apiUser.id);
  const filtered = conversations.filter(c => db.areMutualFollowers(req.apiUser.id, c.id));
  responseEnvelope(res, filtered.map(c => {
    const id = db.getOlmIdentity(c.id);
    return {
      id: String(c.id),
      username: c.username,
      display_name: c.display_name,
      avatar: c.avatar,
      last_id: c.last_id != null ? String(c.last_id) : null,
      last_message: c.last_message,
      last_at: c.last_at,
      unread: c.unread,
      last_from: c.last_from != null ? String(c.last_from) : null,
      last_proto: c.last_proto,
      last_key_for_sender: c.last_key_for_sender,
      last_key_for_recipient: c.last_key_for_recipient,
      last_sender_ciphertext: c.last_sender_ciphertext,
      sender_curve: id ? id.identity_key : null,
      security_active: dm.getDmSecurity(req.apiUser.id, c.id).active,
    };
  }));
});

// Fetch my own keys (must be before :username routes)
router.get('/conversations/keys', requireApiAuth('read:direct'), (req, res) => {
  const publicKey = dm.getPublicKey(req.apiUser.id);
  const encryptedPrivateKey = dm.getEncryptedPrivateKey(req.apiUser.id);
  responseEnvelope(res, { public_key: publicKey, encrypted_private_key: encryptedPrivateKey });
});

// Publish / rotate your keys (must be before :username routes)
router.post('/conversations/keys', requireApiAuth('write:direct'), (req, res) => {
  const publicKey = String(req.body.public_key || '').trim();
  const encryptedPrivateKey = String(req.body.encrypted_private_key || '').trim() || null;
  if (!publicKey || publicKey.length > 5000) {
    return errorResponse(res, 400, 'Bad Request', 'public_key is required and must be <= 5000 chars.');
  }
  dm.setPublicKey(req.apiUser.id, publicKey, encryptedPrivateKey);
  db.auditLog('dm_key_updated', req.apiUser.id, 'Published public key');
  res.json({ data: { ok: true } });
});

// Publish / refresh Olm identity + prekey bundle (supports per-device multi-ID). (must be before :username routes)
router.post('/conversations/prekeys', requireApiAuth('write:direct'), express.json({ limit: '10mb' }), (req, res) => {
  const deviceId = String(req.body.device_id || '').trim();
  const identityKey = String(req.body.identity_key || '').trim();
  const ed25519Key = String(req.body.ed25519_key || '').trim();
  const fallbackKey = String(req.body.fallback_key || '').trim() || null;
  const deviceName = String(req.body.device_name || '').trim() || null;
  const oneTimeKeys = Array.isArray(req.body.one_time_keys) ? req.body.one_time_keys : [];
  const backup = String(req.body.backup || '').trim().slice(0, 8000000) || null;

  if (deviceId && identityKey && ed25519Key) {
    db.registerUserDevice(req.apiUser.id, deviceId, identityKey, ed25519Key, fallbackKey, deviceName);
    if (oneTimeKeys.length) {
      const clean = oneTimeKeys
        .filter(k => k && k.id && k.public_key && String(k.public_key).length <= 5000)
        .map(k => ({ id: String(k.id), public_key: String(k.public_key) }));
      if (clean.length) db.addDevicePrekeys(req.apiUser.id, deviceId, clean);
    }
  } else if (identityKey) {
    if (!ed25519Key || identityKey.length > 5000 || ed25519Key.length > 5000) {
      return errorResponse(res, 400, 'Bad Request', 'identity_key and ed25519_key are required (<=5000 chars).');
    }
    db.setOlmIdentity(req.apiUser.id, identityKey, ed25519Key, fallbackKey);
    if (oneTimeKeys.length) {
      const clean = oneTimeKeys
        .filter(k => k && k.id && k.public_key && String(k.public_key).length <= 5000)
        .map(k => ({ id: String(k.id), public_key: String(k.public_key) }));
      if (clean.length) db.addOlmPrekeys(req.apiUser.id, clean);
    }
  }

  if (backup) {
    const backupIdentity = String(req.body.backup_identity || '').trim() || null;
    const kekSalt = String(req.body.kek_salt || '').trim().slice(0, 200) || null;
    db.setOlmBackup(req.apiUser.id, backup, backupIdentity, kekSalt);
  }
  db.auditLog('dm_olm_keys', req.apiUser.id, 'Published Olm identity + prekeys');
  const avail = deviceId ? db.countAvailableDevicePrekeys(req.apiUser.id, deviceId) : db.countAvailablePrekeys(req.apiUser.id);
  responseEnvelope(res, { ok: true, available: avail, device_id: deviceId || undefined });
});

// List user devices (before :username)
router.get('/conversations/devices', requireApiAuth('read:direct'), (req, res) => {
  responseEnvelope(res, { devices: db.getUserDevices(req.apiUser.id) });
});

// Revoke a user device (before :username)
router.delete('/conversations/devices/:deviceId', requireApiAuth('write:direct'), (req, res) => {
  db.deleteUserDevice(req.apiUser.id, req.params.deviceId);
  responseEnvelope(res, { ok: true });
});

// Upload password-encrypted history backup (before :username)
router.post('/conversations/history/backup', requireApiAuth('write:direct'), express.json({ limit: '10mb' }), (req, res) => {
  const backupData = String(req.body.backup_data || '').trim();
  if (!backupData) return errorResponse(res, 400, 'Bad Request', 'backup_data is required.');
  db.setUserHistoryBackup(req.apiUser.id, backupData);
  responseEnvelope(res, { ok: true });
});

// Download password-encrypted history backup (before :username)
router.get('/conversations/history/backup', requireApiAuth('read:direct'), (req, res) => {
  const backup = db.getUserHistoryBackup(req.apiUser.id);
  responseEnvelope(res, { backup_data: backup ? backup.backup_data : null, updated_at: backup ? backup.updated_at : null });
});

// Download the password-encrypted Olm account backup (for legacy recovery). (before :username)
router.get('/conversations/prekeys/backup', requireApiAuth('read:direct'), (req, res) => {
  const id = db.getOlmIdentity(req.apiUser.id);
  responseEnvelope(res, { backup: id ? id.backup : null, has_identity: !!(id && id.identity_key), backup_identity: id ? id.identity_key : null, salt: id ? id.kek_salt || null : null });
});

// Count of unused one-time prekeys the current user still has published. (before :username)
router.get('/conversations/prekeys/count', requireApiAuth('read:direct'), (req, res) => {
  const deviceId = String(req.query.device_id || '').trim();
  const avail = deviceId ? db.countAvailableDevicePrekeys(req.apiUser.id, deviceId) : db.countAvailablePrekeys(req.apiUser.id);
  responseEnvelope(res, { available: avail });
});

// Message history with a user
router.get('/conversations/:username', requireApiAuth('read:direct'), (req, res) => {
  const other = db.getUserByUsername(req.params.username);
  if (!other) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (!db.areMutualFollowers(req.apiUser.id, other.id)) {
    return errorResponse(res, 403, 'Forbidden', 'You can only message mutual followers.');
  }

  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
  const cursor = req.query.cursor ? decodeCursor(req.query.cursor) : null;
  const messages = dm.getMessages(req.apiUser.id, other.id, limit, cursor ? cursor.id : null);
  // getMessages returns newest-first; reverse for display (oldest-first)
  messages.reverse();

  const items = messages.map(m => ({
    id: String(m.id),
    from_id: String(m.from_id),
    to_id: String(m.to_id),
    body: m.body,
    created_at: m.created_at,
    edited_at: m.edited_at,
    key_for_sender: m.key_for_sender,
    key_for_recipient: m.key_for_recipient,
    proto: m.proto,
    sender_ciphertext: m.sender_ciphertext,
    secure: m.secure === 1,
  }));

  // Cursor points to the oldest message in this batch (first item after reverse)
  // so the next request fetches messages older than that.
  const nextCursor = items.length > 0
    ? Buffer.from(JSON.stringify({ id: items[0].id })).toString('base64url')
    : null;

  responseEnvelope(res, items, {
    pagination: { next: nextCursor },
  });
});

// Send a message
router.post('/conversations/:username/messages', requireApiAuth('write:direct'), requireVerifiedApiWrite, (req, res) => {
  const clientId = req.body.client_id || req.body.nonce || req.body.client_tx_id;
  const other = db.getUserByUsername(req.params.username);
  if (!other) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (!db.areMutualFollowers(req.apiUser.id, other.id)) {
    return errorResponse(res, 403, 'Forbidden', 'You can only message mutual followers.');
  }

  const body = String(req.body.body || '').trim();
  if (!body) return errorResponse(res, 400, 'Bad Request', 'body is required.');
  // Reject oversize: slicing a ciphertext corrupts it (the web client allows
  // up to 65536 — multi-device Olm envelopes are larger than the old 5000 cap).
  if (body.length > 65536) return errorResponse(res, 400, 'Bad Request', 'body is too long.');

  const keyForSender = String(req.body.key_for_sender || '').trim() || null;
  const keyForRecipient = String(req.body.key_for_recipient || '').trim() || null;
  const rawProto = String(req.body.proto || '').trim();
  const senderCiphertextRaw = String(req.body.sender_ciphertext || '').trim();
  if (senderCiphertextRaw.length > 65536) return errorResponse(res, 400, 'Bad Request', 'sender_ciphertext is too long.');

  if (!body.startsWith('/uploads/stickers/')) {
    if (rawProto !== 'mls') {
      return errorResponse(res, 426, 'Upgrade Required', 'LegacyProtocolRetired: Extrovert has upgraded to MLS encryption (RFC 9420). Please refresh your client.');
    }
  }

  const msgId = dm.sendMessage(req.apiUser.id, other.id, body, null, null, 'mls', senderCiphertextRaw || null, dm.getDmSecurity(req.apiUser.id, other.id).active);
  db.createNotification({ userId: other.id, type: 'message', actorId: req.apiUser.id });

  const msg = db.db.prepare(`SELECT id, from_id, to_id, body, created_at, key_for_sender, key_for_recipient, proto, sender_ciphertext, secure FROM messages WHERE id = ?`).get(msgId);
  let senderDeviceId = req.body.sender_device_id || req.body.device_id || null;
  if (!senderDeviceId && body && body.startsWith('{')) {
    try {
      const parsed = JSON.parse(body);
      if (parsed && parsed.sender_device_id) senderDeviceId = parsed.sender_device_id;
    } catch {}
  }
  const senderCurve = db.getSenderCurve(req.apiUser.id, senderDeviceId, req.body.sender_curve);
  const apiUserRow = db.db.prepare(`SELECT username, display_name FROM users WHERE id = ?`).get(req.apiUser.id);
  const dmPayload = {
    message: msg,
    sender_curve: senderCurve,
    from_username: apiUserRow.username,
    from_display: apiUserRow.display_name,
    to_username: other.username,
  };
  if (senderDeviceId) dmPayload.sender_device_id = String(senderDeviceId);
  if (clientId) dmPayload.client_id = String(clientId);
  sendDmEvent(other.username, dmPayload);
  if (apiUserRow.username !== other.username) {
    sendDmEvent(apiUserRow.username, dmPayload);
  }

  const responseData = {
    id: String(msg.id),
    from_id: String(msg.from_id),
    to_id: String(msg.to_id),
    body: msg.body,
    created_at: msg.created_at,
    key_for_sender: msg.key_for_sender,
    key_for_recipient: msg.key_for_recipient,
    proto: msg.proto,
    sender_ciphertext: msg.sender_ciphertext,
    secure: msg.secure === 1,
  };
  if (clientId) responseData.client_id = String(clientId);

  res.status(201).json({
    data: responseData,
  });
});

// Toggle "Additional Security" for this conversation (per-user opt-in; only
// active once both users have enabled it).
router.post('/conversations/:username/security', requireApiAuth('write:direct'), express.json(), (req, res) => {
  const other = db.getUserByUsername(req.params.username);
  if (!other) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (!db.areMutualFollowers(req.apiUser.id, other.id)) {
    return errorResponse(res, 403, 'Forbidden', 'You can only message mutual followers.');
  }
  const enabled = !!req.body.enabled;
  dm.setDmSecurity(req.apiUser.id, other.id, enabled);
  const security = dm.getDmSecurity(req.apiUser.id, other.id);
  db.auditLog('dm_security', req.apiUser.id, 'Set Additional Security to ' + (enabled ? 'on' : 'off') + ' with ' + other.username);
  responseEnvelope(res, { enabled, mine: security.mine, theirs: security.theirs, active: security.active });
});

// Acknowledge receipt of secure messages; the server deletes any message that
// BOTH participants have now received.
router.post('/conversations/:username/received', requireApiAuth('write:direct'), express.json(), (req, res) => {
  const other = db.getUserByUsername(req.params.username);
  if (!other) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (!db.areMutualFollowers(req.apiUser.id, other.id)) {
    return errorResponse(res, 403, 'Forbidden', 'You can only message mutual followers.');
  }
  const ids = Array.isArray(req.body.message_ids)
    ? req.body.message_ids
    : (Array.isArray(req.body.ids) ? req.body.ids : []);
  const result = dm.ackMessagesReceived(req.apiUser.id, other.id, ids);
  responseEnvelope(res, result);
});

// Fetch a recipient's Olm bundle (all active devices of recipient + sender's
// other devices). READ-ONLY: unclaimed OTK preview (?claim=1 = legacy behavior).
router.get('/conversations/:username/bundle', requireApiAuth('read:direct'), (req, res) => {
  const other = db.getUserByUsername(req.params.username);
  if (!other) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (!db.areMutualFollowers(req.apiUser.id, other.id)) {
    return errorResponse(res, 403, 'Forbidden', 'You can only message mutual followers.');
  }
  const bundlesFor = req.query.claim === '1' ? db.claimAllDevicePrekeysForUser : db.getAllDeviceBundlesForUser;
  const recipientDevices = bundlesFor(other.id);
  const senderDevices = bundlesFor(req.apiUser.id);
  const primaryRecipient = recipientDevices[0] || null;

  responseEnvelope(res, {
    devices: recipientDevices,
    sender_devices: senderDevices,
    identity_key: primaryRecipient ? primaryRecipient.identity_key : null,
    ed25519_key: primaryRecipient ? primaryRecipient.ed25519_key : null,
    one_time_key: primaryRecipient ? primaryRecipient.one_time_key : null,
     fallback_key: primaryRecipient ? primaryRecipient.fallback_key : null,
  });
});

// Claim one one-time prekey per device — exactly once per new session.
router.post('/conversations/:username/claim', requireApiAuth('write:direct'), express.json(), (req, res) => {
  const other = db.getUserByUsername(req.params.username);
  if (!other) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (!db.areMutualFollowers(req.apiUser.id, other.id)) {
    return errorResponse(res, 403, 'Forbidden', 'You can only message mutual followers.');
  }
  const cleanIds = (v) => Array.isArray(v)
    ? [...new Set(v.map(x => String(x || '').trim()).filter(Boolean))].slice(0, 50)
    : null;
  const deviceIds = cleanIds(req.body.device_ids);
  const senderDeviceIds = cleanIds(req.body.sender_device_ids);
  const devices = deviceIds ? db.claimAllDevicePrekeysForUser(other.id, deviceIds) : [];
  const senderDevices = senderDeviceIds ? db.claimAllDevicePrekeysForUser(req.apiUser.id, senderDeviceIds) : [];
  const primary = devices[0] || null;
  responseEnvelope(res, {
    devices,
    sender_devices: senderDevices,
    identity_key: primary ? primary.identity_key : null,
    ed25519_key: primary ? primary.ed25519_key : null,
    one_time_key: primary ? primary.one_time_key : null,
    fallback_key: primary ? primary.fallback_key : null,
  });
});

// Recipient ed25519 identity keys for safety-number verification.
router.get('/conversations/:username/safety', requireApiAuth('read:direct'), (req, res) => {
  const other = db.getUserByUsername(req.params.username);
  if (!other) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (!db.areMutualFollowers(req.apiUser.id, other.id)) {
    return errorResponse(res, 403, 'Forbidden', 'You can only message mutual followers.');
  }
  const mine = db.getOlmIdentity(req.apiUser.id);
  const theirs = db.getOlmIdentity(other.id);
  responseEnvelope(res, {
    my_ed25519: mine ? mine.ed25519_key : null,
    their_ed25519: theirs ? theirs.ed25519_key : null,
    my_curve25519: mine ? mine.identity_key : null,
    their_curve25519: theirs ? theirs.identity_key : null,
  });
});

// Fetch a user's public key
router.get('/conversations/:username/keys', requireApiAuth('read:direct'), (req, res) => {
  const other = db.getUserByUsername(req.params.username);
  if (!other) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (!db.areMutualFollowers(req.apiUser.id, other.id)) {
    return errorResponse(res, 403, 'Forbidden', 'You can only message mutual followers.');
  }

  const publicKey = dm.getPublicKey(other.id);
  responseEnvelope(res, { public_key: publicKey });
});

// Edit a message
router.patch('/messages/:id', requireApiAuth('write:direct'), (req, res) => {
  const body = String(req.body.body || '').trim();
  if (!body) return errorResponse(res, 400, 'Bad Request', 'body is required.');
  if (body.length > 65536) return errorResponse(res, 400, 'Bad Request', 'body is too long.');
  const keyForSender = String(req.body.key_for_sender || '').trim() || null;
  const keyForRecipient = String(req.body.key_for_recipient || '').trim() || null;
  const rawProto = String(req.body.proto || 'rsa').trim();
  const proto = (rawProto === 'mls' || rawProto === 'olm') ? rawProto : 'rsa';
  const senderCiphertextRaw = String(req.body.sender_ciphertext || '').trim();
  if (senderCiphertextRaw.length > 65536) return errorResponse(res, 400, 'Bad Request', 'sender_ciphertext is too long.');
  const senderCiphertext = senderCiphertextRaw || null;
  if (!body.startsWith('/uploads/stickers/') && ((proto !== 'olm' && proto !== 'mls') || (proto === 'olm' && !senderCiphertext))) {
    return errorResponse(res, 400, 'Bad Request', 'End-to-end encryption required. All messages must be Olm or MLS encrypted.');
  }
  const ok = dm.editMessage(parseInt(req.params.id, 10), req.apiUser.id, body, keyForSender, keyForRecipient, proto, senderCiphertext);
  if (!ok) return errorResponse(res, 404, 'Not Found', 'Message not found or not yours.');
  const targetMsg = db.db.prepare(`
    SELECT m.*, u.username AS from_username, u2.username AS to_username
    FROM messages m
    JOIN users u ON u.id = m.from_id
    JOIN users u2 ON u2.id = m.to_id
    WHERE m.id = ?
  `).get(parseInt(req.params.id, 10));
  if (targetMsg) {
    const editEvent = { type: 'edit_dm', message: targetMsg, from_username: targetMsg.from_username };
    sendDmEvent(targetMsg.to_username, editEvent);
    sendDmEvent(targetMsg.from_username, editEvent);
  }
  db.auditLog('dm_edited', req.apiUser.id, `Message ${req.params.id}`);
  res.json({ data: { ok: true } });
});

// Delete a message
router.delete('/messages/:id', requireApiAuth('write:direct'), (req, res) => {
  const msgId = parseInt(req.params.id, 10);
  const targetMsg = db.db.prepare(`
    SELECT m.*, u.username AS from_username, u2.username AS to_username
    FROM messages m
    JOIN users u ON u.id = m.from_id
    JOIN users u2 ON u2.id = m.to_id
    WHERE m.id = ?
  `).get(msgId);
  const ok = dm.deleteMessage(msgId, req.apiUser.id);
  if (!ok) return errorResponse(res, 404, 'Not Found', 'Message not found or not yours.');
  if (targetMsg) {
    sendDmEvent(targetMsg.to_username, {
      type: 'delete_dm',
      message_id: msgId,
      from_username: targetMsg.from_username,
    });
    sendDmEvent(targetMsg.from_username, {
      type: 'delete_dm',
      message_id: msgId,
      from_username: targetMsg.from_username,
    });
  }
  db.auditLog('dm_deleted', req.apiUser.id, `Message ${req.params.id}`);
  res.json({ data: { ok: true } });
});

// ---------- Stickers ----------
router.get('/stickers', requireApiAuth('read'), (req, res) => {
  const stickers = db.getMyStickers(req.apiUser.id);
  const data = (stickers || []).map(s => ({
    id: String(s.id),
    file_path: s.file_path,
    url: s.file_path,
    created_at: s.created_at ? new Date(s.created_at).toISOString() : null,
  }));
  responseEnvelope(res, data);
});

router.post('/stickers', requireApiAuth('write'), requireVerifiedApiWrite, (req, res, next) => {
  if (req.is('multipart/form-data')) {
    stickerUpload.single('file')(req, res, async (err) => {
      if (err) {
        if (err.code === 'LIMIT_FILE_SIZE') return errorResponse(res, 400, 'Bad Request', 'Sticker must be under 500 KB.');
        return errorResponse(res, 400, 'Bad Request', 'Invalid sticker file.');
      }
      if (!req.file) return errorResponse(res, 400, 'Bad Request', 'No file uploaded. Use field "file".');
      const fullPath = req.file.path;
      const ext = path.extname(req.file.originalname).toLowerCase();
      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > 250 * 1024 && ext !== '.gif') {
          const img = sharp(fullPath);
          const meta = await img.metadata();
          let compressed;
          if (meta.format === 'jpeg') compressed = await img.jpeg({ quality: 70 }).toBuffer();
          else if (meta.format === 'png') compressed = await img.png({ quality: 70 }).toBuffer();
          else if (meta.format === 'webp') compressed = await img.webp({ quality: 70 }).toBuffer();
          if (compressed && compressed.length < stat.size) {
            fs.writeFileSync(fullPath, compressed);
          }
        }
      } catch (e) {
        try { fs.unlink(fullPath, () => {}); } catch {}
        return errorResponse(res, 400, 'Bad Request', 'Invalid image file.');
      }
      const filePath = '/uploads/stickers/' + req.file.filename;
      const stickerId = db.addSticker(req.apiUser.id, filePath);
      res.status(201).json({
        data: {
          id: String(stickerId || ''),
          file_path: filePath,
          url: filePath,
        },
      });
    });
  } else {
    express.json()(req, res, () => {
      const filePath = String(req.body.path || '').trim();
      if (!filePath.startsWith('/uploads/stickers/')) {
        return errorResponse(res, 400, 'Bad Request', 'Invalid sticker path.');
      }
      const existing = (db.getMyStickers(req.apiUser.id) || []).find(s => s.file_path === filePath);
      if (existing) {
        return res.json({ data: { id: String(existing.id), file_path: existing.file_path, url: existing.file_path } });
      }
      const stickerId = db.addSticker(req.apiUser.id, filePath);
      res.status(201).json({ data: { id: String(stickerId || ''), file_path: filePath, url: filePath } });
    });
  }
});

router.delete('/stickers/:id', requireApiAuth('write'), (req, res) => {
  const stickerId = parseInt(req.params.id, 10);
  const sticker = db.getStickerById(stickerId);
  if (!sticker || sticker.user_id !== req.apiUser.id) {
    return errorResponse(res, 404, 'Not Found', 'Sticker not found or not owned by you.');
  }
  const deleted = db.deleteSticker(stickerId, req.apiUser.id);
  if (!deleted) {
    return errorResponse(res, 404, 'Not Found', 'Sticker not found.');
  }
  res.json({ data: { ok: true } });
});

// ---------- FoF Discovery ----------
router.get('/discover', requireApiAuth('read'), (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 50);
  const users = db.getSuggestedFoafUsers(req.apiUser.id, limit);
  const data = (users || []).map(u => ({
    id: String(u.id),
    username: u.username,
    display_name: u.display_name,
    avatar: u.avatar,
    bio: u.bio,
    created_at: u.created_at ? new Date(u.created_at).toISOString() : null,
  }));
  responseEnvelope(res, data);
});

// ======== Admin API Endpoints (/api/v1/admin/*) ========

function requireApiAdmin(req, res, next) {
  requireApiAuth('read')(req, res, () => {
    if (!req.apiUser || !req.apiUser.is_admin) {
      return errorResponse(res, 403, 'Forbidden', 'Admin privileges required.');
    }
    next();
  });
}

// GET /api/v1/admin/users
router.get('/admin/users', requireApiAdmin, (req, res) => {
  const users = db.getAllUsers();
  responseEnvelope(res, users);
});

// POST /api/v1/admin/users/:id/ban
router.post('/admin/users/:id/ban', requireApiAdmin, (req, res) => {
  const target = db.getUserById(Number(req.params.id));
  if (!target) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (target.is_admin) return errorResponse(res, 403, 'Forbidden', 'Cannot ban another admin.');
  db.banUser(target.id);
  try { sessionStore.destroySessionsForUser(target.id); } catch {}
  db.revokeAllOAuthTokensForUser(target.id);
  db.auditLog('user_banned', req.apiUser.id, target.username, req.ip);
  responseEnvelope(res, { ok: true, banned: true, user_id: target.id });
});

// POST /api/v1/admin/users/:id/unban
router.post('/admin/users/:id/unban', requireApiAdmin, (req, res) => {
  const target = db.getUserById(Number(req.params.id));
  if (!target) return errorResponse(res, 404, 'Not Found', 'User not found.');
  db.unbanUser(target.id);
  db.auditLog('user_unbanned', req.apiUser.id, target.username, req.ip);
  responseEnvelope(res, { ok: true, banned: false, user_id: target.id });
});

// DELETE /api/v1/admin/users/:id
router.delete('/admin/users/:id', requireApiAdmin, (req, res) => {
  const target = db.getUserById(Number(req.params.id));
  if (!target) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (target.is_admin) return errorResponse(res, 403, 'Forbidden', 'Cannot delete an admin.');
  db.deleteUser(target.id);
  try { sessionStore.destroySessionsForUser(target.id); } catch {}
  db.auditLog('user_deleted', req.apiUser.id, target.username, req.ip);
  responseEnvelope(res, { ok: true, deleted: true, user_id: target.id });
});

// POST /api/v1/admin/users/:id/make_admin
router.post('/admin/users/:id/make_admin', requireApiAdmin, (req, res) => {
  const target = db.getUserById(Number(req.params.id));
  if (!target) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (target.is_admin) return errorResponse(res, 400, 'Bad Request', 'Already an admin.');
  if (target.banned) return errorResponse(res, 400, 'Bad Request', 'Cannot promote a banned user.');
  db.promoteUser(target.id);
  db.auditLog('user_promoted', req.apiUser.id, target.username, req.ip);
  responseEnvelope(res, { ok: true, is_admin: true, user_id: target.id });
});

// POST /api/v1/admin/users/:id/remove_admin
router.post('/admin/users/:id/remove_admin', requireApiAdmin, (req, res) => {
  const target = db.getUserById(Number(req.params.id));
  if (!target) return errorResponse(res, 404, 'Not Found', 'User not found.');
  if (target.id === req.apiUser.id) return errorResponse(res, 400, 'Bad Request', 'Cannot demote yourself.');
  db.demoteUser(target.id);
  db.auditLog('user_demoted', req.apiUser.id, target.username, req.ip);
  responseEnvelope(res, { ok: true, is_admin: false, user_id: target.id });
});

// GET /api/v1/admin/reports
router.get('/admin/reports', requireApiAdmin, (req, res) => {
  const reports = db.getPendingReports();
  responseEnvelope(res, reports);
});

// POST /api/v1/admin/reports/:id/resolve
router.post('/admin/reports/:id/resolve', requireApiAdmin, (req, res) => {
  const report = db.getReport(Number(req.params.id));
  if (!report) return errorResponse(res, 404, 'Not Found', 'Report not found.');
  db.resolveReport(report.id);
  db.auditLog('report_resolved', req.apiUser.id, `Report #${report.id}`, req.ip);
  responseEnvelope(res, { ok: true, report_id: report.id });
});

// POST /api/v1/admin/reports/:id/dismiss
router.post('/admin/reports/:id/dismiss', requireApiAdmin, (req, res) => {
  const report = db.getReport(Number(req.params.id));
  if (!report) return errorResponse(res, 404, 'Not Found', 'Report not found.');
  db.dismissReport(report.id);
  db.auditLog('report_dismissed', req.apiUser.id, `Report #${report.id}`, req.ip);
  responseEnvelope(res, { ok: true, report_id: report.id });
});

// GET /api/v1/admin/announcement
router.get('/admin/announcement', requireApiAdmin, (req, res) => {
  const announcement = db.getAnnouncement();
  responseEnvelope(res, { announcement });
});

// POST /api/v1/admin/announcement
router.post('/admin/announcement', requireApiAdmin, express.json(), (req, res) => {
  const body = String((req.body && req.body.body) || '').trim();
  if (!body) return errorResponse(res, 400, 'Bad Request', 'Announcement body is required.');
  db.setAnnouncement(body, req.apiUser.id);
  db.auditLog('announcement_updated', req.apiUser.id, body.slice(0, 50), req.ip);
  responseEnvelope(res, { ok: true, announcement: db.getAnnouncement() });
});

// DELETE /api/v1/admin/announcement
router.delete('/admin/announcement', requireApiAdmin, (req, res) => {
  db.clearAnnouncement();
  db.auditLog('announcement_cleared', req.apiUser.id, '', req.ip);
  responseEnvelope(res, { ok: true, announcement: null });
});

// ---------- WebRTC ICE Servers ----------
router.get('/calls/ice_servers', requireApiAuth('read'), (req, res) => {
  responseEnvelope(res, { ice_servers: getIceServersConfig() });
});

module.exports = router;

