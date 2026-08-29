'use strict';

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const { WebSocketServer } = require('ws');
const SqliteStore = require('./session-store');
const { optionalAuth, requireAuth } = require('./auth');
const { bearerUser } = require('./bearer-auth');
const { initSignaling } = require('./webrtc-signaling');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET environment variable is required');
  process.exit(1);
}

// Ensure data + upload directories exist.
const DATA_DIR = path.join(__dirname, '..', 'data');
const UPLOAD_DIR = path.join(__dirname, '..', 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// View engine.
app.set('view engine', 'ejs');

// Favicon (suppress 404 noise in console).
app.get('/favicon.ico', (req, res) => res.status(204).end());
app.set('views', path.join(__dirname, 'views'));
const TRUST_PROXY = process.env.TRUST_PROXY || 'false';
if (TRUST_PROXY !== 'false') {
  app.set('trust proxy', TRUST_PROXY);
}

// Security headers.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "http:", "https:"],
      mediaSrc: ["'self'"],
      scriptSrc: ["'self'", "'wasm-unsafe-eval'"],
      workerSrc: ["'self'"],
      connectSrc: ["'self'", "ws:", "wss:"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));

// CORS for third-party API clients.
app.use('/api', (req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, Idempotency-Key, X-CSRF-Token');
  res.set('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// CORS for native clients: the webview runs a different origin but authenticates
// with an explicit Bearer header (no cookies), so '*' is safe here.
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-CSRF-Token, X-Requested-With');
    res.set('Access-Control-Max-Age', '86400');
    return res.status(204).end();
  }
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-CSRF-Token, X-Requested-With');
  }
  next();
});

// Session with secure defaults.
app.use(session({
  store: new SqliteStore(),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.EXTV_COOKIE_SECURE === 'false' ? false : process.env.EXTV_COOKIE_SECURE === 'true' ? true : IS_PROD ? 'auto' : false,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 30,
  },
}));

// Auth rate limiter (login + register).
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.EXTV_AUTH_RATE_LIMIT) || 30,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: 'Too many authentication attempts. Try again in a minute.',
});
app.use('/login', authLimiter);
app.use('/register', authLimiter);

// General action rate limiter (lower limit than auth).
//
// Keyed per-USER (signed-in session) with an IP fallback, not per-IP: a NAT
// or a shared proxy IP must not let one user's activity starve everyone else,
// and one user of an app this busy shouldn't be able to lock themselves out.
// Budget is generous and configurable so legitimate use isn't throttled.
const userScope = (req) => (req.session && req.session.userId)
  ? 'u:' + req.session.userId
  : (req.connection && req.connection.remoteAddress) || req.ip;
const actionLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.EXTV_ACTION_RATE_LIMIT) || 240,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: userScope,
  validate: { xForwardedForHeader: false, keyGeneratorIpFallback: false },
  message: 'Too many requests, please slow down.',
});

// E2EE crypto endpoints are NOT abuse-prone the way post/follow are. They are
// authenticated + CSRF-protected, and throttling them is what breaks message
// delivery: `/claim` establishes the Olm inbound session, `/rekey/*` heals a
// desynced ratchet, `send` delivers the ciphertext, and `prekeys`/`devices`/
// `security`/`received` back the whole flow. If these hit the 60/min blanket
// limiter, the client can't claim a prekey or heal a session and every message
// renders `[unable to decrypt]` — a self-inflicted DoS. Give them their own,
// higher, still-per-user budget (configurable).
const ML_CRYPTO_MAX = Number(process.env.EXTV_CRYPTO_RATE_LIMIT) || 600;
const cryptoLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: ML_CRYPTO_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: userScope,
  validate: { xForwardedForHeader: false, keyGeneratorIpFallback: false },
  message: 'Too many crypto requests, please slow down.',
});
// E2EE paths that must never be throttled into a broken decrypt state.
const CRYPTO_PREFIXES = [
  '/chats/',                    // bundle/claim/send/rekey/security/received/delete
  '/rooms/',                    // room key fan-out
];
app.use((req, res, next) => {
  if (req.method !== 'POST' || req.path.startsWith('/api/')) return next();
  if (CRYPTO_PREFIXES.some((p) => req.path.startsWith(p))) return cryptoLimiter(req, res, next);
  return actionLimiter(req, res, next);
});

// API rate limiter — key on OAuth bearer token when available, fallback to IP.
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Bearer ')) return 'token:' + auth.slice(7);
    return req.ip;
  },
  validate: { xForwardedForHeader: false, keyGeneratorIpFallback: false },
  message: { type: 'about:blank', title: 'Too Many Requests', status: 429, detail: 'API rate limit exceeded. See X-RateLimit-* headers for details.' },
});
app.use('/api', apiLimiter);

// Second-factor limiter — tight budget for code-verification endpoints
// (login challenge, OAuth interstitial, passkey ceremonies). In-session
// attempt counters provide the second wall.
const SECOND_FACTOR_MAX = Number(process.env.EXTV_SECOND_FACTOR_RATE_LIMIT) || 10;
const totpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: SECOND_FACTOR_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: 'Too many verification attempts. Try again in a few minutes.',
});
app.use('/login/totp', totpLimiter);
app.use('/passkeys', totpLimiter);

// CSRF middleware — generates and validates tokens per session.
app.use((req, res, next) => {
  // Native clients authenticate every request with a Bearer token; CSRF is
  // irrelevant when the credential isn't a cookie, and creating a session for
  // them is pointless.
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ') && bearerUser(req)) {
    return next();
  }

  // Generate (or reuse) a session CSRF token for EVERY session — including on
  // API routes. The OAuth consent page lives under /api/v1/oauth/authorize and
  // renders req.session.csrfToken into its <form>, so the token must exist
  // there even though /api/* POSTs are exempt from VALIDATION below (they
  // authenticate via Bearer tokens). A fresh login regenerates the session and
  // starts it without a token, and the login redirect goes straight to the
  // consent page — skipping a non-API page — which made the consent POST fail
  // with 'CSRF token missing or invalid. Re-open the authorization request.'
  // (mobile login regression).
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    console.log('CSRF: generated new token for session', req.sessionID, req.session.csrfToken);
  }
  res.locals.csrfToken = req.session.csrfToken;

  // Skip CSRF validation for API routes (Bearer token auth) and multipart forms.
  if (req.path.startsWith('/api/')) return next();

  if (req.method === 'POST' && (
    req.path === '/stickers/upload' ||
    req.path.startsWith('/stickers/upload') ||
    req.path === '/posts' ||
    /^\/u\/[^\/]+\/avatar$/.test(req.path) ||
    req.path === '/push/cancel-pending'
  )) {
    return next();
  }

  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') {
    const bodyToken = req.body && req.body._csrf;
    const token = bodyToken || req.headers['x-csrf-token'];
    if (!token || token !== req.session.csrfToken) {
      // If the session was just created (stale cookie that couldn't be loaded),
      // redirect to GET so the browser gets a fresh session cookie and CSRF token.
      if (req.session.isNew && req.method === 'POST') {
        console.log('CSRF: new session with mismatched token, redirecting to', req.originalUrl);
        const dest = req.originalUrl || req.path;
        return res.redirect(dest);
      }
      console.log('CSRF FAIL', req.method, req.path, 'sessionToken:', req.session.csrfToken, 'received:', token, 'bodyType:', typeof req.body, 'bodyToken:', bodyToken, 'cookie:', req.headers.cookie ? req.headers.cookie.substring(0, 50) : 'none');
      return res.status(403).send('CSRF validation failed');
    }
  }
  next();
});

// Safely resolve redirect targets — only same-origin relative URLs allowed.
app.use((req, res, next) => {
  res.safeRedirect = function safeRedirect(url, fallback = '/') {
    if (typeof url === 'string' && url.startsWith('/') && !url.startsWith('//')) {
      return res.redirect(url);
    }
    res.redirect(fallback);
  };
  res.locals.safeUrl = function safeUrl(url, fallback = '/') {
    if (typeof url === 'string' && url.startsWith('/') && !url.startsWith('//')) {
      return url;
    }
    return fallback;
  };
  next();
});

app.use('/static', express.static(path.join(__dirname, '..', 'public')));
app.use('/uploads', express.static(UPLOAD_DIR, {
  setHeaders: (res) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Content-Disposition', 'inline');
  },
}));
app.use('/api-uploads', express.static(path.join(__dirname, '..', 'data', 'api-uploads'), {
  setHeaders: (res) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Content-Disposition', 'inline');
  },
}));

app.locals.relTime = function relTime(ts) {
  const s = Math.max(1, Math.floor((Date.now() - ts) / 1000));
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  if (s < 604800) return Math.floor(s / 86400) + 'd';
  return new Date(ts).toLocaleDateString();
};

// Never let browsers cache dynamic pages: they are session/user-specific and
// must reflect the deployed version on every load. Without this, heuristic
// caching (ETag + no Cache-Control) can serve a stale page — which looks like
// updates "didn't ship". Static assets below (/static, /uploads) are not
// affected; they keep their own cache headers.
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

app.use(optionalAuth);

// Expose user data to all templates.
app.use((req, res, next) => {
  if (res.locals.currentUser) {
    const { countUnreadNotifications, countUnreadMessages, getUserTheme, getPendingReports, getPendingSecurityReports, getAnnouncement, requireVerifiedEmail } = require('./db');
    res.locals.unreadCount = countUnreadNotifications(res.locals.currentUser.id);
    res.locals.unreadMessages = countUnreadMessages(res.locals.currentUser.id);
    res.locals.pendingReports = res.locals.currentUser.is_admin ? getPendingReports().length : 0;
    res.locals.securityReports = res.locals.currentUser.is_admin ? getPendingSecurityReports().length : 0;
    res.locals.theme = getUserTheme(res.locals.currentUser.id);
    res.locals.announcement = getAnnouncement();
    // Show a banner when email verification is required but the account
    // hasn't verified an address yet.
    res.locals.verifyBanner = requireVerifiedEmail(res.locals.currentUser);
  }
  next();
});

// Route-specific page titles, so every page's <title> and the nav match
// (Nielsen: visibility of status + consistency). Returns null when the default
// "Extrovert" title should be used.
const PAGE_TITLE_PATTERNS = [
  [/^\/$/, 'Your feed'],
  [/^\/chats/, 'Chats'],
  [/^\/inbox/, 'Notifications'],
  [/^\/compose/, 'New post'],
  [/^\/discover/, 'Discover people'],
  [/^\/settings/, 'Settings'],
  [/^\/rooms/, 'Rooms'],
  [/^\/admin/, 'Admin'],
  [/^\/docs/, 'Docs'],
  [/^\/developers/, 'Developer docs'],
  [/^\/stickers/, 'Stickers'],
  [/^\/u\//, 'Profile'],
  [/^\/login/, 'Log in'],
  [/^\/register/, 'Join Extrovert'],
  [/^\/security/, 'Security'],
];
function pageTitleFor(pathname) {
  for (const [re, title] of PAGE_TITLE_PATTERNS) {
    if (re.test(pathname)) return title;
  }
  return null;
}

// Per-request wayfinding context for the nav (active link) and <title>.
app.use((req, res, next) => {
  res.locals.currentPath = req.path;
  res.locals.pageTitle = pageTitleFor(req.path);
  next();
});

// Routes.
app.use('/', require('./routes/auth'));
app.use('/', require('./routes/pages'));      // /, /compose, /discover
app.use('/posts', require('./routes/posts')); // post creation + interactions
app.use('/u', require('./routes/profile'));   // profile view + edit
app.use('/', require('./routes/social'));     // follow/unfollow
app.use('/inbox', require('./routes/notifications'));
app.use('/chats', require('./routes/chats'));
app.use('/settings', require('./routes/settings'));
app.use('/push', require('./routes/push'));
app.use('/passkeys', require('./routes/webauthn'));
app.use('/admin', require('./routes/admin'));
app.use('/stickers', require('./routes/stickers'));
app.use('/rooms', require('./routes/rooms'));
app.use('/', require('./routes/security')); // /security, /security/report, /security.txt

// REST API v1.
app.use('/api/v1', require('./routes/api-v1'));

// Tighter limiter for the OAuth authorize POST when it carries a second-factor
// code (the interstitial submission). Scoped matcher keeps normal consents on
// the regular apiLimiter budget.
const oauthFactorLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: Number(process.env.EXTV_OAUTH_FACTOR_RATE_LIMIT) || 10,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: { type: 'about:blank', title: 'Too Many Requests', status: 429, detail: 'Too many verification attempts. Re-open the authorization request.' },
});
app.use('/api/v1/oauth/authorize', (req, res, next) => {
  if (req.method === 'POST' && req.body && req.body.totp_code !== undefined) {
    return oauthFactorLimiter(req, res, next);
  }
  next();
});

// OIDC well-known endpoints.
app.use('/.well-known', require('./routes/well-known'));

// Developer docs (Swagger UI + OpenAPI spec).
// Swagger UI assets are vendored locally (swagger-ui-dist) — no CDN — so they
// load under the app's own Content-Security-Policy (styleSrc/scriptSrc 'self').
app.use('/developers/swagger-ui', express.static(path.join(__dirname, '..', 'node_modules', 'swagger-ui-dist'), {
  index: false,
  setHeaders: (res) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'public, max-age=3600');
  },
}));
app.use('/developers', require('./routes/docs'));

// In-app wiki (markdown docs rendered at /docs).
app.use('/docs', require('./routes/wiki'));

// Redirect for discoverability.
app.get('/api/v1/openapi.json', (req, res) => res.redirect('/developers/openapi.json'));
app.get('/api/v1/docs', (req, res) => res.redirect('/developers/docs'));

app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ type: 'about:blank', title: 'Not Found', status: 404, detail: 'The requested API endpoint does not exist.' });
  }
  res.status(404).render('404', { thing: 'page' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).send('Internal server error');
});

const server = app.listen(PORT, () => {
  console.log(`Extrovert is running on http://localhost:${PORT}`);
});

const wss = new WebSocketServer({ noServer: true });
initSignaling(wss);

server.on('upgrade', (req, socket, head) => {
  if (!req.url.startsWith('/ws')) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

module.exports = app;
// The module-level listener created at require time (also used by tests, which
// boot their own ephemeral listener and close this one in teardown).
module.exports.httpServer = server;
