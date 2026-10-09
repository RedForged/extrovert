'use strict';

const db = require('./db');

// Resolve an OAuth Bearer token to its user AND granted scopes, or null.
// Lets native clients (which authenticate with OAuth tokens via PKCE, not
// session cookies) use the web E2EE routes through the shared JS crypto —
// while still honoring the token's scope grant.
function resolveBearer(req) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  if (!token) return null;
  const tokenRecord = db.getOAuthToken(token);
  if (!tokenRecord) return null;
  if (tokenRecord.expires_at && Date.now() > tokenRecord.expires_at) return null;
  const user = db.getUserById(tokenRecord.user_id);
  if (!user || user.banned) return null;
  return { user, scopes: String(tokenRecord.scopes || '') };
}

// Backwards-compatible: the resolved user only.
function bearerUser(req) {
  const resolved = resolveBearer(req);
  return resolved ? resolved.user : null;
}

// Express middleware: populate res.locals.currentUser from a valid Bearer token
// when the session middleware hasn't already done so. Records the token's
// scopes so downstream scope checks can tell a session (unrestricted) apart
// from a limited token.
function bearerOrSession(req, res, next) {
  if (res.locals.currentUser) return next();
  const resolved = resolveBearer(req);
  if (resolved) {
    res.locals.currentUser = resolved.user;
    res.locals.bearerScopes = resolved.scopes;
  }
  next();
}

// Enforce the direct-message scope on E2EE routes for Bearer-authenticated
// requests. A session (browser) is a full user credential and is left as-is;
// a token must hold `read:direct` for reads and `write:direct` for mutations,
// otherwise a token granted only `read` could read/send the user's DMs.
function requireDirectScope(req, res, next) {
  if (res.locals.bearerScopes === undefined) return next(); // session, or not-yet-authenticated
  const need = (req.method === 'GET' || req.method === 'HEAD') ? 'read:direct' : 'write:direct';
  if (!String(res.locals.bearerScopes).split(/\s+/).includes(need)) {
    return res.status(403).json({
      error: 'insufficient_scope',
      error_description: `This endpoint requires the ${need} scope.`,
    });
  }
  next();
}

module.exports = { bearerUser, bearerOrSession, requireDirectScope, resolveBearer };
