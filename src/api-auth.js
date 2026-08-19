'use strict';

const crypto = require('node:crypto');
const db = require('./db');

const VALID_SCOPES = new Set(['openid', 'read', 'write', 'follow', 'media.write', 'notifications', 'read:direct', 'write:direct', 'profile', 'email']);

const SCOPE_HIERARCHY = {
  'openid': ['openid'],
  'read': ['read'],
  'write': ['write'],
  'follow': ['follow'],
  'media.write': ['media.write'],
  'notifications': ['notifications'],
  'read:direct': ['read:direct'],
  'write:direct': ['write:direct'],
  'profile': ['profile'],
  'email': ['email'],
};

function validateScopes(tokenScopes, requiredScopes) {
  const granted = tokenScopes.split(' ');
  for (const required of requiredScopes) {
    if (!granted.includes(required)) return false;
  }
  return true;
}

function requireApiAuth(...requiredScopes) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'Missing or invalid Authorization header. Use: Authorization: Bearer <token>',
      });
    }

    const token = authHeader.slice(7);
    const tokenRecord = db.getOAuthToken(token);
    if (!tokenRecord) {
      db.auditLog('api_auth_failure', null, 'Invalid token');
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'The access token is invalid or has been revoked.',
      });
    }

    if (tokenRecord.expires_at && Date.now() > tokenRecord.expires_at) {
      db.auditLog('api_auth_failure', tokenRecord.user_id, 'Expired token');
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'The access token has expired. Use the refresh token to get a new one.',
      });
    }

    if (requiredScopes.length > 0 && !validateScopes(tokenRecord.scopes, requiredScopes)) {
      db.auditLog('api_auth_failure', tokenRecord.user_id, `Missing scope: need ${requiredScopes.join('+')}, have ${tokenRecord.scopes}`);
      return res.status(403).json({
        error: 'insufficient_scope',
        error_description: `This endpoint requires the following scope(s): ${requiredScopes.join(' ')}. Your token has: ${tokenRecord.scopes}`,
      });
    }

    const user = db.getUserById(tokenRecord.user_id);
    if (!user || user.banned) {
      return res.status(403).json({
        error: 'forbidden',
        error_description: 'Your account has been suspended or no longer exists.',
      });
    }

    req.apiToken = tokenRecord;
    req.apiUser = user;
    req.apiApp = db.getOAuthAppById(tokenRecord.app_id);
    next();
  };
}

function clientAppAuth(req, res, next) {
  const clientId = req.body.client_id || req.query.client_id;
  const clientSecret = req.body.client_secret;
  if (!clientId) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'client_id is required.' });
  }
  const app = db.getOAuthAppByClientId(clientId);
  if (!app) {
    return res.status(401).json({ error: 'invalid_client', error_description: 'Unknown client_id.' });
  }
  // Public clients (native/mobile apps using PKCE) cannot safely provide a secret.
  // Only validate client_secret if it was actually sent in the request. Secrets
  // are stored as SHA-256 hashes, so compare the hash of the presented value.
  if (clientSecret !== undefined && app.client_secret && db.hashOAuthToken(clientSecret) !== app.client_secret) {
    return res.status(401).json({ error: 'invalid_client', error_description: 'Client secret does not match.' });
  }
  req.oauthApp = app;
  next();
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { requireApiAuth, clientAppAuth, validateScopes, generateToken, VALID_SCOPES };
