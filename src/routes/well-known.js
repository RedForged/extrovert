'use strict';

const express = require('express');
const { getJwks, ISSUER } = require('../oidc');
const { contactMailto } = require('./security');

const router = express.Router();

// RFC 9116 security.txt — machine-readable disclosure policy + private contact.
router.get('/security.txt', (req, res) => {
  const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
  const lines = [
    '# Extrovert security policy',
    `Contact: ${contactMailto()}`,
    `Contact: ${ISSUER}/security`,
    `Expires: ${expires}`,
    `Policy: ${ISSUER}/security`,
    'Preferred-Languages: en',
    `Canonical: ${ISSUER}/.well-known/security.txt`,
    '',
  ];
  res.type('text/plain; charset=utf-8');
  res.send(lines.join('\n'));
});

router.get('/openid-configuration', (req, res) => {
  const base = ISSUER;
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${base}/api/v1/oauth/authorize`,
    token_endpoint: `${base}/api/v1/oauth/token`,
    userinfo_endpoint: `${base}/api/v1/oauth/userinfo`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    revocation_endpoint: `${base}/api/v1/oauth/revoke`,
    registration_endpoint: `${base}/api/v1/oauth/apps`,
    scopes_supported: [
      'openid', 'read', 'write', 'follow',
      'media.write', 'notifications',
      'read:direct', 'write:direct', 'profile', 'email',
    ],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    claim_types_supported: ['normal'],
    claims_supported: [
      'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time',
      'nonce', 'preferred_username', 'name', 'picture',
      'email', 'email_verified',
    ],
    code_challenge_methods_supported: ['S256'],
  });
});

router.get('/jwks.json', (req, res) => {
  res.json(getJwks());
});

module.exports = router;
