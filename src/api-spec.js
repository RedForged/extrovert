'use strict';

const spec = {
  openapi: '3.1.0',
  info: {
    title: 'Extrovert REST API',
    version: '1.0.1',
    description: `Public REST API for [Extrovert](https://extrovert.redforged.eu), a social network where content is discovered through your network of friends and friends-of-friends.

> Full documentation, including every endpoint's request/response details, E2EE flows, and usage guides, lives in the [in-app wiki](/docs/developers/api-overview).

## Authentication

This API implements **OAuth 2.0** (Authorization Code flow with PKCE) and **OpenID Connect** for third-party authentication.

---

### "Login with Extrovert" — Quick Start

To let users sign in to your platform with their Extrovert account:

**1. Register your application**

Send a POST to \`/api/v1/oauth/apps\` (or use the form at \`/settings/developers\`) with your app name and redirect URI(s). Keep the \`client_id\` and \`client_secret\` — you'll need them.

**2. Redirect the user to authorize**

\`\`\`
GET /api/v1/oauth/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_CALLBACK&response_type=code&scope=openid+profile&state=RANDOM_STATE&nonce=RANDOM_NONCE
\`\`\`

| Parameter | Required | Description |
|-----------|----------|-------------|
| \`client_id\` | yes | Your app's client ID |
| \`redirect_uri\` | yes | Must match one of your registered URIs |
| \`response_type\` | yes | Must be \`code\` |
| \`scope\` | yes | Include \`openid\` for OIDC. Add \`profile\` to get name/avatar. |
| \`state\` | recommended | CSRF protection — echoed back in the redirect |
| \`nonce\` | recommended | OIDC nonce — **must** match the value in the \`id_token\` |
| \`code_challenge\` | recommended | PKCE S256 challenge for public clients |
| \`code_challenge_method\` | recommended | Must be \`S256\` |

**3. Handle the callback**

If the user approves, they're redirected to your \`redirect_uri\`:
\`\`\`
YOUR_CALLBACK?code=AUTH_CODE&state=THE_STATE_YOU_SENT
\`\`\`

Exchange the \`code\` for tokens:
\`\`\`
POST /api/v1/oauth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "code": "AUTH_CODE",
  "code_verifier": "YOUR_PKCE_VERIFIER",
  "redirect_uri": "YOUR_CALLBACK"
}
\`\`\`

Response:
\`\`\`json
{
  "access_token": "ey...",
  "token_type": "Bearer",
  "scope": "openid profile",
  "expires_in": 86400,
  "refresh_token": "rt...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
\`\`\`

If \`openid\` was in the requested scope, the response includes an **\`id_token\`** (a signed JWT).

**4. Verify the ID Token**

Decode and verify the \`id_token\` using the public keys from:

\`\`\`
GET /.well-known/jwks.json
\`\`\`

The token is signed with **RS256**. Verify:
- Signature against the JWKS
- \`iss\` matches \`https://extrovert.redforged.eu\`
- \`aud\` matches your \`client_id\`
- \`exp\` is in the future
- \`nonce\` matches the one you sent (if you sent one)

**5. Get user info**

Call the UserInfo endpoint with the access token:

\`\`\`
GET /api/v1/oauth/userinfo
Authorization: Bearer ACCESS_TOKEN
\`\`\`

Response:
\`\`\`json
{
  "sub": "42",
  "preferred_username": "alice",
  "name": "Alice Johnson",
  "picture": "/uploads/avatars/abc123.jpg"
}
\`\`\`

The \`sub\` claim is the user's unique Extrovert ID. Use this to identify the user in your system.

**6. Token refresh**

When the access token expires (after 24h), use the refresh token:

\`\`\`
POST /api/v1/oauth/token
Content-Type: application/json

{
  "grant_type": "refresh_token",
  "client_id": "YOUR_CLIENT_ID",
  "refresh_token": "YOUR_REFRESH_TOKEN"
}
\`\`\`

---

### Standard API Access

If you only need API access (not authentication), the OAuth 2.0 flow works without \`openid\` in the scope. Available scopes:

| Scope | Access |
|-------|--------|
| \`read\` | Read timelines, posts, profiles |
| \`write\` | Create/delete posts, like, repost |
| \`follow\` | Follow/unfollow accounts |
| \`profile\` | Read/update your profile |
| \`media.write\` | Upload media |
| \`notifications\` | Read/manage notifications |
| \`read:direct\` | Read direct messages |
| \`write:direct\` | Send direct messages |

## Rate Limiting

- Per-token (or per-IP for unauthenticated requests): **120 requests per minute**
- Rate limit headers are returned on every response:
  - \`X-RateLimit-Limit\`
  - \`X-RateLimit-Remaining\`
  - \`X-RateLimit-Reset\`

## Pagination

List endpoints use cursor-based pagination. The response includes a \`pagination\` object:
\`\`\`json
{
  "data": [...],
  "pagination": {
    "next": "base64url-encoded-cursor"
  }
}
\`\`\`
Pass the \`next\` cursor value as the \`?cursor=\` query parameter to get the next page.

## Timestamps

All API body fields use **millisecond Unix timestamps** (e.g. "created_at", "updated_at"). OAuth token "created_at" and JWT claims ("iat", "exp") use **second Unix timestamps**. Check individual field descriptions for details.

## Idempotency

\`POST /api/v1/statuses\` supports the \`Idempotency-Key\` header. If the same key is sent within a short window, duplicate creation is prevented and the original response is returned (with the \`X-Idempotency-Replayed: true\` header).

## Errors

Two error shapes are used:

- **API errors** (\`errorResponse\`) — RFC 9457 problem details:
  \`\`\`json
  { "type": "about:blank", "title": "Bad Request", "status": 400, "detail": "body is required for text posts." }
  \`\`\`
- **Authentication errors** (missing/invalid/expired token, insufficient scope, banned account) — OAuth-style:
  \`\`\`json
  { "error": "unauthorized", "error_description": "The access token has expired. Use the refresh token to get a new one." }
  \`\`\`

Network-visibility rules: accounts and posts outside your visible set return \`404\` (never \`403\`) so their existence cannot be probed.
`,
    contact: {
      name: 'Extrovert Admin',
      url: 'https://extrovert.redforged.eu',
    },
  },
  servers: [
    { url: 'https://extrovert.redforged.eu', description: 'Production' },
    { url: 'http://localhost:3000', description: 'Local development' },
  ],
  paths: {
    '/api/v1/oauth/apps': {
      post: {
        summary: 'Register a new OAuth application',
        tags: ['OAuth'],
        security: [{ sessionAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['name', 'redirect_uris'],
                properties: {
                  name: { type: 'string', description: 'Application name' },
                  description: { type: 'string' },
                  website: { type: 'string', format: 'uri' },
                  redirect_uris: { type: 'string', description: 'Comma-separated redirect URIs' },
                  scopes: { type: 'string', description: 'Space-separated scopes (default: "read")' },
                },
              },
            },
          },
        },
        responses: {
          '201': { description: 'App registered successfully' },
          '400': { description: 'Missing required fields' },
          '401': { description: 'Not logged in' },
        },
      },
      get: {
        summary: 'List your registered OAuth applications',
        tags: ['OAuth'],
        security: [{ sessionAuth: [] }],
        responses: {
          '200': { description: 'List of registered apps' },
        },
      },
    },
    '/api/v1/oauth/authorize': {
      get: {
        summary: 'OAuth authorization endpoint (user-facing)',
        tags: ['OAuth'],
        parameters: [
          { name: 'client_id', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'redirect_uri', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'response_type', in: 'query', required: true, schema: { type: 'string', enum: ['code'] } },
          { name: 'scope', in: 'query', schema: { type: 'string' } },
          { name: 'state', in: 'query', schema: { type: 'string' } },
          { name: 'nonce', in: 'query', schema: { type: 'string' }, description: 'OIDC nonce — will be included in the id_token' },
          { name: 'code_challenge', in: 'query', schema: { type: 'string' }, description: 'PKCE S256 challenge' },
          { name: 'code_challenge_method', in: 'query', schema: { type: 'string', enum: ['S256', 'plain'] } },
        ],
        responses: {
          '302': { description: 'Redirect to login or authorize page' },
          '401': { description: 'Unknown client_id' },
          '400': { description: 'Unsupported response_type or redirect_uri mismatch' },
        },
      },
      post: {
        summary: 'OAuth authorization consent (form submission from the consent page)',
        tags: ['OAuth'],
        security: [{ sessionAuth: [] }],
        requestBody: {
          content: { 'application/x-www-form-urlencoded': { schema: {
            type: 'object',
            required: ['approve'],
            properties: {
              client_id: { type: 'string' },
              redirect_uri: { type: 'string' },
              scope: { type: 'string' },
              state: { type: 'string' },
              nonce: { type: 'string' },
              code_challenge: { type: 'string' },
              code_challenge_method: { type: 'string' },
              approve: { type: 'string', description: '"yes" to approve; anything else denies and redirects with error=access_denied' },
            },
          }}},
        },
        responses: {
          '302': { description: 'Redirect to redirect_uri with ?code=... or ?error=access_denied' },
        },
      },
    },
    '/api/v1/oauth/token': {
      post: {
        summary: 'Exchange authorization code or refresh token',
        description: 'Authenticate the client by sending `client_id` in the body (or query). `client_secret` is only validated if it is actually sent — public clients using PKCE may omit it.',
        tags: ['OAuth'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  grant_type: { type: 'string', enum: ['authorization_code', 'refresh_token'] },
                  client_id: { type: 'string' },
                  client_secret: { type: 'string' },
                  code: { type: 'string', description: 'Authorization code (for authorization_code grant)' },
                  code_verifier: { type: 'string', description: 'PKCE code verifier' },
                  redirect_uri: { type: 'string' },
                  refresh_token: { type: 'string', description: 'Refresh token (for refresh_token grant)' },
                },
              },
            },
          },
        },
        responses: {
          '200': { description: 'Token response' },
          '400': { description: 'Bad request' },
        },
      },
    },
    '/api/v1/oauth/userinfo': {
      get: {
        summary: 'OpenID Connect UserInfo endpoint',
        tags: ['OAuth'],
        security: [{ oauth2: ['openid'] }],
        responses: {
          '200': { description: 'User claims (sub, preferred_username, name, picture)' },
        },
      },
    },
    '/.well-known/openid-configuration': {
      get: {
        summary: 'OpenID Connect Discovery document',
        tags: ['OAuth'],
        responses: { '200': { description: 'OIDC discovery metadata' } },
      },
    },
    '/.well-known/jwks.json': {
      get: {
        summary: 'JSON Web Key Set for ID token signature verification',
        tags: ['OAuth'],
        responses: { '200': { description: 'JWKS with RS256 public key' } },
      },
    },
    '/api/v1/oauth/revoke': {
      post: {
        summary: 'Revoke an access token',
        tags: ['OAuth'],
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['token'],
                properties: {
                  token: { type: 'string' },
                  client_id: { type: 'string' },
                },
              },
            },
          },
        },
        responses: { '200': { description: 'Token revoked (or not found)' } },
      },
    },
    '/api/v1/oauth/authorized_apps': {
      get: {
        summary: 'List apps you have authorized',
        tags: ['OAuth'],
        security: [{ sessionAuth: [] }],
        responses: { '200': { description: 'List of authorized apps' } },
      },
    },
    '/api/v1/oauth/authorized_apps/{appId}/revoke': {
      post: {
        summary: 'Revoke a specific app\'s access',
        tags: ['OAuth'],
        security: [{ sessionAuth: [] }],
        parameters: [{ name: 'appId', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Access revoked' } },
      },
    },
    '/api/v1/accounts/verify_credentials': {
      get: {
        summary: 'Verify and return the authenticated user',
        tags: ['Accounts'],
        security: [{ oauth2: ['read'] }],
        responses: { '200': { description: 'Account object' } },
      },
    },
    '/api/v1/accounts/update_credentials': {
      patch: {
        summary: 'Update the authenticated user\'s profile',
        tags: ['Accounts'],
        security: [{ oauth2: ['profile'] }],
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  display_name: { type: 'string', maxLength: 100 },
                  bio: { type: 'string', maxLength: 500 },
                  theme: { type: 'string', enum: ['light', 'dark', 'default'] },
                },
              },
            },
          },
        },
        responses: { '200': { description: 'Updated account' } },
      },
    },
    '/api/v1/accounts/{id}': {
      get: {
        summary: 'View an account',
        tags: ['Accounts'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: {
          '200': { description: 'Account object' },
          '404': { description: 'Account not found' },
        },
      },
    },
    '/api/v1/accounts/{id}/statuses': {
      get: {
        summary: "View an account's posts",
        tags: ['Accounts'],
        security: [{ oauth2: ['read'] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
          { name: 'cursor', in: 'query', schema: { type: 'string' } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 20, maximum: 40 } },
        ],
        responses: { '200': { description: 'List of posts' } },
      },
    },
    '/api/v1/accounts/{id}/followers': {
      get: {
        summary: "View an account's followers",
        tags: ['Accounts'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'List of accounts' } },
      },
    },
    '/api/v1/accounts/{id}/following': {
      get: {
        summary: "View who an account follows",
        tags: ['Accounts'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'List of accounts' } },
      },
    },
    '/api/v1/accounts/{id}/follow': {
      post: {
        summary: 'Follow an account',
        tags: ['Follows'],
        security: [{ oauth2: ['follow'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'The followed account' } },
      },
    },
    '/api/v1/accounts/{id}/unfollow': {
      post: {
        summary: 'Unfollow an account',
        tags: ['Follows'],
        security: [{ oauth2: ['follow'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'The unfollowed account' } },
      },
    },
    '/api/v1/statuses': {
      post: {
        summary: 'Create a new post',
        tags: ['Statuses'],
        security: [{ oauth2: ['write'] }],
        requestBody: {
          required: true,
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                properties: {
                  type: { type: 'string', enum: ['text', 'photo', 'video', 'repost'] },
                  body: { type: 'string', maxLength: 5000 },
                  media: { type: 'string', format: 'binary', description: 'Photo/video file for photo/video type (max 60 MB, jpg/jpeg/png/gif/webp/mp4/webm/mov)' },
                  repost_of_id: { type: 'integer', description: 'Post ID to repost (for repost type)' },
                },
              },
            },
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  type: { type: 'string', enum: ['text', 'photo', 'video', 'repost'] },
                  body: { type: 'string', maxLength: 5000 },
                  repost_of_id: { type: 'integer', description: 'Post ID to repost (for repost type)' },
                },
              },
            },
          },
        },
        parameters: [
          { name: 'Idempotency-Key', in: 'header', schema: { type: 'string' }, description: 'Prevents duplicate creation on retry; replay responses carry the X-Idempotency-Replayed: true header' },
        ],
        responses: {
          '201': { description: 'Created post' },
          '400': { description: 'Bad request' },
          '404': { description: 'Original post not found (repost type)' },
          '409': { description: 'Already reposted' },
        },
      },
    },
    '/api/v1/statuses/{id}': {
      get: {
        summary: 'View a post',
        tags: ['Statuses'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Post object' } },
      },
      delete: {
        summary: 'Delete your own post',
        tags: ['Statuses'],
        security: [{ oauth2: ['write'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Deleted' } },
      },
    },
    '/api/v1/statuses/{id}/favourite': {
      post: {
        summary: 'Like a post (toggle)',
        tags: ['Statuses'],
        security: [{ oauth2: ['write'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Updated post' } },
      },
    },
    '/api/v1/statuses/{id}/unfavourite': {
      post: {
        summary: 'Unlike a post',
        tags: ['Statuses'],
        security: [{ oauth2: ['write'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Updated post' } },
      },
    },
    '/api/v1/statuses/{id}/reblog': {
      post: {
        summary: 'Repost a post',
        tags: ['Statuses'],
        security: [{ oauth2: ['write'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Updated post' } },
      },
    },
    '/api/v1/statuses/{id}/context': {
      get: {
        summary: 'View post context (ancestors and descendants)',
        tags: ['Statuses'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Context object' } },
      },
    },
    '/api/v1/statuses/{id}/favourited_by': {
      get: {
        summary: 'View who liked a post',
        tags: ['Statuses'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'List of accounts' } },
      },
    },
    '/api/v1/statuses/{id}/reblogged_by': {
      get: {
        summary: 'View who reposted a post',
        tags: ['Statuses'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'List of accounts' } },
      },
    },
    '/api/v1/timelines/home': {
      get: {
        summary: 'View your home timeline',
        tags: ['Timelines'],
        security: [{ oauth2: ['read'] }],
        parameters: [
          { name: 'cursor', in: 'query', schema: { type: 'string' } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 20, maximum: 40 } },
        ],
        responses: { '200': { description: 'List of posts (network-bound)' } },
      },
    },
    '/api/v1/timelines/public': {
      get: {
        summary: 'Public timeline (not available)',
        tags: ['Timelines'],
        responses: { '403': { description: 'Extrovert does not have a public timeline' } },
      },
    },
    '/api/v1/notifications': {
      get: {
        summary: 'View notifications',
        tags: ['Notifications'],
        security: [{ oauth2: ['notifications'] }],
        parameters: [
          { name: 'cursor', in: 'query', schema: { type: 'string' } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 20, maximum: 40 } },
        ],
        responses: { '200': { description: 'List of notifications' } },
      },
    },
    '/api/v1/notifications/clear': {
      post: {
        summary: 'Mark all notifications as read',
        tags: ['Notifications'],
        security: [{ oauth2: ['notifications'] }],
        responses: { '200': { description: 'Cleared' } },
      },
    },
    '/api/v1/media': {
      post: {
        summary: 'Upload a media file',
        tags: ['Media'],
        security: [{ oauth2: ['media.write'] }],
        requestBody: {
          required: true,
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                required: ['file'],
                properties: {
                  file: { type: 'string', format: 'binary' },
                },
              },
            },
          },
        },
        responses: {
          '201': { description: 'Media object' },
          '400': { description: 'No file uploaded' },
        },
      },
    },
    '/api/v1/media/{id}': {
      get: {
        summary: 'View your own media attachment details',
        tags: ['Media'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: {
          '200': { description: 'Media object' },
          '403': { description: 'You do not have access to this media (only the uploader can view it)' },
        },
      },
    },
    '/api/v1/calls/presence': {
      get: {
        summary: 'Get online presence of your network',
        tags: ['Calls'],
        security: [{ oauth2: [] }],
        responses: { '200': { description: 'List of online users in your network (mutual followers only)' } },
      },
    },
    '/api/v1/calls/presence/{username}': {
      get: {
        summary: 'Get presence of a specific user',
        tags: ['Calls'],
        security: [{ oauth2: [] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Presence object' } },
      },
    },
    '/api/v1/push/vapid-public': {
      get: {
        summary: 'Get the VAPID public key for Web Push subscription',
        tags: ['Push'],
        security: [{ oauth2: [] }],
        responses: {
          '200': { description: '{ data: { publicKey: string } }' },
          '404': { description: 'Push is not configured on this server' },
        },
      },
    },
    '/api/v1/push/subscribe': {
      post: {
        summary: 'Register a push subscription (device token for FCM/APNs or Web Push endpoint)',
        tags: ['Push'],
        security: [{ oauth2: [] }],
        requestBody: {
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['platform', 'endpoint'],
            properties: {
              platform: { type: 'string', enum: ['web', 'fcm', 'apns', 'ws'], description: 'Push provider (ws = built-in WebSocket channel for native clients)' },
              endpoint: { type: 'string', description: 'Push endpoint URL (web) or device token (fcm/apns/ws)' },
              p256dh: { type: 'string', description: 'Web Push only: client public key' },
              auth:   { type: 'string', description: 'Web Push only: client auth secret' },
            },
          }}},
        },
        responses: { '200': { description: '{ ok: true }' } },
      },
    },
    '/api/v1/push/unsubscribe': {
      post: {
        summary: 'Remove a push subscription',
        tags: ['Push'],
        security: [{ oauth2: [] }],
        requestBody: {
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['endpoint'],
            properties: { endpoint: { type: 'string' } },
          }}},
        },
        responses: { '200': { description: '{ ok: true }' } },
      },
    },
    '/api/v1/search': {
      get: {
        summary: 'Search accounts and posts',
        tags: ['Search'],
        security: [{ oauth2: ['read'] }],
        parameters: [
          { name: 'q', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'type', in: 'query', schema: { type: 'string', enum: ['accounts', 'statuses'] }, description: 'Limit results to a specific type. If omitted, returns both.' },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 20, maximum: 40 } },
        ],
        responses: {
          '200': { description: 'Search results. Accounts are platform-wide; statuses are network-bound.' },
          '400': { description: 'Missing query parameter "q"' },
        },
      },
    },
    '/api/v1/accounts/relationships': {
      get: {
        summary: 'Check follow relationships with multiple accounts',
        tags: ['Accounts'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'query', required: true, schema: { type: 'string' }, description: 'Comma-separated account IDs' }],
        responses: { '200': { description: 'List of { id, following, followed_by } per account' } },
      },
    },
    '/api/v1/accounts/avatar': {
      post: {
        summary: 'Upload a new avatar (multipart, field "avatar")',
        tags: ['Accounts'],
        security: [{ oauth2: ['profile'] }],
        requestBody: {
          content: { 'multipart/form-data': { schema: {
            type: 'object',
            required: ['avatar'],
            properties: { avatar: { type: 'string', format: 'binary' } },
          }}},
        },
        responses: {
          '200': { description: 'Updated account with new avatar' },
          '400': { description: 'No file uploaded or image could not be processed' },
        },
      },
    },
    '/api/v1/statuses/{id}/comment': {
      post: {
        summary: 'Comment on a post',
        tags: ['Statuses'],
        security: [{ oauth2: ['write'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['body'],
            properties: { body: { type: 'string', maxLength: 1000 } },
          }}},
        },
        responses: { '200': { description: 'Created comment' } },
      },
    },
    '/api/v1/notifications/unread_count': {
      get: {
        summary: 'Get the number of unread notifications',
        tags: ['Notifications'],
        security: [{ oauth2: ['notifications'] }],
        responses: { '200': { description: '{ count: number }' } },
      },
    },
    '/api/v1/notifications/stream': {
      get: {
        summary: 'Server-Sent Events stream of new notifications (event: "notification", heartbeat every 15s)',
        tags: ['Notifications'],
        security: [{ oauth2: ['notifications'] }],
        responses: { '200': { description: 'text/event-stream' } },
      },
    },
    '/api/v1/announcement': {
      get: {
        summary: 'Get the server-wide announcement banner (null if none set)',
        tags: ['General'],
        security: [{ oauth2: ['read'] }],
        responses: { '200': { description: '{ body, author_display_name, author_username, updated_at } or null' } },
      },
    },
    '/api/v1/rooms': {
      get: {
        summary: 'List rooms you are a member of',
        tags: ['Rooms'],
        security: [{ oauth2: ['read'] }],
        responses: { '200': { description: 'List of rooms' } },
      },
    },
    '/api/v1/rooms/{id}': {
      get: {
        summary: 'View a room (channels, members, HTML/CSS)',
        tags: ['Rooms'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: 'Room object' } },
      },
    },
    '/api/v1/rooms/{id}/channels/{cid}/messages': {
      get: {
        summary: 'Fetch messages in a channel (last 50, or older than ?cursor=<message id>)',
        tags: ['Rooms'],
        security: [{ oauth2: ['read'] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
          { name: 'cid', in: 'path', required: true, schema: { type: 'integer' } },
          { name: 'cursor', in: 'query', schema: { type: 'integer' }, description: 'Message ID; returns messages older than it' },
        ],
        responses: { '200': { description: '{ data: { messages: [...], next: id-or-null } }' } },
      },
      post: {
        summary: 'Send a room message (must be Megolm-encrypted unless it is a sticker path)',
        tags: ['Rooms'],
        security: [{ oauth2: ['write'] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
          { name: 'cid', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        requestBody: {
          content: { 'application/json': { schema: {
            type: 'object',
            properties: {
              body: { type: 'string', description: 'Sticker path (/uploads/stickers/...) or empty' },
              proto: { type: 'string', enum: ['megolm'], default: 'megolm' },
              ciphertext: { type: 'string', maxLength: 20000 },
              group_session_id: { type: 'string' },
            },
          }}},
        },
        responses: {
          '201': { description: '{ id: messageId }' },
          '400': { description: 'End-to-end encryption required / unknown group session' },
        },
      },
    },
    '/api/v1/rooms/{id}/channels/{cid}/messages/{mid}': {
      delete: {
        summary: 'Delete a room message (own message, or moderator with MANAGE_MESSAGES / admin)',
        tags: ['Rooms'],
        security: [{ oauth2: ['write'] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
          { name: 'cid', in: 'path', required: true, schema: { type: 'integer' } },
          { name: 'mid', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        responses: {
          '200': { description: '{ ok: true }' },
          '403': { description: 'No permission' },
          '404': { description: 'Room, channel, or message not found' },
        },
      },
    },
    '/api/v1/rooms/{id}/session': {
      post: {
        summary: 'Publish or refresh your Megolm group session for a room, with encrypted keys per member',
        tags: ['Rooms'],
        security: [{ oauth2: ['write'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: {
          content: { 'application/json': { schema: {
            type: 'object',
            properties: {
              keys: { type: 'array', items: { type: 'object', properties: {
                recipient_id: { type: 'integer' },
                encrypted_key: { type: 'string' },
              }}},
              member_ids: { type: 'array', items: { type: 'integer' }, description: 'Members to mark as key recipients' },
              rotate: { type: 'boolean', description: 'Force session rotation' },
            },
          }}},
        },
        responses: { '200': { description: '{ session_id }' } },
      },
    },
    '/api/v1/rooms/{id}/session/keys': {
      get: {
        summary: 'Get pending Megolm session keys addressed to you',
        tags: ['Rooms'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: '{ keys: [{ key_id, session_id, room_id, sender_id, encrypted_key }] }' } },
      },
    },
    '/api/v1/rooms/{id}/session/keys/delivered': {
      post: {
        summary: 'Mark delivered session keys as received',
        tags: ['Rooms'],
        security: [{ oauth2: ['write'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: {
          content: { 'application/json': { schema: {
            type: 'object',
            properties: { key_ids: { type: 'array', items: { type: 'integer' } } },
          }}},
        },
        responses: { '200': { description: '{ ok: true }' } },
      },
    },
    '/api/v1/rooms/{id}/session/status': {
      get: {
        summary: "Which members hold the caller's room session keys",
        tags: ['Rooms'],
        security: [{ oauth2: ['read'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: '{ session_id, recipients: [...], empty_keys_for: [...] }' } },
      },
    },
    '/api/v1/rooms/{id}/bundle/{username}': {
      get: {
        summary: 'Room-scoped Olm prekey bundle of another member (no mutual-follower requirement)',
        tags: ['Rooms'],
        security: [{ oauth2: ['read'] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
          { name: 'username', in: 'path', required: true, schema: { type: 'string' } },
        ],
        responses: { '200': { description: '{ identity_key, ed25519_key, fallback_key, one_time_key }' } },
      },
    },
    '/api/v1/conversations': {
      get: {
        summary: 'List direct-message conversations (mutual followers only); each item includes security_active (Additional Security mode on for both sides)',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['read:direct'] }],
        responses: { '200': { description: 'List of conversations with last message info' } },
      },
    },
    '/api/v1/conversations/keys': {
      get: {
        summary: "Fetch your own legacy RSA public key and encrypted private key",
        tags: ['Direct Messages'],
        security: [{ oauth2: ['read:direct'] }],
        responses: { '200': { description: '{ public_key, encrypted_private_key }' } },
      },
      post: {
        summary: 'Publish or rotate your legacy RSA public key',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['write:direct'] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['public_key'],
            properties: {
              public_key: { type: 'string', maxLength: 5000 },
              encrypted_private_key: { type: 'string' },
            },
          }}},
        },
        responses: { '200': { description: '{ ok: true }' } },
      },
    },
    '/api/v1/conversations/prekeys': {
      post: {
        summary: 'Publish / refresh your Olm identity, ed25519 key, fallback key, and one-time prekeys (public material only)',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['write:direct'] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['identity_key', 'ed25519_key'],
            properties: {
              identity_key: { type: 'string', maxLength: 5000 },
              ed25519_key: { type: 'string', maxLength: 5000 },
              fallback_key: { type: 'string' },
              one_time_keys: { type: 'array', items: { type: 'object', properties: {
                id: { type: 'string' },
                public_key: { type: 'string', maxLength: 5000 },
              }}},
              backup: { type: 'string', maxLength: 200000, description: 'Password-encrypted Olm account backup for recovery' },
            },
          }}},
        },
        responses: { '200': { description: '{ ok: true, available: prekeyCount }' } },
      },
    },
    '/api/v1/conversations/prekeys/backup': {
      get: {
        summary: 'Download your password-encrypted Olm account backup',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['read:direct'] }],
        responses: { '200': { description: '{ backup }' } },
      },
    },
    '/api/v1/conversations/prekeys/count': {
      get: {
        summary: 'Count your unused one-time prekeys',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['read:direct'] }],
        responses: { '200': { description: '{ available }' } },
      },
    },
    '/api/v1/conversations/{username}': {
      get: {
        summary: 'Fetch message history with a user (newest-first, then reversed; ?cursor= for older)',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['read:direct'] }],
        parameters: [
          { name: 'username', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'cursor', in: 'query', schema: { type: 'string' } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 50, maximum: 100 } },
        ],
        responses: { '200': { description: 'List of messages' } },
      },
    },
    '/api/v1/conversations/{username}/messages': {
      post: {
        summary: 'Send a message (Olm-encrypted unless the body is a sticker path). If Additional Security is active for the conversation the message is flagged secure and deleted from the server once both sides have received it.',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['write:direct'] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['body'],
            properties: {
              body: { type: 'string', maxLength: 5000, description: 'Empty for encrypted messages, or a sticker path (/uploads/stickers/...) which skips encryption' },
              proto: { type: 'string', enum: ['olm', 'rsa'], default: 'olm' },
              sender_ciphertext: { type: 'string', maxLength: 5000, description: 'Olm payload (required unless the body is a sticker path)' },
              key_for_sender: { type: 'string' },
              key_for_recipient: { type: 'string' },
            },
          }}},
        },
        responses: {
          '201': { description: 'Created message (includes secure: true when Additional Security is active)' },
          '400': { description: 'End-to-end encryption required' },
          '403': { description: 'You can only message mutual followers' },
        },
      },
    },
    '/api/v1/conversations/{username}/security': {
      post: {
        summary: 'Toggle your Additional Security preference for this conversation (mutual opt-in; active only once both users enabled it)',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['write:direct'] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['enabled'],
            properties: { enabled: { type: 'boolean', description: 'Whether you want the mode on for this conversation' } },
          }}},
        },
        responses: { '200': { description: '{ enabled, mine, theirs, active }' } },
      },
    },
    '/api/v1/conversations/{username}/received': {
      post: {
        summary: 'Acknowledge receipt of secure messages. Once both participants have acknowledged, the server deletes the message (it then exists only on the users\' devices).',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['write:direct'] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['message_ids'],
            properties: { message_ids: { type: 'array', items: { type: 'integer' } } },
          }}},
        },
        responses: { '200': { description: '{ acked, deleted }' } },
      },
    },
    '/api/v1/conversations/{username}/bundle': {
      get: {
        summary: "Fetch a recipient's Olm bundle (identity + one claimed one-time prekey, else fallback)",
        tags: ['Direct Messages'],
        security: [{ oauth2: ['read:direct'] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: '{ identity_key, ed25519_key, one_time_key, fallback_key }' } },
      },
    },
    '/api/v1/conversations/{username}/safety': {
      get: {
        summary: 'Recipient identity keys for safety-number verification',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['read:direct'] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: '{ my_ed25519, their_ed25519, my_curve25519, their_curve25519 }' } },
      },
    },
    '/api/v1/conversations/{username}/keys': {
      get: {
        summary: "Fetch a user's legacy RSA public key",
        tags: ['Direct Messages'],
        security: [{ oauth2: ['read:direct'] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: '{ public_key }' } },
      },
    },
    '/api/v1/messages/{id}': {
      patch: {
        summary: 'Edit one of your messages (Olm-encrypted unless a sticker path)',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['write:direct'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object',
            required: ['body'],
            properties: {
              body: { type: 'string', maxLength: 5000, description: 'Empty for encrypted messages, or a sticker path which skips encryption' },
              proto: { type: 'string', enum: ['olm', 'rsa'] },
              sender_ciphertext: { type: 'string', maxLength: 5000, description: 'Olm payload (required unless the body is a sticker path)' },
              key_for_sender: { type: 'string' },
              key_for_recipient: { type: 'string' },
            },
          }}},
        },
        responses: { '200': { description: '{ ok: true }' } },
      },
      delete: {
        summary: 'Delete one of your messages',
        tags: ['Direct Messages'],
        security: [{ oauth2: ['write:direct'] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        responses: { '200': { description: '{ ok: true }' } },
      },
    },
  },
  components: {
    securitySchemes: {
      oauth2: {
        type: 'oauth2',
        flows: {
          authorizationCode: {
            authorizationUrl: '/api/v1/oauth/authorize',
            tokenUrl: '/api/v1/oauth/token',
            refreshUrl: '/api/v1/oauth/token',
            scopes: {
              openid: 'OpenID Connect — receive an id_token for authentication',
              read: 'Read your data (timelines, posts, profiles)',
              write: 'Create and delete posts, like, repost',
              follow: 'Follow and unfollow accounts',
              'media.write': 'Upload media files',
              notifications: 'Read and manage notifications',
              'read:direct': 'Read direct messages',
              'write:direct': 'Send direct messages',
              profile: 'Read and update your profile',
            },
          },
        },
      },
      sessionAuth: {
        type: 'apiKey',
        in: 'cookie',
        name: 'connect.sid',
        description: 'Browser session cookie (for registering apps and managing authorized apps)',
      },
    },
  },
  externalDocs: {
    description: 'Full documentation wiki (also served in-app at /docs)',
    url: '/docs/developers/api-overview',
  },
};

module.exports = spec;
