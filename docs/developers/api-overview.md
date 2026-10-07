# REST API overview

Base path: `/api/v1` · Live docs: `/developers/docs` (Swagger UI) and `/developers/openapi.json` (OpenAPI 3.1; `/api/v1/openapi.json` redirects there).

## Conventions

### Response envelope

Successful responses wrap data in an object:

```json
{ "data": … }
```

Paginated responses add a cursor:

```json
{
  "data": [ … ],
  "pagination": { "next": "eyJpZCI6NDJ9" }
}
```

`next` is `null` when there are no more pages. Pass it back as `?cursor=<value>`.

### Errors

Standard errors use RFC 7807-ish JSON:

```json
{ "type": "about:blank", "title": "Not Found", "status": 404, "detail": "…" }
```

OAuth token-endpoint errors use the OAuth shape `{ "error": "invalid_client", "error_description": "…" }`.

| Status | Meaning |
|---|---|
| `400` | Bad request (missing/invalid field) |
| `401` | Missing/invalid/expired token |
| `403` | Token lacks required scope, account banned, or action not allowed |
| `404` | Not found — **also used for content you can't see** (never reveals existence) |
| `409` | Conflict (e.g. already reposted) |
| `429` | Rate limited (see `X-RateLimit-*` headers) |

### Timestamps

Body fields are **milliseconds since epoch** (e.g. `created_at` on posts/accounts). The OAuth token response's `created_at` and JWT claims are **seconds since epoch** — don't mix them.

## Authentication

Three credential types:

1. **Session cookie** (browser web app). Several web-facing routes (`/api/v1/oauth/apps`, `/authorized_apps`, `/oauth/authorize`) use session cookies; most REST endpoints use Bearer tokens.
2. **Personal Access Tokens (PATs)** (for native clients, scripts, and CLI bots):
   Tokens prefixed with `ext_pat_...` created via `POST /api/v1/accounts/tokens`. They authenticate directly as Bearer tokens without requiring interactive OAuth webview popups:
   ```
   Authorization: Bearer ext_pat_...
   ```
3. **OAuth 2.0 Bearer token** (for third-party web apps and standard OAuth flows):
   ```
   Authorization: Bearer <access_token>
   ```

Auth middleware (`src/api-auth.js`) validates OAuth bearer tokens and PATs, their expiry/revocation, required **scopes**, and the user's ban status.

### App Registration

Clients can register in two ways:
- **Dynamic Client Registration** (`POST /api/v1/apps`): Unauthenticated RFC 7591 / Mastodon-compatible registration for native and desktop clients.
- **Web App Registration** (`POST /api/v1/oauth/apps`): Session-authenticated registration for developers managing apps through the web UI at `/settings/developers`.

### Scopes

| Scope | Endpoints |
|---|---|
| `openid` | `userinfo`, ID-token issuance |
| `read` | Timelines, posts, accounts, search, media, rooms (read) |
| `write` | Create/delete posts, like/unfavourite, reblog, comment, room messages |
| `follow` | Follow/unfollow |
| `media.write` | `POST /media` |
| `notifications` | Notifications list/clear/unread/SSE |
| `read:direct` | Conversations, message history, keys/bundles |
| `write:direct` | Send/edit/delete messages, publish keys |
| `profile` | `update_credentials`, avatar upload, account tokens and sessions |
| `email` | Email address changes |
| `admin` | Instance administration (admin accounts only) |

Scopes are checked **exactly** — a token must contain each required scope (there is no hierarchy: `write` does not imply `read`). Registering an app defaults its scope list to `read`.

## Rate limits

| Limit | Key |
|---|---|
| **120 requests/minute** on `/api/*` | OAuth bearer token when present, otherwise IP |

See `X-RateLimit-Limit` / `X-RateLimit-Remaining` / `X-RateLimit-Reset` headers. Web endpoints have separate limits (30/min auth per IP, 240/min other authenticated POSTs per user, 600/min on E2EE crypto paths).

## CORS

The API sends `Access-Control-Allow-Origin: *` for all `/api` requests and answers preflight `OPTIONS` with the allowed methods/headers (`Authorization`, `Content-Type`, `Idempotency-Key`, `X-CSRF-Token`). Native clients authenticate with an explicit Bearer header (no cookies), so `*` is safe.

## Idempotency

`POST /api/v1/statuses` supports an `Idempotency-Key` header. Replays of the same key within 24 h return the original response with `X-Idempotency-Replayed: true` instead of creating duplicates.

## Pagination

Cursors are base64url-encoded JSON like `{"id": 42}` pointing at the last item of the previous page. `limit` defaults to 20 and caps at 40. The home timeline and room-message endpoints have their own cursor semantics (see the endpoint reference).

## Timelines & visibility

- `GET /api/v1/timelines/home` — your network feed, ranked by the [feed algorithm](../using/feed.md), cursor-paginated.
- `GET /api/v1/timelines/public` — **always 403**: Extrovert deliberately has no public timeline.

## Media & uploads

- Upload: `POST /api/v1/media` (multipart, field `file`, ≤ 60 MB). Images get `width`/`height` via `sharp`. Files land in `data/api-uploads/` with random hex names.
- `GET /api/v1/media/:id` — metadata, **owner only** (`403` otherwise).
- Media URLs (`/api-uploads/…`) are unguessable-but-public (see [Security](../security.md)).
- Post creation can take `media` in the same multipart request (photo/video types).

## Search

`GET /api/v1/search?q=<query>&type=accounts|statuses` — no `type` returns both. Account search is instance-wide (banned excluded); post search is limited to your visible network.

## Announcement

`GET /api/v1/announcement` returns the server-wide announcement banner, or `data: null` when none is set.

## Endpoint list

See the [full endpoint reference](endpoints.md). For auth flows: [OAuth 2.0 & OpenID Connect](oauth-oidc.md). For streaming: [Realtime](realtime.md).
