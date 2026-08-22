# OAuth 2.0 & OpenID Connect

Extrovert implements **OAuth 2.0** (Authorization Code flow, with PKCE) and **OpenID Connect** (OIDC) on top of it. This is how third-party web apps and native/mobile clients authenticate. The same machinery is used by the REST API.

## Discovery

| Document | URL |
|---|---|
| OIDC discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| Swagger UI | `/developers/docs` |
| OpenAPI spec | `/developers/openapi.json` |

The discovery document advertises:

- `response_types_supported: ["code"]` (authorization code only)
- `grant_types_supported: ["authorization_code", "refresh_token"]`
- `response_modes_supported: ["query"]`
- `token_endpoint_auth_methods_supported: ["client_secret_post", "none"]` — public clients (native apps) are supported
- `code_challenge_methods_supported: ["S256", "plain"]`
- `id_token_signing_alg_values_supported: ["RS256"]`, `subject_types_supported: ["public"]`

## Scopes

| Scope | Meaning |
|---|---|
| `openid` | Issuance of an `id_token`; access to `/oauth/userinfo` |
| `profile` | Profile claims (`preferred_username`, `name`, `picture`) in the ID token / userinfo |
| `read` / `write` | Read / write access to posts, timelines, accounts, rooms |
| `follow` | Follow / unfollow |
| `media.write` | Upload media |
| `notifications` | Notifications + SSE stream |
| `read:direct` / `write:direct` | Encrypted DMs: read history/keys, send/edit/delete |
| `profile` (also used alone) | `update_credentials`, avatar upload |

Scopes are **exact-match** (no hierarchy). The default scope for new apps is `read`.

## Flow walkthrough

### 1. Register your app

```
POST /api/v1/oauth/apps
Cookie: <your session>

{ "name": "My Client", "redirect_uris": "https://app.example.com/cb",
  "website": "https://app.example.com", "scopes": "openid profile read write" }
```

or use the form at `/settings/developers`. Response:

```json
{ "data": { "id": "1", "client_id": "…48 hex…", "client_secret": "…64 hex…",
            "redirect_uris": ["https://app.example.com/cb"], "scopes": "openid profile read write" } }
```

Keep the secret server-side. Public/native clients can omit the secret (see `clientAppAuth`: the secret is only validated **if sent**).

### 2. Redirect the user to authorize

```
GET /api/v1/oauth/authorize?client_id=…&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb
  &response_type=code&scope=openid+profile+read&state=xyz&nonce=abc123
  &code_challenge=<S256(verifier)>&code_challenge_method=S256
```

- `redirect_uri` must exactly match a registered URI.
- The user sees the consent page listing the app and requested scopes.
- If the authorizing account has **two-factor authentication enabled**, a second-factor step is shown *before* consent: the user must enter a TOTP or recovery code (once per session per account; skipped on browsers with a valid "remember this device" cookie). Your app doesn't need to do anything — after verification the consent page renders as usual. A user signing in with a **passkey** skips this step (the passkey already proved possession).
- `state` is echoed back (use it for CSRF protection). `nonce` is echoed into the `id_token`.
- PKCE is strongly recommended for native clients: `code_challenge = base64url(sha256(verifier))`.

Approve → redirect: `https://app.example.com/cb?code=<32-hex>&state=xyz`
Deny → redirect: `https://app.example.com/cb?error=access_denied&state=xyz`

### 3. Exchange the code

```
POST /api/v1/oauth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "client_id": "…",
  "client_secret": "…",            // optional for public clients
  "code": "…",
  "code_verifier": "…",            // required if you sent a code_challenge
  "redirect_uri": "https://app.example.com/cb"
}
```

Response:

```json
{
  "access_token": "…", "token_type": "Bearer", "scope": "openid profile read",
  "created_at": 1750000000,        // unix SECONDS
  "expires_in": 86400,             // 24 h
  "refresh_token": "…",
  "id_token": "eyJ…"               // only when scope included openid
}
```

Authorization codes are single-use and expire after 10 minutes. The code is bound to the app, user, scopes, redirect URI, and PKCE challenge.

### 4. Verify the ID token

`id_token` is an RS256 JWT. Verify against `/.well-known/jwks.json` and check:

- `iss` == your configured `OIDC_ISSUER` (default `https://extrovert.redforged.eu` — self-hosters must set it)
- `aud` == your `client_id`
- `exp`, `iat` sanity
- `nonce` matches the one you sent (if you sent one)
- `auth_time` present

Claims: `sub` (the Extrovert user id, as a string), `preferred_username`, `name`, `picture` (absolute URL) when `profile` was granted.

### 5. UserInfo (optional)

```
GET /api/v1/oauth/userinfo
Authorization: Bearer <access_token>
```

Requires `openid` scope. Returns `sub`, plus profile claims with the `profile` scope.

### 6. Refresh tokens

Access tokens live **24 hours**. When one expires (`401`), exchange the refresh token:

```
POST /api/v1/oauth/token
{ "grant_type": "refresh_token", "client_id": "…", "refresh_token": "…" }
```

Refresh tokens live **90 days** and are **rotated on every use**: the old refresh token is invalidated and a new pair is returned. Keep the new ones. (Clients that don't refresh within 90 days must re-authenticate.)

### 7. Revocation

```
POST /api/v1/oauth/revoke
{ "token": "<access or refresh token>", "client_id": "…" }
```

Always returns `{ok:true}`. Users can also revoke apps at `/settings/developers` or via `POST /api/v1/oauth/authorized_apps/:appId/revoke` (session auth).

## Native client notes

- Public client: register an app, use PKCE (S256), never send a client secret.
- Authenticate the WebSocket as `wss://host/ws?token=<access_token>` for realtime features (presence, calls, DM delivery).
- Use `GET /api/v1/notifications/stream` (SSE) or polling `GET /api/v1/notifications` (120 req/min budget) for badges.
- Call push does **not** use web-push: keep a WebSocket push channel (`{type:"push_register"}`) open via your foreground service (see [Realtime](realtime.md)).

## Key management

- Keys are generated on first start and stored at `data/oidc-keys.json` (chmod 600). Alternatively supply `OIDC_PRIVATE_KEY` (PEM) + `OIDC_KID` env vars.
- `rotateKeys()` (in `src/oidc.js`, no HTTP endpoint) rotates the signing key; up to 2 previous public keys stay in the JWKS so previously issued ID tokens still verify.
