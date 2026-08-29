# Configuration

Extrovert is configured entirely through environment variables. There is no config file. A template lives at `.env.example`.

## Reference

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `SESSION_SECRET` | **yes** | — | Signs session cookies. Server refuses to start without it. Changing it logs everyone out. |
| `PORT` | no | `3000` | HTTP port. |
| `NODE_ENV` | no | — | Set to `production` in production. Controls cookie `secure` mode and logging. |
| `OIDC_ISSUER` | no | `https://extrovert.redforged.eu` | The issuer URL advertised in OpenID Connect discovery, and the `iss` claim of ID tokens. Self-hosters **must** set this to their real public URL. |
| `OIDC_PRIVATE_KEY` | no | — | PEM private key for OIDC ID-token signing. If set, overrides the key file on disk (see below). |
| `OIDC_KID` | no | random | Key ID used when `OIDC_PRIVATE_KEY` is set. |
| `TRUST_PROXY` | no | `false` | Express trust-proxy setting, e.g. `loopback,10.0.0.0/8`. Set only when running behind a reverse proxy that strips client-sent `X-Forwarded-For`. Leave `false` otherwise (see Security). |
| `EXTV_DB_PATH` | no | `data/extrovert.db` | Override the main database path (useful for tests/isolated instances). |
| `EXTV_SESSION_DB_PATH` | no | `data/sessions.db` | Override the session database path. |
| `EXTV_COOKIE_SECURE` | no | auto | `false` for local HTTP dev; `true` to force `Secure` cookies. Defaults to auto (secure in production, insecure otherwise). |
| `VAPID_PUBLIC_KEY` | no | — | Web Push public key (see Push section). Without it, push endpoints 404 and no notifications are sent. |
| `VAPID_PRIVATE_KEY` | no | — | Web Push private key. |
| `VAPID_SUBJECT` | no | `mailto:admin@extrovert.local` | VAPID contact — some push services require a `mailto:`. |
| `SECURITY_CONTACT_EMAIL` | no | `admin@extrovert.local` | Contact shown on the responsible-disclosure page (`/security`) and in `/.well-known/security.txt`. |
| `EXTV_EMAIL_POLICY` | no | `off` | Email verification policy: `off` / `optional` / `required` (see [docs/mail.md](mail.md)). |
| `EXTV_MAIL_*` | no | see [docs/mail.md](mail.md) | Built-in mail server settings (From address, DKIM, relay, STARTTLS, …). Also configurable live from `/admin/mail`. |
| `TOTP_ENCRYPTION_KEY` | for 2FA | — | Key used to encrypt TOTP secrets at rest (AES-256-GCM). Generate with `openssl rand -base64 32`. Without it, users can't enable 2FA (passkeys still work). Changing it invalidates existing TOTP enrollments. |
| `EXTV_AUTH_RATE_LIMIT` | no | `30` | Login/register requests per minute per IP. |
| `EXTV_SECOND_FACTOR_RATE_LIMIT` | no | `10` | Second-factor verification attempts per 5 minutes (login challenge + passkey ceremonies). |
| `EXTV_OAUTH_FACTOR_RATE_LIMIT` | no | `10` | Second-factor attempts per 5 minutes on the OAuth authorize endpoint. |
| `EXTV_ACTION_RATE_LIMIT` | no | `240` | General authenticated POST actions per minute per user (posts, follows, likes, …). |
| `EXTV_CRYPTO_RATE_LIMIT` | no | `600` | E2EE crypto/transport POSTs per minute per user (`/chats/*/claim`, `/chats/*/send`, `/chats/rekey/*`, …). Set generously — throttling these is what breaks Olm decryption. |

### `.env` files

The app does **not** load `.env` files by itself — use your shell, a process manager (systemd `Environment=`), Docker Compose `environment:`, or `export` statements. Example:

```bash
export SESSION_SECRET="$(openssl rand -hex 32)"
export NODE_ENV=production
export OIDC_ISSUER=https://social.example.com
export TRUST_PROXY=loopback
export VAPID_PUBLIC_KEY=...
export VAPID_PRIVATE_KEY=...
```

## OIDC signing keys

- On first startup the server generates an RSA-2048 keypair and writes it to **`data/oidc-keys.json`** (chmod `0600`). This file contains the private signing key — treat it like a password and include it in backups.
- Alternatively, supply the key via `OIDC_PRIVATE_KEY` (PEM) plus `OIDC_KID`; the file is then ignored.
- The public JWKS is served at `/.well-known/jwks.json`. Previous keys are kept in the JWKS during rotation (max 2) so clients can verify ID tokens issued before a rotation.

## Two-factor authentication & passkeys

Users manage both features on **Settings → Security** (`/settings/security`).

**TOTP 2FA** requires `TOTP_ENCRYPTION_KEY` to be set on the server — TOTP secrets are encrypted at rest with it (AES-256-GCM, `v1.`-prefixed ciphertext). Without the key the setup button explains that 2FA is unavailable; existing enrollments keep working but can't be re-created after a key change. Users get 10 single-use recovery codes (stored as SHA-256 hashes) and can opt to remember a browser for 30 days (`extv_td` cookie; only a hash is stored). Enabling or disabling 2FA signs all *other* sessions of the account out.

**Passkeys (WebAuthn)** work without any extra configuration. The relying-party ID is derived from the request hostname — credentials are bound to the hostname the account registered them on, so don't switch between `example.com` and `www.example.com`. A passkey alone is sufficient to sign in (it is phishing-resistant multi-factor by itself); TOTP is not demanded afterwards. Up to 10 passkeys per account.

**OAuth apps:** when the authorizing account has TOTP enabled, the consent flow demands a code first (per account, once per session) unless the browser holds a valid trusted-device cookie — an OAuth token must not be mintable from a merely password-authenticated session.

Rate limits for the new endpoints are tunable via `EXTV_AUTH_RATE_LIMIT`, `EXTV_SECOND_FACTOR_RATE_LIMIT`, and `EXTV_OAUTH_FACTOR_RATE_LIMIT` (see Reference).

## Web Push (browser notifications)

1. Generate a VAPID keypair:

   ```bash
   node scripts/generate-vapid-keys.js
   ```

2. Set `VAPID_PUBLIC_KEY` and `VAPID_PRIVATE_KEY` (and optionally `VAPID_SUBJECT`) in the server environment.
3. Logged-in browsers register a subscription automatically (`/push/vapid-public`, `/push/subscribe`). The service worker (`public/sw.js`) turns push events into ringing call notifications with Answer/Decline actions.

Push is optional: everything works without it; push endpoints return `404 Push not configured` until the variables are set.

Native/mobile clients do **not** need VAPID — they receive call payloads over the WebSocket push channel instead (see [Realtime](developers/realtime.md)).

## Register captcha

`/register` is protected by a **self-hosted image captcha** — fully inside the
Extrovert instance/image: no third-party service, no external requests, no API
keys. The server renders a distorted-text SVG (`GET /register/captcha`, served
`image/svg+xml` with `Cache-Control: no-store`) and the client types the
characters. A plain terminal/scripted client has no way to read the image, so
mass registration via curl/POST is stopped outright.

- The challenge is random per request, bound to the session, expires after 5
  minutes, and is **single-use**: every registration attempt consumes it, so an
  answer can never be replayed and username-enumeration attempts each cost a
  fresh challenge. The expected answer lives only in the server-side session
  store — never in the HTML.
- The image is generated by the battle-tested `svg-captcha` generator (MIT, pure JS, bundled font, regular npm dependency — fully offline). The "new characters" button
  re-loads the image (which regenerates the challenge); answers are
  case-insensitive and confused characters (0/O, 1/l/I) are excluded.
- It stops scripted bots (curl, mass-signup tools). It is anti-spam, **not** a
  security boundary: a bot with OCR or a headless browser can still read the
  image. Only a managed behavioral service would go further, and that would
  require external JS — excluded by this project's self-hosting constraint.
  Registration requires JavaScript only for the refresh button.

## Rate limits (built-in)

| Limit | Scope | Key |
|---|---|---|
| 30 req/min | `POST /login` and `POST /register` | IP |
| 60 req/min | All other `POST` web routes | IP |
| 120 req/min | `/api/*` | OAuth bearer token, fallback IP |

These are constants in `src/server.js` and not configurable via environment variables.

## Hard limits (not configurable)

| Thing | Limit |
|---|---|
| Post body | 5,000 chars (API; web trims) |
| Comment body | 1,000 chars |
| DM body | 5,000 chars |
| Media upload | 60 MB per file |
| Avatar upload | 10 MB per file |
| Sticker upload | 500 KB per file |
| API pagination limit | 40 items per page (default 20) |

## Upgrading / migrations

Schema changes run automatically at startup in `src/db.js` (`CREATE TABLE IF NOT EXISTS` + idempotent `ALTER TABLE ... ADD COLUMN` inside `try/catch`). Just restart the server with the new code; the database migrates itself. Keep a backup of `data/` before upgrading.
