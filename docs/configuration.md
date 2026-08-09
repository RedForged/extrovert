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
| `EXTV_CAPTCHA_DIFFICULTY` | no | `4` | Register captcha strength (integer 1–5). It is the number of leading hex zeroes the proof-of-work must produce — each +1 makes solving 16× harder for the client (default ≈ 65k hashes, under a second). The search range scales with the difficulty so legit solves stay near-certain; 5 ≈ 8M hashes (a few seconds). Higher values also slow legit users' registration; see [Register captcha](#register-captcha). |
| `VAPID_PUBLIC_KEY` | no | — | Web Push public key (see Push section). Without it, push endpoints 404 and no notifications are sent. |
| `VAPID_PRIVATE_KEY` | no | — | Web Push private key. |
| `VAPID_SUBJECT` | no | `mailto:admin@extrovert.local` | VAPID contact — some push services require a `mailto:`. |
| `SECURITY_CONTACT_EMAIL` | no | `admin@extrovert.local` | Contact shown on the responsible-disclosure page (`/security`) and in `/.well-known/security.txt`. |

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

`/register` is protected by a **self-hosted, self-created proof-of-work
captcha** — no third-party service, no external requests, no API keys. The
client finds a `number` such that `sha256(challenge + salt + number)` starts
with `EXTV_CAPTCHA_DIFFICULTY` hex zeroes (default 4); the server verifies with
a single hash, so the cost is paid by the client and verification is not a DoS
vector.

- The challenge is random per request, bound to the session, expires after 5
  minutes, and is **single-use**: every registration attempt consumes it, so a
  solved proof can never be replayed and username-enumeration attempts each
  cost a fresh solve.
- The widget (`/static/captcha.js`) runs a pure-JS SHA-256 — no
  `crypto.subtle` — so it works on plain-HTTP instances too. Registration
  requires JavaScript for the proof-of-work step.
- It stops scripted bots (curl, mass-signup tools) that don't do the work.
  It is anti-spam, **not** a security boundary: a determined attacker can burn
  CPU and solve it. Raise `EXTV_CAPTCHA_DIFFICULTY` (max 5) for stronger
  protection at the cost of slower legit registration.

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
