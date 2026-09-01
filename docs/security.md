# Security model

This page describes how Extrovert protects itself today. The audit history (what was fixed and when) is in [SECURITY.md](../SECURITY.md).

## Responsible disclosure

Security researchers may test the software under the conditions on the in-app **/security** page: no harm to running instances, and all findings reported **privately** to the maintainers before any public disclosure. Reports submitted via the in-app form land in a `security_reports` table visible **only to admins** (`/admin/security-reports`), and are never rendered publicly. The machine-readable policy is served at `/.well-known/security.txt` (RFC 9116); a direct email contact is advertised only when `SECURITY_CONTACT_EMAIL` is set — otherwise the in-app form and the `/security` URL are the contact.

## Authentication

- **Passwords:** bcrypt (10 rounds). Registration enforces a **12-character minimum and a 72-byte maximum** (ASVS 2.1.1). The byte cap (not a character cap) is deliberate: bcrypt truncates at 72 bytes, so anything longer would silently collide with its own prefix — multi-byte characters like emoji count toward the limit, and full Unicode remains supported.
- **Two-factor authentication (TOTP):** RFC 6238, hand-verified against the standard's test vectors. Secrets are encrypted at rest with AES-256-GCM keyed from `TOTP_ENCRYPTION_KEY` (scrypt-derived); ciphertexts carry a `v1.` prefix so plaintext or foreign formats fail closed. Recovery codes are random 40-bit values stored as `sha256$` hashes and consumed atomically (single use). The login challenge is a separate step that never sets `userId` until the code verifies: 5 wrong attempts reset it, failures are generic (no oracle for whether an account has 2FA), and both the challenge endpoint and the OAuth factor step are rate-limited (10/5 min) on top of per-session attempt counters. "Remember this device" issues a random 32-byte token in an httpOnly cookie; only its hash is stored, rows expire after 30 days. Enabling/disabling 2FA signs the account's *other* sessions out.
- **Passkeys (WebAuthn):** verified with `@simplewebauthn/server` — origin/RP-ID checks, single-use session-stored challenges with a 5-minute TTL, and signature-counter replay protection (an assertion whose counter moves backwards is rejected as a possible cloned authenticator). A passkey is treated as **full authentication**: no TOTP is demanded after it. Registration caps at 10 credentials per account; unknown credentials and tampered signatures return the same generic error as bad passwords.
- **OAuth + 2FA:** authorizing an OAuth application for a TOTP-enabled account requires a second factor first (per account, remembered for the session or via trusted-device cookie) — a stolen password-only session cookie cannot mint API tokens.
- **Sessions:** signed cookies (`express-session`), `httpOnly`, `SameSite=Lax`, `Secure` in production, 30-day lifetime, stored server-side in SQLite (`data/sessions.db`, expired rows purged). `SESSION_SECRET` is mandatory — the server refuses to start without it. Session IDs are regenerated on login and registration (anti session-fixation).
- **OAuth:** access tokens (24 h) and rotating refresh tokens (90 days) are random 64-hex values handed to the client once and stored **only as SHA-256 hashes** (`sha256$…`) at rest, so a leaked database dump cannot be replayed. Client secrets and authorization codes are stored the same way (client secrets are shown once at registration; codes are single-use and 10-minute-lived). Endpoints check token validity, expiry, required scopes, and ban status on every request.

## CSRF

- Every state-changing web request (POST/PUT/PATCH/DELETE) must carry the per-session CSRF token (`_csrf` field or `X-CSRF-Token` header), except:
  - `/api/*` routes (Bearer-auth — CSRF is irrelevant without cookies),
  - requests authenticated with a valid Bearer token (native clients),
  - the multipart upload endpoints (`/posts`, avatar upload, `/stickers/upload`, `/push/cancel-pending`).
- Multipart forms carry the token in the `X-CSRF-Token` header via a `<meta>` tag (see `public/e2ee.js`).
- Fresh sessions with mismatched tokens are redirected to a GET (so browsers pick up a new cookie) instead of hard-failing.

## Injection & content safety

- **Profile/room HTML:** sanitized with `sanitize-html` on save **and again on every render** — tag/attribute whitelists, `http(s)`/`mailto` only, no `data:` images, no scripts, no event handlers, `javascript:` URLs stripped.
- **CSS:** `expression()`, `behavior:`, `-moz-binding`, `@import`, `javascript:`/`data:` URLs, and **all** external `url(http/https)` references are neutralized; `</style>` breakout is escaped.
- **SQL:** all queries are parameterized (`node:sqlite` prepared statements) — no string-built SQL with user input.
- **Open redirects:** `safeRedirect()` and `back()` only allow same-origin relative URLs (no `//evil.com`).

## Uploads

- Extension whitelists server-side for posts (`.jpg .jpeg .png .gif .webp .bmp .mp4 .webm .mov .avi .mkv`), API media (`.jpg .jpeg .png .gif .webp .mp4 .webm .mov`), avatars (JPEG/PNG/WebP), and stickers (`.jpg .jpeg .png .gif .webp .bmp`) — the MIME header is not trusted on its own. No HTML/SVG/JS is ever accepted.
- Size caps everywhere (60 MB media, 10 MB avatars, 500 KB stickers).
- Random hex filenames; served with `X-Content-Type-Options: nosniff` and `Content-Disposition: inline`.

## Media access control

- Avatars and stickers are inherently public (they render on public pages).
- Post media and API media are stored under `/uploads/` and `/api-uploads/` and served **public-by-URL**: filenames are random hex (unguessable), but anyone who has a URL keeps access to it. There is no per-post ACL on media files (a known, documented trade-off). Content visibility (who can *see the post page*) is enforced separately by the network rules. Uploads are restricted to a safe allowlist (no HTML/SVG/JS — nothing served as active content) and served with `X-Content-Type-Options: nosniff` + `Content-Disposition: inline`.

## Rate limiting

- 30 req/min on login/register (per IP)
- 60 req/min on other web POSTs (per IP)
- 120 req/min on `/api/*` (per OAuth token, falling back to per IP)
- 10 req/5 min on second-factor verification (`/login/totp`, `/passkeys/*`, OAuth factor step)

## Headers (helmet CSP)

```
default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' http: https:;
media-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self';
connect-src 'self' ws: wss:; frame-ancestors 'none'
```

`script-src 'self'` means profile pages can't load external scripts even if HTML injection slipped through. Swagger UI is served from the same origin (`/developers/swagger-ui/*` — vendored `swagger-ui-dist`, no CDN) under this same CSP, so no route loosens it.

## E2EE threat model

- DMs (Olm) and room messages (Megolm) are encrypted client-side; the server stores ciphertext and public key material only.
- The server **enforces** encryption: plaintext non-sticker messages are rejected with `400`.
- One-time prekeys are claimed atomically on bundle fetch; session keys are delivered wrapped in 1:1 Olm sessions.
- The stored *encrypted* RSA private key is client-encrypted — the server cannot decrypt it.
- The client can upload a password-encrypted account backup for recovery.
- **Limitation:** there is no key-transparency/consistency verification beyond user-comparable safety numbers (ed25519 fingerprints); a malicious server could in principle substitute keys. Verify safety numbers for high-value conversations.

## IP spoofing & trust proxy

`TRUST_PROXY` defaults to **false**. Only set it when running behind a proxy that strips client-sent `X-Forwarded-For`. With `trust proxy` enabled and no stripping proxy, clients could forge their IP and bypass per-IP rate limits or referral anti-farming checks.

## Referral anti-farming

A registration via a referral link is rejected when the registrant's IP matches the referrer's stored IP (`referrer_ip`, refreshed on each login), preventing self-referral farming.

## Notifications & tokens

- Push `cancel_token` values are unguessable UUIDs delivered only via the callee's own push channels; `POST /push/cancel-pending` requires no session but only cancels the matching pending call.
- Push subscription endpoints are SSRF-guarded at subscribe time: must be `https:` URLs pointing at public hosts (loopback, RFC1918, link-local, IPv4-mapped/IPv6 private/6to4/NAT64/Teredo forms, and hosts that don't resolve to a public address are rejected; device-token platforms `fcm`/`apns`/`ws` are unaffected). At send time the endpoint is re-validated and the connection is pinned to the resolved public address (custom `https.Agent` lookup), closing DNS-rebinding between validation and connection.
- OAuth revocation always returns `{ok:true}` to prevent token enumeration.

## Data hygiene

- `audit_log` records privileged/security-relevant actions (OAuth issuance, follows, post create/delete, avatar changes, DM key updates).
- Idempotency keys expire after 24 h and are cleaned on write.
- Sessions are purged on expiry; signaling state is in-memory and evaporates on restart (pending calls are lost — the caller's `calling_offline` wait fails cleanly).

## Known trade-offs

| Item | Status |
|---|---|
| Media files public-by-URL | Accepted and documented (above) |
| OIDC key rotation | Supported in code (`rotateKeys`), no admin UI |
| JWT/refresh token reuse detection | Refresh tokens are rotated on use; a reused token is simply invalid |
| Avatar storage path normalization | One-time migration in `db.js` keeps `/uploads/`-prefixed values for templates |
| Passkeys bound to hostname | WebAuthn rpID = request hostname; changing an instance's public hostname invalidates registered passkeys (documented in configuration.md) |
| `TOTP_ENCRYPTION_KEY` rotation | Changing it breaks existing TOTP enrollments (users can still recover via recovery codes… which also require the secret — treat the key as a backup-critical secret) |
