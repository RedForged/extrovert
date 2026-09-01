# Security Audit — Fixes Applied

## Reporting a vulnerability

Security researchers are welcome. Please report findings **privately**:

- In-app: the **/security** page invites testing and has a private report form — the page itself is public, the submitted **reports are visible only to instance admins** (`/admin/security-reports`).
- Machine-readable policy: `/.well-known/security.txt` (RFC 9116).
- Direct email: optional — set `SECURITY_CONTACT_EMAIL` on the instance to advertise a contact address; when unset, no email is shown and the in-app form is the contact.

Do not publicly disclose findings before they are fixed, and do not test instances you do not own or are not authorized to test.

Current security posture is documented in [docs/security.md](docs/security.md). This file is the historical audit record.

| # | Vulnerability | Fix |
|---|--------------|-----|
| 1 | **No CSRF protection** | Per-session CSRF token validated on all POST/PUT/PATCH/DELETE requests; token embedded in every form as `_csrf` (and as `X-CSRF-Token` header for multipart/XHR flows). Skipped only for `/api/*` (Bearer auth), valid Bearer-authenticated requests, and the multipart upload endpoints. |
| 2 | **Open redirect** via Referer | `back()` functions now reject `//evil.com` protocol-relative URLs; login `next` uses `safeRedirect()` |
| 3 | **File upload MIME spoofing** | Whitelist-based extension validation server-side (`.jpg`, `.png`, `.mp4`, etc.) — MIME type alone is no longer trusted |
| 4 | **`data:` URI on `<img>` → SVG XSS** | Removed `data` from `allowedSchemesByTag.img` in sanitize-html config |
| 5 | **No rate limiting** | `express-rate-limit` added: 30 req/min on auth routes, 60 req/min on all other POST endpoints, 120 req/min on `/api/*` (keyed on OAuth bearer token when present, else IP) |
| 6 | **No security headers** | `helmet` added with CSP (no external scripts), `X-Frame-Options`, `X-Content-Type-Options`, etc. |
| 7 | **Weak session secret** | `SESSION_SECRET` env var is now **required** — server exits at startup if unset; `.env.example` added |
| 8 | **Missing `secure`/`sameSite` cookie flags** | `sameSite: 'lax'`, `secure` in production (`EXTV_COOKIE_SECURE` to override) |
| 9 | **CSS injection (data exfiltration)** | `sanitizeCSS()` strips all `url(http://...)` and `url(https://...)` in addition to previous filters (`expression()`, `javascript:`/`data:` URLs, `behavior:`, `-moz-binding`, `@import`) |
| 10 | **Oversized body parser limit** | Reduced to `1mb` for both urlencoded and JSON parsers |
| 11 | **Username enumeration** | Registration and login use a generic error message; API visibility checks return `404` (not `403`) for out-of-network content |
| 12 | **No password max length** | Added 128-char max on registration and login (bcrypt truncates at 72 bytes) |
| 13 | **Upload MIME sniffing** | `X-Content-Type-Options: nosniff` set on `/uploads` and `/api-uploads` static file serving |
| 14 | **E2EE key upload without CSRF** | `e2ee.js` reads the CSRF token from a `<meta>` tag and sends it as `X-CSRF-Token` header |
| 15 | **IP spoofing via `X-Forwarded-For`** | `TRUST_PROXY` now defaults to `false`; only set it behind a real reverse proxy that strips client-sent headers |
| 16 | **OIDC signing key on disk** | `data/oidc-keys.json` written with `0600` permissions; `OIDC_PRIVATE_KEY` env override available |
| 17 | **Idempotency-key table growth** | Idempotency keys expire after 24 h and are cleaned on every write |
| 18 | **Refresh-token expiry** | Refresh tokens expire after 90 days (`refresh_expires_at`) and rotate on every use |
