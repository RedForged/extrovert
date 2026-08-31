# Changelog

All notable changes to **Extrovert** are documented in this file. The project
follows [Semantic Versioning](https://semver.org/). This is the first tagged
release: the codebase carries its version in `package.json`, and the sections
below reconstruct the history behind each version.

## [1.0.3] - 2026-08-30

### Features
- **Two-factor authentication (planned.md F2)**: TOTP second factor with the
  full supporting surface.
  - Enrollment at **Settings → Security** (`/settings/security`): QR code +
    manual base32 secret, one confirming code required, then 10 single-use
    recovery codes shown once (stored only as `sha256$` hashes).
  - TOTP secrets are **encrypted at rest** (AES-256-GCM, `TOTP_ENCRYPTION_KEY`
    env key, scrypt-derived; `v1.`-prefixed ciphertext fails closed on foreign
    formats). Without the key configured, 2FA is unavailable and the UI says so.
  - Login for enrolled accounts becomes a two-step flow: password first, then a
    challenge page (`/login/totp`) accepting a 6-digit code or a recovery code.
    `userId` stays unset until verification, so protected pages remain locked;
    5 wrong attempts force a restart; all failures are generic (no oracle).
  - **Remember this device** (30 days): hashed-token `trusted_devices` table +
    httpOnly `extv_td` cookie suppresses re-prompting; revocable per-device or
    wholesale from the Security page.
  - Enabling/disabling 2FA signs the account's **other** sessions out (F2.7);
    disabling requires a current code or recovery code — never just a password.
  - **OAuth consent is gated behind the second factor** (F2.5): authorizing an
    app for a TOTP-enabled account demands a code before consent (per account,
    once per session), so API tokens can't be minted from a password-only
    session. Documented in docs/developers/oauth-oidc.md.
- **Passkeys / WebAuthn (planned.md F3)**: passwordless sign-in via platform or
  roaming authenticators.
  - "Sign in with a passkey" on the login page (discoverable-credential flow,
    optional username narrowing) — a passkey is **full authentication**: no
    password and no TOTP step afterwards.
  - Enrollment + management on Settings → Security: rename, delete, max 10 per
    account. Verification via `@simplewebauthn/server` (new dependency):
    origin/RP-ID checks from the request host, single-use session challenges
    (5-min TTL), signature-counter replay protection (backwards counters are
    rejected as cloned authenticators).
  - New tables: `passkeys`, `recovery_codes`, `trusted_devices`; additive
    migrations, cleaned up in the account-deletion cascade. All credential
    events land in `audit_log`.
  - Tighter rate limits on every factor endpoint (10/5 min by default, tunable
    via `EXTV_SECOND_FACTOR_RATE_LIMIT` / `EXTV_OAUTH_FACTOR_RATE_LIMIT`;
    login/register now `EXTV_AUTH_RATE_LIMIT`).
- **Multi-account (planned.md F1)**: sign in to several accounts on one browser
  and switch without logging out. The session model now tracks an ordered list
  of signed-in accounts (`req.session.accountIds`) with `req.session.userId` as
  the active account — every existing `userId` read site is unchanged.
  - Account switcher in the top bar, plus `/account/switch` (picker) and
    `POST /account/switch` / `POST /account/remove` endpoints.
  - Login becomes "add to list + set active"; **logout removes only the active
    account** (whole session is destroyed only when the last account is
    removed, so switching never invalidates other sessions or OAuth tokens);
    "Sign out of all accounts" is available in the switcher menu.
  - **OAuth account selection**: when several accounts are signed in, the
    consent page embeds an "Authorize as" picker; the chosen account's id is
    bound to the authorization code (and its OIDC `nonce`), so the token and
    userinfo follow the selected account. The picker never bypasses consent —
    it only changes which account authorizes.
  - Account lists persist across restarts via the `account_sessions` table in
    the DB-backed session store (`data/sessions.db`).
  - New `npm run test:multi-account` suite (wired into CI) covering list
    seeding, add-account preservation, switching, per-account logout/removal,
    OAuth account binding, tampered-`account_id` rejection, and legacy-session
    fallback.
- **Register captcha (anti-bot)**: `/register` is gated by a **self-hosted
  image captcha**, fully inside the instance/image — no third-party service,
  no external requests, no API keys. The server renders a distorted-text SVG
  (`GET /register/captcha`, `image/svg+xml`, `Cache-Control: no-store`) using
  the `svg-captcha` generator (npm dependency); the client types the characters, so a
  plain terminal/scripted client cannot register. Challenges are random,
  session-bound, expire after 5 minutes, and are single-use (an answer cannot
  be replayed; every username-enumeration attempt costs a fresh challenge); the
  expected answer lives only in the server-side session store. Stops scripted
  bots; documented as anti-spam rather than a security boundary (OCR-capable
  bots can still read the image). Replaces the earlier proof-of-work captcha,
  which a terminal could solve by brute force.
  New `npm run test:captcha` suite (wired into CI) covering verification
  semantics and E2E register rejection of missing/wrong/replayed answers.

### Fixes
- **Rendered template text leaking as markup (settings)**: the email
  verification field printed `Email <span class="muted">(change)</span>` in
  cleartext — the span was built inside an escaped `<%= %>` expression — and
  the update button showed a double-escaped `&amp;`. Both are now real template
  markup; the "✓ verified" badge uses the SVG check icon.
- **Post stat counts stopped updating after any like/share/comment**: the
  client matched counts by emoji (`❤️`, `💬`) that server-rendered SVG icons had
  long replaced, and clicking Like destroyed the heart icon. Stats are now
  addressed via `data-stat` hooks and icons are rebuilt through a new shared
  client icon helper (`public/icons.js`), which also replaces the emoji glyphs
  (`♥` `⋮` `🔊` `📞`) in dynamically created UI.
- **Emoji-as-icon sweep**: remaining text glyphs (✓ → `arrowRight`/`arrowLeft`
  `★` `🔊` `📞` `⋮` in feed, admin, admin-mail, verify-email, rooms, call
  overlays) replaced with the shared inline-SVG icon set.
- **Megolm rooms: sender could not decrypt own messages** — the self-inbound
  group session was keyed by the Megolm base64 id while messages carry the
  server session id; sessions are now keyed consistently by the server id and
  reconciled when missing.

## [1.0.2] - 2026-08-08

First tagged release. Since v1.0.1:

### Security
- **Additional Security mode for DMs**: messages are deleted from the server
  once both users have received them, leaving device-only copies.
- **OAuth 2.0 / OIDC hardening**: consent CSRF protection, redirect-URI
  re-validation, PKCE-or-client-secret enforcement, and scope capping.
- **Password policy**: cap passwords at 72 bytes (bcrypt truncation guard).
- **Responsible disclosure**: public `/security` page with a private report
  form for admins, plus RFC 9116 `/.well-known/security.txt`.
- New **OWASP ASVS v4.0 verification suite** (`npm run test:asvs`, automatable
  Level 1 + select Level 2 subset) and the hardening fixes it drove.

### Fixes
- DM "unable to decrypt" when the sender has multiple devices or rotated keys.
- Admin/self account deletion 500 (`deleteUser` missed FK-referencing tables).
- Fabricated `created_at`/`bio` in search, status context, and notifications.
- UX consistency pass (Nielsen heuristics + wayfinding); chat/conversation and
  notification rows no longer hug card borders.

## [1.0.1] - 2026-08-02

- **OWASP Top 10 (2021) security suite** (`npm run test:owasp`) plus the
  hardening fixes it drove: access control, crypto-at-rest, injection/XSS,
  rate limiting, helmet headers, session regeneration, CSRF, audit logging,
  SSRF validation.
- **GPLv3 licensing**: Extrovert is now GPL-3.0-or-later (`LICENSE`).
- **In-app docs wiki** at `/docs` (markdown-it renderer, sidebar, link
  rewriting) — 19 pages covering every feature; full Docker/docs packaging fix.
- **Complete OpenAPI 3.1 spec**: +25 missing endpoints (rooms, E2EE DMs,
  avatar, relationships, comments, SSE stream, unread count, announcement,
  OAuth consent), corrected response shapes and scopes.
- **Built-in push channel** over the signaling WebSocket for native clients;
  missed-call pushes on offline-call timeout (web-push stays for browsers).
- Native-client support: Bearer-token auth for web E2EE routes, file-store
  crypto backend, E2EE fixes for fresh devices and room self-sessions.

## [1.0.0] - 2026-07-31 — "Embrace"

Initial release: the complete Extrovert feature set.

- **Network model**: you only see content from friends and friends-of-friends;
  no public timeline, no firehose. Deterministic, explained feed ranking.
- **Posts**: text/photo/video, reposts, comment threads, edit history, full
  deletion, inline editing.
- **Profiles**: fully customizable pages with user-written HTML and CSS
  (no JavaScript), avatars, themes.
- **Social**: follow, like, comment, share, "follow because of a post".
- **Discovery**: friend-of-friend suggestions and network-bound post search.
- **E2EE messaging**: Signal-grade Olm double-ratchet DMs (mandatory for
  direct messages), safety numbers, key backup; **Megolm** E2EE group chat in
  rooms with role-based permissions and voice channels.
- **Calls**: peer-to-peer WebRTC calls with presence, offline-call rings, and
  push wake-ups.
- **Notifications**: inbox, unread badges, realtime SSE stream, web push.
- **Stickers**, server-wide announcements, full **admin panel** (bans, user
  deletion, moderation, reports queue).
- **REST API**: OAuth 2.0 + OpenID Connect (PKCE), OpenAPI spec, Swagger UI.
- **Docker**: slim multi-stage image (~392 MB, unprivileged `node` user).
- UI: neobrutalism-minimalist dark/light themes with the concentric-rings
  signature motif.

[1.0.2]: https://github.com/AxoIsAxo/extrovert/releases/tag/v1.0.2
[1.0.1]: https://github.com/AxoIsAxo/extrovert/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/AxoIsAxo/extrovert/releases/tag/v1.0.0
