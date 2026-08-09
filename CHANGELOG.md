# Changelog

All notable changes to **Extrovert** are documented in this file. The project
follows [Semantic Versioning](https://semver.org/). This is the first tagged
release: the codebase carries its version in `package.json`, and the sections
below reconstruct the history behind each version.

## [Unreleased]

### Features
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
