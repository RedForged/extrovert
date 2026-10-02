# Development & testing

## Project layout

```
src/
  server.js            Express app: middleware pipeline (helmet, sessions, rate
                       limits, CSRF, CORS), static serving, WS upgrade, 404/500
  db.js                SQLite schema + migrations + every query helper
                       (users, follows, posts, likes, comments, shares,
                       notifications, messages, E2EE keys, rooms, roles,
                       channels, reports, OAuth, media, search, audit log,
                       announcement, idempotency)
  feed.js              Feed algorithm (scoring, boosts, dedupe) + 30s feed cache
  network.js           Visibility: friends, friends-of-friends, canView
  sanitize.js          Profile/room HTML (sanitize-html) + CSS sanitization
  auth.js              requireAuth / optionalAuth (session)
  bearer-auth.js       OAuth Bearer → user (for web E2EE routes, CSRF bypass)
  api-auth.js          requireApiAuth(scopes), clientAppAuth, token helpers
  oidc.js              OIDC keys (file/env), JWKS, ID-token signing, rotation
  push.js              VAPID web push fan-out (call/missed_call)
  dm.js                Shared DM logic for web + API (messages, keys)
  notif-broadcaster.js In-process EventEmitter for notification pushes (SSE)
  session-store.js     express-session store on SQLite (expiry purge)
  webrtc-signaling.js  WS signaling: presence, 1:1 calls, offline calls,
                       voice channels, live DM + push-channel delivery
  api-spec.js          Hand-written OpenAPI 3.1 spec (served + Swagger UI)
  routes/
    auth.js            login/register/logout/become-admin
    pages.js           / , /compose, /discover (feed + search + suggestions)
    posts.js           post CRUD, like/comment/share/repost/follow-from,
                       edit/delete, history
    profile.js         profile view/edit, HTML/CSS customization, avatar,
                       followers/following, referral link
    social.js          follow/unfollow
    notifications.js   /inbox
    chats.js           DMs: threads, send/edit, pubkey/prekeys/backup/bundle/safety
    rooms.js           rooms, channels, roles, members, join requests, reports,
                       Megolm session endpoints, voice members
    settings.js        theme, account deletion, developer OAuth apps
    admin.js           user management, rooms, reports, announcement
    stickers.js        upload/manage/sticker list
    security.js        /security responsible-disclosure page, private report form, security.txt
    push.js            VAPID public key, subscribe/unsubscribe, cancel-pending
    api-v1.js          The whole REST API (OAuth, accounts, statuses,
                       timelines, notifications, media, search, presence,
                       push, rooms, DMs, announcement)
    well-known.js      OIDC discovery + JWKS
    docs.js            Swagger UI + OpenAPI JSON
  views/               EJS templates (feed, profile, chat, rooms/, admin…)
public/
  app.css theme.css    Design system + themes (Fraunces, Hanken Grotesk)
  *.js                 Client logic: compose, interact, e2ee, rooms, room-e2ee,
                       webrtc, webrtc-ui, webrtc-room, stickers, avatar,
                       push-register, announcement, admin, copy-ref
  lib/olm.js + .wasm   Bundled Olm (no CDN)
  sw.js                Service worker for call push notifications
  manifest.webmanifest PWA manifest
scripts/
  test.js              npm test — feed algorithm + sanitization unit tests
  api-test.js          npm run test:api — API integration tests (node --test)
  owasp-test.js        npm run test:owasp — OWASP Top 10 security suite (node --test)
  asvs-test.js         npm run test:asvs — OWASP ASVS v4.0 suite, automatable subset (node --test)
  crypto-test.js       npm run test:crypto — Olm protocol regression tests
  megolm-room-test.js  npm run test:megolm — group E2EE session/rotation tests
  megolm-integration-test.js — server-side Megolm endpoint flow
  live-dm-test.js      npm run test:live-dm — WS new_dm delivery test
  self-session-test.js / session-reload-test.js — DM ratchet reload regression
  test-offline-call.js — offline-call flow vs real signaling server (isolated DB)
  smoke.sh             HTTP end-to-end smoke test
  smoke_media.sh       upload + repost smoke test
  generate-vapid-keys.js — VAPID keypair generator
  fetch-fonts.js       one-time font fetch (committed, offline at runtime)
```

## npm scripts

| Script | Command | What it does |
|---|---|---|
| start | `npm start` | `node src/server.js` |
| dev | `npm run dev` | `node --watch src/server.js` |
| test | `npm test` | Feed algorithm + sanitization tests |
| test:api | `npm run test:api` | API integration suite (`node --test`) |
| test:owasp | `npm run test:owasp` | OWASP Top 10 security suite (access control, crypto-at-rest, injection, XSS, misconfig, dependency audit, auth, CSRF, logging, SSRF) |
| test:asvs | `npm run test:asvs` | OWASP ASVS v4.0 suite — automatable Level 1 (+ select L2) items mapped to chapter/ID (V2–V14), with a MANUAL_REVIEW/N-A scorecard for non-automatable items |
| test:crypto | `npm run test:crypto` | Olm protocol regression |
| test:megolm | `npm run test:megolm` | Megolm room-session tests |
| test:megolm:integration | `npm run test:megolm:integration` | Server Megolm flow |
| test:live-dm | `npm run test:live-dm` | Live WS DM delivery |
| test:self-session / test:session-reload | — | DM ratchet reload regressions |
| test:client | `npm run test:client` | Client API parity test suite (`node --test`) |
| test:bootstrap | `npm run test:bootstrap` | Client bootstrap route test suite (`node --test`) |
| test:client-e2ee | `npm run test:client-e2ee` | Client E2EE room batching & realtime push suite (`node --test`) |
| seed:client | `npm run seed:client` | Populate database with deterministic fixtures for client development |

## Manual smoke tests

```bash
# Requires a running server (npm start) and curl
scripts/smoke.sh          # register → post → like → comment → follow → feed
scripts/smoke_media.sh    # photo upload → post → repost
node scripts/test-offline-call.js   # offline-call flow, isolated DB
```

## Testing approach

- Unit-ish tests run directly against `src/` modules with a temp database (`EXTV_DB_PATH` / `EXTV_SESSION_DB_PATH` point at throwaway files — see `scripts/api-test.js` for the pattern).
- `scripts/owasp-test.js` boots the full app (session + CSRF for web routes, Bearer tokens for the API) and covers the OWASP Top 10 (2021): broken access control, crypto failures (bcrypt + OAuth tokens hashed at rest), injection/SQLi/XSS, insecure design (rate limiting, referral anti-farming), misconfiguration (helmet headers, no stack leaks), vulnerable components (`npm audit`), auth failures (session regeneration, enumeration), integrity failures (CSRF, open redirects, prototype pollution), logging (audit log), and SSRF (push endpoint validation). It runs `npm audit` for A06 and skips gracefully offline.
- `scripts/asvs-test.js` maps tests to OWASP ASVS v4.0 chapter/IDs (V2 Authentication, V3 Sessions, V4 Access, V5 Validation, V6 Stored Crypto, V7 Error/Logging, V8 Data Protection, V10 Malicious Code, V11 Business Logic, V12 Files, V13 API, V14 Config). It runs with `TRUST_PROXY=loopback` + `X-Forwarded-Proto: https` so the Secure-cookie requirement (3.1.3) is exercised like production. Items that cannot be black-box verified (V1, TLS/proxy config V9, business-logic review, etc.) are listed in the suite's scorecard as MANUAL_REVIEW with guidance, never counted as passing.
- The signaling tests spin up a real `WebSocketServer` and drive it with mock HTTP upgrade requests.
- The Olm/Megolm tests use the real `@matrix-org/olm` package to validate the exact protocol patterns the browser frontend (`public/e2ee.js`, `public/room-e2ee.js`) relies on.

## Client-side crypto modules

| File | Responsibility |
|---|---|
| `public/e2ee.js` | 1:1 DM crypto (Olm), key publishing, bundle fetching, safety numbers, backup |
| `public/room-e2ee.js` | Room Megolm sessions, key wrap/unwrap via 1:1 Olm, rotation |
| `public/webrtc.js` / `webrtc-ui.js` | 1:1 calls + UI |
| `public/webrtc-room.js` | Voice channels |
| `public/rooms.js` | Room chat UI + Megolm send/receive |
| `public/push-register.js` | VAPID subscription registration |
| `public/sw.js` | Push service worker (call notifications) |

## Contributing notes

- Node `node:sqlite` is required — do not add a native SQLite dependency.
- Never loosen the sanitizer whitelists without a review (`src/sanitize.js`).
- Schema changes go in `src/db.js` as idempotent `try/catch` migrations.
- The OpenAPI spec (`src/api-spec.js`) is hand-maintained — keep it in sync with `src/routes/api-v1.js` when adding endpoints.
- Fonts are vendored in `public/fonts/` (fetched once by `scripts/fetch-fonts.js`); no runtime network calls.
