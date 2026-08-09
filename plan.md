# Extrovert — Comprehensive Fix / Change / Improve Plan

> Grounded in direct source analysis. File:line citations throughout.
> Status: **mostly implemented.** Every item below carries a per-item status tag (✅ FIXED / ⚠️ PARTIAL / ⏳ OPEN), verified against the current code on 2026-06 (see `planned.md` for forward-looking features). The original file:line citations are stale — they point at an earlier revision; `Where:` lines now note the current location.

---

## Status summary (verified 2026-06, per-item audit)

| Group | Status |
|---|---|
| **A. Bugs** | ✅ A1–A9 **all fixed** (avatar URL, notification/context avatars, cursor pagination, idempotency TTL, media dimensions, refresh-token TTL, per-token rate limit, trust-proxy env, absolute `picture` URL) |
| **B. Spec / code consistency** | ✅ B1–B6 fixed (spec aligned to code); ⏳ B7 optional OIDC `claims_supported` note |
| **C. Native-client features** | ✅ C1–C6 all built (DM REST API + `src/dm.js`, avatar upload API, `theme` update, relationships, SSE notifications, unread_count); ⏳ C7 optional instance endpoint |
| **D. Security hardening** | ✅ D2 (OIDC key `0600` + env override), D5 (CSRF), D6 (helmet/CSP); ⚠️ D3 rotation exists but has no admin/CLI trigger; ⏳ D1 intentional (public-by-URL, documented), D4 P3 token-theft detection |
| **E. General improvements** | ✅ E5 fixed (real `created_at`/`bio` in search/context/notifications); ⚠️ E2 (test gaps), E3 (no score cursor), E4 (serializePost N+1), E6 (hardcoded limits), E7 (no CI drift check) partial; ⏳ E1 refactor |

**Remaining work:** D3 trigger, D4, E2/E3/E4/E6/E7 partials, optional P3s (B7, C7, E1), and the intentional D1 decision. The "Suggested execution order" at the bottom is historical — Phases 1–4 are complete. **planned.md F1 (multi-account with OAuth account selection) is implemented** (2026-08-09) — see planned.md; F2 (2FA), F3 (passkeys), F4 (ActivityPub), F5 (bots) remain open.

---

## Structure

- **A. Bugs** — incorrect behavior, fix first
- **B. Spec / code consistency** — spec and server drift
- **C. Native-client enabling features** — new endpoints a native Tauri client needs
- **D. Security hardening** — side channels, access control, credential hygiene
- **E. General improvements** — perf, maintainability, testing

Each item has a `[PRIORITY]` tag: P0 (blocker / data-loss), P1 (incorrect), P2 (missing UX), P3 (nice-to-have).

---

## A. Bugs

### A1. Avatar double-`/uploads/` prefix in API serialization  [P1]  [✅ FIXED]

**Where:** `src/routes/api-v1.js:75`
- `serializeAccount`: `avatar: user.avatar ? \`/uploads/${user.avatar}\` : null`
- `src/routes/profile.js:225` stores avatars as the **full path**: `/uploads/avatars/<hex>.jpg`
- Result: `/uploads//uploads/avatars/<hex>.jpg` — broken on every client.
- Same bug on two other lines:
  - `api-v1.js:306` — `id_token` `picture` claim
  - `api-v1.js:394` — `/oauth/userinfo` `picture` field

**Fix:** Store only the **basename** (`avatars/<hex>.jpg`) in the `users.avatar` column. Keep single `/uploads/` prefix in the serializer. Add a one-time migration to fix existing rows. Apply the same basename assumption across all three call sites.

### A2. `avatar: null` hardcoded in notifications and status context  [P1]  [✅ FIXED]

**Where:**
- `src/routes/api-v1.js:691` — notifications serializer passes `avatar: null` unconditionally
- `api-v1.js:603` — `/statuses/:id/context` descendants also pass `avatar: null`

**Root cause:** `getNotifications` (`src/db.js:577-586`) and `commentsForPost` (`db.js:469-475`) join `username` and `display_name` from `users` but **never select `avatar`**. The serializer then has no real value to pass.

**Fix:**
- Add `u.avatar AS actor_avatar` to `getNotifications` SQL
- Add `u.avatar` to `commentsForPost` SQL
- Thread the real avatar into the synthesized account objects

### A3. Notifications cursor accepted but ignored  [P1]  [✅ FIXED]

**Where:** `src/routes/api-v1.js:682-694`
- Handler reads `req.query.limit` but **never reads `req.query.cursor`**
- The OpenAPI spec advertises a cursor parameter that does nothing
- `getNotifications` (`db.js:577`) has no keyset-pagination support — always returns latest `N`

**Fix:** Either implement true keyset pagination (`WHERE n.id < ? ORDER BY n.id DESC LIMIT ?`, reusing `decodeCursor` from `api-v1.js:63`) or **remove** the `cursor` param from `api-spec.js` to stop lying to clients.

### A4. Idempotency keys never expire (unbounded growth)  [P1]  [✅ FIXED]

**Where:** `src/db.js:249-254` — `idempotency_keys` table has `created_at` but no TTL check on read.
- `getIdempotencyKey` (`db.js:1089-1091`) reads with no `WHERE created_at > ?`
- No periodic cleanup whatsoever → unbounded table growth

**Fix:**
- Add a TTL window (e.g. 24h) to the read: `WHERE key = ? AND created_at > ?`
- Add a `DELETE WHERE created_at < ?` on each write to stay lean
- The OpenAPI spec says "within a short window" — codify it

### A5. `media_attachments` dimensions never populated  [P2]  [✅ FIXED]

**Where:** `src/routes/api-v1.js:703-723`
- `POST /api/v1/media` inserts a `media_attachments` row but **never calls** `updateMediaAttachmentDimensions` (`db.js:1084-1086`)
- Response always returns `width: null, height: null`

**Fix:** After storing the file, use `sharp` (already a dependency) to read image dimensions; call `updateMediaAttachmentDimensions` before responding. Video requires `ffprobe` (new dep) or skip.

### A6. Refresh token TTL == access token TTL (24h)  [P2]  [✅ FIXED]

**Where:**
- `src/routes/api-v1.js:280` (initial issue) and `:327` (refresh rotation) — both `expiresAt = Date.now() + 86400000`
- Single `expires_at` column in `oauth_tokens` (`db.js:225-234`) shared by access + refresh

**Issue:** A client idle >24h can never refresh — must force re-auth. Unusual for OAuth 2.0 where refresh tokens are long-lived.

**Fix:** Add a separate `refresh_expires_at` column (e.g. 90 days) and check that in the refresh flow instead of the shared column. Requires a schema migration.

### A7. Rate-limit spec is wrong (per-IP, not per-token)  [P1]  [✅ FIXED]

**Where:**
- `src/server.js:83-117` — `express-rate-limit` default key = `req.ip`
- `api-spec.js:147` — claims "Per-token limit: 120 requests per minute"

**Fix:** Either make the limiter per-token by keying on the OAuth bearer token (fallback to IP for unauth'd), or correct the spec text to "per-IP". Per-token is more correct for a multi‑client API.

### A8. `trust proxy 1` + no X-Forwarded-For validation = IP spoofing  [P1]  [✅ FIXED]

**Where:**
- `src/server.js:37` — `app.set('trust proxy', 1)`
- `server.js:88,98,114` — `validate: { xForwardedForHeader: false }`

With `trust proxy 1`, `req.ip` is the first `X-Forwarded-For` value — forgeable by any client if the app isn't behind a trusted proxy. This breaks per-IP rate limiting and pollutes the `referrer_ip` audit column (`db.js:27`).

**Fix:** Make trust-proxy config env-driven (`TRUST_PROXY=loopback,10.0.0.0/8`). Default to `false` — only enable when the operator has configured a real reverse proxy (nginx, Caddy, HAProxy) that strips client-sent `X-Forwarded-For`.

### A9. `picture` claim in id_token/userinfo is a relative path  [P1]  [✅ FIXED]

**Where:** `src/routes/api-v1.js:306`, `:394`
- Hardcoded `'/uploads/' + user.avatar`
- OIDC `picture` should be an **absolute** URL per the OIDC Core spec

**Fix:** Prepend `${ISSUER}` (already imported from `oidc.js`): `` `${ISSUER}/uploads/${user.avatar}` ``.

---

## B. Spec / code consistency

### B1. Scope requirements for `/accounts/*_credentials`  [P2]  [✅ FIXED]

**Where:**
- `api-spec.js:332` → spec says `verify_credentials` needs `read profile`; code (`api-v1.js:401`) requires **only `read`**
- `api-spec.js:340` → spec says `update_credentials` needs `write profile`; code (`api-v1.js:405`) requires **only `profile`**

**Fix:** Align spec to code (document the real requirement).

### B2. `token_endpoint_auth_methods_supported` omits `none`  [P2]  [✅ FIXED]

**Where:** `src/routes/well-known.js:26` — lists `['client_secret_post']` only.

Server supports public clients without a secret (`api-auth.js:83-100`) but the OIDC discovery doc doesn't advertise it. Native clients auto-detecting OIDC may assume a secret is mandatory.

**Fix:** Add `'none'` to the array (the IANA-standard value for PKCE public clients).

### B3. Undocumented endpoints missing from `api-spec.js`  [P2]  [✅ FIXED]

**Where:** Paths defined in `src/routes/api-v1.js` but absent from `api-spec.js`:
- `POST /api/v1/oauth/authorize` (consent-form submit, `api-v1.js:209` — browser-only, document as "not for native clients")
- `GET /api/v1/calls/presence` and `/calls/presence/:username` (`api-v1.js:780-788` — Bearer-auth, fully usable)

**Fix:** Add calls/presence to the spec; optionally note the POST authorize exists.

### B4. `response_modes_supported` advertises `fragment` but code doesn't support it  [P3]  [✅ FIXED]

**Where:** `src/routes/well-known.js:24` — `['query', 'fragment']`. The authorize callback always uses `?code=...` (query).

**Fix:** Either implement fragment-mode or remove `'fragment'` from the discovery doc.

### B5. Mixed timestamp units undocumented  [P2]  [✅ FIXED]

**Where:** API body fields are **millisecond** epochs; OAuth token `created_at` is **unix seconds** (`api-v1.js:289`); JWT claims are **seconds** (`oidc.js:78-81`). The OpenAPI spec declares `format` for none of them.

**Fix:** Document per field in `api-spec.js`: `type: integer, description: "milliseconds since epoch"` vs `"seconds since epoch"`.

### B6. `statuses_count` missing from Account  [P2]  [✅ FIXED]

**Where:** `serializeAccount` (`api-v1.js:70-83`) returns `followers_count`/`following_count` but no post count. Clients must paginate `/accounts/:id/statuses` to guess whether a profile has posts.

**Fix:** Add `statuses_count: db.countPostsByUser(user.id)`. Add the helper to `db.js`.

### B7. `claims_supported` in discovery doc  [P2]  [⏳ OPEN — optional OIDC conformance note (nonce conditionality)]

**Where:** `src/routes/well-known.js:31-34` — lists claims that are always present.

The `claims_supported` array includes `nonce` (conditional — only present if the user sent one) and omits nothing. Fine, but should note which are conditional if you want a strict OIDC conformance pass.

---

## C. Native-client enabling features

### C1. DM REST API (E2E-encrypted) — largest item  [User decision]  [✅ FIXED]

**Background:** DMs exist E2E-encrypted in the DB (`messages` table `db.js:101-110`, `user_public_keys` `db.js:112-116`, per-side ciphertexts `db.js:284-285`) and the web UI (`src/routes/chats.js`, session-cookie only). Scopes `read:direct`/`write:direct` are defined and accepted (`api-auth.js:6`) but **no route checks them.**

**Plan (new Bearer-authenticated REST endpoints):**

| Endpoint | Scope | Purpose |
|---|---|---|
| `GET /api/v1/conversations` | `read:direct` | List mutual-follow conversations (last-message preview) |
| `GET /api/v1/conversations/:username` | `read:direct` | Message history, paginated, keyset on `messages.id` |
| `POST /api/v1/conversations/:username/messages` | `write:direct` | Send E2E message (accepts both ciphertexts) |
| `GET /api/v1/conversations/:username/keys` | `read:direct` | Fetch a user's public key for key exchange |
| `POST /api/v1/conversations/keys` | `write:direct` | Publish / rotate your public + encrypted private key |
| `PATCH /api/v1/messages/:id` | `write:direct` | Edit a message (if within edit window) |
| `DELETE /api/v1/messages/:id` | `write:direct` | Delete a message |

- Guard all with `requireApiAuth('read:direct')` / `('write:direct')` and the existing `areMutualFollowers` check (`db.js:621-628`).
- Extract crypto + DB logic from `chats.js` into a shared `src/dm.js` module so web + API share code.
- Check for `mutual_followers` before returning conversations.

### C2. Avatar upload via API  [P2]  [✅ FIXED]

**Where:** Currently only the web session form `/u/:username/avatar` (`profile.js:200-233`) can upload an avatar. No API endpoint — native clients can't change avatars.

**Plan:**
- Add `POST /api/v1/accounts/avatar` (multipart, `profile` or `media.write` scope)
- Reuse the sharp resize-to-200×200-JPEG-q85 logic from `profile.js:223`
- Store as **basename** (`avatars/<hex>.jpg`) per fix A1
- Accept avatar from the web route too

### C3. Profile update extend fields  [P2]  [✅ FIXED]

**Where:** `PATCH /accounts/update_credentials` (`api-v1.js:405-413`) only accepts `display_name` and `bio`.

**Plan:** Extend to also accept `theme` (`light`/`dark`/`default`, already in `users` table `db.js:957-963`). Web-only features (custom profile HTML/CSS) can stay as web-only.

### C4. Account relationships endpoint  [P2]  [✅ FIXED]

**Where:** No batch `/api/v1/accounts/relationships`. Native client must check `is_following` one-by-one.

**Plan:** `GET /api/v1/accounts/relationships?id=1,2,3` → `{ data: [{ id, following, followed_by }] }`. Useful for search results, follower lists, and the composer's "reply privacy" indicator.

### C5. Realtime notifications (SSE)  [User decision]  [✅ FIXED]

**Where:** `/ws` (`server.js:246-257`, `webrtc-signaling.js`) is WebRTC-signaling + presence — **session-cookie auth only**, Bearer not accepted, no notification stream. Native clients must poll `/notifications` within the 120/min per-IP budget.

**Plan:**
- Add `GET /api/v1/notifications/stream` — SSE endpoint (Bearer `notifications` scope)
- Hook into `createNotification` (`db.js:570-575`) via an in-process EventEmitter
- Heartbeat every 15s
- No Redis needed (single-process server)
- Moderate effort, transformative UX

### C6. Unread notification count endpoint  [P2]  [✅ FIXED]

**Where:** `countUnreadNotifications` (`db.js:588-593`) exists and is used by the web (`routes/notifications.js:14`) but **not exposed via API**.

**Plan:** `GET /api/v1/notifications/unread_count` → `{ data: { count } }`. Trivial, high value for native app badges.

### C7. Instance info endpoint  [P3]  [⏳ OPEN — optional instance info endpoint (P3)]

**Where:** none exists — clients hardcode the base URL.

**Plan:** `GET /api/v1/instance` → `{ data: { title, description, version, urls: { ... }, rules: [...] } }`. Optional; useful for self-hosted instances.

---

## D. Security hardening

### D1. Media served publicly with no access control  [User decision]  [⏳ OPEN — intentional, documented decision (public-by-URL, docs/security.md)]

**Where:** `src/server.js:167-179` — `/uploads` and `/api-uploads` are `express.static` with **no auth, no signed URLs, no expiry**.

Post media files (`/api-uploads/<hex>.<ext>`) are public-by-URL. Filenames are 128-bit random hex (unguessable) but anyone with the URL keeps access forever. No post-level access control.

**Options:**
- (a) Accept as-is (document in SECURITY.md, avatars/stickers are inherently public; post media is public-by-obscurity)
- (b) Gate `/api-uploads/*` behind a Bearer-or-session check that calls `canView` on the owning post — needs a media↔post ownership migration (no FK exists)

Recommend (a) for now with a security note.

### D2. OIDC private key stored in plaintext on disk  [P1]  [✅ FIXED]

**Where:** `src/oidc.js:43-44` writes `privateKeyPem` to `data/oidc-keys.json` in plaintext. The file is in `.gitignore` (verify) but any process compromise leaks the RS256 signing key.

**Fix:**
- Verify / enforce `data/oidc-keys.json` is `0600` on first write
- Add env option to load the private key directly (`OIDC_PRIVATE_KEY` PEM string) instead of reading from disk
- Document the file's sensitivity in SECURITY.md

### D3. No JWT key rotation mechanism  [P2]  [⚠️ PARTIAL — rotateKeys() works but has no admin/CLI trigger]

**Where:** `src/oidc.js` generates one keypair at startup, never rotates. `getJwks` returns one key. If the private key is compromised, you have no way to roll.

**Fix:**
- Store multiple keys (old + new) in the JWKS during rollover
- Sign with the newest `kid`; accept verification against any active key
- Add an admin HTTP endpoint or CLI script to rotate keys

### D4. Refresh-token reuse detection doesn't revoke the family  [P3]  [⏳ OPEN — P3 advanced token-theft detection]

**Where:** `src/routes/api-v1.js:314-340` — rotated refresh token deletes the old row (`db.rotateRefreshToken`, `db.js:1054-1064`) but doesn't invalidate the current access token or notify the user.

**Fix (advanced):** On reuse, revoke all tokens for that user+app combination — not just the rotated row. Standard for OAuth token-theft detection. Lower priority.

### D5. Validate session cookie auth for web forms  [P2]  [✅ FIXED]

**Where:** `src/server.js:128` skips CSRF for `/api/` (correct — Bearer clients don't need CSRF). **Audit that CSRF is actually applied** to all state-changing web POST routes (`/posts/*`, `/chats/*`, `/u/:username/avatar`, `/settings/*`). Quick audit item.

### D6. Helmet / security headers audit  [P2]  [✅ FIXED]

**Where:** `helmet` is a dependency (`package.json:10`). Verify it's `app.use(helmet())`'d and the headers (CSP, X-Frame-Options, HSTS) aren't loosened for the API in a way that affects the web app templates.

---

## E. General improvements

### E1. `db.js` is 1200+ lines of raw SQL — modularize  [P3]  [⏳ OPEN — P3 refactor (db.js now ~1700 lines)]

`src/db.js` (1216 lines) contains all DDL, queries, and helpers across every domain. This is workable but error-prone (the avatar bug A1 and notification-avatar bug A2 both come from split attention across different functions in the same file).

**Plan (future):** Split into `db/schema.js`, `db/accounts.js`, `db/posts.js`, `db/oauth.js`, `db/notifications.js`, `db/search.js`, `db/media.js`. Not urgent.

### E2. No automated tests covering the API surface  [P1]  [⚠️ PARTIAL — suites exist; avatar/cursor assertions + CI missing]

`package.json` has `test` / `test:api` scripts that exist but don't cover OAuth flows, serialization (avatar bugs), pagination, or visibility rules (`canView`). Bugs A1–A5 would each be caught by a simple integration test.

**Plan:**
- Add tests for `serializeAccount` → avatar URL format
- Add tests for `GET /notifications` → cursor, avatar in response
- Add tests for `/oauth/token` → PKCE flow, refresh rotation
- Add tests for `/timelines/home` → cursor pagination stability
- Add tests for `/statuses/context` → descendant avatars

### E3. `feed.buildFeed` runs O(N) per request with no caching  [P2]  [⚠️ PARTIAL — feed cache + TTL done; score-based cursor missing]

**Where:** `/timelines/home` (`api-v1.js:654-660`) recomputes the entire feed on every request, then locates the cursor id by linear scan. Shifting ranking between requests can cause duplicate/skip (cursor `id` is not a score, so items above the cursor can reorder).

**Plan:**
- Cache the ranked feed per-user with a short TTL (30-60s) in an in-memory Map
- Use a **score-based cursor** (store the rank score, not just post id) for stable pagination across rank changes

### E4. `serializePost` runs N+1 `COUNT(*)` queries per post  [P2]  [⚠️ PARTIAL — timeline batched; serializePost N+1 remains]

**Where:** `src/routes/api-v1.js:97-99` runs three `COUNT(*)` queries (likes/shares/comments) per post in the serialization loop. A 40-post timeline = 120+ queries.

**Plan:** Aggregate counts in the feed query (`feed.js`) using left joins + `GROUP BY`, or batch-fetch counts for all page post ids in one query. Big perf win for timeline endpoints.

### E5. `created_at: 0` synthesized accounts break sorting  [P2]  [✅ FIXED — real created_at/bio now flow through search/context/notifications]

**Where:** `api-v1.js:691, 603` synthesize account objects with `created_at: 0`. Any client sorting accounts by join date will cluster these at epoch.

**Fix:** Fetch the real `created_at` in the SQL join — the `users` table is already joined, just add the column. Combine with A2 fix.

### E6. Env-driven config audit  [P2]  [⚠️ PARTIAL — env docs done; upload limits/max post length hardcoded, no log-level env]

**Where:** `src/.env.example` exists. Key items to verify:
- `OIDC_ISSUER` — default (`oidc.js:9`) is `https://extrovert.redforged.eu` — fine for prod but self-hosters must set it
- `TRUST_PROXY` — should default off, see A8
- Session secret, DB path, upload limits, max post length — all into `.env.example`
- `HELPLESS` / `DEBUG` — log level control

### E7. OpenAPI spec is hand-maintained and has drifted  [P2]  [⚠️ PARTIAL — spec hand-maintained; no CI drift check]

`api-spec.js` (21 KB, hand-written) already disagrees with the code on scopes (B1), endpoints (B3), and rate-limit docs (A7).

**Plan:** Either:
- Generate the spec from route annotations (e.g. `@asteasolutions/zod-to-openapi` or `swagger-jsdoc`)
- Or add a CI test that walks the Express router and diffs registered paths against `api-spec.js` paths + security arrays

---

## Suggested execution order

> Status: **Phases 1–4 are complete** (A bugs, B spec, C native-client, plus D2/D5/D6). Remaining: Phase 5–6 tail (E3/E4/E6 partials, D3 trigger, D1 decision, D4) and optional P3s (B7, C7, E1). Historical — kept for reference.

```
Phase 1 — Bugs (server integrity)
  A1, A10   Avatar URL fix (serializer + id_token + userinfo)
  A2        Notifications/context avatar fix
  A3        Notifications pagination (implement or remove param)
  A4        Idempotency TTL
  A8 / A9   Trust-proxy config + rate-limit keying

Phase 2 — Spec reconciliation + writing tests for Phase 1 fixes
  B1–B7     Spec alignment pass
  E2        Integration tests for each Phase 1 fix

Phase 3 — Native-client blocking features
  C2        Avatar upload API
  C6        Unread count endpoint
  C4        Relationships endpoint
  C3        Profile update extend

Phase 4 — Realtime + notifications
  C5        SSE notification stream
  C1        DM REST API (requires user decision)

Phase 5 — Performance
  E3 / E4   Feed caching + N+1 reduction
  E1        db.js modularization (could split alongside Phase 3)

Phase 6 — Security
  D1        Media access control decision + implementation
  D2 / D3   OIDC key hygiene
  D4        Token-theft detection
  D5 / D6   CSRF + Helmet audit

Future
  E7        Spec generation
  C7        Instance info endpoint
```

---

## Decisions needed before implementation

| # | Question | Options |
|---|---|---|
| 1 | **Avatar storage fix (A1):** migrate existing rows to basename, or only normalize in serializer? | (a) Migration (cleaner), (b) Serializer-only (no schema change) |
| 2 | **Refresh-token TTL (A6):** introduce longer-lived refresh (e.g. 90d) or keep 24h-and-reauth? | (a) Longer expire (needs migration), (b) Keep 24h (intentional) |
| 3 | **DM REST API (C1):** in scope now, deferred, or never? | (a) Now, (b) Deferred, (c) Out of scope |
| 4 | **Media access control (D1):** leave public-by-URL or gate behind `canView`? | (a) Public-by-URL + doc, (b) ACL gated (needs migration) |
| 5 | **SSE notifications (C5):** in scope or stick with polling? | (a) SSE, (b) Polling for v1 |
| 6 | **Spec drift (E7):** CI diff test or generated specs? | (a) CI diff, (b) Generated |
