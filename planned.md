# Extrovert — Planned Features

> Grounded in direct source analysis. File:line citations throughout.
> Status: **F1 (multi-account) implemented** on 2026-08-09; **F2 (2FA) and
> F3 (passkeys) implemented** on 2026-08-22; F4–F5 remain planning-phase.
> Implemented items carry a `[✅ DONE]`
> tag verified against the current code.

---

## Structure

- **F1. Multi-Account (with account selection at OAuth)** [✅ DONE]
- **F2. Two-Factor Authentication (2FA)** [✅ DONE]
- **F3. Passkeys (WebAuthn)** [✅ DONE]
- **F4. Federation (ActivityPub)**
- **F5. Bots (Discord/Telegram-style bot accounts)**

Each item has a `[PRIORITY]` tag: P0 (blocker / data-loss), P1 (incorrect), P2 (missing UX), P3 (nice-to-have).

Cross-cutting note: every feature below touches the shared session + OAuth flow, so the database
migrations (F1.2, F2.2, F3.2) and the login page rework (F1.3, F2.4, F3.3) should land together to
avoid shipping an intermediate login UX twice.

---

## F1. Multi-Account (with account selection at OAuth)

**Goal:** Let a user of one browser / install sign in to several Extrovert accounts and switch
between them; when an OAuth client asks for authorization, the user picks **which** account
authorizes the app, instead of the server blindly using the session's current account.

### F1.1 Session model: single `userId` → list of signed-in accounts  [P1]  [✅ DONE]

**Where:** `src/routes/auth.js:70-96` (login), `src/routes/auth.js:98-100` (logout), `src/session-store.js` (session persistence).

Today `req.session.userId` is a single integer set on login and destroyed on logout.

**Change:**
- Add `req.session.accountIds` — the ordered list of accounts signed in on this device.
- Keep `req.session.userId` as "the active account" (compat shim: every existing
  `req.session.userId` read site keeps working unchanged).
- Login becomes "add to list + set active" (does not destroy the list). Logout becomes "remove
  from list" — destroy the whole session only when the last account is removed, so switching
  accounts does not invalidate other sessions/tokens.
- `req.session.regenerate()` on login (`auth.js:83`) must be reworked: regenerate the session but
  re-seed `accountIds` from the just-signed-in account instead of wiping state.

### F1.2 Persist account list across restarts (remembered devices)  [P1]  [✅ DONE]

**Where:** `src/session-store.js` (express-session store), `src/db.js:304+` (ALTER TABLE migration pattern).

**Change:**
- New table `account_sessions` (`session_id`, `user_id`, `active INTEGER`, `created_at`) — one row
  per (session, account). This survives server restarts because the session store is DB-backed.
- On login/logout/switch, upsert/delete rows; `active` marks the current account.
- Follow the existing `try { db.exec(...) } catch {}` migration idiom (`db.js:304-323`) — this is
  additive-only, so existing installs upgrade in place.

### F1.3 Account switcher UI  [P2]  [✅ DONE]

**Where:** `src/views/login.ejs`, header layout (in `src/views/`), `src/routes/auth.js`.

**Change:**
- Login page shows "signed in on this device" list + "add another account" (multi-user picker, same
  pattern as GitHub/Google account chooser).
- A switcher menu in the app header lists all `accountIds` accounts with display name + avatar, and
  an "Add account" entry that goes through the login page with a `?next=` that preserves the
  original destination.
- New endpoints: `GET /account/switch` (renders picker), `POST /account/switch` (sets active),
  `POST /account/remove` (removes one account from the list).

### F1.4 OAuth: account selection at authorization time  [P1]  [✅ DONE] — the headline feature

**Where:** `src/routes/api-v1.js:200-250` (GET `/oauth/authorize`), `src/routes/api-v1.js:254+` (POST `/oauth/authorize`).

Today GET `/oauth/authorize` redirects to `/login?next=...` when `!req.session.userId`
(`api-v1.js:201-203`) and otherwise renders the consent page for the session's account.

**Change:**
- If multiple accounts are signed in, GET `/oauth/authorize` renders a **"choose account"** step
  first (or the consent page embeds the account picker): each signed-in account plus "sign in with
  a different account". The chosen `account_id` is carried through to the consent POST.
- POST `/oauth/authorize` takes `account_id` (defaulting to the active account) and issues the
  authorization code **bound to that account** — `authCode.user_id` is the selected account, and
  `/oauth/token` (`api-v1.js:305`) and `/oauth/userinfo` (`api-v1.js:463`) follow automatically
  because they already read `user_id` off the code/token.
- Security rule: the account selector must never let a client bypass consent — the picker only
  changes *which* account, the consent approval step stays mandatory. Guard the picker with the same
  CSRF check already used at `api-v1.js:258`.
- The OIDC `nonce` (stored on `oauth_codes`, `db.js:322`) must be bound to the selected account as
  well, so a code issued for account A can't be replayed against account B.

### F1.5 All other endpoints keep using the active account  [P2]  [✅ DONE]

**Where:** every `req.session.userId` read across `src/routes/*`.

No behavior change: `userId` stays the active account everywhere (API, chat, admin). Switching
accounts atomically swaps `req.session.userId`. Audit that no route accidentally reads the *list*
where it meant the *active* account.

### F1.6 Implementation notes  [✅ DONE]

Landing commit: **2026-08-09** (see `CHANGELOG.md` → Unreleased).

- `src/accounts.js` is the single owner of the list/active semantics
  (`getAccountIds` / `addAccount` / `setActiveAccount` / `removeAccount`); `src/auth.js`
  middleware exposes `res.locals.signedInAccounts` to every template.
- The `account_sessions` table lives in the **session store DB** (`src/session-store.js`,
  `data/sessions.db`), synced on every session write from `accountIds` + `userId`, and cleaned
  up on `destroy`/`clear`/expiry purge. It survives restarts alongside the session row.
- Login carries the existing account list across `regenerate()` **only when the session was
  already signed in** (add-another-account flow); a fresh login seeds the list with just the
  new account, preserving the anti-fixation property (`src/routes/auth.js`).
- Logout removes the active account and keeps the session when others remain
  (`POST /logout`, plus `?all=1` to sign out of the whole device — a small addition to the
  plan for the switcher menu).
- New endpoints: `GET/POST /account/switch` (picker page + set-active) and
  `POST /account/remove`; all CSRF-guarded by the existing global middleware.
- F1.4 chose the **consent page embeds the picker** variant ("Authorize as" radios, plus a
  "Use a different account" link): `GET /api/v1/oauth/authorize` passes the signed-in
  accounts, `POST /api/v1/oauth/authorize` validates `account_id` against the device list
  and binds the code (and its `nonce`) to the selected account. Consent remains mandatory;
  the picker only changes *which* account.
- Covered by `scripts/multi-account-test.js` (`npm run test:multi-account`, wired into CI):
  list seeding, add-account preservation, switching, per-account logout/removal, OAuth
  account binding (id_token `sub`/`nonce`, userinfo), tampered-`account_id` rejection,
  legacy-session (no `accountIds`) fallback, and deleted-account cleanup.
- **Deleted accounts never leave ghosts behind**: `getSignedInAccounts` drops ids that no
  longer resolve (admin/other-device deletion) and falls back to the first remaining
  account; `/settings/delete` removes only the deleted account from the device list,
  keeping other signed-in accounts (the session is destroyed only when it was the last).

---

## F2. Two-Factor Authentication (2FA)  [✅ DONE 2026-08-22]

**Goal:** TOTP-based second factor on login (and optionally on sensitive actions), with recovery
codes so users are never locked out.

> Implemented: `src/twofa.js` (RFC 6238 hand-rolled, AES-256-GCM secret
> encryption via `TOTP_ENCRYPTION_KEY`, hashed recovery codes), `src/db.js`
> (`totp_*` columns + `recovery_codes`/`trusted_devices` tables), the two-step
> login in `src/routes/auth.js` (challenge page `/login/totp`, generic errors,
> attempt lockout), enrollment/disable/regenerate on Settings → Security,
> trusted-device cookie (30 d), sibling-session purge on state change, and the
> F2.5 OAuth gate in `src/routes/api-v1.js`. Suite: `npm run test:twofa`.

### F2.1 Dependencies  [P1]

**Where:** `package.json`.

No 2FA support exists today (only `bcryptjs`). Add:
- `otplib` (TOTP generation/verification) — or implement HOTP/TOTP directly (RFC 6238) with the
  existing `crypto` module to avoid a new dependency.
- Optional: `qrcode` for the enrollment QR.

### F2.2 Database: `two_factor` columns + `recovery_codes` table  [P1]

**Where:** `src/db.js:17` (users table), `src/db.js:304+` (migration idiom).

**Change** (additive, in the existing try/catch style):
- `users.totp_secret TEXT` — encrypted at rest (see F2.3), NULL = 2FA not enrolled.
- `users.totp_enabled INTEGER NOT NULL DEFAULT 0`.
- `users.totp_confirmed_at INTEGER` — set after a successful verification code proves enrollment.
- New table `recovery_codes (id, user_id, code_hash TEXT, used_at INTEGER, UNIQUE(user_id, code_hash))`
  — store **hashes** (bcrypt or sha256+pepper), never plaintext codes, so a DB leak doesn't leak
  working codes.
- New accessors in `db.js` next to `getUserByUsername` (`db.js:467`) / `getUserById` (`db.js:471`):
  `getRecoveryCodes`, `consumeRecoveryCode`, `setTOTPSecret`.

### F2.3 Secret encryption at rest  [P1]

**Where:** `src/db.js`, config in `.env.example`.

TOTP secrets are equivalent to passwords — store them encrypted with a server-side key from env
(`TOTP_ENCRYPTION_KEY`), consistent with how the app already treats other credential material.
Reject plaintext storage.

### F2.4 Login flow: second step  [P1]

**Where:** `src/routes/auth.js:70-96` (POST `/login`).

**Change:**
- After the password/bcrypt check (`auth.js:77`): if `user.totp_enabled`, **do not** set
  `req.session.userId` yet. Instead set a short-lived `req.session.pending2fa = { userId, next }`
  (with a TTL, e.g. 5 minutes) and render a "enter 6-digit code or recovery code" step.
- Verify with `otplib` against `user.totp_secret`; on success run the existing session-regenerate
  logic (`auth.js:83-95`) and clear the pending flag.
- Brute-force guard: rate-limit the 2FA step (per `pending2fa` + IP) using the existing
  `express-rate-limit` dependency, and lock out after N failures.
- Failed 2FA must not reveal *whether* the account has 2FA — return the same generic error.
- Add a "remember this device for N days" trusted-device cookie (signed, stores a device token
  table row) to avoid re-prompting 2FA on every login.

### F2.5 2FA also enforced for OAuth device authorizations  [P1]

**Where:** `src/routes/api-v1.js:200` (GET `/oauth/authorize`).

Because OAuth tokens grant API access, an OAuth authorization from a device that isn't
2FA-trusted must complete the same second-factor step before consent (`api-v1.js:240`) is shown.
This reuses the F2.4 pending-2FA machinery; the `?next=` redirect at `api-v1.js:202` already
round-trips the original OAuth request.

### F2.6 Enrollment + management UI  [P2]

**Where:** `src/routes/settings.js`, views in `src/views/`, `src/routes/auth.js`.

**Change:**
- Settings → Security: "Set up 2FA" — generate secret server-side, show QR / manual entry,
  require one valid code to confirm (sets `totp_confirmed_at`), then reveal one-time recovery codes.
- "Disable 2FA" requires the current TOTP code or a recovery code (never just the password alone).
- Regenerate recovery codes; list remaining unused codes with `used_at` timestamps.
- Warn during enrollment that recovery codes are shown once.

### F2.7 Session bootstrap of new accounts  [P2]

First login after enrollment must not leave the old (pre-2FA) session alive — enforce the same
session-regenerate step used at `auth.js:83` whenever 2FA state changes, so an attacker holding a
pre-enrollment session cookie is cut off.

---

## F3. Passkeys (WebAuthn)  [✅ DONE 2026-08-22]

**Goal:** Passwordless sign-in and 2FA-class authentication using platform/roaming passkeys
(WebAuthn), including a first-passkey enrollment bootstrap so new accounts can register a passkey
at signup.

> Implemented: `src/webauthn.js` + `src/routes/webauthn.js` (@simplewebauthn/
> server v13, host-derived rpID/origin, single-use session challenges) and
> `public/passkeys.js` (+ login/settings glue). Passkeys are **full auth** —
> no TOTP afterwards (the chosen model; F3.6's ambiguity resolved). Enrollment
> and management live on Settings → Security; signup-time bootstrap (F3.5) was
> left out for now — passkeys are added post-signup from Security settings.
> Attestation policy is `none` (F3.7 default). Suite: `npm run test:passkeys`.

### F3.1 Dependencies  [P1]

**Where:** `package.json`.

Add `@simplewebauthn/server` (or implement the WebAuthn ceremony verification directly with
`crypto`): handles attestation/assertion parsing, challenge verification, origin/RP-ID checks,
counter replay protection.

### F3.2 Database: credentials table  [P1]

**Where:** `src/db.js` (new table next to existing schema), migration idiom `src/db.js:304+`.

**Change:**
- New table `passkeys`:
  - `id INTEGER PRIMARY KEY`, `user_id INTEGER REFERENCES users(id)`
  - `credential_id TEXT UNIQUE NOT NULL` — base64url credential ID from the authenticator
  - `public_key TEXT NOT NULL` — CBOR-encoded COSE public key (stored as-is from the authenticator)
  - `counter INTEGER NOT NULL DEFAULT 0` — signature counter; reject replay / cloned-device use if
    the new counter is lower
  - `device_name TEXT`, `transports TEXT`, `created_at INTEGER`, `last_used_at INTEGER`
- Index on `user_id`.
- Foreign key + `ON DELETE CASCADE` so deleting an account removes its passkeys.

### F3.3 Authentication ceremony (login)  [P1]

**Where:** `src/routes/auth.js` (login flow), `src/routes/api-auth.js` or a new `src/routes/webauthn.js`.

**Change:**
- `POST /auth/webauthn/begin` — given a username (or discoverable-credential "passkey-first"
  mode), return `{ challenge, allowCredentials, rpId, timeout, userVerification }`. Challenge is a
  random 32-byte value stored in a short-lived session field (never in the DB) with a TTL.
- `POST /auth/webauthn/complete` — verify the assertion: signature over `clientDataJSON ||
  authData` against the stored public key, check `rpIdHash`, `challenge` equality, origin, and the
  counter. On success, run the F1-style add-account logic and `req.session.regenerate()`
  (`auth.js:83`).
- Passkeys and the existing password login (`auth.js:70`) coexist on the same login page.

### F3.4 Registration ceremony (enrollment)  [P1]

**Where:** `src/routes/auth.js` (register), `src/routes/settings.js` (Security → Passkeys).

**Change:**
- `POST /auth/webauthn/register/begin` (requires an authenticated session) → options with
  `rp.id` derived from the request host (same-origin rule), `user.id` = stable random
  base64url per user, `excludeCredentials` = existing passkey IDs to prevent duplicates.
- `POST /auth/webauthn/register/complete` — verify attestation, store the credential row (F3.2),
  enforce at most N passkeys per user (configurable, default e.g. 10).
- Optionally use a passkey as a **second factor** (F2.5-style pending-2FA step) in addition to
  passwordless-first-factor mode — this is the "passkeys can be 2FA-class" posture.

### F3.5 First-passkey bootstrap at signup  [P3]

**Where:** `src/routes/auth.js:17-63` (POST `/register`).

On account creation, offer "create a passkey now" so the user can enroll during onboarding rather
than hunting through settings later. Register endpoint must enforce: registration only allowed for
the just-created account (bound to the new session), never cross-account.

### F3.6 Recovery / UX guardrails  [P1]

**Where:** `src/routes/settings.js`, login view.

- A user who deletes all passkeys falls back to password + 2FA (F2) — never an empty credential
  set with no recovery path.
- Show per-device list (name, last used) with remove buttons; removing the *last* passkey for a
  user who has no password/2FA fallback is blocked with an explanatory error.
- 2FA + passkey interaction: document and enforce one of two models (choose at implementation:
  passkey *replaces* TOTP as the second factor, or passkey is passwordless-first-factor and TOTP
  still applies). Do not implement both semantics ambiguously.

### F3.7 Attestation policy  [P3]

**Where:** new `src/routes/webauthn.js`.

Decide and configure: `none` attestation (privacy-preserving, recommended default) vs. platform
attestation verification for enterprise trust. This is a config flag, not a code fork.

---

## F4. Federation (ActivityPub)

**Goal:** Make Extrovert interoperable with the fediverse (Mastodon, Pleroma, Lemmy, etc.) — local
users can follow remote users and vice versa, public posts federate outward, and remote activity
flows in through a standard ActivityPub inbox. **No federation code exists today** — `well-known.js`
only serves OIDC discovery, and `grep` for `activitypub|webfinger|inbox|outbox` finds only the
unrelated notifications inbox. This is a greenfield build.

### F4.1 Dependencies  [P1]

**Where:** `package.json`.

- Recommend **`@fedify/fedify`** (TypeScript ActivityPub server toolkit: actor, inbox/outbox,
  HTTP signatures, webfinger, nodeinfo) — by far the most maintained option for Node.
- Alternative: implement the protocol core manually with the existing `crypto` + `express` stack
  (HTTP signatures per draft-cavage, ActivityStreams 2.0 JSON-LD, `POST`/`GET` inbox routing) —
  more control, significantly more work and attack surface.
- JSON-LD handling needs a dependency either way (`jsonld` package or fedify's built-in).

### F4.2 Protocol surface: actor + discovery  [P1]

**Where:** `src/routes/well-known.js` (extend, don't replace — keep OIDC discovery), new
`src/routes/federation.js`, new `src/activitypub.js` module (mirrors the `src/dm.js` extraction
pattern from C1).

**Change:**
- `GET /.well-known/webfinger?resource=acct:user@domain` → JRD with `self` link to the actor URL.
  Derive `domain` from the request host (same rule as OIDC `ISSUER`, `oidc.js:9`).
- `GET /users/:username` → ActivityStreams **Actor** document (JSON-LD `Person`), served with
  `application/activity+json` (content negotiation: HTML for browsers, AS2 JSON for federated
  peers — the route already exists as a profile page at `src/routes/profile.js`; add the JSON
  branch there or in the new federation router).
- Actor fields: `id` (canonical `https://domain/users/:username`), `inbox`, `outbox`,
  `followers`/`following` collections, `publicKey` (RSA public key — reuse the OIDC keypair
  machinery from `oidc.js` or a per-actor key, see F4.5), `preferredUsername`, `name`,
  `icon` (avatar), `summary` (bio).
- `GET /.well-known/nodeinfo` + `GET /nodeinfo/2.1` so instances can be discovered by other
  servers' software pages.

### F4.3 Sending: outbound federation  [P1]

**Where:** new `src/activitypub.js`, hooks into existing post/comment/follow flows.

**Change:**
- On post creation (`db.js` `createPost`), enqueue delivery of an AS2 `Create`/`Note` activity to
  the `sharedInbox` (or per-actor `inbox`) of every remote follower.
- On follow/unfollow (`db.follow`), deliver `Follow`/`Undo` to the remote actor's inbox.
- Likes/shares/comments also map to `Like`/`Announce`/`Create` activities.
- **HTTP Signatures** (draft-cavage) on every outbound request: sign with the actor's key, include
  `(request-target)`, `host`, `date`, `digest`. Retry with exponential backoff (table
  `delivery_queue` with `next_attempt_at`, `attempts`, `last_error`); drop after N failures.
- Outbound visibility rule: **only public posts federate.** Extrovert's friends-of-friends model
  (see `feed.js`) never leaves the instance — see F4.6.

### F4.4 Receiving: inbound federation  [P1]

**Where:** `POST /users/:username/inbox` (+ `sharedInbox`), new `src/routes/federation.js`.

**Change:**
- Verify the HTTP signature against the claimed actor's `publicKey` (fetch the actor document,
  cache it with a TTL, guard against SSRF — only `https` URLs, reject localhost/private ranges).
- Reject if the `body` is not valid ActivityStreams JSON-LD, exceeds a size cap (e.g. 1 MB), or
  the `actor` doesn't match the signature key owner.
- Handle activity types: `Follow` (create a remote-follower relationship → notify local user),
  `Accept`/`Reject` (remote accepted/rejected our follow), `Create`/`Note` (store remote post,
  mapped to the local `posts` table with `federated=1` and `remote_actor` link — migration in
  F4.5), `Like`, `Announce` (reblog), `Delete`, `Undo` (unfollow/unlike), `Update` (profile edit),
  `Move` (optional).
- Sanitize every `content` field with the existing `sanitize-html` pipeline (`src/sanitize.js`)
  before storing; strip remote CSS/scripts.
- Idempotency: dedupe by activity `id` (reuse the pattern from `idempotency_keys`, `db.js:1528`).

### F4.5 Data model: remote actors and posts  [P1]

**Where:** `src/db.js` (migrations in the existing `try { ALTER TABLE ... } catch {}` idiom,
`db.js:304+`).

**Change (additive):**
- `users`: add `federated INTEGER NOT NULL DEFAULT 0`, `actor_url TEXT UNIQUE`, `inbox_url TEXT`,
  `public_key TEXT` (per-actor RSA public key, base64 PEM). Remote actors live in the same
  `users` table so every existing join/serializer keeps working — mirror of the local identity.
- `posts`: add `remote_id TEXT UNIQUE` (the remote activity's `id`), `federated INTEGER NOT NULL
  DEFAULT 0`, `remote_actor_id INTEGER REFERENCES users(id)`.
- New tables: `delivery_queue` (F4.3), `followers_remote` (or reuse `follows` with a
  `remote INTEGER` flag), `actor_cache` (F4.4).
- New `db.js` accessors next to `getUserByUsername` (`db.js:467`): `getOrCreateRemoteActor`,
  `getRemoteActorByUrl`, `insertRemotePost`, `enqueueDelivery`, `getDueDeliveries`.

### F4.6 Visibility and access control  [P1]

**Where:** `src/feed.js` (visibility computation), `src/routes/api-v1.js` (serializers).

**Change:**
- **Public posts only** are eligible for federation. Posts aimed at friends/friends-of-friends
  (the `feed.js` visibility model) are never delivered and remote copies are never created.
- Inbound remote posts are stored as public-by-default; the existing `canView` checks
  (`scripts/test.js` covers them) continue to gate them for local rendering — remote public posts
  are visible to everyone on the instance.
- **Defederation:** new `blocked_domains` table + admin UI (`src/routes/admin.js`); a blocked
  domain's activities are rejected at the inbox, its actors' posts are hidden, and outbound
  delivery to it stops. Optional allowlist mode (`FEDERATION_ALLOWLIST` env) for private
  instances.
- Rate-limit the inbox with the existing `express-rate-limit` (per-IP + per-actor), reuse the
  hardening from plan.md A7/A8.

### F4.7 Discovery and UX  [P2]

**Where:** search (`src/routes/api-v1.js` `/search`), profile pages, notifications.

**Change:**
- Search: local search stays as-is; add remote lookups via webfinger
  (`GET /api/v1/search?q=user@remote.domain` resolves acct:). Resolved remote users get a
  follow button that issues an ActivityPub `Follow`.
- Profile page (`src/routes/profile.js`) shows federated handles (`@user@domain`) and a "federated"
  badge; posts from remote users render with their remote avatar/bio (already flowing through the
  E5-fixed serializers).
- Notifications: remote `Follow`, `Like`, `Announce`, and `Create` on your posts arrive via the
  existing `createNotification` path (`db.js:741`, wired to SSE at `db.js:748`).

### F4.8 E2E DMs stay local  [User decision]

**Where:** `src/dm.js` (E2E direct messages).

Extrovert DMs are end-to-end encrypted (Olm, `src/dm.js`) and bound to this instance's key
infrastructure. Federating encrypted DMs is a large, separate project. **Recommendation:** v1 of
federation is **public content only** — DMs never federate; remote users can't DM local users and
vice versa. Document this in SECURITY.md rather than half-supporting it.

### F4.9 Testing  [P2]

- Unit: HTTP signature sign/verify round-trip, webfinger JRD shape, actor JSON-LD shape,
  inbox dedupe, sanitization of remote HTML.
- Integration: spin up two instances in-process (mirroring `scripts/api-test.js`'s temp-DB
  pattern) and drive a follow → accept → post → announce round trip.
- Fuzz/abuse: oversized bodies, malformed JSON-LD, mismatched signature/actor, SSRF attempts on
  inbox actor fetches.

---

## F5. Bots (Discord/Telegram-style bot accounts)

**Goal:** First-class bot accounts — non-human members that run server-side, typically written in
Rust but explicitly **usable from any programming language** — with a stable, language-agnostic API
and event delivery, mirroring how Discord/Telegram bots operate. Everything below reuses the
existing Bearer-token API, so a bot author needs nothing beyond an HTTP client.

### F5.1 Bot accounts  [P1]

**Where:** `src/db.js:17` (users table), migration idiom `db.js:304+`, `src/routes/admin.js`.

**Change (additive, existing `try { ALTER TABLE } catch {}` style):**
- Add `users.is_bot INTEGER NOT NULL DEFAULT 0`.
- Bot creation via admin UI (`src/routes/admin.js`) or an admin-only `POST /api/v1/bots` endpoint:
  inserts a `users` row with `is_bot=1` and **no password** — bots never do interactive login.
- Bots are exempt from the human flows: password login (`src/routes/auth.js:70`), the 2FA second
  step (F2), and the OAuth consent page (`api-v1.js:200`). They authenticate purely with long-lived
  bot tokens.

### F5.2 Bot tokens  [P1]

**Where:** `src/routes/api-auth.js` (Bearer auth pipeline), `db.js` (`oauth_tokens` /
`createOAuthToken`), `src/routes/admin.js`.

**Change:**
- Issue long-lived bot tokens (dedicated `bot_tokens` table or reuse `oauth_tokens` with a `bot`
  scope); token creation + revocation endpoints, with an admin revoke UI and every issuance logged
  via `db.auditLog`.
- Authentication is plain `Authorization: Bearer <token>` through the existing `requireApiAuth`
  chain — works from any HTTP stack (Rust `reqwest`, Go, Python, curl). No SDK required.

### F5.3 Event delivery  [P1]

**Where:** `src/routes/api-v1.js:886-908` (existing SSE `/notifications/stream`),
`src/notif-broadcaster.js`, `db.js:748` (EventEmitter emit on `createNotification`).

**Change:**
- **SSE (recommended for long-running Rust bots):** reuse the existing stream + in-process
  EventEmitter unchanged — a bot holds a connection and receives mention/reply/follow events.
- **Webhooks (for stateless bots):** `POST /api/v1/bots/webhook` registers a URL + secret; the
  server POSTs JSON events signed with an `X-Webhook-Signature: HMAC-SHA256` header (verify before
  processing). Retry with exponential backoff, reusing the delivery-queue pattern from F4.3.
- Webhook secret rotation via settings/admin; one webhook endpoint per bot.

### F5.4 API surface for bots  [P2]

**Where:** `src/routes/api-v1.js`, `src/api-spec.js` (OpenAPI, cf. plan.md E7).

**Change:**
- Bots drive the **existing** REST API (post, reply, like, share, follow, read timelines) — already
  Bearer-authenticated and per-token rate-limited (plan.md A7, `src/server.js:132-145`).
- `src/api-spec.js` is the bot-author contract: Rust bots codegen clients from it
  (`openapi-generator` / `typify`), which makes the E7 spec-drift fix more important once external
  authors depend on it.
- Small bot-friendly additions: `GET /api/v1/bot/me` (own identity), `GET /api/v1/timelines/mentions`
  (mentions-only feed — cheap, high value), optional `is_bot` flag in `serializeAccount`
  (`api-v1.js:74`).

### F5.5 Guardrails  [P1]

- **Rate limits:** per-token budgets already exist (A7); make bot limits configurable (lower burst,
  sustained throughput) via env.
- **Anti-abuse:** bots can't register through normal signup (`src/routes/auth.js:17`) — admin-only
  creation; `is_bot` badge surfaced on profiles; audit trail on token issuance/revocation.
- **DMs:** direct messages are E2E-encrypted and local (`src/dm.js`, F4.8). v1 keeps bot DMs out of
  scope (or adds a separate plaintext bot-DM scope — **user decision**).

### F5.6 Reference clients  [P3]

- Ship a minimal Rust example bot (`examples/bot-rust/`, `reqwest` + `serde` + eventsource) and a
  second one in another language (e.g. Python) to prove the "any language" claim and document the
  happy path: token → stream/webhook → post/reply.

---

## Security review checklist (applies to all five features)

- **Side channels:** 2FA/passkey failures return identical generic errors; no user enumeration via
  "this account has 2FA" messages (F2.4).
- **Credential hygiene:** TOTP secrets encrypted at rest (F2.3); recovery codes hashed (F2.2);
  passkey private keys never leave the authenticator (by construction).
- **Replay:** passkey counters (F3.2), challenge TTLs, code-bound-to-account (F1.4), OAuth code
  binding (F1.4, `api-v1.js:322`).
- **CSRF:** all new session-cookie endpoints follow the existing CSRF-token enforcement shown at
  `api-v1.js:258` and `auth.js` POST handlers.
- **Rate limiting:** reuse the existing `express-rate-limit` dependency for 2FA attempts (F2.4)
  and passkey ceremonies.
- **Session fixation:** every auth-state change re-runs `req.session.regenerate()` (F1.1, F2.4,
  F3.3) — never mutate a session in place across an auth boundary.
- **Lockout safety:** recovery codes (F2.2) and password fallback (F3.6) guarantee a user can
  always get back in; admin accounts get the same recovery paths (no special-case bypass).
