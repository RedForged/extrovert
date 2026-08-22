# FAQ

## General

### What makes Extrovert different from other social networks?
Your feed only contains content from **you, your friends, and your friends-of-friends**. There is no public timeline, no global algorithm, no discoverability outside your network. You literally cannot see content from people you aren't connected to (the API returns 404 for it).

### How do I find people to follow?
The **Discover** page (`/discover`) — search by username/display name, or use the "Suggested for you" list (friends-of-friends you don't follow yet).

### Do I need to follow someone back to see their posts?
No — following is one-way. **Mutual following** (both follow each other) is only required for direct messages and 1:1 calls.

### Is there a public timeline?
No. `GET /api/v1/timelines/public` exists and returns `403 Forbidden` by design.

## Feed

### Why is my post missing from my feed?
The feed is ranked, cached for 30 seconds, and de-duplicated: if your content surfaces both directly and via a repost, only the higher-ranked appearance is shown. Older content may also fall off the candidate window (the most recent 500 posts in your network).

### Why does a comment without a like not boost the post?
By design: commenting without liking is treated as interest in the *author* rather than the post, so it boosts the author's **other** content — only for you.

### How do I make a post rank higher?
Get real engagement (likes, shares, comments-with-likes). A follow-from-post gives the biggest single boost (+1000) — when someone follows you because of one of your posts, that post jumps.

## Profiles

### Can I really write raw HTML and CSS?
Yes — profile bodies are user HTML with a sanitized tag/attribute whitelist, and CSS is scrubbed of script-capable and external-request vectors. JavaScript is never allowed. Put `<!--POSTS-->` where you want posts to render.

### Why was part of my HTML removed on save?
The sanitizer discards anything not on the whitelist (e.g. `script`, `iframe`, `video`, `form`, `onclick`, `data:` URLs, external CSS `url()`s). See [Profiles](using/profiles.md) for the full list.

## Messaging & encryption

### Why can't I message someone?
DMs require **mutual followers** — both of you must follow each other.

### Is the server able to read my messages?
For current (Olm) messages the server stores ciphertext only and enforces encryption. The legacy `rsa` protocol stores ciphertext wrapped for sender/recipient. The stored RSA private key is client-encrypted. The honest caveat: key distribution has no transparency log — verify **safety numbers** with your contacts for high-value conversations (see [Security](security.md)).

### What happens if I lose my browser?
If your client uploaded a password-encrypted **account backup** (`/chats/prekeys/backup`), a new browser can download and decrypt it. Otherwise your private keys are gone — you'll need to publish new keys, and old sessions can't be decrypted by you.

## Rooms & calls

### What's the difference between a Share and a Repost?
A **share** is a lightweight boost signal (notifies the author, +60 to the post's feed score). A **repost** re-publishes the content into your own stream as a post of its own — it surfaces content to *your* network.

### Why are room messages "end-to-end encrypted required"?
Room chat is Megolm-encrypted and the server rejects plaintext messages. Stickers (paths under `/uploads/stickers/`) are the exception.

### How do offline calls work?
The call is queued for 120 seconds, a `missed_call` notification is created, and the callee's devices are woken with a push (web push for browsers, WebSocket push for native). If the callee reconnects in time they get rung; otherwise the caller gets `call_unanswered`.

## Accounts & administration

### Someone took admin on my new instance — help?
The first account on a fresh instance is offered admin via `/become-admin`; this is by design. Claim it immediately after first setup. If an attacker got there first, delete `data/extrovert.db` to start fresh (there is no admin-recovery backdoor).

### How do I reset the whole instance?
Stop the server, delete `data/` and `uploads/`, restart. Fresh database, fresh uploads, new admin flow.

### Can I self-host behind a domain?
Yes — set `OIDC_ISSUER` to your public URL, `TRUST_PROXY` to your proxy's addresses, and proxy `/` + `/ws` to port 3000. See [Configuration](configuration.md).

### Do I need to configure anything for Docker?
The sample `docker-compose.yml` is complete on its own: it just needs `SESSION_SECRET` from the host environment (and an existing `nginx-proxy-manager_default` network). No extra services, no external dependencies.

### How do I turn on two-factor authentication?
Users enable it themselves at **Settings → Security** — but the server operator must set `TOTP_ENCRYPTION_KEY` first (generate with `openssl rand -base64 32`; TOTP secrets are encrypted with it). Without the key, 2FA setup shows an explanatory message. Passkeys work without any configuration.

### I lost my authenticator device — am I locked out?
No. Each of your 10 recovery codes works exactly once in place of a TOTP code, both on the login screen and on the "turn off 2FA" form. If you've burned all recovery codes and lost the device, an admin can delete the account; there is deliberately **no bypass** of 2FA (not even for admins).

## Developers

### How do third-party apps authenticate?
OAuth 2.0 Authorization Code + PKCE, with OpenID Connect on top. Register an app at `/settings/developers` (or `POST /api/v1/oauth/apps`), follow the flow in [OAuth & OIDC](developers/oauth-oidc.md).

### Is there an OpenAPI spec?
Yes — live at `/developers/openapi.json` with a Swagger UI at `/developers/docs`.

### How do I get realtime events?
Notification SSE (`GET /api/v1/notifications/stream`), WebSocket signaling for calls/presence (`/ws`), and VAPID web push for browsers. See [Realtime](developers/realtime.md).

### Which Node version do I need?
Node 22+ (uses the built-in `node:sqlite`).
