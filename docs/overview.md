# Overview & concepts

> **Where this wiki lives:** the same pages you're reading are served inside the app at `/docs` (from Settings → Documentation). The repository copies are in `docs/` with the rest of the source.

## What Extrovert is

Extrovert is a self-hosted social network built on a deliberately simple idea: **your feed only ever contains content from people in your social graph** — you, the people you follow (your *friends*), and the people they follow (your *friends-of-friends*). Everyone else is invisible to you, and you are invisible to them.

There is no public timeline. `GET /api/v1/timelines/public` exists but returns `403` on purpose. Content is network-bound by design, and all visibility checks are enforced both in the web UI and in the REST API.

## The network model

All visibility rules live in `src/network.js`:

| Concept | Definition | Code |
|---|---|---|
| **You** | Your own content is always visible to you | `canView(viewer, viewer)` → `true` |
| **Friend** | Someone you follow (one-way) | `friendIds(userId)` |
| **Friend-of-friend** | Someone followed by one of your friends — excluding you and your direct friends | `foafIds(userId)` |
| **Visible set** | You + friends + friends-of-friends | `visibleUserIds(viewerId)` |
| **canView** | `authorId` is in the viewer's visible set | `canView(viewerId, authorId)` |

Key consequences:

- **Following is the only discovery mechanism.** You cannot see, search, or interact with content from people outside your visible set. The API returns `404 Not Found` for accounts/posts you can't see (never `403`, to avoid confirming existence).
- **Searching for people is not network-bound** (you can search any username), but **searching posts is**: post search only matches posts by authors in your visible set.
- **Mutual followers** (both follow each other) unlock the privacy-sensitive features: direct messages and 1:1 calls. Everything else works one-way.

## Terminology

| Term | Meaning |
|---|---|
| **Post** | A unit of content: text, photo, video, or repost. |
| **Original content** | The underlying post that a repost wraps. Engagement always targets the original. |
| **Repost** | Re-publishing someone else's post into your own stream. Doesn't split engagement. |
| **Share** | A one-click "boost" signal with a notification to the author. |
| **Follow-from-post** | The "Follow because of this post" button — a big, personal feed boost to that post. |
| **Friend** | Someone you follow. |
| **Mutual followers** | Two users who both follow each other. |
| **Room** | A group space (public or private) with channels and roles. |
| **Channel** | A text or voice channel inside a room. |
| **E2EE** | End-to-end encryption: direct messages and room messages both use MLS (RFC 9420). |

## The feed algorithm in one sentence

Every post in your network is scored as `recency base + engagement boosts`; the highest-scoring post wins the top of the feed, and the same content appearing both directly and via a repost is de-duplicated to its best-ranked appearance. Full details in [Posts & the feed algorithm](using/feed.md).

## Realtime architecture

Realtime features (presence, calls, live DM delivery, native push) run over a single WebSocket endpoint (`/ws`) implemented in `src/webrtc-signaling.js`. Notifications additionally have a server-sent-events stream on the API. See [Realtime](developers/realtime.md).

## Tech stack

| Layer | Choice |
|---|---|
| Runtime | Node.js (≥22, uses the built-in `node:sqlite`) |
| Server | Express 4 + `express-session` (SQLite-backed sessions) |
| Database | SQLite (WAL mode), one file `data/extrovert.db` + `data/sessions.db` |
| Views | EJS templates with a hand-rolled design system (`public/theme.css`, Fraunces + Hanken Grotesk fonts) |
| Encryption | `ts-mls` (RFC 9420), bundled for the browser as `public/lib/mls.js` from `src/client-mls/` via esbuild (`npm run build:mls`) |
| Media | `sharp` for image processing (avatars, stickers, dimensions) |
| Push | `web-push` (VAPID) for browsers; WebSocket push channel for native clients |
| Realtime | `ws` (WebSocket) for signaling/presence/calls |
| Security | `helmet`, `express-rate-limit`, `sanitize-html`, bcryptjs |

## Data stored on disk

| Path | Contents |
|---|---|
| `data/extrovert.db` | All app data (users, posts, follows, messages, rooms, OAuth tokens, …) |
| `data/sessions.db` | Session cookies |
| `data/oidc-keys.json` | The OIDC signing keypair (private key — keep safe) |
| `data/api-uploads/` | Media uploaded through the REST API |
| `uploads/` | Post media, avatars (`uploads/avatars/`), stickers (`uploads/stickers/`) |

To reset everything, stop the server and delete `data/` and `uploads/`.

## Project layout

A full map lives in [Development & testing](development.md). The short version:

```
src/
  server.js            Express app, middleware pipeline, WS server
  db.js                SQLite schema, migrations, all query helpers
  feed.js              Feed algorithm + 30s per-user cache
  network.js           Visibility rules (friends / friends-of-friends)
  sanitize.js          Profile/room HTML + CSS sanitization
  auth.js              Session auth middleware
  bearer-auth.js       OAuth Bearer → user resolution for web routes
  api-auth.js          API auth middleware, scopes, token validation
  oidc.js              OIDC key management, JWKS, ID token signing
  push.js              VAPID web push
  dm.js                Shared DM logic (web + API)
  notif-broadcaster.js In-process notification events (SSE)
  webrtc-signaling.js  WS signaling: presence, calls, voice channels, DM pushes
  session-store.js     express-session SQLite store
  api-spec.js          OpenAPI 3.1 spec
  routes/              One router per area (see Development)
  views/               EJS templates
public/                Static assets, client JS, fonts, service worker
scripts/               Tests and tooling
```
