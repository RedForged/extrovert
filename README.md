# Extrovert

> [!NOTE]
> **Canonical repository:** Extrovert is actively maintained at [git.new-eve.org/redforged/extrovert](https://git.new-eve.org/redforged/extrovert).
> The GitHub repository is an automated mirror.

A social network where you can **only discover content from friends and friends-of-friends**. You cannot see anything from people you aren't connected to — there is no public timeline, no firehose, no algorithm mining the whole internet. Just your network.

<p align="center">
  <a href="LICENSE"><img alt="License: GPL-3.0-or-later" src="https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg"></a>
  <a href="https://github.com/AxoIsAxo/extrovert/actions/workflows/ci.yml"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/AxoIsAxo/extrovert/ci.yml?branch=master"></a>
  <a href="#development--testing"><img alt="all suites pass" src="https://img.shields.io/badge/tests-all_suites_pass-brightgreen.svg"></a>
  <a href="https://hub.docker.com/r/axoisaxo/extrovert"><img alt="Docker image size" src="https://img.shields.io/docker/image-size/axoisaxo/extrovert"></a>
  <a href="https://github.com/AxoIsAxo/extrovert/issues"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg"></a>
</p>

The signature motif is three concentric rings: **you** (inner), your **friends** (middle), and your **friends-of-friends** (outer).

```
┌────────────────────────────────────────────┐
│  o o o o o o o o o o o o o o o o o o o o   │   friends-of-friends (visible content)
│  o   ┌────────────────────────────┐     o  │
│  o   │ o o o o o o o o o o o o o  │     o  │   friends (visible content)
│  o   │ o o o ┌────────────┐  o o  │     o  │
│  o   │ o o o │    you     │  o o  │     o  │   you (your own content)
│  o   │ o o o └────────────┘  o o  │     o  │
│  o   │ o o o o o o o o o o o o o  │     o  │
│  o   └────────────────────────────┘     o  │
│  o o o o o o o o o o o o o o o o o o o o   │
└────────────────────────────────────────────┘
  everyone else: invisible
```

## Feature overview

| Area | What you get |
|---|---|
| **Posts** | Text, photo, or video posts; Markdown support; reposts; comment threads; edit history; full deletion |
| **Feed** | A deterministic, explained ranking algorithm over your network only (see [Feed](docs/using/feed.md)) |
| **Profiles** | Fully customizable profile pages — every user can write their own **HTML and CSS** (no JavaScript) |
| **Social** | Follow, like, comment, share, repost, "follow because of a post" |
| **Discovery** | [Discover](docs/using/discovery.md) page: search users, friend-of-friend suggestions, network-bound post search |
| **Messaging** | End-to-end-encrypted direct messages between mutual followers (MLS, RFC 9420); optional **Additional Security** mode deletes messages from the server once both users have received them (device-only copies) |
| **Rooms** | Group spaces with channels (text + voice), role-based permissions, E2EE group chat (MLS), voice calls |
| **Calls** | Peer-to-peer WebRTC calls with presence, offline-call rings, and push wake-ups |
| **Notifications** | Inbox, unread badges, realtime SSE stream, web push |
| **Stickers** | Personal sticker packs usable in posts, comments, and messages |
| **Admin** | Bans, user deletion, promotions, room moderation, reports queue, server-wide announcement |
| **API** | Full REST API (OAuth 2.0 + OpenID Connect, Dynamic Client Registration, Personal Access Tokens) with OpenAPI 3.1 spec, Swagger UI, and Realtime WebSocket Gateway |
| **Security** | Responsible disclosure: public `/security` page with a private report form for admins, plus RFC 9116 `/.well-known/security.txt` |

Security posture is documented in [docs/security.md](docs/security.md); the audit history lives in [SECURITY.md](SECURITY.md). Security researchers can test the software under the conditions on the in-app `/security` page and report findings privately.

## Quick start

```bash
npm install
npm start          # http://localhost:3000
```

You must set a `SESSION_SECRET` environment variable before the server will start. See [Getting started](docs/getting-started.md) and [Configuration](docs/configuration.md).

## Development & testing

Every push and pull request runs all of the following on GitHub Actions — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). The Docker image build is
part of CI too.

- `npm test` — feed algorithm + sanitization unit tests (24 assertions)
- `npm run test:api` — REST API integration suite (36 tests)
- `npm run test:client` — Native client REST API & Realtime Gateway parity suite (25 tests)
- `npm run test:bootstrap` — Client bootstrap, device pairing & optimistic sync suite (10 tests)
- `npm run test:owasp` — OWASP Top 10 (2021) security suite (47 tests)
- `npm run test:asvs` — OWASP ASVS v4.0 suite (57 tests; automatable subset, with a MANUAL_REVIEW/N-A scorecard)
- `npm run seed:client` — Seed deterministic fixtures and PATs for client testing (`alice`, `bob`, `charlie`)
- plus the MLS suites (`npm run test:mls`, `test:ietf`, `test:interop`, `test:scale`), OAuth, 2FA, passkeys, captcha, email and render suites — see [Development & testing](docs/development.md)

## Documentation index

**Basics**

- [Overview & concepts](docs/overview.md) — the network model, terminology
- [Getting started](docs/getting-started.md) — install, first run, day-one usage
- [Configuration](docs/configuration.md) — environment variables, Docker, reverse proxy, push keys

**Using Extrovert**

- [Posts & the feed algorithm](docs/using/feed.md)
- [Profiles & customization](docs/using/profiles.md)
- [Discovery & search](docs/using/discovery.md)
- [Notifications](docs/using/notifications.md)
- [Direct messages (E2EE)](docs/using/messaging.md)
- [Rooms & voice channels](docs/using/rooms.md)
- [Calls & presence](docs/using/calls.md)
- [Stickers](docs/using/stickers.md)
- [Settings & account](docs/using/settings.md)
- [Admin guide](docs/using/admin.md)

**For developers**

- [REST API overview](docs/developers/api-overview.md)
- [API endpoint reference](docs/developers/endpoints.md)
- [OAuth 2.0 & OpenID Connect](docs/developers/oauth-oidc.md)
- [Realtime: WebSocket, SSE, push](docs/developers/realtime.md)

**Reference**

- [Security model](docs/security.md)
- [Development & testing](docs/development.md)
- [FAQ](docs/faq.md)

## License

Extrovert is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License, version 3 or any later version** — see [LICENSE](LICENSE) for the full text. It is distributed in the hope that it will be useful, but **without any warranty**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GPLv3 for details.

The app includes bundled third-party software under their own licenses (e.g. [`ts-mls`](https://www.npmjs.com/package/ts-mls), the RFC 9420 implementation bundled into `public/lib/mls.js`).
