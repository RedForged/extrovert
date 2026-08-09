# Getting started

## Requirements

- **Node.js 22 or newer** — Extrovert uses the built-in `node:sqlite` module, which is stable in Node 22+. No native compilation is needed.
- `npm` (bundled with Node).
- Nothing else. The database is SQLite (a file), so there is no external database server.

## Install & run

```bash
npm install
export SESSION_SECRET="$(openssl rand -hex 32)"   # required — see below
npm start                                          # http://localhost:3000
```

Or for development with auto-restart:

```bash
npm run dev        # node --watch src/server.js
```

The server will create `data/` and `uploads/` automatically on first start.

### `SESSION_SECRET` is mandatory

The server **exits at startup** if `SESSION_SECRET` is not set:

```
FATAL: SESSION_SECRET environment variable is required
```

Generate one with `openssl rand -hex 32` (or `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`). Changing it invalidates all existing session cookies (users are logged out), so treat it as a long-lived secret.

## First run

1. Open `http://localhost:3000`.
2. **Sign up** (`/register`) — usernames are 3–20 letters, numbers, or underscores; passwords at least 12 characters and at most 72 bytes (multi-byte characters such as emoji count more). Registration includes a self-hosted image captcha (type the characters shown) to keep bots out — no third-party service involved.
3. You will be redirected to **Become Admin** (`/become-admin`): the very first account on a fresh instance is offered the admin role. Anyone can claim it as long as **no admin exists yet** — so do this immediately after setting up a new instance. Later sign-ups are never offered it.
4. Find someone by username on the **Discover** page (`/discover`), follow them, and your feed fills with their content and their friends' content.

## Typical usage flow

| Step | Where |
|---|---|
| Write a post (text / photo / video) | Feed composer or `/compose` |
| Find people | `/discover` (search + suggestions) |
| Follow someone because of a post | "Follow" button on a post card |
| Like / comment / share / repost | Buttons under each post |
| Message a friend | `/chats/<username>` (mutual followers only, E2EE) |
| Start a room | `/rooms/create` |
| Call a friend | Chat page or profile (needs WebSocket + mutual follow) |
| Change your profile | `/u/<you>/edit` |
| Manage the instance | `/admin` |

## Running behind a reverse proxy

Extrovert expects to run behind a proxy (nginx, Caddy, HAProxy) in production — it is a single Node process listening on port 3000.

1. Proxy `/` (HTTP) and `/ws` (WebSocket upgrade) to `127.0.0.1:3000`.
2. Set `TRUST_PROXY` in the app environment so `req.ip` (used for rate limiting and referral anti-farming) reflects the real client IP — see [Configuration](configuration.md).
3. Behind TLS, the session cookie is marked `secure` automatically when `NODE_ENV=production` (see `EXTV_COOKIE_SECURE` for edge cases).

## Docker

A sample `docker-compose.yml` ships in the repo: it runs the published `axoisaxo/extrovert:latest` image, mounts `data/` and `uploads/` as named volumes, and joins an existing `nginx-proxy-manager_default` network for the reverse proxy.

```yaml
services:
  extrovert:
    image: axoisaxo/extrovert:latest
    restart: unless-stopped
    expose:
      - "3000"
    networks:
      - nginx-proxy-manager_default
    volumes:
      - extrovert_data:/app/data
      - extrovert_uploads:/app/uploads
    environment:
      - NODE_ENV=production
      - SESSION_SECRET
```

`SESSION_SECRET` is pulled from your shell/host environment. No extra services are required — this is the whole stack.

The image runs as the **unprivileged `node` user (uid 1000)**, with `/app/data` and `/app/uploads` owned by it. Fresh named volumes inherit that ownership automatically, but **if you are upgrading an instance whose volumes were created by an older (root) image**, fix ownership once before starting the new image:

```bash
docker run --rm -v extrovert_data:/app/data -v extrovert_uploads:/app/uploads \
  --user root axoisaxo/extrovert:latest chown -R 1000:1000 /app/data /app/uploads
```

Then `docker compose pull && docker compose up -d`.

## Resetting everything

Stop the server, then delete:

```bash
rm -rf data uploads
```

This wipes accounts, posts, sessions, OAuth keys, and all uploaded media. Start the server again for a fresh instance (and set up the first admin again).
