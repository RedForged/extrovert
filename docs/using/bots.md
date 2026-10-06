# Bots

Discord/Telegram-style **bot accounts** — non-human members that run server-side and drive the
regular REST API with a plain HTTP client. Any language works; example bots ship in
`examples/bot-rust/` (SSE, recommended for long-running bots) and `examples/bot-python/`
(webhook/polling, proves the "any language" claim).

## Quick start

1. **An admin creates the bot** (bots can never sign up or log in interactively):

   ```bash
   curl -X POST https://extrovert.redforged.eu/api/v1/bots \
     -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
     -d '{"username":"echo_bot","display_name":"Echo Bot"}'
   ```

   The response contains `data.token` — a long-lived **bot token shown exactly once**
   (only its hash is stored). Keep it secret; revoke and reissue if it leaks.

2. **Call the API** with `Authorization: Bearer exb_…` — everything works: post, reply,
   like, share, follow, read timelines. `GET /api/v1/bot/me` returns the bot's own account.

3. **Receive events** — two modes:

   - **SSE (recommended):** hold `GET /api/v1/notifications/stream` open and you receive
     `event: notification` frames (mention / comment / follow) live, with heartbeats.
   - **Webhooks:** `POST /api/v1/bots/webhook {"url":"https://…"}` registers an endpoint and
     returns the signing **secret once** (`POST /api/v1/bots/webhook/rotate` to rotate). The
     server POSTs each notification as JSON with
     `X-Webhook-Signature: hex(HMAC-SHA256(secret, raw_body))` — **verify before processing**.
     Failed deliveries retry with exponential backoff (5 attempts).

4. **Mentions timeline:** `GET /api/v1/timelines/mentions` — the posts that mentioned the bot,
   newest first. Perfect trigger source for reply bots.

## Accounts & tokens

- `POST /api/v1/bots` (admin) — create bot + first token. `GET /api/v1/bots` (admin) — list.
- `POST /api/v1/bots/:id/tokens` (admin) — issue another token; `GET` lists prefixes only;
  `DELETE /api/v1/bots/:id/tokens/:tokenId` revokes. Every issuance/revocation is audit-logged.
- `is_bot` is exposed on accounts (`GET /api/v1/accounts/:id`) and shown as a **bot** badge on
  profiles so people always know when they're talking to software.

## Guardrails

- Bots are **admin-created only** — they can't register or password-login (the login form
  rejects them exactly like a wrong password).
- Bot tokens authenticate through the same Bearer pipeline as OAuth/PATs and carry
  `read write follow notifications media.write profile` scopes.
- Dedicated rate budget: `EXTV_BOT_RATE_LIMIT` requests per minute per token (default 120).
- **DMs are out of scope for bots in v1** — direct messages are end-to-end encrypted between
  human devices and bots hold no MLS device state.

## Webhook signature verification

```python
import hashlib, hmac
def verify(signature, body, secret):
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature)
```
