# Realtime: WebSocket Gateway, WebRTC, SSE, push

Extrovert provides a unified realtime system over WebSocket (`/ws`), Server-Sent Events (`/api/v1/notifications/stream`), and Web Push:

| Channel | For | Auth |
|---|---|---|
| `/ws` — Gateway & Signaling | Realtime events (feed, rooms, notifications), presence, 1:1 calls, voice channels, live DMs | Session cookie, `Authorization: Bearer`, `?token=`, or message `token` |
| `/ws` — push channel | native/mobile call wake-ups | same |
| `GET /api/v1/notifications/stream` | notification SSE stream | Bearer (`notifications`) |
| Web Push (VAPID) | browser call notifications | subscription-based |

## Realtime Gateway Multiplexing (`/ws`)

The WebSocket endpoint `/ws` functions as a full multiplexed event gateway for external and native clients (such as `extrovert_native`).

### Connecting & Authentication

Clients can authenticate through multiple methods:
1. **HTTP Handshake Header:** `Authorization: Bearer <access_token_or_pat>`
2. **Query Parameter:** `wss://host/ws?token=<access_token_or_pat>&auto_subscribe=1` (supports OAuth tokens and Personal Access Tokens `ext_pat_...`). Passing `auto_subscribe=1` automatically attaches the socket to `timeline:home`, `notifications`, `presence`, and all rooms the user is a member of.
3. **In-Frame Authentication:** Sockets can connect unauthenticated and provide their token in subscription, auth, or resume messages:
   ```json
   { "action": "subscribe", "topic": "timeline:home", "token": "ext_pat_..." }
   ```
4. **Session Cookie:** Web browsers pass session cookies automatically.

### Auto-Subscription & Room Lifecycle

Clients do not need to manually subscribe to each room individually. By passing `auto_subscribe=1` in the connection URL or sending `{ "action": "auto_subscribe" }` (or `{ "action": "resume", "auto_subscribe": true }`), the server:
- Automatically subscribes the connection to `timeline:home`, `notifications`, `presence`, and every room the user has joined.
- Dynamically attaches new room topics whenever the user joins a room via REST (`POST /api/v1/rooms/:id/join`).
- Dynamically detaches room topics when the user leaves a room (`POST /api/v1/rooms/:id/leave`).

### Optimistic UI (`client_id` Echo)

When sending posts (`POST /statuses`), comments (`POST /statuses/:id/comments`), or room messages (`POST /rooms/:id/channels/:cid/messages`), clients can include an optional `client_id` (or `client_tx_id` / `nonce`). The server echoes this exact string back in both the HTTP response and the WebSocket broadcast event payload (`msg.data.client_id`). This allows clients to instantly transition pending local items into confirmed state with zero duplicate rendering.

### Gateway Topics

Clients subscribe to specific topics using `{ "action": "subscribe", "topic": "<topic>" }`:

| Topic | Events Broadcasted | Description |
|---|---|---|
| `timeline:home` | `post_create`, `comment_create`, `post_delete` | Realtime home timeline updates |
| `room:<id>` | `message_create`, `message_delete`, `member_join`, `member_leave`, `room_session_key`, `typing` | Room text and member events (membership enforced). `room_session_key` is pushed in realtime when a peer shares a Megolm session. |
| `notifications` | `notification_new` | Push notifications to active client |
| `presence` | `user_online`, `user_offline`, `otk_low` | Presence updates of mutual followers, plus proactive `otk_low` warnings when one-time prekeys fall below 10. |

### Gateway Opcodes (Client → Server)

| Action | Payload | Description |
|---|---|---|
| `auto_subscribe` | `{ "action": "auto_subscribe" }` | Automatically subscribe to feed, notifications, presence, and all joined rooms. |
| `subscribe` | `{ "topic": "room:1", "token": "...", "auto_subscribe": true }` | Subscribe to an event topic (accepts `topic`, `channel`, or `channels` array). |
| `unsubscribe` | `{ "topic": "room:1" }` | Unsubscribe from an event topic. |
| `resume` | `{ "seq": 105, "auto_subscribe": true }` | Replay missed events since sequence number `seq` after a network drop. |
| `typing` | `{ "channel": "room:1", "typing": true }` | Send a typing indicator to a room channel or direct chat. |
| `ping` | `{ "action": "ping" }` | Keepalive heartbeat (server replies `{ "type": "pong" }`). |

### Gateway Events (Server → Client)

All broadcast events carry a strictly monotonic sequence number (`seq`) backed by a 500-event ring buffer on the server.

For Megolm-encrypted room messages, if the receiving client has a pending session key for the message's `group_session_id`, the server automatically inlines `session_key` directly in `data` so the client decrypts instantly with **zero round-trips**:

```json
{
  "seq": 106,
  "type": "gateway_event",
  "topic": "room:1",
  "event": "message_create",
  "data": {
    "id": "42",
    "room_id": "1",
    "channel_id": "1",
    "author": { "id": "7", "username": "alice", "display_name": "Alice" },
    "proto": "megolm",
    "ciphertext": "...",
    "group_session_id": "1",
    "created_at": "2026-10-03T00:00:00.000Z",
    "session_key": {
      "key_id": 2,
      "encrypted_key": "...",
      "sender_id": "7"
    }
  }
}
```

When reconnecting after a disconnection, send `{ "action": "resume", "seq": 106 }`. The server replies:

```json
{
  "type": "resumed",
  "replayed": 2,
  "last_seq": 108
}
```
followed by each missed event frame in order.

---

## WebRTC Signaling (`/ws`)

In addition to the event gateway, `/ws` handles WebRTC 1:1 call signaling and room voice channels:

| Type | Payload | Meaning |
|---|---|---|
| `pong` | — | Reply to ping. |
| `push_registered` | — | Push channel accepted. |
| `user_online` / `user_offline` | `{username, display_name}` | A mutual follower connected/disconnected (broadcast to mutuals). |
| `callee_available` | `{to}` | Callee is online and free — proceed with the offer. |
| `user_busy` | `{from}` / `{to}` | Callee in a call (or already has a pending call). |
| `calling_offline` | `{to, expires_at}` | Callee offline; pending call queued (120 s TTL). |
| `user_offline` | `{from}` | Call target unreachable. |
| `incoming_call` | `{from, from_display, sdp?}` | Ring. With `sdp` it's a forwarded offer (1:1 or voice channel with `channel_id`). |
| `callee_ringing` | `{to}` | Callee reconnected and is being rung. |
| `call_answered` | `{from, from_display, sdp}` | Call accepted. |
| `call_ended` | `{from}` | Peer hung up. |
| `call_declined` | `{from}` | Peer declined. |
| `call_unanswered` | `{from, to}` | Offline call timed out. |
| `new_dm` | `{message: {…ciphertext…}, sender_curve, from_username, from_display}` | Live DM ciphertext to **every open tab** of the recipient. |
| `channel_joined` | `{channel_id, self, members}` | Voice channel join ack. |
| `user_joined_channel` / `user_left_channel` | `{channel_id, username, display_name?}` | Room voice-channel membership changes. |
| `call` (push channel) | `{type:"call", from, from_display, cancel_token}` | Native call wake-up. |
| `missed_call` (push channel) | `{type:"missed_call", from, from_display}` | Native missed-call notification. |

## Notification SSE

`GET /api/v1/notifications/stream` with `Authorization: Bearer <token>` (scope `notifications`):

```
event: connected
data: {}

event: notification
data: {"id":12,"type":"like","actor_id":7,"post_id":21,"created_at":1750000000000}

: heartbeat
```

- One `notification` event per new notification, pushed in-process the moment it's created (`src/notif-broadcaster.js`).
- Heartbeat comment lines every 15 s keep proxies happy; `X-Accel-Buffering: no` is set.
- Close the connection to stop receiving.

## Web Push (browsers)

1. Server must be configured with `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_SUBJECT`.
2. The browser fetches `GET /api/v1/push/vapid-public`, calls `pushManager.subscribe`, and registers via `POST /api/v1/push/subscribe` (`{platform:"web", endpoint, p256dh, auth}`).
3. Payloads delivered by the server (via `web-push`, urgency high, TTL 120):

   | Payload | When |
   |---|---|
   | `{type:"call", from, from_display, cancel_token}` | Incoming offline call → service worker shows a ringing notification with **Answer** / **Decline** actions. |
   | `{type:"missed_call", from, from_display}` | The pending call timed out. |

4. **Answer** opens the chat page; the server rings on WS reconnect. **Decline** POSTs `{cancel_token}` to `/push/cancel-pending` — no session needed, the unguessable token is the credential.
5. Dead subscriptions (HTTP 400/404/410) are deleted automatically.

## Native push channel

Instead of web-push, the native app's foreground service keeps a WebSocket open and sends `push_register`. The server delivers `call` / `missed_call` payloads over that socket (see above). This avoids third-party push relays entirely.

## Presence API

- `GET /api/v1/calls/presence` → online **mutual followers** `[{id, username, display_name, in_call}]`
- `GET /api/v1/calls/presence/:username` → `{online, in_call}`

These read the in-memory signaling registry (`getOnlineUsers` / `getUserPresence` in `src/webrtc-signaling.js`).
