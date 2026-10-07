# Calls & presence

Extrovert has peer-to-peer **WebRTC audio/video calls**: 1:1 calls between mutual followers, and voice channels inside rooms. Signaling, presence, and live push all flow through a single WebSocket endpoint (`/ws`) implemented in `src/webrtc-signaling.js`.

## Presence

- Each user keeps one signaling WebSocket connection (last connection wins per user).
- When you connect, mutual followers are told `user_online`; when you disconnect, `user_offline`. (Only mutual followers can see each other's presence.)
- Presence is visible in the chats list ("online" dot) and via the API (`GET /api/v1/calls/presence`, `GET /api/v1/calls/presence/:username`).
- A user currently in a call is marked `in_call`; the API presence objects include `in_call`.

## 1:1 calls

Flow (client scripts in `public/webrtc.js` / `webrtc-ui.js`):

| Step | WS message | Meaning |
|---|---|---|
| 1 | `call_request {to}` | "Can I call them?" Server answers: `callee_available`, `user_busy` (callee already in a call or has a pending call), or `user_offline` |
| 2 | `call_offer {to, sdp}` | Server relays to the callee as `incoming_call {from, sdp}` (rejects if busy) |
| 3 | `call_answer {to, sdp}` | Relayed to caller as `call_answered` |
| 4 | `ice_candidate {to, candidate}` | Relayed to the peer |
| 5 | `call_end {to}` / `call_decline {to}` | Tear down; both sides clear `in_call` |

1:1 calls are only possible between **mutual followers** (checked server-side). Voice channels have no such requirement — any member of the channel can talk to any other. While `in_call`, further 1:1 incoming calls get `user_busy`.

## Offline calls (ringing an offline user)

When the callee is offline:

1. The server creates a **pending call** (120-second TTL) keyed to the callee.
2. The caller immediately gets `calling_offline {to, expires_at}`.
3. A `missed_call` notification is created for the callee.
4. **Push wake-ups:** browser subscriptions get a web-push `call` payload (ringing system notification with Answer/Decline actions, via `public/sw.js`); native clients get a `call` payload over their always-on WS push channel. Both carry a `cancel_token`.
5. If the callee reconnects before the TTL, the server rings them (`incoming_call`) and tells the caller `callee_ringing`.
6. If the TTL expires, the caller gets `call_unanswered` and the callee's devices get a `missed_call` push + WS push.
7. **Declining from the push notification** posts `{cancel_token}` to `/push/cancel-pending` (no session needed — the unguessable token is the credential), and the caller receives `call_declined`.

## Voice channels (rooms)

Voice channels are rooms-with-audio: members join a channel and talk peer-to-peer within it.

- `join_channel {channel_id}` → server replies `channel_joined {self, members}` and broadcasts `user_joined_channel` to other room members; `leave_channel` broadcasts `user_left_channel`.
- **Joining turns your microphone on** (the browser asks for permission) and shows the **call bar** — channel name, timer, and a mic chip that reads `Mic on`, `Speaking` or `Muted`.
- Offers/answers/candidates route within the channel: `call_offer {channel_id, to, sdp}` → `incoming_call` to the targeted member, `call_answer`/`ice_candidate`/`call_end`/`call_decline` similarly (`to` is optional).
- **Speaking indicators:** your own audio level is measured locally and shown next to each member in the channel's list (your row is marked "you"); the mic chip switches to `Speaking` while you talk and to `Muted` when your mic is off.
- Disconnecting — or navigating away from the room page — stops your microphone and removes you from all voice channels, telling the room you left.
- The room page shows who is in each voice channel (the REST endpoint `GET /api/v1/rooms/:id` returns channels without rosters).

## Native/mobile push channel

The native app's foreground service connects to `/ws` and sends `{type: "push_register"}` as its **first** message. That connection is registered as a *push channel* — the user never appears online (so the pending-call flow still runs) but receives `call`, `missed_call`, and `push_registered` payloads directly over the socket. Browser signaling clients send anything else first (typically `{type: "ping"}` → `pong`).

## Authentication

WebSocket connections authenticate by **session cookie** (browser) or by **OAuth bearer token** via query param (`/ws?token=<access_token>` — native clients). Unauthenticated connections are closed with code `4001`.

## Protocol reference

Full message table and field lists: [Realtime protocol](../developers/realtime.md). End-to-end offline-call test: `scripts/test-offline-call.js`.
