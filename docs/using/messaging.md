# Direct messages (E2EE)

Direct messages are **end-to-end encrypted**, and — consistent with the network-first design — you can only DM **mutual followers** (both of you follow each other).

## Where DMs live

- Web: `/chats` (conversation list) and `/chats/<username>` (thread).
- API: `/api/v1/conversations*` endpoints (scopes `read:direct` / `write:direct`) — same crypto, same routes, Bearer auth. See the [endpoint reference](../developers/endpoints.md#direct-messages).

## Encryption model

Messages are encrypted with **MLS (RFC 9420)**. The protocol is marked per message in the `proto` column (`mls`), and the server **enforces** it: a non-sticker message whose `proto` isn't `mls` is rejected with **426 Upgrade Required** (`LegacyProtocolRetired: …`). The ciphertext lives in `body` (≤ 65,536 characters) and your own encrypted self-copy in `sender_ciphertext` — the server stores nothing else.

### Your key material (the server only stores public or encrypted parts)

| Concept | Where | Contents |
|---|---|---|
| MLS devices | `/mls/device/register`, `/mls/devices` | One MLS device per browser profile; the account can list and remove them. |
| Key packages | `/mls/keypackages` | Public MLS KeyPackages, published per device and **consumed** when a peer starts a group with you. |
| MLS group state | client only | Epoch and message secrets stay in the browser; the server keeps ciphertext plus your encrypted self-copy. |
| Welcomes | `/mls/welcomes`, `/mls/welcomes/ack` | Pending MLS Welcome messages addressed to your devices. |
| History backup | `/mls/backup` | Optional password-encrypted account backup, restorable on a new browser session. |

### Key lifecycle

- **Publish:** your client registers its device (`POST /mls/device/register`) and uploads public key packages (`POST /mls/keypackages`); `GET /mls/keypackages/status` reports how many are left.
- **Start a conversation:** fetching a peer's packages (`GET /mls/keypackages/:userId`) **consumes** them. The initiator creates the group (`POST /mls/groups/init`) and the peer picks up the Welcome (`GET /mls/welcomes`).
- **Change the group:** membership and key changes are MLS commits (`POST /mls/groups/:groupId/proposals`, `…/commit`), with the ordered history under `GET /mls/groups/:groupId/commits` so every device lands on the same epoch.
- **Backup / recovery:** `POST /mls/backup` stores a password-encrypted copy of your client state.
- **Config:** `GET /mls/config` reports the server's MLS settings, including `legacy_e2ee_enabled: false`.

## Conversation features

| Feature | Notes |
|---|---|
| List | `/chats` — last message preview, unread counts, **online presence** per conversation, and the peer's curve25519 key |
| History | Oldest-first thread; API returns newest-first with a cursor for backward pagination |
| Send | `proto: "mls"` with a ciphertext ≤ 65,536 chars; sticker paths are sent as plaintext |
| Stickers | A message whose body starts with `/uploads/stickers/` is allowed as a plaintext sticker path (see [Stickers](stickers.md)) |
| Edit | Author only, up to 65,536 chars, re-encrypted; recorded in edit history, marked "(edited)" |
| Delete | API: `DELETE /api/v1/messages/:id`; the record (including ciphertext) is removed |
| Read state | Unread counts per conversation; opening a thread marks it read |
| Live delivery | New messages are pushed in realtime over the WebSocket `new_dm` event to **every open tab** of the recipient (ciphertext only) |
| Additional Security | Per-conversation opt-in (both users) that deletes messages from the server once both have received them — see below |

## Sending files and photos

Attach a file with the **+** button next to Send. In one message you can send text, a file, or both.

- The file is **sealed in your browser** before it is uploaded: a fresh AES-256-GCM key encrypts it,
  and that key travels inside the MLS-encrypted message. The server stores an opaque blob and never
  learns the file's name, type or which conversation it belongs to — the stored file has no
  extension, and its `user_files` row carries no name or MIME type.
- The recipient's client decrypts it in memory and renders it (images and video inline, everything
  else as a download link). Nothing is written to disk in the clear, on either side.
- Sealed attachments count against your [Drive](../using/drive.md) quota like any other upload. If
  the file doesn't fit in your remaining space you're told before anything is sent.
- Deleting the message removes the reference; the blob stays in your Drive until you delete it there
  (which is what frees the space).

## Additional Security mode

A per-conversation mode for users who want **no server-side copy at all** once a message is delivered:

- **Mutual opt-in.** Each user toggles it on their side (`POST /chats/<username>/security` web, or `POST /api/v1/conversations/<username>/security` API). The mode only takes effect once **both** users have enabled it — a user whose client can't store messages locally is never silently cut off from history.
- **New messages only.** Messages sent while the mode is active are stored with `secure = 1`; existing history is untouched.
- **Deleted once both received.** Each client keeps a **device-local copy** (encrypted with the device key) and acknowledges receipt (`POST /chats/<username>/received`, or `POST /api/v1/conversations/<username>/received` with `message_ids`). When the sender *and* the recipient have both acknowledged, the server deletes the row — ciphertext, sender copy, everything. Until the recipient has received a message (e.g. they're offline), it stays on the server so delivery can't be lost.
- **Recovery.** The chat thread re-renders from the device-local store (IndexedDB), so history survives server deletion on the same device. Clearing browser data, or signing in from a brand-new device, means old secure messages are not recoverable — that's the point of the mode.
- The conversation list shows a lock badge, and the thread header shows the mode state (`Secure DM: On` / `waiting for @peer` / `Off`).

## Live notifications

Sending a DM creates a `message` notification for the recipient (inbox + SSE + badge). Live ciphertext delivery is handled by the signaling WebSocket — see [Realtime](../developers/realtime.md).

## Sending messages via API

Example:

```
POST /api/v1/conversations/alice/messages
Authorization: Bearer <token>
Content-Type: application/json

{
  "body": "mls-ciphertext…",        // ciphertext, or the plaintext path for a sticker
  "proto": "mls",
  "sender_ciphertext": "…",         // your own encrypted copy, for your other devices
  "sender_device_id": "…"
}
```

Both participants must be mutual followers or the server returns `403`; a missing or non-`mls` protocol returns `426`.

## Migration & legacy data

Extrovert's earlier Olm/Megolm stack has been retired. The client no longer bundles it, and the server refuses to accept anything but `proto: "mls"` — the response is `426 Upgrade Required` with a message telling the client to refresh. `GET /mls/config` reports `legacy_e2ee_enabled: false`.

## Client-side notes (for implementers)

- The web client implements the MLS flows in `public/e2ee.js`, on top of the bundled RFC 9420 implementation: `public/lib/mls.js`, built from `src/client-mls/` with `npm run build:mls` (no external CDN).
- History is restored from the device-local store plus the optional password-encrypted backup (`/mls/backup`).
- Regression coverage lives in the MLS suites — `npm run test:mls` runs `scripts/mls-conformance-test.js`, `scripts/mls-db-test.js`, `scripts/mls-api-test.js`, `scripts/mls-e2ee-chat-test.js`, `scripts/mls-welcome-recovery-test.js` and `scripts/mls-client-regression-test.js`; `npm run test:ietf` checks the RFC vectors and `npm run test:interop` cross-checks against the Rust implementation.
