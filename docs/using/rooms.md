# Rooms & voice channels

Rooms are shared group spaces with multiple **channels**, a **role & permission** system, and **end-to-end-encrypted group chat**. Rooms are open to the whole instance (not network-bound): anyone can find public rooms, and private rooms use invites and join requests.

- Web: `/rooms` (list), `/rooms/create`, `/rooms/<id>`.
- API: `/api/v1/rooms*` (Bearer auth, same behavior).

## Room lifecycle

| Action | Who | Notes |
|---|---|---|
| Create | any logged-in user | Name (required), description, public/private. Creates the **Founder** role, the **Member** role, and a default **general** text channel automatically. |
| Join | anyone | Public rooms: instant, join with the default Member role. Private rooms: request (below). |
| Request to join | anyone | Private room → pending `join_requests`; approved/rejected by members with `MANAGE_MEMBERS`. |
| Invite | `MANAGE_MEMBERS` | Adds a user directly with the default role (`/rooms/:id/invite`). |
| Leave | members | Non-founders just leave. **Founders** must transfer the founder role first, or the room is deleted if they are the last member. |
| Settings | `MANAGE_ROOM` or instance admin | Rename, description, **custom HTML/CSS** (sanitized like profiles), public/private toggle. |
| Delete | founder (types `DELETE` + room name to confirm) or instance admin | Wipes messages, channels, members, roles. |

## Channels

| Type | Purpose |
|---|---|
| `text` | Megolm-encrypted chat (see E2EE below) |
| `voice` | Real-time voice channel over WebRTC (see [Calls](calls.md)) |

Channel management requires `MANAGE_CHANNELS`:

- Create a channel with a name and type; optionally restrict **which roles can view** (`view_role_ids`) and **which roles can write** (`write_role_ids`) by selecting roles in the form (stored as JSON role-id arrays).
- Delete a channel (removes its messages too).

The room page only lists channels your role can view; the message API enforces view/write role restrictions server-side.

## Roles & permissions

Permissions are a bitmask on each role:

| Bit | Permission | Value |
|---|---|---|
| `VIEW` | View the room / channels | 1 |
| `WRITE` | Send messages | 2 |
| `MANAGE_CHANNELS` | Create/delete channels | 4 |
| `MANAGE_ROLES` | Create/edit/delete roles | 8 |
| `MANAGE_MESSAGES` | Delete anyone's messages | 16 |
| `MANAGE_MEMBERS` | Kick, change roles, approve join requests, invite | 32 |
| `MANAGE_ROOM` | Edit room settings | 64 |

- **Founder** role: all permissions (127), `is_founder`, gold color, highest position. Cannot be edited or deleted.
- **Member** role: `VIEW` + `WRITE` (3), created automatically per room. New members join with it.
- Extra roles: `MANAGE_ROLES` holders can create/update/delete roles (name, color, permission checkboxes), assign them to members (never to the founder), and kick members (never the founder).
- **Transfer founder:** the founder can hand the room to any member (`/rooms/:id/transfer`); the old founder drops to the default role.
- Instance admins bypass room permissions everywhere.

## Messaging & E2EE (Megolm)

Room messages are **end-to-end encrypted with Megolm** (group-session ratchet) — the server stores ciphertext only:

| Concept | Notes |
|---|---|
| Group session | One Megolm outbound session per (room, sender). `publishRoomGroupSession` creates/rotates it; rotation deletes the old session so new members can't read history. |
| Session keys | Wrapped in the recipient's **1:1 Olm session** and stored server-side as pending key deliveries (`room_group_session_keys`). |
| Publish | `POST /rooms/:id/session` with `keys: [{recipient_id, encrypted_key}]` and `member_ids` (to mark members covered). `rotate: true` starts a fresh session. Pushes `room_session_key` in real time to connected recipients via WebSocket. |
| Atomic Sync | `POST /rooms/:id/session/sync` — publishes keys for room members, covers keyless members (`member_ids`), returns inbound pending keys for the caller, acks delivered keys (`ack_key_ids`), and lists `missing_members` in 1 round-trip. |
| Fetch pending | `GET /rooms/:id/session/keys` — the client decrypts each key with its 1:1 Olm session with the sender (filtered to this room). |
| Acknowledge | `POST /rooms/:id/session/keys/delivered` with `key_ids`. |
| Status | `GET /rooms/:id/session/status` — who has your key, and which covered members have an empty key (you should re-share to them). |
| Prekey bundles | `GET /rooms/:id/bundles` — batch Olm prekey bundle fetch for all room members in 1 call. Supports `?missing_for_session=<sessionId>` and `?claim=1` (pass `claim=1` when wrapping a session to consume prekeys). Multi-device clients must iterate `devices[]` to encrypt to all devices per member. |
| Zero-latency keys | When a member sends a message, subscribers needing that sender's session key have it automatically inlined as `session_key` directly inside the `message_create` WebSocket event, allowing immediate decryption without an extra round trip. |

**Server enforcement:** a non-sticker room message must carry `proto: "megolm"`, a `ciphertext` (<= 20,000 chars), and a `group_session_id` that matches the sender's current session (or a superseded session within the 15-minute rotation grace period) — otherwise `400 End-to-end encryption required. Room messages must be Megolm-encrypted.` Sticker messages (body starts with `/uploads/stickers/`) are allowed as plaintext paths.

### Message operations

- **Edit** — author only, re-encrypted, recorded in edit history.
- **Delete** — author, or anyone with `MANAGE_MESSAGES`, or an instance admin.
- **Report** — any member can report a message with a reason; it lands in the admin reports queue (see [Admin](admin.md)).

## Room E2EE bootstrap for implementers

Modern clients can implement room E2EE in just two optimized steps:

1. **Batch prekeys & atomic sync:**
   - Fetch missing member bundles with `GET /rooms/:id/bundles?missing_for_session=<sessionId>&claim=1`.
   - Iterate each member's `devices[]` and encrypt your Megolm session key with each device's 1:1 Olm session.
   - Atomically publish keys, cover any keyless members via `member_ids`, retrieve pending keys for yourself, and ack via `POST /rooms/:id/session/sync`.
2. **Realtime decryption:**
   - Inbound session keys arrive in real time over `/ws` via the `room_session_key` event, or inlined directly within `message_create` events.
   - Once unwrapped with your 1:1 Olm session, import into your Megolm inbound session and decrypt the channel message.
   - Periodic rotation (`rotate: true`) invalidates old sessions, keeping past history private from late joiners.

The protocol and client ergonomics are exercised by `scripts/client-e2ee-test.js`, `scripts/megolm-room-test.js`, and `scripts/megolm-integration-test.js`.
