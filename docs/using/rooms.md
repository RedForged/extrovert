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
| `text` | MLS-encrypted chat (see E2EE below) |
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

## Messaging & E2EE (MLS)

Room messages are **end-to-end encrypted with MLS (RFC 9420)**, the same protocol as direct messages — the server stores ciphertext only:

| Concept | Notes |
|---|---|
| Group | One MLS group per room channel, over the channel's members. Membership changes (join, leave, kick, role removal) are MLS commits. |
| Devices | Every member device joins through a Welcome; the server addresses keys per device, never per username. |
| Key packages | Public MLS KeyPackages live at `/mls/keypackages`; adding a member consumes one of theirs. |
| Commit log | The server keeps the ordered MLS commits for a group (`GET /mls/groups/<groupId>/commits`) so clients can apply the current epoch. |
| Realtime | New ciphertext is broadcast over `/ws` as `room:<id>` `message_create` gateway events; clients decrypt locally. |
| Late joiners | A device added at a later epoch can read only from the point it joined — earlier history stays private. |

**Server enforcement:** a non-sticker room message must carry `proto: "mls"` and a `ciphertext` of at most 20,000 characters — otherwise the server replies **426 Upgrade Required** (`LegacyProtocolRetired: …`). Sticker messages (body starts with `/uploads/stickers/`) are allowed as plaintext paths.

### Message operations

- **Edit** — author only, re-encrypted, recorded in edit history.
- **Delete** — author, or anyone with `MANAGE_MESSAGES`, or an instance admin.
- **Report** — any member can report a message with a reason; it lands in the admin reports queue (see [Admin](admin.md)).

## Sending files and photos

The **+** button next to Send attaches a file to a room message. Like DMs, it is **sealed in your
browser** first (AES-256-GCM, key inside the MLS-encrypted message), so the server stores an opaque
blob with no name, type or extension and can't tell what was shared with the channel. Images and
video render inline after decryption; anything else becomes a download link. Sealed files count
against your [Drive](drive.md) quota.

## Room E2EE bootstrap for implementers

Modern clients can implement room E2EE with the MLS device flow:

1. **Devices & key packages:** register the device (`POST /mls/device/register`) and publish public key packages (`POST /mls/keypackages`). Adding a member consumes one of theirs (`GET /mls/keypackages/:userId`).
2. **Build the group:** create the channel's group (`POST /mls/groups/init`) — every member device is added through a Welcome it picks up from `GET /mls/welcomes` (acknowledged with `/mls/welcomes/ack`). Later membership changes go through `POST /mls/groups/:groupId/proposals` and `…/commit`, with the ordered history at `GET /mls/groups/:groupId/commits`.
3. **Send & receive:** post ciphertext with the room message endpoint (`proto: "mls"`) and decrypt incoming `message_create` events locally; the commit log keeps every device on the same epoch.

The protocol and client ergonomics are exercised by `npm run test:mls` (`scripts/mls-conformance-test.js`, `scripts/mls-db-test.js`, `scripts/mls-api-test.js`, `scripts/mls-e2ee-chat-test.js`, `scripts/mls-welcome-recovery-test.js`, `scripts/mls-client-regression-test.js`) and cross-checked against the Rust implementation with `npm run test:interop`.
