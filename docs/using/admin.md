# Admin guide

The admin area (`/admin`) is the moderation and instance-management console. Access requires `is_admin`; the nav shows a shield icon with a pending-reports badge for admins.

## Becoming an admin

On a **fresh instance**, the first account to log in is offered the **Become Admin** screen (`/become-admin`) — anyone can claim admin while *no* admin exists, so claim it immediately after first setup. Once an admin exists, the option is gone. Admins can promote other users from `/admin`.

## User management (`/admin`)

| Action | Route | Notes |
|---|---|---|
| Ban / unban | `POST /admin/ban/:id`, `POST /admin/unban/:id` | Banned users can't log in ("Your account has been suspended") and are rejected by API auth. Can't ban admins. |
| Delete user | `POST /admin/delete/:id` | Full data wipe (same as self-deletion). Can't delete admins. |
| Make admin | `POST /admin/make-admin/:id` | Can't promote banned users or existing admins. |
| Remove referral badge | `POST /admin/remove-referral/:id` | Clears the user's referral code and severs `referred_by` links pointing at them. |

The dashboard lists all users (username, display name, referral code, referral count, join date, flags) and all rooms (with member counts and creator), plus the pending reports queue.

## Reports

Users can report **room messages** (a reason is required) from any room they can see. Reports land here:

- `GET /admin/reports` — pending queue (reporter, reported user, room, channel, message body, reason, date).
- `POST /admin/reports/:id/ban` — ban the reported user **and** resolve the report.
- `POST /admin/reports/:id/dismiss` — dismiss without action.

Reports are either `pending`, `resolved`, or `dismissed`.

## Room moderation

- Delete any room: `POST /admin/rooms/:id/delete` (no confirmation needed for admins).
- Admins bypass room role permissions everywhere (message deletion, settings, member management, joining private rooms).

## Server-wide announcement

One announcement at a time, shown to everyone as a banner in the header (dismissible pill):

- `GET /admin/announcement` — edit form (shows current announcement + author).
- `POST /admin/announcement` — set or update (body required).
- `POST /admin/announcement/clear` — remove it.

The API exposes the current announcement at `GET /api/v1/announcement` (any `read` token) so clients can render the banner natively.

## Security reports (responsible disclosure)

The public `/security` page invites security research and offers a **private** report form. Submissions land in the admin-only **security inbox**:

- `GET /admin/security-reports` — all submissions (reporter name/contact, summary, details, date, status), never shown publicly.
- `POST /admin/security-reports/:id/handle` — mark an open report handled (records which admin handled it).

The nav badge for admins counts open security reports together with moderation reports. The machine-readable policy is at `/.well-known/security.txt` (RFC 9116); the contact address is set with `SECURITY_CONTACT_EMAIL`.

## Storage quota (`/admin/storage`)

Every user has one storage pool — their **Drive** — covering chat attachments, post media, avatars,
stickers and API media. There is no per-file limit; uploads are refused once the user's space is
used up.

- Set the **quota per user** in megabytes and save. It applies to the next upload immediately, with
  no restart.
- Leave the field blank to fall back to `EXTV_DRIVE_QUOTA_BYTES`, or to the built-in 50 MB default.
- The panel also shows total storage across the instance and the ten largest accounts, flagging any
  that are already over the quota (they keep their files but can't upload until they free space).

## Audit notes

Selected admin-adjacent actions (OAuth app creation, token issuance, follows, post creation/deletion, DM key updates, avatar changes, media uploads) are written to the `audit_log` table with actor and timestamp.
