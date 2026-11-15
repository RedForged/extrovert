# Drive

Every file you upload — chat attachments, post media, stickers, avatars, API media and custom
profile fonts — is stored in your **Drive**. It has a size limit (50 MB by default) rather than a
per-file limit: a single file may use as much of your remaining space as it needs.

## Your own Nextcloud

You can point your Drive at a Nextcloud you control instead of this server's disk. Open
**Settings → Storage → Connect a Nextcloud**, enter the **URL** of your instance (e.g.
`https://cloud.example.com`), and approve Extrovert in the Nextcloud page that opens.

This is Nextcloud's browser login flow — the same one its desktop and mobile apps use. You sign in
to Nextcloud itself (2FA/SSO included) and Nextcloud issues Extrovert a dedicated app password.
**Your Nextcloud password is never sent to or stored by Extrovert.** You can revoke that access at
any time under *Settings → Security → Devices & sessions* in Nextcloud.

New uploads are written to an `Extrovert` folder in your Nextcloud. Because those bytes are not
stored here, **the Drive size limit no longer applies** — your Nextcloud's own quota is the only
limit. The files are still served through the same `/drive/f/<name>` links; the server fetches them
from your Nextcloud when someone opens the link.

What to expect:

- Files uploaded **before** you connected stay where they are (on this server, counting against the
  limit). New uploads go to Nextcloud. Connecting does not move old files.
- Avatars, stickers and profile fonts remain on this server. They are small and still count against
  your local allowance, so those uploads can still hit the limit.
- **Pause new uploads** keeps the connection so files already in your Nextcloud still open and can
  still be deleted, but new uploads go back to this server (and the size limit applies again).
- **Remove connection** deletes the stored credentials. The files stay in your Nextcloud, but their
  Drive links stop working until you reconnect.
- Sealed chat attachments are encrypted in your browser before upload, so your Nextcloud only ever
  receives ciphertext for those.

## Quota

- Default **50 MB per user**. Admins change it in `/admin/storage` (applies immediately, no restart)
  or set `EXTV_DRIVE_QUOTA_BYTES`. The admin value wins, then the environment variable, then 50 MB.
- The quota covers bytes this server stores. It does not apply to a connected Nextcloud — those
  files are yours and are not counted toward your limit.
- The check happens *before* the file is written, so a refused upload leaves nothing behind. The
  message tells you how much space is left.
- Usage shows in `/settings` under **Storage** and on the Drive page.
- Files you already had before the Drive existed were counted into your usage automatically.
- An account that is over its quota (say an admin lowered it) keeps its files but can't upload until
  it deletes something. The Drive shows "over your quota".

## Managing files

`/drive` lists everything you store, with its size and kind (`chat`, `post`, `sticker`, `avatar`,
`api`, `drive`). From there you can:

- **Upload** a file straight to the Drive.
- **Copy link** for a non-sealed file. The URL is public — anyone with the link can fetch it.
- **Delete** files the Drive owns. Deleting frees the space immediately, and removes the file from
  disk. A file a post is still using can't be deleted here; delete the post instead, which frees it.

## Sealed attachments

Files sent in a **DM or room** are *sealed*: your browser encrypts the file with a fresh AES-256-GCM
key before uploading, and the key travels inside the end-to-end encrypted message. The server stores
an unreadable blob, with no extension, name or type recorded — it can't tell an image from a PDF.
Only the people in that conversation can open it.

Post media is public by design (posts are public), so it is stored as-is and served like any other
image.

## Where files live

`data/drive/` on the server, under server-generated random names. The URL is the capability — the
same model as the older `/api-uploads` path. A sealed blob is useless without the key from the
message.

Stored files carry no active content: anything with an extension a browser would interpret
(`.html`, `.svg`, `.js`) is stored extensionless and served as an opaque download.
