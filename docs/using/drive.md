# Drive

Every file you upload — chat attachments, post media, stickers and avatars — is stored in your
**Drive**. It has a size limit (50 MB by default) rather than a per-file limit: a single file may use
as much of your remaining space as it needs.

## Quota

- Default **50 MB per user**. Admins change it in `/admin/storage` (applies immediately, no restart)
  or set `EXTV_DRIVE_QUOTA_BYTES`. The admin value wins, then the environment variable, then 50 MB.
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
