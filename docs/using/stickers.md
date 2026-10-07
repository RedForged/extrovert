# Stickers

Stickers are small images you can drop into posts, comments, and messages. Each user has their own personal sticker collection.

## Managing stickers

| Route | Purpose |
|---|---|
| `/stickers/manage` | Manage page — list, upload |
| `POST /stickers/upload` | Multipart upload, field `sticker` |
| `/stickers/mine` (JSON) | List your stickers (used by the composer) |
| `POST /stickers/add` | Add a sticker path that's already uploaded (de-duplicates) |

Upload rules:

- Formats: JPEG, PNG, GIF, WebP, BMP.
- Max size: **500 KB**.
- Files over 250 KB that aren't GIFs are **auto-compressed** with `sharp` (JPEG/PNG/WebP at quality 70) when the result is smaller.
- Stored at `uploads/stickers/<random-hex>.<ext>`, served from `/uploads/stickers/…`.

## Using stickers

- In the **composer** and **comments**: click the smile icon to open your sticker picker; picking one inserts the sticker.
- In **DMs and room messages**: a message whose body starts with `/uploads/stickers/` is sent as a plaintext sticker path — the E2EE requirement is waived for stickers (the sticker itself is public media; the path is not sensitive).

## Notes

- Sticker paths are validated on the server (`/uploads/stickers/` prefix) both in chat and in `POST /stickers/add`.
- Deleting a sticker file isn't exposed in the UI; stickers accumulate per user.
