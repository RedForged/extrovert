# API endpoint reference

Base path: `/api/v1` unless noted. Auth notation: **session** = logged-in web session; **Bearer** = OAuth token (scope in parentheses). All responses use the envelope from the [API overview](api-overview.md).

## Client Ergonomics & Device Pairing

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/client/bootstrap` | Bearer (`read`) | **Unified startup state** in 1 round-trip: returns `{ user, initial_seq, unread_notifications, rooms, timeline, ice_servers, server }`. |
| POST | `/auth/pair/init` | Bearer or session (`write`) | Generate a short-lived 5-minute device pairing code (e.g. `EXT-A1B2C3D4`) + QR pairing URL for zero-typing native login. |
| POST | `/auth/pair/claim` | none | Exchange pairing code (`code`, `client_name`) for a permanent Personal Access Token (`ext_pat_...`) and user profile. Single-use. |

## OAuth & OIDC

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/apps` | none | Dynamic Client Registration (RFC 7591 / Mastodon-compatible). Body: `client_name`*, `redirect_uris`, `scopes`, `website`. Returns `client_id` + `client_secret` + `vapid_key`. |
| POST | `/oauth/apps` | session | Register an app via web session. Body: `name`*, `redirect_uris`* (string or array), `description`, `website`, `scopes` (space-separated, default `read`). Returns `client_id` + `client_secret`. |
| GET | `/oauth/apps` | session | Your registered apps. |
| GET | `/oauth/authorize` | session | Consent page. Params: `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method` (S256/plain). Browser-only. |
| POST | `/oauth/authorize` | session | Approve/deny (`approve=yes` → redirect with `code`; else `error=access_denied`). Browser-only. |
| POST | `/oauth/token` | client | Token endpoint. `grant_type=authorization_code` (needs `client_id`, `code`, `redirect_uri`, `code_verifier` if PKCE) or `grant_type=refresh_token`. Public clients (no secret) supported. |
| POST | `/oauth/revoke` | client | Revoke a token. Body: `token`, `client_id`. Always `{ok:true}` (no enumeration). |
| GET | `/oauth/authorized_apps` | session | Apps you've authorized. |
| POST | `/oauth/authorized_apps/:appId/revoke` | session | Revoke one app's access. |
| GET | `/oauth/userinfo` | Bearer (`openid`) | OIDC UserInfo: `sub`, plus `preferred_username`/`name`/`picture` when `profile` scope granted. |
| GET | `/.well-known/openid-configuration` | none | OIDC discovery document. |
| GET | `/.well-known/jwks.json` | none | Signing keys for ID-token verification. |

Full flow documentation: [OAuth 2.0 & OpenID Connect](oauth-oidc.md).

## Accounts

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/accounts/verify_credentials` | Bearer (`read`) | Your own account. |
| PATCH | `/accounts/update_credentials` | Bearer (`profile`) | Update `display_name` (≤100), `bio` (≤500), `theme` (`light`/`dark`/`default`). |
| POST | `/accounts/avatar` | Bearer (`profile`) | Multipart `avatar` (image, ≤10 MB) → resized 200×200 JPEG. |
| DELETE | `/accounts/me` | Bearer (`write`) | Permanently delete your account. Body: `password`*. |
| GET | `/accounts/tokens` | Bearer (`read` or `profile`) | List your personal access tokens (`id, name, token_prefix, scopes, created_at, expires_at`). |
| POST | `/accounts/tokens` | Bearer (`write` or `profile`) | Create a Personal Access Token (`name`*, `scopes`, `expires_in_days`). Returns full `token` (shown once). |
| DELETE | `/accounts/tokens/:id` | Bearer (`write` or `profile`) | Revoke a personal access token. |
| GET | `/accounts/sessions` | Bearer (`read` or `profile`) | List your active login sessions. |
| DELETE | `/accounts/sessions/:id` | Bearer (`write` or `profile`) | Revoke an active login session. |
| GET | `/accounts/relationships?id=1,2,3` | Bearer (`read`) | Batch: `[{id, following, followed_by}]`. |
| GET | `/accounts/:id` | Bearer (`read`) | Account (404 if outside your network). |
| GET | `/accounts/:id/statuses` | Bearer (`read`) | Posts, newest first, `limit`+`cursor`. Network-gated. |
| GET | `/accounts/:id/followers` | Bearer (`read`) | Follower list. |
| GET | `/accounts/:id/following` | Bearer (`read`) | Following list. |
| POST | `/accounts/:id/follow` | Bearer (`follow`) | Follow (notifies the target). |
| POST | `/accounts/:id/unfollow` | Bearer (`follow`) | Unfollow. |

### Account shape

```json
{
  "id": "42", "username": "alice", "display_name": "Alice",
  "avatar": "/uploads/avatars/abc.jpg", "bio": "",
  "created_at": 1750000000000,
  "statuses_count": 3, "followers_count": 10, "following_count": 5,
  "is_following": true, "is_self": false
}
```

## Statuses (posts)

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/statuses` | Bearer (`write`) | Create. Multipart (optional `media`) or JSON. `type`: `text`/`photo`/`video`/`repost`; `body` or `status` ≤ 5000; `repost_of_id` for reposts (must be visible, not your own, not already reposted). Supports `Idempotency-Key`. Broadcasts `post_create` over gateway. |
| GET | `/statuses/:id` | Bearer (`read`) | One post (404 outside network). Includes `content` (Markdown) and `content_html`. |
| PATCH | `/statuses/:id` | Bearer (`write`) | Edit a post (author only). Body: `body` or `status` ≤ 5000. Re-renders Markdown and logs revision. |
| DELETE | `/statuses/:id` | Bearer (`write`) | Delete (owner only, cascades). Broadcasts `post_delete` over gateway. |
| GET | `/statuses/:id/history` | Bearer (`read`) | Revision edit history of a post: `[{id, entity_id, body, edited_at}]`. |
| POST | `/statuses/:id/follow_from` | Bearer (`follow`) | Attribution referral: record that you followed author because of this post. |
| POST | `/statuses/:id/favourite` | Bearer (`write`) | Toggle like. |
| POST | `/statuses/:id/unfavourite` | Bearer (`write`) | Remove like. |
| POST | `/statuses/:id/reblog` | Bearer (`write`) | Repost (not your own; no-op if already reposted). |
| GET | `/statuses/:id/context` | Bearer (`read`) | `{ancestors: [], descendants: [comments…]}`. |
| POST | `/statuses/:id/comment` | Bearer (`write`) | Comment (`body` ≤ 1000). |
| PATCH | `/statuses/:id/comments/:cid` | Bearer (`write`) | Edit a comment (author only, `body` ≤ 1000). |
| DELETE | `/statuses/:id/comments/:cid` | Bearer (`write`) | Delete a comment (author only). |
| GET | `/statuses/:id/favourited_by` | Bearer (`read`) | Who liked it. |
| GET | `/statuses/:id/reblogged_by` | Bearer (`read`) | Who reposted it. |

### Status shape

```json
{
  "id": "9", "type": "photo", "body": "…", "media_path": "/uploads/…",
  "created_at": 1750000000000,
  "account": { … },
  "likes_count": 2, "shares_count": 1, "comments_count": 0,
  "liked": false, "shared": false, "repost_of_id": null, "is_own": true
}
```

Engagement counts always target the **original** content (reposts don't split engagement).

## Timelines

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/timelines/home` | Bearer (`read`) | Ranked network feed. `limit` (≤40), `cursor` (id-based). Batch-counted engagement. |
| GET | `/timelines/public` | — | **403 by design** — there is no public timeline. |

## Notifications

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/notifications` | Bearer (`notifications`) | Newest first, cursor-paginated. Item: `id, type, created_at, read, account, post_id`. |
| POST | `/notifications/clear` | Bearer (`notifications`) | Mark all read. |
| GET | `/notifications/unread_count` | Bearer (`notifications`) | `{data:{count}}`. |
| GET | `/notifications/stream` | Bearer (`notifications`) | SSE stream — see [Realtime](realtime.md). |

## Media

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/media` | Bearer (`media.write`) | Upload (`file` field, ≤60 MB, image/video). Returns `url`, `mime_type`, `file_size`, `width`, `height`. |
| GET | `/media/:id` | Bearer (`read`) | Metadata, owner only. |

## Search

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/search?q=…&type=…&limit=…` | Bearer (`read`) | `type=accounts` / `type=statuses` / both. Posts limited to your network. |

## Presence

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/calls/presence` | Bearer (any) | Online mutual followers: `[{id, username, display_name, in_call}]`. |
| GET | `/calls/presence/:username` | Bearer (any) | `{online, in_call}` for one user. |

## Push (native/PWA)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/push/vapid-public` | Bearer (any) | VAPID public key for browser subscriptions (404 if unconfigured). |
| POST | `/push/subscribe` | Bearer (any) | Register: `{platform, endpoint, p256dh, auth}`. |
| POST | `/push/unsubscribe` | Bearer (any) | Remove: `{endpoint}`. |

## Rooms

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/rooms` | Bearer (`read`) | Your rooms (with member counts). |
| POST | `/rooms` | Bearer (`write`) | Create room. Body: `name`*, `description`, `is_public`. |
| GET | `/rooms/:id` | Bearer (`read`) | Room detail: channels (id/name/type), members, `html`/`css`, `is_public`, `is_member`. |
| PATCH | `/rooms/:id` | Bearer (`write`) | Update room settings / custom styling (`name`, `description`, `custom_css`/`css`, `custom_html`/`html`, `is_public`). |
| DELETE | `/rooms/:id` | Bearer (`write`) | Delete room (founder only). |
| POST | `/rooms/:id/join` | Bearer (`write`) | Join public room or submit join request for private room. |
| POST | `/rooms/:id/leave` | Bearer (`write`) | Leave room (founders must transfer first or be last member). |
| POST | `/rooms/:id/channels` | Bearer (`write`) | Create channel (`name`*, `type`: `text`/`voice`). |
| PATCH | `/rooms/:id/channels/:cid` | Bearer (`write`) | Rename channel (`name`*). |
| DELETE | `/rooms/:id/channels/:cid` | Bearer (`write`) | Delete channel. |
| GET | `/rooms/:id/roles` | Bearer (`read`) | List roles in room. |
| POST | `/rooms/:id/roles` | Bearer (`write`) | Create role (`name`*, `color`, `permissions`). |
| PATCH | `/rooms/:id/roles/:role_id` | Bearer (`write`) | Update role (`name`, `color`, `permissions`). |
| DELETE | `/rooms/:id/roles/:role_id` | Bearer (`write`) | Delete role. |
| POST | `/rooms/:id/members/:uid/roles` | Bearer (`write`) | Assign role to member (`role_id`*). |
| POST | `/rooms/:id/members/:uid/kick` | Bearer (`write`) | Kick member from room (`MANAGE_MEMBERS`). |
| POST | `/rooms/:id/transfer` | Bearer (`write`) | Transfer founder ownership (`target_user_id`*). |
| GET | `/rooms/:id/requests` | Bearer (`read`) | List pending join requests for private room. |
| POST | `/rooms/:id/requests` | Bearer (`write`) | Approve or reject join request (`request_id`*, `action`: `approve`/`reject`). |
| POST | `/rooms/:id/invite` | Bearer (`write`) | Invite user to room (`username`*). |
| GET | `/rooms/:id/channels/:cid/messages` | Bearer (`read`) | Channel history, newest last, `cursor` (message id) → next 50. |
| POST | `/rooms/:id/channels/:cid/messages` | Bearer (`write`) | Send. Must be `proto:"megolm"` + `ciphertext` + `group_session_id` (current session) unless the body is a sticker path. Broadcasts `message_create`. |
| DELETE | `/rooms/:id/channels/:cid/messages/:mid` | Bearer (`write`) | Delete message (author or `MANAGE_MESSAGES`). Broadcasts `message_delete`. |
| POST | `/rooms/:id/session` | Bearer (`write`) | Publish/rotate your Megolm session. Body: `keys:[{recipient_id, encrypted_key}]`, `member_ids:[]`, `rotate`. |
| GET | `/rooms/:id/session/keys` | Bearer (`read`) | Pending encrypted session keys for you. |
| POST | `/rooms/:id/session/keys/delivered` | Bearer (`write`) | Ack delivered keys: `{key_ids: []}`. |
| GET | `/rooms/:id/session/status` | Bearer (`read`) | `{session_id, recipients, empty_keys_for}`. |
| GET | `/rooms/:id/bundle/:username` | Bearer (`read`) | Member's Olm bundle (identity + claimed one-time key) for room key-sharing. |

Rooms support 100% REST API parity alongside the web UI under `/rooms/*`.

## Direct messages

All require mutual followers with the peer.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/conversations` | Bearer (`read:direct`) | Conversations with last message, unread counts, peer curve key. |
| GET | `/conversations/keys` | Bearer (`read:direct`) | Your public key + encrypted private key. |
| POST | `/conversations/keys` | Bearer (`write:direct`) | Publish `public_key` (+ optional `encrypted_private_key`). |
| POST | `/conversations/prekeys` | Bearer (`write:direct`) | Publish Olm identity + one-time keys + backup. |
| GET | `/conversations/prekeys/backup` | Bearer (`read:direct`) | Your stored account backup. |
| GET | `/conversations/prekeys/count` | Bearer (`read:direct`) | Remaining one-time prekeys. |
| GET | `/conversations/:username` | Bearer (`read:direct`) | History, newest first + `next` cursor; `limit` ≤100. |
| POST | `/conversations/:username/messages` | Bearer (`write:direct`) | Send. Non-sticker messages must be `proto:"olm"` with `sender_ciphertext`. |
| GET | `/conversations/:username/bundle` | Bearer (`read:direct`) | Peer's Olm bundle (claims one one-time prekey). |
| GET | `/conversations/:username/safety` | Bearer (`read:direct`) | Both sides' ed25519 + curve25519 keys. |
| GET | `/conversations/:username/keys` | Bearer (`read:direct`) | Peer's legacy public key. |
| PATCH | `/messages/:id` | Bearer (`write:direct`) | Edit (author only, ≤5000, re-encrypted). |
| DELETE | `/messages/:id` | Bearer (`write:direct`) | Delete (author only). |

## Announcement

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/announcement` | Bearer (`read`) | `{body, author_display_name, author_username, updated_at}` or `data: null`. |

## Stickers

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/stickers` | Bearer (`read`) | List your personal stickers (`[{id, file_path, url, created_at}]`). |
| POST | `/stickers` | Bearer (`write`) | Upload sticker (multipart `file`, ≤500 KB, auto-compressed) or save existing (`path`). |
| DELETE | `/stickers/:id` | Bearer (`write`) | Delete one of your personal stickers. |

## Network Discovery & Calls

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/discover` | Bearer (`read`) | Friend-of-a-Friend (FoF) suggested users within your 2-hop graph (`limit` ≤50). |
| GET | `/calls/ice_servers` | Bearer (`read`) | WebRTC STUN/TURN ICE servers configuration: `{ice_servers: [{urls: "..."}]}`. |

## Web session routes (not part of the REST API)

The full HTML surface for reference — all require login and CSRF:

| Area | Routes |
|---|---|
| Auth | `GET/POST /login`, `GET/POST /register`, `POST /logout`, `GET/POST /become-admin` |
| Pages | `GET /`, `GET /compose`, `GET /discover` |
| Posts | `POST /posts`, `POST /posts/:id/like`, `/comment`, `/share`, `/repost`, `/follow-from`, `/edit`, `GET/POST /posts/:id/delete`, `GET /posts/:id/history` |
| Profiles | `GET /u/:username`, `GET/POST /u/:username/edit`, `POST /u/:username/avatar`, `/avatar/remove`, `POST /u/:username/referral`, `GET /u/:username/followers|following` |
| Social | `POST /follow/:username`, `POST /unfollow/:username` |
| Notifications | `GET /inbox` |
| Chats | `GET /chats`, `GET /chats/:username`, `POST /chats/:username/send`, `/edit/:mid`, `GET/POST /chats/pubkey`, `POST /chats/prekeys`, `GET /chats/prekeys/backup|count`, `GET /chats/:username/bundle|safety` |
| Rooms | `GET/POST /rooms/create`, `GET/POST /rooms/:id/settings`, `POST /rooms/:id/delete|join|leave|request|invite|transfer`, `GET/POST /rooms/:id/channels*`, `GET/POST /rooms/:id/roles*`, `GET/POST /rooms/:id/members*`, `GET/POST /rooms/:id/requests/*`, AJAX messages/session/bundle/report |
| Settings | `GET/POST /settings`, `GET/POST /settings/delete`, `GET/POST /settings/developers*` |
| Push | `GET /push/vapid-public`, `POST /push/subscribe|unsubscribe`, `POST /push/cancel-pending` (no auth, token-gated) |
| Admin | `GET /admin`, `POST /admin/ban|unban|delete|make-admin|remove-referral/:id`, `POST /admin/rooms/:id/delete`, `GET/POST /admin/reports*`, `GET/POST /admin/announcement*` |
| Stickers | `GET /stickers/manage`, `POST /stickers/upload|add`, `GET /stickers/mine` |
| Docs | `GET /docs` and `GET /docs/*` (in-app wiki), `GET /developers/docs` (Swagger UI), `GET /developers/openapi.json` (OpenAPI 3.1) |
