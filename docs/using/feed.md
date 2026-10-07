# Posts & the feed algorithm

## Post types

| Type | What it is | Media |
|---|---|---|
| `text` | Plain text post (up to 5,000 chars) | none |
| `photo` | Text + one image | JPEG, PNG, GIF, WebP, BMP (web); JPEG, PNG, GIF, WebP (API) |
| `video` | Text + one video | MP4, WebM, MOV, AVI, MKV (web); MP4, WebM, MOV (API) |
| `repost` | Re-publishes someone else's post into your own stream | inherited from the original |

Uploads are stored on disk (max 60 MB per file) under `uploads/` (web) or `data/api-uploads/` (API) with random hex filenames, and served from `/uploads/…` and `/api-uploads/…`.

## Engagement actions

Every action is available in the web UI and in the API.

| Action | Web route | Effect |
|---|---|---|
| **Like** | `POST /posts/:id/like` | Toggles. Notifies the author. Counts toward feed boost. |
| **Comment** | `POST /posts/:id/comment` | Adds to the thread (1,000 char limit). Notifies the author. |
| **Share** | `POST /posts/:id/share` | One-click boost signal. Notifies the author. Does **not** create a new post. |
| **Repost** | `POST /posts/:id/repost` | Creates a new post in your stream pointing at the original. Can't repost your own posts or the same post twice. |
| **Follow from post** | `POST /posts/:id/follow-from` | Follows the author *because of* this post — the biggest feed boost there is (see below). |
| **Edit** | `POST /posts/:id/edit` | Owner only. Saves every revision to edit history. |
| **Delete** | `GET`/`POST /posts/:id/delete` | Owner only, with a confirmation page. Cascades: likes, comments, shares, follow-from records, notifications, and reposts pointing at the post are removed. |

Comments can also be edited and deleted by their author; both record edit history.

### Repost semantics

- A repost **does not split engagement**: likes/comments/shares always target the *original* post, wherever it surfaces. The same original appearing directly *and* via a repost in one feed is de-duplicated to its highest-ranked appearance.
- Reposts carry a "reposted by" attribution on the card.
- Deleting the original deletes reposts that point to it.

### Edit history

Every edit to a post, comment, DM, or room message is appended to `edit_history` (old body, new body, editor, timestamp) and is visible on the "(edited)" link at `/posts/:id/history?type=post|comment`. DM and room-message edits follow the same rule and show an "(edited)" marker.

## The feed

Your home feed (`/`) contains **only**:

1. your own posts,
2. posts by people you follow (friends),
3. posts by people your friends follow (friends-of-friends).

Everything else is invisible — there is no public timeline anywhere in the product.

### Scoring

Each candidate post is scored:

```
score = recencyBase + engagementBoosts
recencyBase = 400 × exp(−ageHours / 48)
```

Fresh content starts at 400 and decays exponentially with a 48-hour half-life.

### Boost rules (constants in `src/feed.js`)

| Action | Boost | Notes |
|---|---|---|
| **Follow from post** (the "follow because of this post" button) | **+1000** | **Personal**: only the viewer who followed because of *that* post gets it. Unfollowing the author removes it. |
| **Share** | +60 | A little more than a like. |
| **Like** | +30 | |
| **Comment + like** | +30 | A comment only boosts the post if the commenter also liked it. |
| **Comment without like** | +50 | No boost to that post at all. Instead the *poster's other content* is boosted — and only for the commenter. The commented post itself gets nothing. |

Engagement counts are computed against the **effective (original) content** and exclude the author's own self-engagement (likes/shares/comments by the author don't count toward the boost).

### Ranking details

- Candidates are limited to the most recent 500 posts in your network.
- Ties are broken by recency (newer first).
- The ranked feed is **cached per user for 30 seconds**; following/unfollowing invalidates your cache immediately.
- The web feed paginates 15 posts per page (`?page=N`); the API uses cursor pagination (see [API overview](../developers/api-overview.md)).

### Why the comment-without-like rule?

It's the algorithm's "curiosity" signal: a comment without a like is a person *engaging* with an author, not with one specific post. It rewards the author's overall body of work for that one viewer instead of inflating a single post.

## Attachments

A post can carry one attachment, and it need not be an image or video: the composer accepts any file
the Drive accepts. Images and video render inline in the feed; every other type renders as a download
link labelled with the original filename.

Attachments are stored in the uploader's [Drive](drive.md) under `data/drive/`, are public (posts are
public — this is the opposite of sealed chat attachments), and count against the uploader's Drive
quota. Deleting the post removes the file and frees its space.

## Media handling

- Web uploads go through the [Drive](drive.md) pipeline (`src/drive.js`) and accept any type the Drive's
  safe-extension list allows; the API accepts a narrower set (`src/routes/api-v1.js`).
- Files are stored with random hex names and `nosniff` headers when served.
- API media metadata (dimensions) is extracted with `sharp` for images.
- Stickers and avatars are separate media features — see [Stickers](stickers.md) and [Profiles](profiles.md).
