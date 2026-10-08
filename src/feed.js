'use strict';

const { db } = require('./db');
const { getDisplayPost, getUserById, commentsForPost, hasLiked, hasShared, areMutualFollowers } = require('./db');

// In-memory feed cache per user with TTL
const feedCache = new Map();
const FEED_CACHE_TTL = 30_000; // 30 seconds

function getCachedFeed(viewerId) {
  const entry = feedCache.get(viewerId);
  if (entry && Date.now() - entry.ts < FEED_CACHE_TTL) {
    return entry.feed;
  }
  return null;
}

function setCachedFeed(viewerId, feed) {
  feedCache.set(viewerId, { feed, ts: Date.now() });
}

function invalidateFeedCache(userId) {
  feedCache.delete(userId);
}

// ---------------------------------------------------------------------------
// Extrovert feed algorithm
// ---------------------------------------------------------------------------
// Content is only ever sourced from friends and friends-of-friends. Among that
// candidate pool, posts are ranked by
//   score = recency base + freshness boost + engagement boosts.
// Boost rules (see spec):
//
//   * Fresh posts                          -> a short-lived freshness bump that
//                                            decays over hours (easier to find).
//   * Follow someone *because of a post*  -> that post gets a BIG boost.
//   * Like a post                          -> small boost to the post.
//   * Comment on a post                    -> small boost to the post
//                                            (only counts when the commenter
//                                             also liked it).
//   * Share a post                         -> a little more boost than like.
//   * Comment WITHOUT liking               -> NO boost to that post; instead it
//                                            boosts the POSTER'S other content,
//                                            and ONLY for the commenter.
//
// Engagement (likes / comments / shares / follow-from) always targets the
// underlying original content. A repost is just a way content surfaces into a
// new network; it does not split engagement.
// ---------------------------------------------------------------------------

const BOOST = {
  FOLLOW_FROM_POST: 1000, // big
  SHARE: 60,              // a little more than small
  LIKE: 30,               // small
  COMMENT_WITH_LIKE: 30,  // small (only when commenter also liked)
  COMMENT_WITHOUT_LIKE_POSTER: 50, // boosts poster's content, commenter only
};

function recencyBase(createdAtMs, now = Date.now()) {
  const ageHours = (now - createdAtMs) / 36e5;
  return 400 * Math.exp(-ageHours / 48);
}

// A short-lived bump on top of the slow recency decay, so brand-new posts
// surface readily and then settle back under engagement. It halves every
// FRESHNESS_HALF_LIFE_HOURS and is negligible within a day or so.
const FRESHNESS_BOOST = 200;         // extra score at age 0
const FRESHNESS_HALF_LIFE_HOURS = 3; // decays to half every 3 hours

function freshnessBoost(createdAtMs, now = Date.now()) {
  const ageHours = Math.max(0, (now - createdAtMs) / 36e5); // clamp clock skew
  return FRESHNESS_BOOST * Math.pow(0.5, ageHours / FRESHNESS_HALF_LIFE_HOURS);
}

// Candidate post rows visible to the viewer, with engagement counts computed
// against the *effective* content id (the original, for reposts). eff_author_id
// is the original content's author (the reposter for a repost row).
function candidatePosts(viewerId, limit = 500) {
  return db.prepare(`
    WITH friends AS (
      SELECT followee_id AS uid FROM follows WHERE follower_id = ?1
    ),
    foaf AS (
      SELECT DISTINCT f2.followee_id AS uid
      FROM follows f2
      JOIN friends ON friends.uid = f2.follower_id
      WHERE f2.followee_id <> ?1
        AND f2.followee_id NOT IN (SELECT uid FROM friends)
    ),
    base AS (
      SELECT p.*,
        CASE WHEN p.type='repost' AND p.repost_of_id IS NOT NULL
             THEN p.repost_of_id ELSE p.id END AS eff_id,
        CASE WHEN p.type='repost' AND p.repost_of_id IS NOT NULL
             THEN (SELECT user_id FROM posts WHERE id = p.repost_of_id)
             ELSE p.user_id END AS eff_author_id
      FROM posts p
      WHERE p.user_id = ?1
         OR p.user_id IN (SELECT uid FROM friends)
         OR p.user_id IN (SELECT uid FROM foaf)
    )
    SELECT b.id, b.user_id, b.type, b.body, b.media_path, b.repost_of_id, b.created_at, b.edited_at,
           b.eff_id, b.eff_author_id,
           u.username  AS author_username,
           u.display_name AS author_name,
            (SELECT COUNT(*) FROM likes l            WHERE l.post_id = b.eff_id AND l.user_id <> b.eff_author_id) AS like_count,
            (SELECT COUNT(*) FROM shares s           WHERE s.post_id = b.eff_id AND s.user_id <> b.eff_author_id) AS share_count,
           (SELECT COUNT(*) FROM follows_from_post f WHERE f.post_id = b.eff_id) AS follow_boost_count,
       EXISTS(SELECT 1 FROM follows_from_post f WHERE f.post_id = b.eff_id AND f.follower_id = ?1) AS viewer_follow_boost,
            (SELECT COUNT(*) FROM comments c
               WHERE c.post_id = b.eff_id
                 AND c.user_id <> b.eff_author_id
                 AND EXISTS (
                  SELECT 1 FROM likes l2
                  WHERE l2.user_id = c.user_id AND l2.post_id = b.eff_id
                )) AS comment_with_like_count
    FROM base b
    JOIN users u ON u.id = b.user_id
    ORDER BY b.created_at DESC
    LIMIT ?2
  `).all(viewerId, limit);
}

// Authors for whom the viewer has commented WITHOUT liking (>=1 of their posts).
function commentWithoutLikeAuthors(viewerId) {
  const rows = db.prepare(`
    SELECT DISTINCT p.user_id AS author_id
    FROM comments c
    JOIN posts p ON p.id = c.post_id
    WHERE c.user_id = ?1
      AND NOT EXISTS (
        SELECT 1 FROM likes l
        WHERE l.user_id = c.user_id AND l.post_id = c.post_id
      )
  `).all(viewerId);
  return new Set(rows.map(r => r.author_id));
}

// Specific content posts the viewer commented on WITHOUT liking. These get NO
// boost at all ("it does nothing") — only the poster's OTHER content is boosted.
function commentWithoutLikePostIds(viewerId) {
  const rows = db.prepare(`
    SELECT c.post_id AS id
    FROM comments c
    WHERE c.user_id = ?1
      AND NOT EXISTS (
        SELECT 1 FROM likes l
        WHERE l.user_id = c.user_id AND l.post_id = c.post_id
      )
  `).all(viewerId);
  return new Set(rows.map(r => r.id));
}

function scorePost(row, cwolAuthors, cwolPostIds, now) {
  let score = recencyBase(row.created_at, now) + freshnessBoost(row.created_at, now);

  // General boosts on this content (visible to everyone in the network).
  score += BOOST.LIKE * row.like_count;
  score += BOOST.SHARE * row.share_count;
  // Follow-from-post is PERSONAL: only the viewer who followed because of this
  // post gets the big boost, so unfollowing that author entirely removes it.
  score += BOOST.FOLLOW_FROM_POST * (row.viewer_follow_boost ? 1 : 0);
  score += BOOST.COMMENT_WITH_LIKE * row.comment_with_like_count;

  // Viewer-specific: the poster's OTHER content is boosted for the commenter.
  if (cwolAuthors.has(row.eff_author_id) && !cwolPostIds.has(row.eff_id)) {
    score += BOOST.COMMENT_WITHOUT_LIKE_POSTER;
  }

  return score;
}

function hydrateItem(row, viewerId, score) {
  const reposter = getUserById(row.user_id);
  let contentPost = row;
  let author = reposter;
  if (row.type === 'repost' && row.repost_of_id) {
    const disp = getDisplayPost(row.repost_of_id);
    if (disp) {
      contentPost = disp.post;
      author = getUserById(contentPost.user_id);
    }
  }
  const interactId = contentPost.id; // engagement targets underlying content
  const comments = commentsForPost(interactId);
  return {
    id: row.id,
    interactId,
    type: contentPost.type,
    body: contentPost.body,
    mediaPath: contentPost.media_path,
    createdAt: row.created_at,
    editedAt: contentPost.edited_at,
    isRepost: row.type === 'repost',
    reposterName: row.type === 'repost' ? reposter?.display_name : null,
    reposterUsername: row.type === 'repost' ? reposter?.username : null,
    authorId: author.id,
    authorUsername: author.username,
    authorName: author.display_name,
    authorAvatar: author.avatar,
    likeCount: row.like_count,
    shareCount: row.share_count,
    commentCount: comments.length,
    followBoost: row.follow_boost_count,
    liked: hasLiked(viewerId, interactId),
    shared: hasShared(viewerId, interactId),
    followingAuthor: require('./db').isFollowing(viewerId, author.id),
    mutual: author.id !== viewerId && areMutualFollowers(viewerId, author.id),
    isOwn: author.id === viewerId,
    comments,
    score,
  };
}

function buildFeed(viewerId, { page = 1, perPage = 20 } = {}) {
  const cached = getCachedFeed(viewerId);
  if (cached) {
    const start = (page - 1) * perPage;
    const pageItems = cached.items.slice(start, start + perPage);
    return { items: pageItems, page, perPage, hasMore: start + perPage < cached.items.length };
  }

  const now = Date.now();
  const candidates = candidatePosts(viewerId);
  const cwolAuthors = commentWithoutLikeAuthors(viewerId);
  const cwolPostIds = commentWithoutLikePostIds(viewerId);

  const scored = candidates.map(row => ({
    row,
    score: scorePost(row, cwolAuthors, cwolPostIds, now),
  }));

  // Dedupe by effective content id: if the same original surfaces both
  // directly and via a repost, keep only the higher-ranked surface.
  const bestByEff = new Map();
  for (const s of scored) {
    const key = s.row.eff_id;
    if (!bestByEff.has(key) || s.score > bestByEff.get(key).score) {
      bestByEff.set(key, s);
    }
  }
  const deduped = [...bestByEff.values()];
  deduped.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return b.row.created_at - a.row.created_at;
  });

  const allItems = deduped.map(({ row, score }) => hydrateItem(row, viewerId, score));
  setCachedFeed(viewerId, { items: allItems });

  const start = (page - 1) * perPage;
  const pageItems = allItems.slice(start, start + perPage);
  return { items: pageItems, page, perPage, hasMore: start + perPage < allItems.length };
}

module.exports = {
  buildFeed, scorePost, BOOST,
  recencyBase, freshnessBoost, FRESHNESS_BOOST, FRESHNESS_HALF_LIFE_HOURS,
  candidatePosts, commentWithoutLikeAuthors, commentWithoutLikePostIds,
  invalidateFeedCache,
};
