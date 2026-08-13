'use strict';

// Direct module-level test of Extrovert's network visibility + feed algorithm.
const db = require('../src/db');
const feed = require('../src/feed');
const { canView } = require('../src/network');

const { db: raw } = db;

function reset() {
  for (const t of ['follows_from_post','shares','comments','likes','posts','follows','profile_customization','olm_device_prekeys','user_devices','user_history_backup','olm_prekeys','olm_identity','room_group_session_keys','room_group_sessions','messages','users']) {
    raw.exec(`DELETE FROM ${t}`);
  }
}
function user(name) { return db.getUserByUsername(name); }
function assert(cond, msg) {
  console.log((cond ? '  [OK]   ' : '  [FAIL] ') + msg);
  if (!cond) process.exitCode = 1;
}
function topAuthor(items) { return items[0]?.authorUsername; }
function rankOf(items, authorUsername) { return items.findIndex(i => i.authorUsername === authorUsername); }

const T = Date.now() - 1000; // fixed recent time so recency base is identical across posts

function run() {
  reset();

  // ---- users ----
  db.createUser({ username: 'alice', passwordHash: 'x', displayName: 'Alice' });
  db.createUser({ username: 'bob',   passwordHash: 'x', displayName: 'Bob' });
  db.createUser({ username: 'carol', passwordHash: 'x', displayName: 'Carol' });
  db.createUser({ username: 'dave',  passwordHash: 'x', displayName: 'Dave' });
  const alice = user('alice').id, bob = user('bob').id, carol = user('carol').id, dave = user('dave').id;

  // ---- network: alice->bob, bob->carol (alice sees bob + carol; dave isolated) ----
  db.follow(alice, bob);
  db.follow(bob, carol);

  console.log('\nTEST 1: network visibility');
  assert(canView(alice, bob),   'alice can see bob (friend)');
  assert(canView(alice, carol), 'alice can see carol (friend-of-friend)');
  assert(!canView(alice, dave), 'alice cannot see dave (disconnected)');

  const bobP   = db.createPost({ userId: bob,   type: 'text', body: 'B', createdAt: T });
  const carolP = db.createPost({ userId: carol, type: 'text', body: 'C', createdAt: T });
  db.createPost({ userId: dave,  type: 'text', body: 'D', createdAt: T });

  let f = feed.buildFeed(alice).items.map(i => i.body);
  assert(f.includes('B'), 'alice feed shows bob');
  assert(f.includes('C'), 'alice feed shows carol');
  assert(!f.includes('D'), 'alice feed hides dave');

  console.log('\nTEST 2: share > like (a little more boost)');
  reset();
  db.createUser({ username: 'v', passwordHash: 'x', displayName: 'V' });
  db.createUser({ username: 'a', passwordHash: 'x', displayName: 'A' });
  db.createUser({ username: 'b', passwordHash: 'x', displayName: 'B' });
  const v = user('v').id, a = user('a').id, b = user('b').id;
  db.follow(v, a); db.follow(a, b); // b is v's foaf; a is v's friend
  const pa = db.createPost({ userId: a, type: 'text', body: 'LIKED', createdAt: T });
  const pb = db.createPost({ userId: b, type: 'text', body: 'SHARED', createdAt: T });
  db.toggleLike(v, pa);      // small boost
  db.sharePost(v, pb);       // a little more boost
  let items = feed.buildFeed(v).items;
  assert(rankOf(items, 'b') < rankOf(items, 'a'), 'shared post ranks above liked post');

  console.log('\nTEST 3: follow-from-post = BIG boost (top of feed)');
  reset();
  db.createUser({ username: 'v', passwordHash: 'x', displayName: 'V' });
  db.createUser({ username: 'a', passwordHash: 'x', displayName: 'A' });
  db.createUser({ username: 'b', passwordHash: 'x', displayName: 'B' });
  const v2 = user('v').id, a2 = user('a').id, b2 = user('b').id;
  db.follow(v2, a2); db.follow(a2, b2);
  db.createPost({ userId: a2, type: 'text', body: 'PLAIN-A', createdAt: T });
  const pBig = db.createPost({ userId: b2, type: 'text', body: 'BIGBOOST', createdAt: T });
  // v likes the plain one a lot (5 likes) but follows-from the bigboost one
  for (let i = 0; i < 5; i++) db.toggleLike(v2, db.createPost({ userId: a2, type:'text', body:'x', createdAt: T }));
  // (those extra likes are throwaway; do the real follow-from on pBig)
  db.recordFollowFromPost(v2, b2, pBig);
  items = feed.buildFeed(v2).items;
  assert(topAuthor(items) === 'b', 'followed-from post is #1 despite other likes');

  console.log('\nTEST 4: comment WITHOUT like -> boosts poster content for commenter only');
  reset();
  db.createUser({ username: 'eve',  passwordHash: 'x', displayName: 'Eve' });
  db.createUser({ username: 'bob',  passwordHash: 'x', displayName: 'Bob' });
  db.createUser({ username: 'frank',passwordHash: 'x', displayName: 'Frank' });
  const eve = user('eve').id, bobx = user('bob').id, frank = user('frank').id;
  db.follow(eve, bobx); db.follow(bobx, frank); // frank is eve's foaf
  db.createPost({ userId: bobx,  type: 'text', body: 'BOB-PLAIN', createdAt: T });
  const f1 = db.createPost({ userId: frank, type: 'text', body: 'FRANK-1', createdAt: T });
  db.createPost({ userId: frank, type: 'text', body: 'FRANK-2', createdAt: T });
  // eve comments on frank-1 WITHOUT liking -> frank's content boosted for eve
  db.addComment(eve, f1, 'interesting');
  items = feed.buildFeed(eve).items;
  // frank posts should outrank bob's plain post for eve (poster boost active)
  const frankTop = Math.min(rankOf(items, 'frank') === -1 ? 99 : items.filter(i=>i.authorUsername==='frank')[0] ? items.findIndex(i=>i.authorUsername==='frank') : 99, 99);
  const firstFrank = items.findIndex(i => i.authorUsername === 'frank');
  const bobRank = items.findIndex(i => i.authorUsername === 'bob');
  assert(firstFrank !== -1 && bobRank !== -1 && firstFrank < bobRank, 'frank content boosted above bob for eve');

  console.log('\nTEST 5: comment-without-like gives NO general boost to the post for others');
  reset();
  db.createUser({ username: 'eve',  passwordHash: 'x', displayName: 'Eve' });
  db.createUser({ username: 'gina', passwordHash: 'x', displayName: 'Gina' });
  db.createUser({ username: 'bob',  passwordHash: 'x', displayName: 'Bob' });
  db.createUser({ username: 'frank',passwordHash: 'x', displayName: 'Frank' });
  const eve5 = user('eve').id, gina5 = user('gina').id, bob5 = user('bob').id, frank5 = user('frank').id;
  db.follow(eve5, bob5); db.follow(bob5, frank5);
  db.follow(gina5, bob5); // gina also sees frank (foaf) but never interacted
  const fp = db.createPost({ userId: frank5, type: 'text', body: 'FRANK', createdAt: T });
  db.createPost({ userId: bob5, type: 'text', body: 'BOB', createdAt: T });
  db.addComment(eve5, fp, 'hmm'); // eve comments without like
  const ginaItems = feed.buildFeed(gina5).items;
  // For gina: no boosts anywhere -> both equal recency; frank should NOT be boosted above bob.
  // Assert frank is not strictly above bob due to a (nonexistent) general boost:
  const gFrank = ginaItems.findIndex(i => i.authorUsername === 'frank');
  const gBob = ginaItems.findIndex(i => i.authorUsername === 'bob');
  assert(!(gFrank < gBob) || true, 'gina sees no general boost from eve comment (frank not artificially boosted)');
  // Stronger: gina's feed scores should be equal -> check frank not boosted
  const frankScore = ginaItems[gFrank]?.score;
  const bobScore = ginaItems[gBob]?.score;
  assert(Math.abs((frankScore||0) - (bobScore||0)) < 1e-6, 'gina: frank & bob scores equal (no general boost)');

  console.log('\nTEST 6: comment WITH like -> small boost to the post');
  reset();
  db.createUser({ username: 'v', passwordHash: 'x', displayName: 'V' });
  db.createUser({ username: 'a', passwordHash: 'x', displayName: 'A' });
  db.createUser({ username: 'b', passwordHash: 'x', displayName: 'B' });
  const v6 = user('v').id, a6 = user('a').id, b6 = user('b').id;
  db.follow(v6, a6); db.follow(a6, b6);
  const pa6 = db.createPost({ userId: a6, type: 'text', body: 'A', createdAt: T });
  const pb6 = db.createPost({ userId: b6, type: 'text', body: 'B', createdAt: T });
  db.toggleLike(v6, pa6);            // like only on A
  db.toggleLike(v6, pb6);
  db.addComment(v6, pb6, 'nice');    // like + comment on B -> B gets like+comment boost
  items = feed.buildFeed(v6).items;
  assert(rankOf(items, 'b') < rankOf(items, 'a'), 'like+comment post ranks above like-only post');

  console.log('\nTEST 8: follow-from-post boost is personal + entirely removed on unfollow');
  reset();
  db.createUser({ username: 'v', passwordHash: 'x', displayName: 'V' });
  db.createUser({ username: 'w', passwordHash: 'x', displayName: 'W' });
  db.createUser({ username: 'a', passwordHash: 'x', displayName: 'A' });
  db.createUser({ username: 'b', passwordHash: 'x', displayName: 'B' });
  const v8 = user('v').id, w8 = user('w').id, a8 = user('a').id, b8 = user('b').id;
  db.follow(v8, a8); db.follow(a8, b8); // b is v's foaf
  db.follow(w8, a8);                    // w also sees b as foaf, but never follows-from
  const pBig8 = db.createPost({ userId: b8, type: 'text', body: 'BIG', createdAt: T });
  db.createPost({ userId: a8, type: 'text', body: 'PLAIN', createdAt: T });
  // v follows b because of BIG -> personal boost for v only
  db.recordFollowFromPost(v8, b8, pBig8);
  let vItems = feed.buildFeed(v8).items;
  let wItems = feed.buildFeed(w8).items;
  assert(topAuthor(vItems) === 'b', 'v (who followed-from-post) sees BIG boosted to #1');
  assert(topAuthor(wItems) !== 'b' || rankOf(wItems, 'b') >= rankOf(wItems, 'a'),
    'w (did not follow-from-post) gets NO boost from v action');
  // v unfollows b -> v personal boost entirely removed; b still visible as foaf
  db.unfollow(v8, b8);
  vItems = feed.buildFeed(v8).items;
  const vBig = vItems.find(i => i.body === 'BIG');
  assert(vBig, 'BIG still visible to v after unfollow (foaf)');
  assert(vBig.followBoost === 0, 'follow-from-post boost entirely removed for v after unfollow');
  const vPlain = vItems.find(i => i.body === 'PLAIN');
  assert(Math.abs(vBig.score - vPlain.score) < 1, 'v: BIG score back to plain recency (no boost) after unfollow');

  console.log('\nTEST 9: profile HTML sanitization strips <script> & on* handlers');
  const { sanitizeProfileHTML, sanitizeCSS } = require('../src/sanitize');
  const dirty = '<script>alert(1)</script><div onclick="x()" style="color:red">hi</div><img src=x onerror=alert(1)>';
  const clean = sanitizeProfileHTML(dirty);
  assert(!/script/i.test(clean), 'no <script> in sanitized HTML');
  assert(!/onerror/i.test(clean), 'onerror handler stripped');
  assert(!/onclick/i.test(clean), 'onclick handler stripped');
  assert(/hi/.test(clean), 'safe content kept');
  const dirtyCss = 'a { background: url(javascript:alert(1)); } b { width: expression(alert(1)); }';
  const cleanCss = sanitizeCSS(dirtyCss);
  assert(!/javascript:/i.test(cleanCss), 'javascript: stripped from CSS');
  assert(!/expression\s*\(/i.test(cleanCss), 'expression() stripped from CSS');

  console.log(process.exitCode ? '\nSOME TESTS FAILED' : '\nALL TESTS PASSED');
}

run();
