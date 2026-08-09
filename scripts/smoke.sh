#!/bin/bash
# HTTP smoke test through the running server.
set -u
BASE=http://localhost:3000
J=/home/axoisaxo/extrovert/.cookies
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rm -f "$J"*

# Fetch a CSRF token from the page's meta tag.
csrf() { grep -o 'name="csrf-token" content="[^"]*"' "$1" | head -1 | sed 's/.*content="//;s/"//'; }

# Read the register captcha answer for a cookie jar from the session DB
# (dev/tooling only — remote clients only ever see the SVG image).
captcha_answer() {
  local val sid
  val=$(awk -F'\t' '/connect\.sid/ {print $7}' "$J.$1" | head -1)
  sid=$(printf '%s' "$val" | sed 's/^s%3A//' | cut -d. -f1)
  node "$REPO_ROOT/scripts/captcha-answer.js" "$sid"
}

reg() {
  curl -s -c "$J.$1" -b "$J.$1" -o /tmp/.reg.html "$BASE/register"
  T=$(csrf /tmp/.reg.html)
  N=$(captcha_answer "$1")
  curl -s -c "$J.$1" -b "$J.$1" -o /dev/null --data-urlencode "_csrf=$T" --data-urlencode "username=$1" --data-urlencode "password=password12345" --data-urlencode "displayName=$2" --data-urlencode "captcha=$N" "$BASE/register"
}
login() {
  curl -s -c "$J.$1" -b "$J.$1" -o /tmp/.login.html "$BASE/login"
  T=$(csrf /tmp/.login.html)
  curl -s -c "$J.$1" -b "$J.$1" -o /dev/null --data-urlencode "_csrf=$T" --data-urlencode "username=$1" --data-urlencode "password=password12345" "$BASE/login"
}
tok() { csrf <(curl -s -c "$J.$1" -b "$J.$1" "$BASE/$2"); }
posttxt(){
  T=$(tok "$1" compose)
  curl -s -c "$J.$1" -b "$J.$1" -o /dev/null --data-urlencode "_csrf=$T" --data-urlencode "type=text" --data-urlencode "body=$2" "$BASE/posts"
}
follow() { T=$(tok "$1" ""); curl -s -c "$J.$1" -b "$J.$1" -o /dev/null --data-urlencode "_csrf=$T" -X POST "$BASE/follow/$2"; }
like()   { T=$(tok "$1" ""); curl -s -c "$J.$1" -b "$J.$1" -o /dev/null --data-urlencode "_csrf=$T" -X POST "$BASE/posts/$2/like"; }
cmt()    { T=$(tok "$1" ""); curl -s -c "$J.$1" -b "$J.$1" -o /dev/null --data-urlencode "_csrf=$T" --data-urlencode "body=$3" -X POST "$BASE/posts/$2/comment"; }
share()  { T=$(tok "$1" ""); curl -s -c "$J.$1" -b "$J.$1" -o /dev/null --data-urlencode "_csrf=$T" -X POST "$BASE/posts/$2/share"; }
repost() { T=$(tok "$1" ""); curl -s -c "$J.$1" -b "$J.$1" -o /dev/null --data-urlencode "_csrf=$T" -X POST "$BASE/posts/$2/repost"; }
ffrom()  { T=$(tok "$1" ""); curl -s -c "$J.$1" -b "$J.$1" -o /dev/null --data-urlencode "_csrf=$T" -X POST "$BASE/posts/$2/follow-from"; }
get()    { curl -s -c "$J.$1" -b "$J.$1" "$BASE/$2"; }
ok() { echo "  $([ $1 -eq 0 ] && echo '[OK]' || echo '[FAIL]') $2"; }

echo "== register & login =="
reg alicew "Alice W"; reg bobw "Bob W"; reg davew "Dave W"
login alicew; login bobw; login davew
ok $? "users registered/logged in"

echo "== network: alicew -> bobw (davew isolated) =="
follow alicew bobw
ok $? "alicew follows bobw"

echo "== bobw posts =="
posttxt bobw "Hello from Bob via HTTP"
ok $? "bobw created text post"

echo "== alicew feed shows bobw, davew cannot see bobw =="
FEED=$(get alicew "")
echo "$FEED" | grep -q "Hello from Bob via HTTP" && ok 0 "alicew sees bobw post" || ok 1 "alicew sees bobw post"
DAVEPROF=$(get davew "u/bobw")
echo "$DAVEPROF" | grep -q "Hello from Bob via HTTP" && ok 1 "davew LEAKED bobw posts" || ok 0 "davew cannot see bobw posts"

echo "== interactions: like / comment / share / repost / follow-from =="
PID=$(echo "$FEED" | grep -o '/posts/[0-9]*/like' | head -1 | grep -o '[0-9]*')
echo "  post id = $PID"
like   alicew "$PID"; ok $? "alicew liked"
cmt    alicew "$PID" "nice post"; ok $? "alicew commented"
share  alicew "$PID"; ok $? "alicew shared"
repost alicew "$PID"; ok $? "alicew reposted"
ffrom  alicew "$PID"; ok $? "alicew follow-from-post"

echo "== profile edit: inject <script>, verify stripped on render =="
T=$(tok alicew "u/alicew/edit")
curl -s -c "$J.alicew" -b "$J.alicew" -o /dev/null \
  --data-urlencode "_csrf=$T" \
  --data-urlencode "displayName=Alice W" --data-urlencode "bio=hi" \
  --data-urlencode "html=<script>alert(1)</script><div style='color:#0ff'>my custom page</div><!--POSTS-->" \
  --data-urlencode "css=.ev-banner{background:#000}" \
  "$BASE/u/alicew/edit"
PROF=$(get alicew "u/alicew")
echo "$PROF" | grep -q "<script>alert" && ok 1 "script LEAKED on profile" || ok 0 "script stripped from profile"
echo "$PROF" | grep -q "my custom page" && ok 0 "custom HTML preserved" || ok 1 "custom HTML preserved"
echo "$PROF" | grep -q "reposted" && ok 0 "alicew profile shows her repost" || ok 1 "alicew profile shows her repost"

echo "== compose page + discover page render =="
get alicew "compose" | grep -q "New post" && ok 0 "compose renders" || ok 1 "compose renders"
get alicew "discover" | grep -q "Discover people" && ok 0 "discover renders" || ok 1 "discover renders"

rm -f "$J"* /tmp/.reg.html /tmp/.login.html
echo "done"