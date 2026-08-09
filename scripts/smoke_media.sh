#!/bin/bash
# Media upload + repost visibility test.
set -u
BASE=http://localhost:3000
J="${TMPDIR:-/tmp}/extrovert-smoke-media-cookies"
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rm -f "$J"*
ok() { echo "  $([ $1 -eq 0 ] && echo '[OK]' || echo '[FAIL]') $2"; }

# Fetch a CSRF token from the page's hidden form input.
csrf() { grep -o 'name="_csrf" value="[^"]*"' "$1" | head -1 | sed 's/.*value="//;s/"//'; }

# Solve the register proof-of-work captcha embedded in the fetched page, using
# the app's own verifier module (same hash the server checks).
captcha() {
  grep -o 'data-challenge="[^"]*" data-salt="[^"]*" data-maxnumber="[0-9]*" data-difficulty="[0-9]*"' "$1" | head -1 \
  | sed 's/data-challenge="\([^"]*\)" data-salt="\([^"]*\)" data-maxnumber="\([0-9]*\)" data-difficulty="\([0-9]*\)"/\1 \2 \3 \4/' \
  | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const[c,salt,m,d]=s.trim().split(' ');const{findNumber}=require(process.argv[1]);console.log(findNumber(c,salt,Number(m),Number(d)))})" "$REPO_ROOT/src/captcha.js"
}

# Registration and login require CSRF + a 12+ character password + captcha solve.
reg() {
  curl -s -c "$J.$1" -b "$J.$1" -o /tmp/.smreg.html "$BASE/register"
  T=$(csrf /tmp/.smreg.html)
  N=$(captcha /tmp/.smreg.html)
  curl -s -c "$J.$1" -b "$J.$1" -o /dev/null \
    --data-urlencode "_csrf=$T" --data-urlencode "username=$1" \
    --data-urlencode "password=password12345" --data-urlencode "displayName=$2" \
    --data-urlencode "captcha_number=$N" "$BASE/register"
}
login() {
  curl -s -c "$J.$1" -b "$J.$1" -o /tmp/.smlogin.html "$BASE/login"
  T=$(csrf /tmp/.smlogin.html)
  curl -s -c "$J.$1" -b "$J.$1" -o /dev/null \
    --data-urlencode "_csrf=$T" --data-urlencode "username=$1" --data-urlencode "password=password12345" "$BASE/login"
}
tok()   { curl -s -c "$J.$1" -b "$J.$1" "$BASE/$2" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"//'; }
follow() { T=$(tok "$1" ""); curl -s -c "$J.$1" -b "$J.$1" -o /dev/null --data-urlencode "_csrf=$T" -X POST "$BASE/follow/$2"; }
get()    { curl -s -c "$J.$1" -b "$J.$1" "$BASE/$2"; }

reg mediabob "Media Bob"; reg mediaval "Media Val"
login mediabob; login mediaval
follow mediaval mediabob

# 1x1 transparent PNG
PNG="${TMPDIR:-/tmp}/extrovert-smoke-test.png"
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82' > "$PNG"
ls -la "$PNG" >/dev/null && ok 0 "test png created" || ok 1 "test png created"

echo "== photo upload =="
T=$(tok mediabob "compose")
curl -s -c "$J.mediabob" -b "$J.mediabob" -o /dev/null \
  -F "_csrf=$T" -F "type=photo" -F "body=sunset pic" -F "media=@$PNG;type=image/png" "$BASE/posts"
ok $? "mediabob uploaded photo"

FEED=$(get mediaval "")
echo "$FEED" | grep -q "sunset pic" && ok 0 "photo post visible in feed" || ok 1 "photo post visible in feed"
echo "$FEED" | grep -q '<img class="post-media"' && ok 0 "img tag rendered" || ok 1 "img tag rendered"

PID=$(echo "$FEED" | grep -o '/posts/[0-9]*/like' | head -1 | grep -o '[0-9]*')
echo "  photo post id = $PID"

echo "== repost should now appear on reposter's profile =="
T=$(tok mediaval "")
curl -s -c "$J.mediaval" -b "$J.mediaval" -o /dev/null --data-urlencode "_csrf=$T" -X POST "$BASE/posts/$PID/repost"
PROF=$(get mediaval "u/mediaval")
echo "$PROF" | grep -q "reposted" && ok 0 "repost shown on profile" || ok 1 "repost shown on profile"
echo "$PROF" | grep -q "sunset pic" && ok 0 "reposted content (sunset pic) shown on profile" || ok 1 "reposted content shown on profile"

echo "== video upload (tiny webm-ish blob accepted by mimetype) =="
MP4="${TMPDIR:-/tmp}/extrovert-smoke-test.mp4"
echo "fakevideo" > "$MP4"
T=$(tok mediabob "compose")
curl -s -c "$J.mediabob" -b "$J.mediabob" -o /dev/null \
  -F "_csrf=$T" -F "type=video" -F "body=clip" -F "media=@$MP4;type=video/mp4" "$BASE/posts"
# The feed is cached for 30s, so check the author's (freshly rendered) profile instead.
PROFB=$(get mediabob "u/mediabob")
echo "$PROFB" | grep -q '<video class="post-media"' && ok 0 "video tag rendered" || ok 1 "video tag rendered"

rm -f "$J"* "$PNG" "$MP4" /tmp/.smreg.html /tmp/.smlogin.html
echo "done"
