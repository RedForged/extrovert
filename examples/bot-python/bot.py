#!/usr/bin/env python3
"""Minimal Extrovert bot (planned.md F5.6) — proves the "any language" claim.

Setup (as an instance admin):
    curl -X POST "$EXTROVERT_URL/api/v1/bots" \
      -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
      -d '{"username":"echo_bot","display_name":"Echo Bot"}'
  -> response.data.token is the bot token (shown once).

Run (webhook mode):
    pip install requests
    EXTROVERT_BOT_TOKEN=exb_... python3 bot.py            # polls mentions
    EXTROVERT_BOT_TOKEN=exb_... EXTROVERT_SSE=1 python3 bot.py   # SSE mode

The webhook mode of operation is what the server-side dispatch
(POST /api/v1/bots/webhook) targets: verify X-Webhook-Signature as shown in
verify() below before trusting an event.
"""

import hashlib
import hmac
import json
import os
import sys
import time

import requests

BASE = os.environ.get("EXTROVERT_URL", "https://extrovert.redforged.eu").rstrip("/")
TOKEN = os.environ["EXTROVERT_BOT_TOKEN"]
SECRET = os.environ.get("EXTROVERT_WEBHOOK_SECRET", "")
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def api(method, path, body=None):
    r = requests.request(method, BASE + "/api/v1" + path, headers=HEADERS, json=body, timeout=15)
    r.raise_for_status()
    return r.json()


def verify(signature: str, body: bytes) -> bool:
    """Verify X-Webhook-Signature: hex(HMAC-SHA256(secret, raw_body))."""
    if not SECRET:
        return True
    digest = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature)


def handle(event: dict) -> None:
    etype = event.get("type")
    actor_id = event.get("actor_id")
    if not actor_id:
        return
    actor = api("GET", f"/accounts/{actor_id}")["data"]
    if etype == "mention" and event.get("post_id"):
        post = api("GET", f"/statuses/{event['post_id']}")["data"]
        text = f"@{actor['username']} thanks for the mention! You said: {post.get('body', '')[:80]}"
        api("POST", "/statuses", {"type": "text", "body": text})
        print("replied to mention from", actor["username"])
    elif etype == "follow":
        api("POST", "/follow", {"uri": actor["username"]})
        print("followed back", actor["username"])


def poll_mentions():
    """Fallback mode: poll the mentions timeline every 60s."""
    seen = set()
    while True:
        try:
            for post in api("GET", "/timelines/mentions")["data"]:
                pid = post["id"]
                if pid in seen:
                    continue
                seen.add(pid)
                handle({"type": "mention", "actor_id": post["account"]["id"], "post_id": pid})
        except Exception as exc:  # noqa: BLE001
            print("poll error:", exc, file=sys.stderr)
        time.sleep(60)


def stream_sse():
    """Recommended for long-running bots: one open connection, live events."""
    with requests.get(BASE + "/api/v1/notifications/stream", headers=HEADERS, stream=True, timeout=None) as r:
        r.raise_for_status()
        for line in r.iter_lines(decode_unicode=True):
            if line and line.startswith("data: "):
                event = json.loads(line[6:])
                try:
                    handle(event)
                except Exception as exc:  # noqa: BLE001
                    print("handle error:", exc, file=sys.stderr)


if __name__ == "__main__":
    me = api("GET", "/bot/me")["data"]
    print(f"running as @{me['username']} (bot={me.get('is_bot')})")
    stream_sse() if os.environ.get("EXTROVERT_SSE") else poll_mentions()
