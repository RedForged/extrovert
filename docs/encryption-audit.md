# Extrovert E2EE — Encryption Bug Audit

Scope: every file touching encryption/decryption of messages (DMs via Olm, rooms
via Megolm, key transport, backups, and the supporting server endpoints).
Method: full read of `public/e2ee.js`, `public/room-e2ee.js`, `public/rooms.js`,
`src/routes/chats.js`, `src/routes/rooms.js`, `src/routes/api-v1.js`, `src/db.js`,
`src/dm.js`, `src/webrtc-signaling.js`, plus the crypto helpers (OIDC, captcha,
mailer) and the existing test/repro scripts. I also ran a live probe against the
bundled `@matrix-org/olm@3.2.15` to confirm the actual libolm behavior the client
relies on (results inline where relevant).

Severity legend:
- **P0** — directly causes the reported "fails to decrypt, after some time / randomly".
- **P1** — causes message loss or breaks a whole device/class of messages.
- **P2** — real cryptographic or correctness weakness, lower blast radius.

---

## Executive summary

The reported symptom — *messages decrypt fine for a while, then start failing,
seemingly at random* — is not one bug. It is a chain of four defects that feed
each other:

1. The client **rebuilds the Olm session on essentially every message send**
   (P0-1), because a "session healing" check misfires.
2. That rebuild **deletes the inbound session and baselines** needed to read the
   peer's messages and history (P0-2, P0-5).
3. When decryption does fail, the **recovery (rekey) path is dead code**: the
   function it calls doesn't exist, and the polling loop that would heal the
   session is never wired up (P0-3, P0-4).
4. The one thing that would mask all of this — the device-local plaintext cache —
   is **actively purged** for anything outside the visible window (P1-6), and the
   visible window itself fetches the wrong end of the history (P1-7).

Net effect: everything works while the plaintext cache covers the conversation;
the moment a message falls out of that window, or a session rotates, or a second
device/tab is involved, it becomes `[unable to decrypt]` and can never recover
except via a full manual key reset.

---

## P0 — root causes of the reported symptom

### P0-1. Outbound Olm session is torn down and rebuilt on (almost) every send

**Where**
- Client: `public/e2ee.js` `encryptOlm()` (~line 937) calls `fetchBundle()` on
  every send; `getOrCreateDeviceOutboundSession()` (lines 828–882).
- Server: `src/routes/chats.js` `GET /:username/bundle` (lines 186–205) →
  `claimAllDevicePrekeysForUser()`; `src/db.js` `claimDevicePrekey()` (1288–1298)
  and `claimAllDevicePrekeysForUser()` (1300–1330).

**What happens**
The bundle endpoint is a *read with destructive side effects*: every call runs
`claimDevicePrekey()`, which selects the next `used = 0` one-time prekey, sets
`used = 1`, and returns it. So each bundle fetch returns a **different**
`one_time_key.id`.

On the client, `getOrCreateDeviceOutboundSession()` treats "the peer's fresh OTK
id differs from the one I used last" as proof the peer reset their session, and
responds by deleting **all** session state and creating a brand-new outbound
session:

```js
if (freshOtkId) {
  checks.push(idbGet(STORE_OLM, sessionOtkKey(fullKey)).then(function (usedOtk) {
    return !!(usedOtk && String(usedOtk) !== String(freshOtkId));
  }));
}
...
if (flags.some(Boolean)) {
  // delete sessionOut, sessionKey, sessionBase, sessionIn, sessionInBase
}
```

Because a *new* OTK id is claimed on every fetch, `usedOtk !== freshOtkId` is
true on every send (as long as the peer's prekey pool is non-empty). The result:
a fresh PreKey session is established for nearly every message, the ratchet is
reset constantly, and one-time prekeys are burned at ~2 per message (one for the
recipient's devices, one for the sender's own devices — the bundle claims both).

**Why it breaks decryption**
- Each rotation overwrites the recipient's inbound baseline (see P0-5), so prior
  history can no longer be baseline-decrypted.
- It deletes the sender's inbound session (P0-2), so replies fail.
- It exhausts prekey pools, pushing sessions onto fallback keys and making the
  "healing" trigger even more erratically — hence the *random* feel.

**Proposed fix**
- Make prekey claiming happen **only when actually establishing a session**, not
  on every bundle read. Split the endpoint: a `bundle`/`keys` read that returns
  identity + fallback + an *unclaimed* OTK preview, and a separate
  `claim` call invoked exactly once per new session. Alternatively, keep claiming
  but have the client **not** treat a changed OTK as a reset signal when it
  already holds a working session (only rotate on an explicit identity-key
  change).
- Stop fetching the bundle on every send; reuse the existing session and only hit
  the server when no usable session exists.

### P0-2. Session rotation deletes the *inbound* session and baselines

**Where** `public/e2ee.js` `getOrCreateDeviceOutboundSession()`, lines 850–860.

**What happens**
When rotation triggers, the code deletes not just the outbound session but also
`sessionInKey(fullKey)` and `sessionInBaseKey(fullKey)`. The inbound session under
that key is exactly what decrypts messages **from** the peer.

**Why it breaks decryption**
Alice sends to Bob → rotation fires → Alice deletes her inbound session for Bob.
Bob's next normal (type-1) message arrives on his existing session; Alice has no
inbound session, no baseline, and it isn't a PreKey message, so it can't be
decrypted. Bidirectional conversations break immediately after one side sends.
Because rotation fires on most sends (P0-1), this happens constantly.

**Proposed fix**
Never delete inbound state when rotating an outbound session. Outbound and
inbound ratchets are independent; only delete/replace the specific session being
rebuilt, and keep inbound sessions + baselines until they are explicitly
superseded by a *received* new PreKey.

### P0-3. `requestRekeyFrom` is called but never defined → `ReferenceError`

**Where** `public/e2ee.js` lines 1204 and 1208 (inside `decryptOlm()` failure
paths). `requestRekeyFrom` is **not defined anywhere** in the shipped code — the
repro script (`scripts/decrypt-repro.js`) simulates the intended behavior, but the
real client has no such function.

**What happens**
Every time decryption exhausts all session candidates and should ask the peer to
rebuild the session, the client instead throws
`ReferenceError: requestRekeyFrom is not defined`. The intended rekey request is
never sent, and the thrown error masks the real one.

**Proposed fix**
Implement `requestRekeyFrom(otherIdStr)` → `POST /chats/rekey/request` with
`{ other_id }` (the endpoint already exists: `chats.js` line 210,
`db.requestDmRekey`). Guard with a try/catch so a network failure can't break the
decrypt error path.

### P0-4. The rekey-healing protocol is never run (dead client code)

**Where**
- Declared but unused: `REKEY_NEEDED_URL`, `REKEY_ACK_URL`, `REKEY_CHECK_MS`,
  `rekeyLastCheck`, `rekeyRequestedAt` (`public/e2ee.js` lines 31–45). No polling
  loop, no `fetch` of `/chats/rekey/needed`, no call to `/chats/rekey/ack`.
- Server side fully exists: `GET /chats/rekey/needed`, `POST /chats/rekey/ack`
  (`chats.js` 218–232), `dmRekeyNeeded`/`clearDmRekey` (`db.js` 1200–1205).

**What happens**
Even if P0-3 were fixed and a rekey request were registered, the sender never
checks for it and never rebuilds its outbound session. Combined with P0-3, a
desynced session has **no automatic recovery** — every subsequent message shows
`[unable to decrypt]` until a manual key reset.

**Proposed fix**
Wire the loop the constants imply: before reusing an outbound session (and on a
`REKEY_CHECK_MS` interval), poll `/chats/rekey/needed?requester_id=<peer>`; if
`needed`, rebuild the outbound session from a fresh bundle, send the next message
as a PreKey, then `POST /chats/rekey/ack`. This is the "heal" the repro script
already models.

### P0-5. Recipient overwrites its inbound baseline on every new PreKey message

**Where** `public/e2ee.js` `decryptOlm()` incoming path, `create_inbound` branch
(~lines 1175–1192) → `saveInboundSessionBaseline()` (474–484).

**What happens**
Because P0-1 makes nearly every message a fresh PreKey, the recipient runs
`create_inbound` + `saveInboundSessionBaseline` repeatedly, each time
**overwriting** the previous baseline with the newest session's state. The old
session's baseline — the only thing that could replay older messages — is gone.
And `account.remove_one_time_keys()` has already consumed the old OTKs, so those
older PreKey messages can't be re-derived either.

**Why it breaks decryption**
History older than the current session can only be read from the plaintext cache.
Once that cache is purged (P1-6), cleared, or absent (new device), those messages
are permanently `[unable to decrypt]`.

**Proposed fix**
Keep baselines per-session (keyed by the session/OTK they belong to) instead of a
single overwritable slot, or stop rotating every message (P0-1) so the baseline
stays valid. Fixing P0-1 largely removes this problem.

---

## P1 — message loss / broken device classes

### P1-6. Local plaintext cache is purged for messages outside the visible window

**Where** `public/e2ee.js` `renderLocalSecureMessages()`, lines ~1935–1943.

**What happens**
After decrypting, the code deletes from the device-local secure store any cached
message that is **not currently in the DOM** and not flagged secure:

```js
var deletedNonSecure = msgs.filter(function (m) {
  return !existing[String(m.id)] && !m.msg_secure && !m.secure;
});
deletedNonSecure.forEach(function (d) { secureDeleteMessage(otherIdStr, d.id); });
```

The intent was "drop messages deleted on the server," but it cannot distinguish
*deleted on server* from *not rendered because it's outside the loaded window*.
Since the page only renders a bounded slice of history, every visit silently wipes
cached plaintexts for older messages — destroying the only recovery path that was
masking P0-1/P0-5.

**Proposed fix**
Only purge ids the server explicitly reports as deleted (e.g. via a delete event /
a tombstone list), never "absent from the current DOM slice."

### P1-7. `getMessages` returns the *oldest* 100 messages, not the newest

**Where** `src/db.js` `getMessages()` (lines 1068–1078):
`ORDER BY m.created_at ASC LIMIT ?` with `limit = 100`, no cursor.

**What happens**
For conversations longer than 100 messages the chat page loads the **first** 100
messages and drops the most recent ones. (The API path, `src/dm.js getMessages`,
correctly uses `DESC` + cursor pagination — the web path is inconsistent with it.)
This hides recent messages and, combined with P1-6, determines which cached
plaintexts survive.

**Proposed fix**
Fetch the newest N (`ORDER BY created_at DESC LIMIT ?`) and reverse for display,
matching the API path; add real pagination for older history.

### P1-8. Multi-device rooms: Megolm key is only delivered to one device

**Where**
- `public/e2ee.js` `getOrCreateRoomOutboundSession()` (1453–1470) uses the legacy
  single-target session key `session:<uid>:<peer>` (no device id).
- `fetchRoomBundle()` → `src/routes/rooms.js` `GET /:id/bundle/:username`
  (473–492) claims prekeys for **all** devices but the client only uses the
  primary's `identity_key`/`one_time_key`.

**What happens**
Room session keys are wrapped for the recipient's primary device only. A member
reading the room from a second device cannot decrypt the room key and therefore
cannot decrypt any room messages there. It also claims (burns) prekeys for devices
it never uses.

**Proposed fix**
Mirror the DM fan-out: wrap the Megolm session key for **each** recipient device
(per-device 1:1 sessions), and store one encrypted key per (session, recipient,
device).

### P1-9. Room rotation deletes not-yet-delivered session keys

**Where** `src/db.js` `publishRoomGroupSession()` (1595–1606): on `rotate` it
`DELETE FROM room_group_session_keys WHERE session_id = ?` and drops the session.

**What happens**
If a member hadn't fetched/imported their key before the rotation, that key is
destroyed server-side. Messages already sent under the old session become
permanently undecryptable for that member.

**Proposed fix**
Keep prior sessions and their pending keys until all recipients are marked
delivered (or until an explicit grace period/rotation acknowledgement), instead of
deleting on rotate.

### P1-10. Sender's *other* devices never get the sender's own room key

**Where** `public/e2ee.js` `shareRoomSession()` (1482–1503) shares only to
`others` (members minus self); `saveSelfGroupInbound()` (1440–1444) only stores an
inbound copy on the **local** device.

**What happens**
The sender's second device never receives the outbound Megolm session key, so it
can't decrypt the sender's own room messages.

**Proposed fix**
Also share/derive the session key for the sender's other registered devices
(analogous to the DM `sender_devices` fan-out).

---

## P2 — cryptographic / correctness weaknesses

### P2-11. Concurrent sends can reuse a ratchet counter (AES-GCM key+nonce reuse)

Two tabs (or two rapid sends) can load the same outbound/self session pickle and
both encrypt different plaintexts at the same message counter before either
persists the advanced state. Probe result: libolm still decrypts both
(`olm dup-counter: m1 -> first`, `m2 -> second`), so it doesn't *fail* — but
encrypting two different plaintexts under the same message key + nonce breaks
AES-GCM confidentiality/authenticity guarantees. There is no locking/serialization
around session use or persistence.

**Fix:** serialize encrypt→persist per session (a per-session promise queue, like
`secureWriteQueues`), and reload-then-advance rather than caching long-lived
session objects across async boundaries.

### P2-12. Own-message decrypt path doesn't restore session state on failure

The incoming path snapshots `livePickle` and restores it if `decrypt` throws
(lines ~1137–1148); the `isOwn` path (1050–1110) doesn't. A failed decrypt can
leave the in-memory session in an inconsistent state. (Lower risk — libolm doesn't
advance on a failed decrypt — but inconsistent and fragile.)

**Fix:** apply the same snapshot/restore discipline to the own-message path.

### P2-13. PBKDF2 salt is the (predictable) username

`deriveKek()` (261–269) salts PBKDF2 with `username.toLowerCase()`. 600k SHA-256
iterations is good, but a public, predictable salt enables precomputation if the
backup store leaks. Add a random per-account salt stored alongside the backup.

### P2-14. Oversize ciphertext is silently truncated instead of rejected

`src/routes/chats.js` slices `body`/`sender_ciphertext` at 65536;
`src/routes/api-v1.js` at 5000; `src/routes/rooms.js` at 20000. Truncating a
ciphertext corrupts it and stores a permanently-undecryptable message with no
error. Reject oversize payloads (4xx) instead of slicing.

---

## Minor / observations

- `decryptSelfFallback()` returns the literal string
  `[Unable to decrypt — encrypted for previous session]` as if it were message
  content; it then gets persisted into the local store as a "plaintext." Should be
  a distinct failure state, not text.
- `uploadBackup()` no-ops when `kek` is null, so the server-side account backup can
  go stale silently after key material changes.
- OIDC `previousKeys` (for rotation) is in-memory only and `rotateKeys()` is never
  invoked — harmless today, but key rotation would lose verification keys across a
  restart.

---

## Verified as *not* broken (checked so you don't chase these)

- AES-GCM IV handling (`encryptWithKd`/`encryptWithKek`) uses a fresh random
  12-byte IV per encryption — correct.
- Pickle-at-rest encryption with the non-extractable device key `Kd` is sound.
- Megolm inbound sessions **can** decrypt out-of-order/older indices once the key
  is imported (probe: `megolm old (#3) after newest -> msg-3`). The room failures
  is key *delivery* (P1-8/9/10), not Megolm itself.
- A failed Olm decrypt does not corrupt/advance the session (probe), and replaying
  an already-consumed message fails with `BAD_MESSAGE_MAC` as expected — which is
  exactly why the baseline mechanism exists.
- Captcha uses `timingSafeEqual` with a length pre-check; OIDC signing keys are
  persisted to disk with `0600`.

---

## Suggested remediation order

1. **Stop the churn (P0-1):** don't claim prekeys on bundle reads; don't rotate on
   a changed OTK while a session works. This alone removes most "random" failures.
2. **Stop deleting inbound state on rotation (P0-2)** and **stop overwriting
   baselines (P0-5).**
3. **Make recovery real (P0-3, P0-4):** implement `requestRekeyFrom` and the
   sender-side `/rekey/needed` poll + rebuild + ack.
4. **Stop destroying the safety net (P1-6):** purge cache only on explicit server
   deletes; fix the history window (P1-7).
5. **Fix multi-device rooms (P1-8, P1-9, P1-10).**
6. **Harden (P2):** serialize session use, snapshot/restore on all decrypt paths,
   random PBKDF2 salt, reject oversize ciphertext.

Items 1–4 are what will actually stop users seeing `[unable to decrypt]`; items 5–6
fix specific device classes and reduce cryptographic risk.
