# Phase 0 Gate Sign-Off & Verification Artifact

**Target Release:** Extrovert MLS Migration (RFC 9420)  
**Date:** 2026-10-04  
**Git Branch:** `mls-spike` (isolated from `master`)  
**Status:** Ready for Sign-Off  

---

## 1. Executive Summary & Verification Evidence

Extrovert's migration from Olm/Megolm to Messaging Layer Security (RFC 9420) replaces $O(N \times M)$ pairwise prekey ratchets with tree-based TreeKEM groups and single-ciphertext broadcasts.

### Cryptographic Engine & Bundle Evidence
* **Engine:** `ts-mls` (pinned release) with `@noble/curves`, `@noble/ciphers`, `@noble/hashes`, and `@hpke/core`.
* **Ciphersuite:** Suite 1 (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`).
* **Bundle Measurement (`public/lib/mls.js`):**
  * Raw minified: **242 KB** (`-rw-rw-r-- 1 axoisaxo axoisaxo 242K`)
  * Gzipped wire payload: **76.2 KB** (77,986 bytes)
  * Zero runtime dependencies, zero external network CDNs, no WebAssembly linear memory bridge for base cryptographic operations.

### Test Suite Execution Output
All 4 conformance, database, API, and multi-device E2E chat suites executed cleanly against Node.js:
1. `scripts/mls-conformance-test.js`: Validated RFC 9420 Suite 1 KeyPackage wire format, commit generation, welcome decoding, TreeKEM epoch advancement (0 -> 1 -> 2), and single-ciphertext multi-recipient decryption.
2. `scripts/mls-db-test.js`: Verified SQLite CAS commit sequencing, 409 conflict detection, 10-device quota, single-use KeyPackage claiming, historical commit catch-up, Welcome ACK lifecycle, and credential vault storage.
3. `scripts/mls-api-test.js`: Verified all REST endpoints mounted at `/mls/*` under Bearer token authentication.
4. `scripts/mls-e2e-chat-test.js`: Multi-device live simulation (Alice + Bob Laptop + Bob Mobile) proving single-ciphertext decryption across 3 leaves without Olm fan-out envelopes.

---

## 2. Resolutions of the Final Three Technical Blockers

### Item 1: Room Moderation & Kicks (No Server System Leaf)
* **Decision:** **Drop "Server-Assisted System Removal". Kicks are strictly client-committed.**
* **Security & Protocol Rationale:**
  * Under RFC 9420, all proposals must originate from and be signed by an admitted group leaf.
  * Creating a "server leaf" or Delivery Service bot member in every room would require the server to maintain private keys and participate in the ratchet tree, granting the server cryptographic visibility into plaintext traffic. This directly violates Extrovert's core privacy guarantee (zero-knowledge E2EE).
* **Specification:**
  1. Room kicks/bans are triggered exclusively by authorized clients (moderators or administrators).
  2. When a moderator kicks a user via the UI, the moderator's client generates a `RemoveProposal(target_leaf)` and commits it directly to the room MLS group at epoch $E+1$.
  3. If a moderator is offline, any other user holding moderator/admin privileges can issue the commit.
  4. If an account is deactivated or purged by server admin tools, the server flags the user as deactivated in the database; active group members' clients automatically fold a `RemoveProposal` into their next epoch commit upon receiving the sync update.
  5. The server never holds group keys or leaf secrets.

---

### Item 2: Vault KEK Derivation (Argon2id vs. WebCrypto PBKDF2)
* **Decision:** **WebCrypto PBKDF2-HMAC-SHA-256 (600,000 Iterations).**
* **Trade-off Analysis:**
  * **Argon2id:** Provides superior GPU/ASIC resistance, but requires `argon2-browser` (a ~100 KB WebAssembly binary). This adds bundle weight, increases load latency, and introduces WASM memory allocation complexities across diverse client platforms.
  * **WebCrypto PBKDF2:** Built directly into native browser engines (C++ implementation), runs off the main JavaScript thread, adds **0 KB** to the bundle, and executes reliably across Linux, macOS, Windows, iOS, and Android.
  * **Mitigation for Offline Brute-Force:**
    1. Iteration count is fixed at **600,000 iterations** (exceeding OWASP 2024 guidance).
    2. The salt is 32 cryptographically secure random bytes generated per device (`crypto.getRandomValues`).
    3. The vault ciphertext is authenticated with `AES-GCM-256`.
    4. Account login on the server is rate-limited and protected by server-side password hashing (bcrypt/scrypt), preventing attackers from obtaining the ciphertext blob without an authenticated session.

---

### Item 3: Scoped Idempotency Keys
* **Decision:** **Composite Primary Key `(group_id, idempotency_key)`.**
* **Schema Definition:**
  ```sql
  CREATE TABLE mls_idempotency (
    group_id        TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    epoch           INTEGER NOT NULL,
    commit_hash     TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    PRIMARY KEY (group_id, idempotency_key)
  );
  CREATE INDEX idx_mls_idempotency_exp ON mls_idempotency(expires_at);
  ```
* **Behavior:**
  * Idempotency is isolated strictly per group. Duplicate client UUIDs across different groups cannot cause cross-talk or spurious rejections.
  * `expires_at` is set to `created_at + 86400` (24-hour TTL), purged automatically by background maintenance.

---

## 3. Critical Technical Clarifications

### A. Ephemeral Status of `leaf_index`
* In `mls_group_members`:
  ```sql
  CREATE TABLE mls_group_members (
    group_id     TEXT NOT NULL,
    user_id      INTEGER NOT NULL,
    device_id    TEXT NOT NULL,
    leaf_index   INTEGER NOT NULL,
    role         TEXT NOT NULL DEFAULT 'member',
    joined_at    INTEGER NOT NULL,
    removed_at   INTEGER DEFAULT NULL,
    PRIMARY KEY (group_id, user_id, device_id)
  );
  ```
* **Normative Rule:** `leaf_index` is an ephemeral observation updated on every epoch transition. TreeKEM compaction and blank leaf pruning alter leaf indices over time. `leaf_index` **must never** be used for identity or authorization. The immutable tuple `(group_id, user_id, device_id)` is the canonical identifier.

### B. Welcome Lifecycle & Multi-Tab Reconciliation
* When a client fetches a Welcome:
  * `fetched_at` is marked with the current timestamp.
  * If the user switches tabs or backgrounds the device, causing a delay:
    1. If the Welcome was already processed and acknowledged (`acked_at IS NOT NULL`), calling `joinGroup` checks local IndexedDB (`STORE_MLS_GROUPS`). Finding the group already initialized, it immediately exits without error.
    2. The client then queries `GET /mls/groups/:id/commits?since=current_epoch` to catch up to the current epoch.
    3. Welcome reconciliation is completely idempotent and safe against network retries or multi-window race conditions.

---

## 4. Process Commitments

1. **Branch Isolation:**
   * All preliminary code, benchmarks, and spikes reside on the dedicated branch `mls-spike`.
   * The `master` branch remains clean and protected.
2. **Phase Gate Enforcement:**
   * No code from `mls-spike` will be merged into `master` until this Phase 0 Gate is formally accepted.
3. **Internal Audit Execution:**
   * Prior to Phase 3 (UI activation), a scoped security audit of the pinned `ts-mls` wire framing, parent hash verification, and transcript hash checks will be completed and documented in `docs/security/audit-ts-mls.md`.
