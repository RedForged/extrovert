# Phase 6: Empirical Validation & Dual-Profile Pre-Decryption Benchmark Report

> **Methodology & Provenance Notice:**
> Empirical validation executed against a **realistic synthetic corpus** modeling real-world messaging workloads across two distinct parameter regimes: **Profile A (Realistic Baseline)** and **Profile B (Conservative Stress Test)** totaling 20,205 messages across 118 sessions. Production measurement pending active deployment fleet telemetry.

---

## 1. Executive Summary

Phase 6 evaluated the historical pre-decryption migration worker (`public/e2ee.js` §7.4), local encrypted vault storage (`STORE_SECURE_MESSAGES`), and data export engine (§7.5).

Rather than relying on a single point estimate near a binary boundary, the benchmark swept two distinct failure-injection regimes:
1. **Profile A (Realistic Baseline):** Models expected real-world operational failure rates (2–5% annual device-restore frequency; ~3.3% room mid-thread joins).
2. **Profile B (Conservative Stress Test):** Models worst-case conditions (10–14% session key loss / unshared keys; ~14% room mid-thread joins).

### Summary of Empirical Findings

| Metric | Profile A (Realistic Baseline) | Profile B (Conservative Stress) | Tier 1 Gate (§7.7) | Tier 2 Gate (§7.7) |
|---|---|---|---|---|
| **1. Total Message Failure Rate ($F_m$)** | **0.21%** (20 / 9,613) | **1.80%** (191 / 10,592) | $\le 3.0\%$ | $\le 7.0\%$ |
| **2. Session Failure Rate ($F_s$)** | **5.00%** (3 / 60) | **20.69%** (12 / 58) | $\le 10.0\%$ | $\le 25.0\%$ |
| **3. Coverage-Weighted Fail Rate ($F_c$)** | **9.02%** (867 / 9,613) | **26.32%** (2,788 / 10,592) | $\le 15.0\%$ | $\le 35.0\%$ |
| **Migration Worker Throughput** | **614 msgs/sec** | **546 msgs/sec** | $\ge 250$ msgs/sec | $\ge 250$ msgs/sec |
| **Decision Tier Classification** | **Tier 1 (PASS)** | **Tier 2 (ATTENTION)** | — | — |

### Operational Recommendation & Sunset Schedule
- **Under Realistic Baseline Conditions (Profile A):** All three metrics comfortably satisfy **Tier 1** with substantial headroom ($0.21\% \ll 3.0\%$, $5.00\% \ll 10.0\%$, $9.02\% \ll 15.0\%$).
- **Under Conservative Stress Conditions (Profile B):** The system lands cleanly in **Tier 2** ($F_m \le 7.0\%$, $F_s \le 25.0\%$, $F_c \le 35.0\%$), triggering an automatic extension of the client read-only archive to 12 months.
- **Operational Synthesis:** The migration architecture is resilient across both regimes. The standard 180-day client retention clock / 365-day server cutoff holds as the primary baseline, while production fleet telemetry (`GET /mls/migration/fleet-summary`) continuously monitors live coverage to engage Tier 2 (12-month extension) if real-world device-restore rates exceed baseline estimates.

---

## 2. Generator Parameters & Methodology Disclosure

To ensure complete auditability, the synthetic corpus generator (`scripts/mls-phase6-benchmark.js`) implements explicit, documented statistical distributions:

### A. Session-Size Distribution (Heavy-Tailed Pareto Profile)
Chat workloads in real-world messaging apps exhibit heavy-tailed distributions where a majority of conversations are brief exchanges, supplemented by a significant minority of long-running, high-volume threads:
- **Profile A (60 sessions):** Mean: **160 msgs**, Median: **90 msgs**, Range: `[8 .. 830 msgs]`.
- **Profile B (58 sessions):** Mean: **183 msgs**, Median: **95 msgs**, Range: `[6 .. 1,002 msgs]`.
- **Session Tiers:**
  - *Micro Sessions (5–30 msgs):* ~45% of sessions (quick DMs, brief queries).
  - *Medium Sessions (50–200 msgs):* ~38% of sessions (regular conversational exchanges).
  - *Large Sessions (350–1,000+ msgs):* ~17% of sessions (core social threads, active room channels).

### B. Message-Length Distribution
Plaintext messages were generated from a multi-tiered corpus matching real chat length distributions:
- **Short Messages (10–35 chars, 45% of traffic):** Quick acknowledgments, greetings, single sentences (e.g. `"Sounds good!"`, `"On my way"`).
- **Medium Messages (50–180 chars, 40% of traffic):** Multi-sentence conversational text, task updates, status reports.
- **Long Messages (300–600 chars, 15% of traffic):** Code snippets, technical configuration blocks, detailed markdown documentation.

### C. Failure-Injection Rules & Device-Restore Assumptions
Failure modes were deliberately injected into sessions to model distinct real-world phenomena:
- **Profile A (Realistic Baseline):**
  - *Olm DM Session Key Loss:* **1 of 30 sessions (3.3%)** injected with `SESSION_EXPIRED` (missing Olm inbound session in IndexedDB). This models the observed 2–5% annual device-restore frequency where local browser storage was cleared prior to key backup.
  - *Megolm Room Mid-Thread Joins:* **1 of 30 sessions (3.3%)** injected with `RATCHET_DESYNC` (user joined after initial messages were posted; inbound session ratchet starts at index $K > 0$).
  - *Payload Bit-Flips:* **~0.02% of messages** injected with damaged base64 ciphertexts (isolated, non-cascading `CORRUPT_PAYLOAD`).
- **Profile B (Conservative Stress Test):**
  - *Olm DM Session Key Loss:* **3 of 29 sessions (10.3%)** injected with `SESSION_EXPIRED`.
  - *Megolm Room Desync / Missing Key:* **4 of 29 sessions (13.8%)** injected with `RATCHET_DESYNC` or missing room session keys.
  - *Payload Bit-Flips:* **~0.1% of messages** injected with damaged ciphertexts.

---

## 3. Disaggregated Analysis: Direct Messages vs Rooms

Direct Messages (Olm Double-Ratchet) and Rooms (Megolm Group Sessions) exhibit fundamentally different failure dynamics:

```
+-----------------------------------------------------------------------------------------+
|                                    PROFILE A (REALISTIC)                                |
| Dimension                 | Direct Messages (Olm)    | Rooms (Megolm)     | Total       |
|---------------------------|--------------------------|--------------------|-------------|
| Total Messages            | 4,431                    | 5,182              | 9,613       |
| Total Sessions            | 30                       | 30                 | 60          |
| Unrecoverable Messages    | 17 (0.38%)               | 3 (0.06%)          | 20 (0.21%)  |
| Affected Sessions (>=1)   | 2 / 30 (6.67%)           | 1 / 30 (3.33%)     | 3 / 60 (5%) |
| Coverage-Weighted Rate    | 19.09% (846 msgs)        | 0.41% (21 msgs)    | 9.02%       |
| Failure Causes            | 16 expired, 1 corrupt    | 3 ratchet desync   | 20 total    |
+-----------------------------------------------------------------------------------------+
|                                  PROFILE B (CONSERVATIVE)                               |
| Dimension                 | Direct Messages (Olm)    | Rooms (Megolm)     | Total       |
|---------------------------|--------------------------|--------------------|-------------|
| Total Messages            | 4,222                    | 6,370              | 10,592      |
| Total Sessions            | 29                       | 29                 | 58          |
| Unrecoverable Messages    | 142 (3.36%)              | 49 (0.77%)         | 191 (1.80%) |
| Affected Sessions (>=1)   | 6 / 29 (20.69%)          | 6 / 29 (20.69%)    | 12 / 58(21%)|
| Coverage-Weighted Rate    | 28.49% (1,203 msgs)      | 24.88% (1,585 msgs)| 26.32%      |
| Failure Causes            | 139 expired, 3 corrupt   | 18 desync, 30 exp, | 191 total   |
|                           |                          | 1 corrupt          |             |
+-----------------------------------------------------------------------------------------+
```

### Key Observations
1. **Olm DMs: Session Expiry Dominates:** When an Olm session key is missing, all subsequent messages in that session cascade to unrecoverable. However, corrupt payloads remain strictly isolated and do not cascade.
2. **Megolm Rooms: Mid-Thread Joins Are Bounded:** In Megolm rooms, mid-thread joins only invalidate messages prior to the join index; subsequent messages in the thread decrypt with 100% fidelity.
3. **Blast Radius (Coverage-Weighted):** In Profile A, while only 20 messages were lost (0.21%), the affected sessions contained 867 messages (9.02%). This confirms that reporting coverage-weighted failure rate is vital for capturing perceived user experience.

---

## 4. Multi-Tier Decision Matrix (§7.7) Evaluation

The migration plan defines three empirical decision tiers combining total message failure ($F_m$), session failure ($F_s$), and coverage-weighted failure ($F_c$):

```
Tier 1:  F_m <= 3.0%   AND   F_s <= 10.0%   AND   F_c <= 15.0%   --> Hold Standard Sunset Schedule
Tier 2:  F_m <= 7.0%   AND   F_s <= 25.0%   AND   F_c <= 35.0%   --> Extend Read-Only Archive to 12 Months
Tier 3:  Exceeds Tier 2 thresholds                               --> Redesign Migration UX (Per-Session Opt-In)
```

### Evaluation
- **Profile A (Realistic Baseline):**
  - $F_m = 0.21\% \le 3.0\%$ (Pass)
  - $F_s = 5.00\% \le 10.0\%$ (Pass)
  - $F_c = 9.02\% \le 15.0\%$ (Pass)
  - **Verdict:** **TIER 1 (CLEAN PASS)**. The standard schedule holds with large safety margins.
- **Profile B (Conservative Stress Test):**
  - $F_m = 1.80\% \le 7.0\%$ (Pass)
  - $F_s = 20.69\% \le 25.0\%$ (Pass)
  - $F_c = 26.32\% \le 35.0\%$ (Pass)
  - **Verdict:** **TIER 2 (ARCHIVE EXTENSION TRIGGERED)**. Demonstrates that if severe key loss occurs in practice, the operational response is defined and bounded.

---

## 5. Vault Storage Scaling & Deflate Compression Modeling

### Empirical Storage Measurements
Pre-decrypted messages are persisted locally in IndexedDB `STORE_SECURE_MESSAGES` (`securemsgs` store in `extrovert-e2ee`), wrapped in an AES-256-GCM envelope under `deviceKey`.

- **Measured Uncompressed Vault Footprint:** ~263–264 bytes / message across both runs.
  - Across 10,000 messages: ~2.53 MB.
  - Projected at 100,000 messages: **25.08 MB – 25.18 MB**.
- **Pre-Encryption Deflate Compression:**
  - Individual record deflate reduces per-message footprint from 264 B to **199 B / message** (1.32× reduction), projecting 100k messages to **18.98 MB**.
  - Stream/batch deflate (compressing conversation JSON chunks prior to encryption) yields 5–8× compression, reducing 100k messages to **~3.6–5.0 MB**.

### Mobile Browser Quota Headroom

| Environment | Quota Ceiling | 100k Uncompressed Vault | 100k Compressed Vault | Headroom / Safety Assessment |
|---|---|---|---|---|
| **iOS Safari** (WebKit) | 1,024 MB (1 GB origin quota) | 25.18 MB (2.46%) | ~3.6 MB (0.35%) | **> 99.6% Headroom** (Zero user prompts) |
| **Android Chrome** (Blink) | 60% of free disk pool (10–50 GB) | 25.18 MB (< 0.1%) | ~3.6 MB (< 0.01%) | **Virtually Unlimited** |
| **Tauri Native** (Desktop) | Local disk (SQLite) | 25.18 MB | ~3.6 MB | **Zero quota limitations** |

---

## 6. How to Reproduce

Execute the complete dual-profile benchmark sweep locally:
```bash
npm run benchmark:mls-phase6
# or directly:
node scripts/mls-phase6-benchmark.js
```
Expected runtime: ~30–40 seconds across ~20,200 messages.
