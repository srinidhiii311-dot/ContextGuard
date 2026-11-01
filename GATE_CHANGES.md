# GATE_CHANGES.md — Gate Freeze & Performance Revisions

## 1. Freeze Tags Overview
- **`gate-frozen-v2`** (`commit 3b56298`):
  - Fixed principled navigation gap: verified `CLICK` href destinations against allowlists.
  - Enforced exact host matching in `_is_trusted_navigation`.
  - Added leave-one-out ablation flags for C1, C2, C3, C4, and characterizer.
- **`gate-frozen-v2-perf`** (`commit 06bff80`):
  - Replaced synchronous per-decision disk writes (`JSONL`, `HMAC hash chain`, external anchor, and SQLite) with a background worker thread (`_PersistWorker`) using group commits (flush every 50 entries or 200 ms timeout; `os.fsync` on flush and shutdown).
  - Hardened URL trust verification (`_is_trusted_navigation`) against 44 trick vectors: userinfo `@` stripping, IDNA punycode normalization, hex/octal/decimal IP format rejection, strict port enforcement, protocol-relative URI rejection, and recursive open-redirect parameter inspection.
  - Verified 100% decision parity on the DEV split (0 mismatches across 680 cases).

---

## 2. File-by-File Changes Between `gate-frozen-v2` and `gate-frozen-v2-perf`

### A. `contextguard/audit_log.py`
- **Background Group Commit Worker**: Introduced `_PersistWorker` daemon thread and `_PERSIST_QUEUE`.
- **Synchronous Sequence & In-Memory Chain**: `index`, running HMAC SHA-256 `prev_hash`, and `entry_hash` are calculated deterministically on the calling thread under a re-entrant lock (`_REGISTRY_LOCK = threading.RLock()`), ensuring ordering and tamper-evidence.
- **Batched Disk I/O & `os.fsync`**: Offloaded synchronous per-entry file appending and database transactions to batch commits. Flushes occur upon accumulating 50 records or after a 200 ms timeout. Each batch executes `os.fsync()` on both the audit log and the HMAC anchor file.
- **Shutdown & Clean Exit Hooks**: Added `flush()` and `shutdown()` methods, registered with `atexit` to guarantee zero loss on graceful process exit.
- **Verification Guarantee**: `verify_audit_log()` flushes any pending worker queue items before computing cryptographic verification.

### B. `contextguard/consistency_checker.py`
- **Userinfo `@` Stripping**: Switched from `parsed.netloc.split(":")[0]` to `parsed.hostname` to prevent credential injection (`user:pass@attacker.com` resolving to `user`). Explicitly rejected embedded or percent-encoded `@` (%40) characters.
- **Punycode & Homoglyph Normalization**: Applied `.encode("idna").decode("ascii")` to canonicalize hostnames, preventing Cyrillic lookalike characters from spoofing ASCII allowlist entries.
- **Alternative IP Format Rejection**: Prohibited non-canonical IP representations including decimal dwords, octal dotted quads, and hexadecimal addresses.
- **Port Matching & High Ports**: Explicitly resolved default scheme ports (80 for `http`, 443 for `https`) and validated custom ports against allowlist entries.
- **Protocol-Relative and Non-HTTP Schemes**: Enforced scheme to be strictly `http` or `https`, rejecting `//attacker.com`, `javascript:`, `data:`, and `file:` URIs.
- **Open-Redirect Parameter Traversal**: Recursively inspected query parameters (`url`, `redirect`, `dest`, `target`, `next`, `goto`, `out`, `link`) to reject redirects to unapproved external destinations.

### C. `contextguard/gate.py`
- **Asynchronous Persistence Callbacks**: Wrapped SQLite database insertions (`insert_verification_result`, `insert_threat_detection`, `insert_risk_assessment`, `insert_policy_decision`, `insert_audit_record`) into deferred callback closures submitted to the audit logger queue, decoupling database write latency from policy decision latency.

### D. `tests/test_block4a_integrity.py`
- **Explicit Flush in Integrity Tests**: Inserted `logger.flush()` before inspecting raw files on disk to prevent race conditions against the 200 ms background write buffer in tamper detection tests.

### E. `tests/test_url_trust.py`
- **New Test Suite**: Added 44 comprehensive unit tests verifying resilience against URL tricks across all categories.

---

## 3. Operational Durability vs. Latency Summary
| Metric | `gate-frozen-v2` (Synchronous) | `gate-frozen-v2-perf` (Group Commit) |
| :--- | :---: | :---: |
| **Decision Latency ($p_{50}$)** | 128.46 ms | **5.64 ms** (22.8x faster) |
| **Decision Latency ($p_{95}$)** | 173.58 ms | **16.98 ms** (10.2x faster) |
| **Gate-Only Throughput (Single Domain)** | ~15 cases/s | **333.3 cases/s** |
| **Durability Window** | Immediate ($0\text{ ms}$) | Within $200\text{ ms}$ or $50\text{ entries}$ |
| **Crash Exposure (Ungraceful SIGKILL)** | $0\text{ entries}$ | Up to $49\text{ entries}$ or $200\text{ ms}$ |
| **Normal Shutdown Entry Loss** | $0\text{ entries}$ | **$0\text{ entries}$** (`flush` + `atexit`) |
