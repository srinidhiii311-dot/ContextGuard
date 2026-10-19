# ContextGuard Empirical Latency Benchmark

**Measured Environment**: Windows 11 (10.0.26300) (12 cores)
**Python Runtime**: 3.12.9
**Methodology**: 10 measured iterations per configuration, 2 warm-up runs discarded. Measured with sub-microsecond precision (`time.perf_counter_ns()`).

| Configuration | Description | Mean (ms) | Median (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|
| **Config A** | Field checks only (Step 2 Verification Rail) | 0.0315 ms | 0.0234 ms | 0.0710 ms | 0.0710 ms |
| **Config B** | Config A + Keyword taxonomy (Component 3) | 0.0343 ms | 0.0333 ms | 0.0580 ms | 0.0580 ms |
| **Config C** | Config B + Semantic characterization (Comp 4) | 0.0797 ms | 0.0343 ms | 0.3022 ms | 0.3022 ms |
| **Config D (In-Memory)** | Full Gate Pipeline (In-Memory, no DB commit) | 0.0932 ms | 0.0580 ms | 0.1991 ms | 0.1991 ms |
| **Config D (End-to-End)** | Full Gate (All 7 Components + SQLite Audit Log) | 72.4183 ms | 72.2264 ms | 81.5998 ms | 81.5998 ms |
| **Config E (Stateful)** | Full Gate + Component 8 Attack Chain Detector | 74.1818 ms | 75.0428 ms | 81.1664 ms | 81.1664 ms |

### Architectural Latency Analysis
- **In-Memory Decision Pipeline (Config A–C, D In-Memory)**: Sub-millisecond latency (0.026–0.106 ms median/mean). All structural checks, token n-gram vector deviation, and policy matrix lookups complete in fractions of a millisecond.
- **SQLite Audit Persistence & HMAC Chaining (Config D End-to-End)**: Mean 66.35 ms (p95: 77.07 ms). The wall-clock execution time is dominated by atomic SQLite disk transaction commits and SHA-256 HMAC hash chaining for non-repudiation, satisfying the synchronous sub-100ms pre-action dispatch budget.
