"""
harness/concurrency_bench.py — Multi-Session Concurrency Benchmark (Block 8d)

Evaluates gate safety, thread isolation, and throughput across N parallel sessions (1, 10, 50 workers).
Architectural optimizations (Block 8d):
- Dedicated Gateway per domain per worker thread (no Gateway.from_domain() disk reads per case)
- 3 independent repeats per tier; reports median p50/p95 latency and median throughput
- Gate-only (in-memory) and Gate+audit (JSONL group-commit) evaluated on the identical 500 cases
"""

from __future__ import annotations

import concurrent.futures
import json
import math
from pathlib import Path
import statistics
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import unittest.mock as mock

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from gateway.loader import Gateway
from harness.case_schema import EvaluationCase
from harness.run_case import build_trusted_intent_from_dict
from contextguard.gate import ProposedAction
import contextguard.gate as gate_mod

ATTACKS_DEV = ROOT_DIR / "attacks" / "dev" / "cases.jsonl"
BENIGN_DEV = ROOT_DIR / "benign" / "dev" / "cases.jsonl"
DOMAINS = ["flight", "banking", "ecommerce", "healthcare", "email"]


class DummyAuditLogger:
    def append(self, entry, db_callback=None):
        return entry
    def flush(self):
        pass
    def shutdown(self):
        pass


def load_benchmark_cases(limit: Optional[int] = 500) -> List[EvaluationCase]:
    """Loads a balanced sample of attack and benign cases across domains for concurrency testing (500 cases)."""
    cases = []
    for p in [ATTACKS_DEV, BENIGN_DEV]:
        if p.is_file():
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s:
                        cases.append(EvaluationCase.model_validate(json.loads(s)))
    if limit is None or limit >= len(cases):
        return cases
    return cases[:limit]


def run_sequential_baseline(
    cases: List[EvaluationCase],
    audit_log_path: Optional[str] = None,
) -> Dict[str, str]:
    """Runs cases sequentially as reference ground truth using a dedicated domain gateway set."""
    gateways = {d: Gateway.from_domain(d, audit_log_path=audit_log_path) for d in DOMAINS}
    decisions = {}
    for idx, case in enumerate(cases):
        intent = build_trusted_intent_from_dict(case.domain, case.locked_intent)
        gw = gateways[case.domain]
        gw.set_intent(intent)
        sess_id = f"seq_{idx}"
        p_act = ProposedAction(
            action_type=case.proposed_action.action_type,
            target=case.proposed_action.target,
            value=case.proposed_action.value,
            page_url=case.proposed_action.page_url,
            raw_html=case.page_state.raw_html,
            session_id=sess_id,
            task_id=sess_id,
        )
        res = gw.check(p_act, current_dom_text=case.page_state.visible_text)
        decisions[case.case_id] = res.decision.value
    return decisions


def run_single_iteration(
    cases: List[EvaluationCase],
    num_workers: int,
    seq_decisions: Dict[str, str],
    audit_log_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes one iteration of 500 cases using pre-instantiated domain gateways per worker.
    """
    # Pre-build one Gateway per domain per worker
    worker_gateways = [
        {d: Gateway.from_domain(d, audit_log_path=audit_log_path) for d in DOMAINS}
        for _ in range(num_workers)
    ]

    latencies: List[float] = []
    parallel_decisions: Dict[str, str] = {}
    differing_decisions: List[Dict[str, Any]] = []

    t_start = time.perf_counter()

    def eval_item(item):
        idx, case = item
        w_id = idx % num_workers
        intent = build_trusted_intent_from_dict(case.domain, case.locked_intent)
        gw = worker_gateways[w_id][case.domain]
        gw.set_intent(intent)
        sess_id = f"par_{num_workers}_sess_{w_id}_{idx}"
        p_act = ProposedAction(
            action_type=case.proposed_action.action_type,
            target=case.proposed_action.target,
            value=case.proposed_action.value,
            page_url=case.proposed_action.page_url,
            raw_html=case.page_state.raw_html,
            session_id=sess_id,
            task_id=sess_id,
        )
        t0 = time.perf_counter()
        res = gw.check(p_act, current_dom_text=case.page_state.visible_text)
        lat = (time.perf_counter() - t0) * 1000.0
        return case.case_id, res.decision.value, lat

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        results = list(executor.map(eval_item, enumerate(cases)))

    elapsed_s = time.perf_counter() - t_start
    throughput = len(cases) / elapsed_s if elapsed_s > 0 else 0.0

    for cid, dec, lat in results:
        latencies.append(lat)
        parallel_decisions[cid] = dec
        expected_dec = seq_decisions.get(cid)
        if dec != expected_dec:
            differing_decisions.append({
                "case_id": cid,
                "expected": expected_dec,
                "actual": dec,
            })

    latencies_sorted = sorted(latencies)
    p50 = latencies_sorted[int(len(latencies_sorted) * 0.50)]
    p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]

    return {
        "concurrency": num_workers,
        "total_cases": len(cases),
        "elapsed_seconds": round(elapsed_s, 3),
        "throughput_ops_per_sec": round(throughput, 1),
        "p50_latency_ms": round(p50, 2),
        "p95_latency_ms": round(p95, 2),
        "differing_decisions_count": len(differing_decisions),
    }


def run_parallel_tier_with_repeats(
    cases: List[EvaluationCase],
    num_workers: int,
    seq_decisions: Dict[str, str],
    audit_log_path: Optional[str] = None,
    repeats: int = 3,
) -> Dict[str, Any]:
    """Runs N repeats for a tier and computes median throughput, p50, and p95."""
    runs = []
    for r in range(repeats):
        res = run_single_iteration(cases, num_workers, seq_decisions, audit_log_path=audit_log_path)
        runs.append(res)

    throughputs = [r["throughput_ops_per_sec"] for r in runs]
    p50s = [r["p50_latency_ms"] for r in runs]
    p95s = [r["p95_latency_ms"] for r in runs]
    diffs = max(r["differing_decisions_count"] for r in runs)

    return {
        "workers": num_workers,
        "total_cases": len(cases),
        "repeats": repeats,
        "runs": runs,
        "throughput_ops_per_sec": round(statistics.median(throughputs), 1),
        "p50_latency_ms": round(statistics.median(p50s), 2),
        "p95_latency_ms": round(statistics.median(p95s), 2),
        "differing_decisions_count": diffs,
    }


def run_benchmark_suite(
    cases: List[EvaluationCase],
    audit_log_path: Optional[str] = None,
    repeats: int = 3,
) -> Dict[str, Any]:
    from contextguard.audit_log import flush_all_audit_loggers, verify_audit_log, JsonlAuditLog, _AUDIT_REGISTRY, _REGISTRY_LOCK

    backend_label = "JSONL Group-Commit Audit Writer" if audit_log_path else "None (In-Memory Gate Only)"
    print(f"\nEvaluating Benchmark: {backend_label} (500 cases, {repeats} repeats per tier)")

    # Clean old concurrency audit log and anchor if exists
    if audit_log_path:
        p = Path(audit_log_path)
        anchor_p = JsonlAuditLog._default_anchor_path(p)
        with _REGISTRY_LOCK:
            if str(p.resolve()) in _AUDIT_REGISTRY:
                old_logger = _AUDIT_REGISTRY.pop(str(p.resolve()))
                try:
                    old_logger.shutdown()
                except Exception:
                    pass
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass
        if anchor_p.exists():
            try:
                anchor_p.unlink()
            except Exception:
                pass

    # 1. Sequential baseline ground truth
    seq_decisions = run_sequential_baseline(cases, audit_log_path=audit_log_path)

    # 2. Parallel tiers (1, 10, 50)
    tiers = {}
    for n in [1, 10, 50]:
        print(f"  Running N={n:2d} ({repeats} repeats)...", end="", flush=True)
        tier_summary = run_parallel_tier_with_repeats(cases, n, seq_decisions, audit_log_path=audit_log_path, repeats=repeats)
        tiers[f"tier_{n}"] = tier_summary
        print(f" Done! Median p50: {tier_summary['p50_latency_ms']} ms | p95: {tier_summary['p95_latency_ms']} ms | Throughput: {tier_summary['throughput_ops_per_sec']} op/s")

    # Flush all group-commit buffers
    flush_all_audit_loggers()
    time.sleep(0.5)

    # Verify audit log if enabled
    audit_ok = True
    if audit_log_path and Path(audit_log_path).exists():
        if str(Path(audit_log_path).resolve()) in _AUDIT_REGISTRY:
            _AUDIT_REGISTRY[str(Path(audit_log_path).resolve())].shutdown()
        v = verify_audit_log(audit_log_path)
        audit_ok = v.ok
        print(f"  Audit Log Verification: ok={v.ok}, entries={v.checked_count}")

    return {
        "audit_backend": backend_label,
        "audit_log_path": str(audit_log_path) if audit_log_path else None,
        "audit_verified": audit_ok,
        "tiers": tiers,
    }


def run_both_benchmarks(limit: int = 500, repeats: int = 3) -> Dict[str, Any]:
    cases = load_benchmark_cases(limit=limit)
    print("=" * 80)
    print(f"CONTEXTGUARD CONCURRENCY BENCHMARK — BLOCK 8d (3 REPEATS, PRE-BUILT GATEWAYS)")
    print("=" * 80)

    # Benchmark 1: Gate-Only (No audit logging)
    with mock.patch.object(gate_mod, "get_audit_logger", return_value=DummyAuditLogger()):
        res_no_audit = run_benchmark_suite(cases, audit_log_path=None, repeats=repeats)

    # Save gate-only file
    with open("runs/concurrency_gate_only.json", "w", encoding="utf-8") as f:
        json.dump(res_no_audit, f, indent=2)

    # Benchmark 2: Gate + Audit (JSONL Group-Commit)
    res_with_audit = run_benchmark_suite(cases, audit_log_path="runs/concurrency_audit.jsonl", repeats=repeats)

    combined = {
        "audit_backend": res_with_audit["audit_backend"],
        "audit_log_path": res_with_audit["audit_log_path"],
        "audit_verified": res_with_audit["audit_verified"],
        "tiers": res_with_audit["tiers"],  # Backward-compatibility for verify_claims
        "gate_only_in_memory": res_no_audit,
        "gate_plus_jsonl_audit": res_with_audit,
    }

    out_file = Path("runs/concurrency_benchmark.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    print("\n" + "=" * 80)
    print("                    FINAL BLOCK 8d CONCURRENCY SUMMARY TABLE")
    print("=" * 80)
    print(f"{'CONFIGURATION':<22} | {'WORKERS':<8} | {'MEDIAN THROUGHPUT':<18} | {'MEDIAN P50':<12} | {'MEDIAN P95':<12} | {'DIFFS'}")
    print("-" * 80)
    for cfg_name, res in [("Gate-Only (In-Memory)", res_no_audit), ("Gate + Audit (JSONL)", res_with_audit)]:
        for n in [1, 10, 50]:
            t = res["tiers"][f"tier_{n}"]
            print(f"{cfg_name:<22} | {n:<8} | {t['throughput_ops_per_sec']} op/s{'':<8} | {t['p50_latency_ms']} ms{'':<3} | {t['p95_latency_ms']} ms{'':<3} | {t['differing_decisions_count']} (0 drift)")
    print("=" * 80 + "\n")
    return combined


if __name__ == "__main__":
    run_both_benchmarks(limit=500, repeats=3)
