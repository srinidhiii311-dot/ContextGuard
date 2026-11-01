"""
harness/concurrency_bench.py — Multi-Session Concurrency Benchmark (Block 4a)

Evaluates gate safety, thread isolation, and throughput across N parallel sessions (1, 10, 50 workers).
Measures:
- Throughput (actions / second)
- p50 and p95 latency (ms)
- Decision parity against sequential run (detects race conditions or decision drift)
"""

from __future__ import annotations

import concurrent.futures
import json
import math
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from gateway.loader import Gateway
from harness.case_schema import EvaluationCase
from harness.run_case import build_trusted_intent_from_dict
from contextguard.gate import ProposedAction

ATTACKS_DEV = ROOT_DIR / "attacks" / "dev" / "cases.jsonl"
BENIGN_DEV = ROOT_DIR / "benign" / "dev" / "cases.jsonl"


def load_benchmark_cases(limit: Optional[int] = 500) -> List[EvaluationCase]:
    """Loads a balanced sample of attack and benign cases across domains for concurrency testing (default: 500+ cases)."""
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


def evaluate_single_case(
    case: EvaluationCase,
    session_id: str,
    audit_log_path: Optional[str] = None,
) -> Tuple[str, str, float]:
    """
    Evaluates one case through its own session on a domain gateway.
    Returns: (case_id, decision_str, latency_ms)
    """
    intent = build_trusted_intent_from_dict(case.domain, case.locked_intent)
    gw = Gateway.from_domain(
        case.domain,
        trusted_intent=intent,
        task_id=session_id,
        audit_log_path=audit_log_path,
    )
    p_act = ProposedAction(
        action_type=case.proposed_action.action_type,
        target=case.proposed_action.target,
        value=case.proposed_action.value,
        page_url=case.proposed_action.page_url,
        raw_html=case.page_state.raw_html,
        session_id=session_id,
        task_id=session_id,
    )
    t0 = time.perf_counter()
    res = gw.check(p_act, current_dom_text=case.page_state.visible_text)
    latency_ms = (time.perf_counter() - t0) * 1000.0
    return case.case_id, res.decision.value, latency_ms


def run_sequential_baseline(cases: List[EvaluationCase]) -> Tuple[Dict[str, str], List[float]]:
    """Runs cases sequentially as reference ground truth."""
    decisions = {}
    latencies = []
    for idx, c in enumerate(cases):
        sess_id = f"seq_sess_{idx}"
        cid, dec, lat = evaluate_single_case(c, sess_id)
        decisions[cid] = dec
        latencies.append(lat)
    return decisions, latencies


def run_parallel_tier(
    cases: List[EvaluationCase],
    num_workers: int,
    seq_decisions: Dict[str, str],
    audit_log_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes all cases using a thread pool of num_workers concurrent sessions.
    Compares decisions to the sequential run.
    """
    latencies: List[float] = []
    parallel_decisions: Dict[str, str] = {}
    differing_decisions: List[Dict[str, Any]] = []

    t_start = time.perf_counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = {}
        for idx, case in enumerate(cases):
            sess_id = f"par_{num_workers}_sess_{idx % num_workers}_{idx}"
            fut = executor.submit(evaluate_single_case, case, sess_id, audit_log_path)
            futures[fut] = case

        for fut in concurrent.futures.as_completed(futures):
            case = futures[fut]
            cid, dec, lat = fut.result()
            latencies.append(lat)
            parallel_decisions[cid] = dec

            expected_dec = seq_decisions.get(cid)
            if dec != expected_dec:
                differing_decisions.append({
                    "case_id": cid,
                    "domain": case.domain,
                    "expected": expected_dec,
                    "actual": dec,
                })

    elapsed_s = time.perf_counter() - t_start
    throughput = len(cases) / elapsed_s if elapsed_s > 0 else 0.0

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
        "differing_decisions": differing_decisions,
    }


def run_concurrency_benchmarks(
    cases: Optional[List[EvaluationCase]] = None,
    audit_log_path: Optional[str] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """Runs 1, 10, and 50 concurrent session tiers with at least 500 cases and prints the results."""
    test_cases = cases or load_benchmark_cases(limit=limit)
    print(f"Loaded {len(test_cases)} benchmark cases across 5 domains.")

    # 1. Sequential run
    print("Running sequential baseline...")
    seq_decisions, _ = run_sequential_baseline(test_cases)

    # 2. Parallel tiers (1, 10, 50)
    results = {}
    for n in [1, 10, 50]:
        print(f"Running concurrency tier N={n}...")
        tier_res = run_parallel_tier(test_cases, n, seq_decisions, audit_log_path=audit_log_path)
        results[f"tier_{n}"] = tier_res

    print("\n" + "=" * 80)
    print("                CONTEXTGUARD CONCURRENCY BENCHMARK RESULTS")
    print("=" * 80)
    print(f"{'CONCURRENCY':<12} | {'CASES':<8} | {'THROUGHPUT':<14} | {'P50 LATENCY':<14} | {'P95 LATENCY':<14} | {'DIFFS'}")
    print("-" * 80)

    for n in [1, 10, 50]:
        r = results[f"tier_{n}"]
        th_str = f"{r['throughput_ops_per_sec']} op/s"
        p50_str = f"{r['p50_latency_ms']} ms"
        p95_str = f"{r['p95_latency_ms']} ms"
        diff_str = f"{r['differing_decisions_count']} (0 drift)" if r['differing_decisions_count'] == 0 else f"FAIL ({r['differing_decisions_count']})"
        print(f"{n:<12} | {r['total_cases']:<8} | {th_str:<14} | {p50_str:<14} | {p95_str:<14} | {diff_str}")

    print("=" * 80 + "\n")
    return results


if __name__ == "__main__":
    run_concurrency_benchmarks()

