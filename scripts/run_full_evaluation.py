"""
scripts/run_full_evaluation.py — Comprehensive Multi-Run Benchmark Harness for TC-1 to TC-8

Runs each of the 8 testbed scenarios multiple times (e.g., 3 runs per scenario),
collecting:
  - Risk score
  - Decision
  - Detection step
  - Ground Truth & Classification (TP, TN, FP, FN)
  - Latency (ms)
  - Primary Evidence / Reason
  - Final task result

Outputs a rich markdown summary and JSON artifact with aggregate metrics.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# Windows terminal UTF-8 handling
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

PYTHON_EXE = sys.executable

SCENARIO_ORDER = [
    "baseline",               # TC-1: Safe Baseline Flight Booking
    "prompt_injection",       # TC-2: Visible Adversarial Prompt Injection
    "unexpected_navigation",   # TC-3: External Untrusted Navigation
    "goal_deviation",         # TC-4: Contextual Goal Deviation
    "malicious_page_content", # TC-5: Malicious Page Advisory
    "suspicious_form",        # TC-6: Tampered / Injected Form Fields
    "unauthorized_action",    # TC-7: Unauthorized Action / Direct Checkout
    "redirect_scenario",      # TC-8: Multi-Hop Redirect Scenario
]

SCENARIO_TITLES = {
    "baseline": "TC-1 Baseline (Safe)",
    "prompt_injection": "TC-2 Prompt Injection",
    "unexpected_navigation": "TC-3 Unexpected Navigation",
    "goal_deviation": "TC-4 Goal Deviation",
    "malicious_page_content": "TC-5 Malicious Content",
    "suspicious_form": "TC-6 Suspicious Form",
    "unauthorized_action": "TC-7 Unauthorized Action",
    "redirect_scenario": "TC-8 Redirect Scenario",
}


def run_single_session(
    scenario_id: str,
    run_idx: int,
    speed: float = 0.05,
    slowmo: int = 0,
    headless: bool = True,
) -> Dict[str, Any]:
    """
    Executes a single test session via run_agent_session.py, parses output and database,
    and returns full empirical evaluation metrics.
    """
    cmd = [
        PYTHON_EXE,
        "-u",
        str(ROOT_DIR / "run_agent_session.py"),
        "--scenario", scenario_id,
        "--speed", str(speed),
        "--slowmo", str(slowmo),
    ]
    if headless:
        cmd.append("--headless")

    t_start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    duration_s = time.perf_counter() - t_start

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    # Extract session ID from stdout
    session_id = ""
    for line in stdout.splitlines():
        if "Session ID :" in line:
            session_id = line.split("Session ID :")[-1].strip()
            break

    if not session_id:
        # Fallback: query latest session from DB
        try:
            from backend.database.db import get_conn
            conn = get_conn()
            row = conn.execute("SELECT session_id FROM sessions ORDER BY rowid DESC LIMIT 1").fetchone()
            conn.close()
            if row:
                session_id = row["session_id"]
        except Exception:
            pass

    # Query EvaluationDAO for empirical comparison
    from backend.database.db import EvaluationDAO, ContextGuardRuntimeDAO
    eval_data = EvaluationDAO.get_session_evaluation(session_id) if session_id else {}
    audit_data = ContextGuardRuntimeDAO.get_session_audit_trail(session_id) if session_id else {}

    decisions = audit_data.get("decisions", [])
    predictions = audit_data.get("predictions", [])
    states = audit_data.get("states", [])

    # Extract primary evidence and decision
    primary_decision = "ALLOW"
    primary_evidence = "Within normal baseline parameters"
    detection_step = len(states) if states else 1

    for d in decisions:
        dec = d.get("decision", "ALLOW")
        if dec in ("BLOCK", "PAUSE", "WARN"):
            primary_decision = dec
            primary_evidence = d.get("reason", "")
            detection_step = d.get("step_number", detection_step)
            break

    # Determine peak risk score
    max_risk = eval_data.get("max_risk_score", 0)
    for p in predictions:
        r = p.get("risk_score", 0)
        if r > max_risk:
            max_risk = r
    for d in decisions:
        r = d.get("risk_score", 0)
        if r > max_risk:
            max_risk = r

    # Determine final outcome
    session_info = audit_data.get("session", {})
    status = session_info.get("status", "UNKNOWN")
    final_result = "SUCCESS_COMPLETED" if status == "COMPLETED" else f"HALTED ({status})"
    if "PAUSED" in stdout:
        final_result = "PAUSED_FOR_OPERATOR_VERIFICATION"
    elif "BLOCKED" in stdout:
        final_result = "BLOCKED_BY_PRE_ACTION_GATE"
    elif "HALTED" in stdout:
        final_result = "HALTED_BY_POST_ACTION_ENGINE"
    elif "Booking confirmed" in stdout:
        final_result = "SUCCESS_COMPLETED"

    classification = eval_data.get("classification", "UNKNOWN")
    latency_ms = eval_data.get("latency", {}).get("mean_ms", round(duration_s * 1000 / max(1, len(states)), 2))

    return {
        "scenario_id": scenario_id,
        "scenario_title": SCENARIO_TITLES.get(scenario_id, scenario_id),
        "run_index": run_idx,
        "session_id": session_id,
        "ground_truth": eval_data.get("ground_truth_meaning", "Unknown"),
        "classification": classification,
        "peak_risk_score": max_risk,
        "decision": primary_decision,
        "detection_step": detection_step,
        "latency_ms": round(latency_ms, 2),
        "primary_evidence": primary_evidence,
        "final_task_result": final_result,
        "total_steps": len(states),
        "duration_sec": round(duration_s, 2),
    }


def run_benchmark(runs_per_scenario: int = 3) -> Dict[str, Any]:
    print("=" * 80)
    print(f"  CONTEXTGUARD EXPERIMENTAL BENCHMARK HARNESS")
    print(f"  Scenarios: {len(SCENARIO_ORDER)} | Runs per Scenario: {runs_per_scenario} | Total Runs: {len(SCENARIO_ORDER) * runs_per_scenario}")
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print("=" * 80)

    all_results: List[Dict[str, Any]] = []
    summary_by_scenario: Dict[str, Dict[str, Any]] = {}

    for sc_idx, sc_id in enumerate(SCENARIO_ORDER, 1):
        title = SCENARIO_TITLES.get(sc_id, sc_id)
        print(f"\n[{sc_idx}/{len(SCENARIO_ORDER)}] Running {title} ({sc_id})...")
        sc_runs: List[Dict[str, Any]] = []

        for r in range(1, runs_per_scenario + 1):
            sys.stdout.write(f"    Run {r}/{runs_per_scenario} ... ")
            sys.stdout.flush()

            res = run_single_session(sc_id, r, speed=0.05, slowmo=0, headless=True)
            sc_runs.append(res)
            all_results.append(res)

            print(f"Outcome: {res['final_task_result']} | Dec: {res['decision']} | Peak Risk: {res['peak_risk_score']}/100 | Class: {res['classification']} | Latency: {res['latency_ms']}ms")

        # Aggregate for this scenario
        tp_count = sum(1 for x in sc_runs if x["classification"] == "TRUE_POSITIVE")
        tn_count = sum(1 for x in sc_runs if x["classification"] == "TRUE_NEGATIVE")
        fp_count = sum(1 for x in sc_runs if x["classification"] == "FALSE_POSITIVE")
        fn_count = sum(1 for x in sc_runs if x["classification"] == "FALSE_NEGATIVE")
        avg_risk = sum(x["peak_risk_score"] for x in sc_runs) / len(sc_runs)
        avg_lat = sum(x["latency_ms"] for x in sc_runs) / len(sc_runs)

        is_adversarial = sc_id != "baseline"
        if is_adversarial:
            accuracy = (tp_count / len(sc_runs)) * 100
        else:
            accuracy = (tn_count / len(sc_runs)) * 100

        summary_by_scenario[sc_id] = {
            "title": title,
            "category": "BENIGN" if not is_adversarial else "ADVERSARIAL",
            "runs": len(sc_runs),
            "accuracy_pct": round(accuracy, 1),
            "tp": tp_count,
            "tn": tn_count,
            "fp": fp_count,
            "fn": fn_count,
            "avg_peak_risk": round(avg_risk, 1),
            "avg_latency_ms": round(avg_lat, 2),
            "sample_evidence": sc_runs[0]["primary_evidence"],
            "sample_detection_step": sc_runs[0]["detection_step"],
            "sample_decision": sc_runs[0]["decision"],
            "sample_result": sc_runs[0]["final_task_result"],
        }

    # Overall Metrics
    total_runs = len(all_results)
    total_tp = sum(1 for x in all_results if x["classification"] == "TRUE_POSITIVE")
    total_tn = sum(1 for x in all_results if x["classification"] == "TRUE_NEGATIVE")
    total_fp = sum(1 for x in all_results if x["classification"] == "FALSE_POSITIVE")
    total_fn = sum(1 for x in all_results if x["classification"] == "FALSE_NEGATIVE")

    total_adversarial = total_tp + total_fn
    total_benign = total_tn + total_fp

    tpr = (total_tp / total_adversarial * 100) if total_adversarial else 100.0
    fpr = (total_fp / total_benign * 100) if total_benign else 0.0
    fnr = (total_fn / total_adversarial * 100) if total_adversarial else 0.0
    overall_acc = ((total_tp + total_tn) / total_runs * 100) if total_runs else 100.0
    overall_latency = sum(x["latency_ms"] for x in all_results) / total_runs if total_runs else 0.0

    benchmark_summary = {
        "timestamp": datetime.now().isoformat(),
        "total_runs": total_runs,
        "runs_per_scenario": runs_per_scenario,
        "overall_accuracy_pct": round(overall_acc, 2),
        "true_positive_rate_pct": round(tpr, 2),
        "false_positive_rate_pct": round(fpr, 2),
        "false_negative_rate_pct": round(fnr, 2),
        "mean_inspection_latency_ms": round(overall_latency, 2),
        "counts": {
            "TP": total_tp,
            "TN": total_tn,
            "FP": total_fp,
            "FN": total_fn,
        },
        "scenario_summary": summary_by_scenario,
        "raw_results": all_results,
    }

    # Save to disk
    out_dir = ROOT_DIR / "eval_results"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"benchmark_results_{int(time.time())}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_summary, f, indent=2)

    latest_path = out_dir / "latest_benchmark_results.json"
    with open(latest_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_summary, f, indent=2)

    print("\n" + "=" * 80)
    print(f"  BENCHMARK COMPLETE — OVERALL ACCURACY: {overall_acc:.1f}%")
    print(f"  TP: {total_tp} | TN: {total_tn} | FP: {total_fp} | FN: {total_fn}")
    print(f"  True Positive Rate (TPR): {tpr:.1f}% | False Positive Rate (FPR): {fpr:.1f}%")
    print(f"  Mean Inspection Latency: {overall_latency:.2f} ms")
    print(f"  Saved to: {out_path}")
    print("=" * 80)

    return benchmark_summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ContextGuard Benchmark Harness")
    parser.add_argument("--runs", type=int, default=3, help="Number of repetitions per test case scenario")
    args = parser.parse_args()

    run_benchmark(runs_per_scenario=args.runs)
