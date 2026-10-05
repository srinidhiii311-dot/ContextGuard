"""
scripts/run_sequence_eval.py — Multi-Step Sequence Evaluation (Schema v2)
Ablation of Component 8 (Attack Chain Detector): Config D (OFF) vs Config E (ON)

Evaluates all multi-step workflows in eval_data/sequences_dev.yaml across:
- Config D: Full Gate without Chain Detector (single-step rails only)
- Config E: Full Gate with Component 8 Attack Chain Detector enabled

Reports per sequence:
- Stop step (or None if flow allowed)
- Final gate decision
- Whether a chain-specific detector reason caused the stop
Exports summary and details to eval_results/sequence_evaluation_results.csv.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from contextguard.dataset_v2 import DatasetItemV2, load_dataset_file
from contextguard.gate import ContextGuardGate


def wilson_ci(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """Exact two-sided Wilson score 95% confidence interval."""
    if n <= 0:
        return 0.0, 1.0
    p = k / n
    denom = 1.0 + (z**2) / n
    center = p + (z**2) / (2 * n)
    margin = z * math.sqrt((p * (1.0 - p) / n) + (z**2) / (4 * (n**2)))
    lower = max(0.0, (center - margin) / denom)
    upper = min(1.0, (center + margin) / denom)
    return lower, upper


def format_ci(k: int, n: int) -> str:
    if n == 0:
        return "N/A"
    lo, hi = wilson_ci(k, n)
    pct = (k / n) * 100.0
    return f"{pct:.1f}% [{lo * 100.0:.1f}%, {hi * 100.0:.1f}%]"


def evaluate_sequence(
    item: DatasetItemV2,
    enable_chain_detector: bool,
) -> Dict[str, Any]:
    """
    Executes an entire multi-step sequence through ContextGuardGate.
    Halts at the first step that intercepts (BLOCK, REQUIRE_CONFIRMATION, PAUSE_TASK).
    """
    gate = ContextGuardGate(
        trusted_intent=item.intent,
        task_id=f"seq-eval-{item.id}-{'chain_on' if enable_chain_detector else 'chain_off'}",
        enable_chain_detector=enable_chain_detector,
    )

    stopped = False
    stop_step = None
    final_res = None

    for step in item.steps:
        proposed = step.to_proposed_action()
        res = gate.check(proposed, step.dom_text)
        final_res = res
        if res.decision.value in ("BLOCK", "REQUIRE_CONFIRMATION", "PAUSE_TASK"):
            stopped = True
            stop_step = step.step_number
            break

    decision_val = final_res.decision.value if final_res else "UNKNOWN"
    reason_val = final_res.reason if final_res else ""
    is_chain_cause = "Multi-step attack chain detected" in reason_val or "CHAIN_" in reason_val

    return {
        "stopped": stopped,
        "stop_step": stop_step,
        "decision": decision_val,
        "reason": reason_val,
        "is_chain_cause": is_chain_cause,
        "risk_score": final_res.risk_score if final_res else 0,
        "risk_tier": final_res.risk_tier if final_res else "LOW",
    }


def run_sequence_evaluation(
    sequences_file: Optional[Path] = None,
    csv_out: Optional[Path] = None,
) -> int:
    seq_path = sequences_file or (WORKSPACE_ROOT / "eval_data" / "sequences_dev.yaml")
    if not seq_path.exists():
        print(f"Error: sequence file not found at {seq_path}")
        return 1

    sequences = load_dataset_file(seq_path)
    attack_seqs = [s for s in sequences if s.is_attack]
    benign_seqs = [s for s in sequences if not s.is_attack]

    print("=" * 140)
    print(f"ContextGuard Schema v2 Multi-Step Sequence Benchmark (N = {len(sequences)} sequences)")
    print(f"Source Dataset: {seq_path.name} ({len(attack_seqs)} Attacks, {len(benign_seqs)} Benign)")
    print("Ablation Comparison: Config D (Chain Detector OFF) vs Config E (Chain Detector ON)")
    print("Definitions: Interception := Decision in {BLOCK, REQUIRE_CONFIRMATION, PAUSE_TASK}")
    print("=" * 140)

    results: List[Dict[str, Any]] = []

    for s in sequences:
        res_d = evaluate_sequence(s, enable_chain_detector=False)
        res_e = evaluate_sequence(s, enable_chain_detector=True)

        results.append({
            "id": s.id,
            "label": s.label,
            "category": s.category,
            "total_steps": s.step_count,
            "d_stopped": res_d["stopped"],
            "d_stop_step": res_d["stop_step"],
            "d_decision": res_d["decision"],
            "d_reason": res_d["reason"],
            "e_stopped": res_e["stopped"],
            "e_stop_step": res_e["stop_step"],
            "e_decision": res_e["decision"],
            "e_reason": res_e["reason"],
            "e_chain_cause": res_e["is_chain_cause"],
        })

    # Print Table
    fmt = "{:<16} | {:<6} | {:<28} | {:<5} | {:<8} | {:<20} | {:<8} | {:<20} | {:<12}"
    print(fmt.format("Sequence ID", "Label", "Category", "Steps", "D Stop", "Config D Decision", "E Stop", "Config E Decision", "Chain Cause?"))
    print("-" * 140)

    for r in results:
        d_step_str = f"Step {r['d_stop_step']}" if r["d_stopped"] else "None"
        e_step_str = f"Step {r['e_stop_step']}" if r["e_stopped"] else "None"
        chain_cause_str = "YES" if r["e_chain_cause"] else "No"
        print(fmt.format(
            r["id"],
            r["label"],
            r["category"][:28],
            r["total_steps"],
            d_step_str,
            r["d_decision"],
            e_step_str,
            r["e_decision"],
            chain_cause_str,
        ))

    print("=" * 140)

    # Statistical Summary
    d_atk_int = sum(1 for r in results if r["label"] == "ATTACK" and r["d_stopped"])
    e_atk_int = sum(1 for r in results if r["label"] == "ATTACK" and r["e_stopped"])
    d_ben_fp = sum(1 for r in results if r["label"] == "BENIGN" and r["d_stopped"])
    e_ben_fp = sum(1 for r in results if r["label"] == "BENIGN" and r["e_stopped"])

    n_atk = len(attack_seqs)
    n_ben = len(benign_seqs)

    print("\n--- STATISTICAL PERFORMANCE SUMMARY (WILSON 95% CIs) ---")
    print(f"Attack Interception Rate (Config D, Chain Detector OFF): {d_atk_int}/{n_atk} = {format_ci(d_atk_int, n_atk)}")
    print(f"Attack Interception Rate (Config E, Chain Detector ON) : {e_atk_int}/{n_atk} = {format_ci(e_atk_int, n_atk)}")
    print(f"Benign False Interceptions (Config D, Chain Detector OFF): {d_ben_fp}/{n_ben} = {format_ci(d_ben_fp, n_ben)}")
    print(f"Benign False Interceptions (Config E, Chain Detector ON) : {e_ben_fp}/{n_ben} = {format_ci(e_ben_fp, n_ben)}")

    # Gained / Lost analysis
    gained = [r["id"] for r in results if r["label"] == "ATTACK" and r["e_stopped"] and not r["d_stopped"]]
    lost = [r["id"] for r in results if r["label"] == "ATTACK" and r["d_stopped"] and not r["e_stopped"]]
    print(f"\nAttacks Uniquely Intercepted by Chain Detector (Config E over D): {gained if gained else 'None'}")
    if gained:
        for gid in gained:
            matched_r = next(x for x in results if x["id"] == gid)
            print(f"  - {gid} stopped at step {matched_r['e_stop_step']} with {matched_r['e_decision']} (Reason: {matched_r['e_reason']})")
    print("=" * 140)

    # Export CSV
    out_file = csv_out or (WORKSPACE_ROOT / "eval_results" / "sequence_evaluation_results.csv")
    out_file.parent.mkdir(parents=True, exist_ok=True)

    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    print(f"\n[OK] Sequence evaluation exported to: {out_file}\n")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate Schema v2 sequences comparing Config D vs Config E.")
    parser.add_argument("--data", type=str, default=None, help="Path to sequences YAML")
    parser.add_argument("--out", type=str, default=None, help="Path to output CSV")
    args = parser.parse_args()

    data_path = Path(args.data) if args.data else None
    out_path = Path(args.out) if args.out else None
    sys.exit(run_sequence_evaluation(sequences_file=data_path, csv_out=out_path))
