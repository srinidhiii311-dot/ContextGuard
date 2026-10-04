"""
scripts/run_dataset_ablation.py — Comprehensive Benchmark & Component Ablation on Combined Dataset

Loads:
- eval_data/attacks.yaml (34 distinct attack payloads, 18 evasion + 16 taxonomy)
- eval_data/benign.yaml  (32 distinct benign tasks across booking lifecycle)

Methodological Standards:
- Distinct Items Evaluation: Runs each item once (repeatable if stochastic).
- Strict Interception Definition:
    interception := decision in {BLOCK, REQUIRE_CONFIRMATION, PAUSE_TASK}
    ALLOW_WITH_FLAG is reported separately as 'flagged only'.
- Exact two-sided 95% Wilson Score Confidence Intervals computed over distinct items.
- Component Ablation (A/B/C/D) across all 66 items.
- Detailed exports to CSV in eval_results/.
"""

from __future__ import annotations

import argparse
import csv
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# Add workspace root to sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from contextguard.gate import ContextGuardGate, ProposedAction, TrustedIntent
from scripts.stats import format_ci, wilson


def load_datasets(benign_path: Optional[str] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    attacks_file = WORKSPACE_ROOT / "eval_data" / "attacks.yaml"
    ben_file = Path(benign_path) if benign_path else (WORKSPACE_ROOT / "eval_data" / "benign.yaml")
    if not ben_file.exists():
        ben_file = WORKSPACE_ROOT / "eval_data" / "benign_original.yaml"

    if not attacks_file.exists() or not ben_file.exists():
        raise FileNotFoundError(f"Benchmark dataset files missing: {attacks_file} or {ben_file}")

    attacks = yaml.safe_load(attacks_file.read_text(encoding="utf-8"))
    benign = yaml.safe_load(ben_file.read_text(encoding="utf-8"))
    return attacks, benign


def make_proposed_action(item: Dict[str, Any]) -> ProposedAction:
    act_data = item["action"]
    return ProposedAction(
        action_type=act_data["action_type"],
        target=act_data["target"],
        value=act_data.get("value"),
        page_url=act_data.get("page_url", f"http://127.0.0.1:8000/{item.get('page', 'search')}"),
    )


def evaluate_ablation_step(
    config_key: str,
    gate: ContextGuardGate,
    action: ProposedAction,
    dom_text: str,
) -> Tuple[bool, bool, str, float]:
    """
    Evaluates proposed action under an ablation configuration.
    Returns: (is_intercepted, is_flagged_only, decision_str, latency_ms)
    """
    t0 = time.perf_counter_ns()

    if config_key == "A":
        # Config A: Field checks only (Step 2 Verification Rail)
        model_action = action.to_model()
        locked_intent = gate.trusted_intent.to_locked_intent()
        report = gate._verifier.verify(locked_intent, model_action, dom_text)
        field_violations = [
            inc for inc in report.inconsistencies
            if inc.check_type in ("FIELD_MISMATCH", "NAVIGATION_BOUNDARY")
        ]
        lat = (time.perf_counter_ns() - t0) / 1_000_000.0
        intercepted = len(field_violations) > 0
        decision = "BLOCK" if intercepted else "ALLOW"
        flagged_only = False
        return intercepted, flagged_only, decision, lat

    elif config_key == "B":
        # Config B: Config A + Keyword Taxonomy (Component 3)
        model_action = action.to_model()
        locked_intent = gate.trusted_intent.to_locked_intent()
        report = gate._verifier.verify(locked_intent, model_action, dom_text)
        field_violations = [
            inc for inc in report.inconsistencies
            if inc.check_type in ("FIELD_MISMATCH", "NAVIGATION_BOUNDARY")
        ]
        detection = gate._detector.detect(
            consistency_report=report,
            dom_text=dom_text,
            justification_text=action.source_text,
            action_target=action.target,
            action_type=action.action_type,
        )
        keyword_hit = (
            detection.is_threat
            and detection.confidence >= gate._detector.confidence_threshold
            and detection.attack_type is not None
        )
        lat = (time.perf_counter_ns() - t0) / 1_000_000.0
        intercepted = len(field_violations) > 0 or keyword_hit
        decision = "BLOCK" if intercepted else "ALLOW"
        flagged_only = False
        return intercepted, flagged_only, decision, lat

    elif config_key == "C":
        # Config C: Config B + Component 4 Semantic Deviation Characterization
        model_action = action.to_model()
        locked_intent = gate.trusted_intent.to_locked_intent()
        report = gate._verifier.verify(locked_intent, model_action, dom_text)
        field_violations = [
            inc for inc in report.inconsistencies
            if inc.check_type in ("FIELD_MISMATCH", "NAVIGATION_BOUNDARY")
        ]
        pipe_res = gate._run_threat_pipeline(report, dom_text, action)
        c4_hit = pipe_res.is_threat and (
            pipe_res.characterization_label is not None
            or (pipe_res.confidence >= gate._detector.confidence_threshold and pipe_res.attack_type is not None)
        )
        marker_hit = any(inc.check_type in ("INJECTION_MARKER", "PROCESS_INTEGRITY") for inc in report.inconsistencies)
        lat = (time.perf_counter_ns() - t0) / 1_000_000.0
        intercepted = len(field_violations) > 0 or c4_hit or marker_hit
        decision = "BLOCK" if intercepted else "ALLOW"
        flagged_only = False
        return intercepted, flagged_only, decision, lat

    elif config_key == "D":
        # Config D: Full Gate (all 7 components + ML Risk Engine + Declarative Policy Matrix)
        res = gate.check(action, dom_text)
        lat = (time.perf_counter_ns() - t0) / 1_000_000.0
        intercepted = res.decision.value in ("BLOCK", "REQUIRE_CONFIRMATION", "PAUSE_TASK")
        flagged_only = res.decision.value in ("ALLOW_WITH_FLAG", "FLAG")
        return intercepted, flagged_only, res.decision.value, lat

    else:
        # Config E: Config D + Attack Chain Detector (Component 8 Stateful Defense)
        gate.enable_chain_detector = True
        if gate._chain_detector is None:
            from contextguard.chain_detector import ChainDetector
            gate._chain_detector = ChainDetector(db_path=":memory:")
        res = gate.check(action, dom_text)
        lat = (time.perf_counter_ns() - t0) / 1_000_000.0
        intercepted = res.decision.value in ("BLOCK", "REQUIRE_CONFIRMATION", "PAUSE_TASK")
        flagged_only = res.decision.value in ("ALLOW_WITH_FLAG", "FLAG")
        return intercepted, flagged_only, res.decision.value, lat



def run_benchmark_and_ablation(
    csv_ablation_path: Optional[str] = None,
    csv_details_path: Optional[str] = None,
    benign_file: Optional[str] = None,
):
    attacks, benign = load_datasets(benign_path=benign_file)

    n_attacks = len(attacks)
    n_benign = len(benign)
    n_total = n_attacks + n_benign

    print("=" * 135)
    print("ContextGuard Benchmark Evaluation on Combined Dataset")
    print(f"Total Items: {n_total} distinct items ({n_attacks} Attacks, {n_benign} Benign tasks)")
    print(f"Benign Dataset Source: {benign_file or 'eval_data/benign_original.yaml (or benign.yaml)'}")
    print("Evaluation Protocol: 1 run per distinct item. Deterministic items evaluated over distinct task distribution.")
    print("Definitions: Interception := {BLOCK, REQUIRE_CONFIRMATION, PAUSE_TASK} | 'flagged only' := {ALLOW_WITH_FLAG}")
    print("Statistical Inference: Exact Two-Sided Wilson 95% Confidence Intervals [lower, upper]")
    print("=" * 135)

    intent_yaml = WORKSPACE_ROOT / "eval_data" / "default_intent.yaml"
    if intent_yaml.exists():
        intent_dict = yaml.safe_load(intent_yaml.read_text(encoding="utf-8"))
        trusted_intent = TrustedIntent.from_dict(intent_dict)
    else:
        trusted_intent = TrustedIntent(
            origin="Chennai",
            destination="Delhi",
            cabin_class="Economy",
            passenger_count=1,
        )

    # 1. Full Gate (Config D) Individual Item Evaluation
    detailed_results: List[Dict[str, Any]] = []

    # Evaluate Attacks
    for item in attacks:
        action = make_proposed_action(item)
        gate = ContextGuardGate(trusted_intent=trusted_intent, task_id=f"eval-{item['id']}")
        t0 = time.perf_counter_ns()
        res = gate.check(action, item["dom_text"])
        lat = (time.perf_counter_ns() - t0) / 1_000_000.0

        is_int = res.decision.value in ("BLOCK", "REQUIRE_CONFIRMATION", "PAUSE_TASK")
        is_flg = res.decision.value in ("ALLOW_WITH_FLAG", "FLAG")

        detailed_results.append({
            "id": item["id"],
            "name": item["name"],
            "dataset": "ATTACK",
            "category": item["category"],
            "evades_taxonomy": item.get("evades_taxonomy", False),
            "action": f"{action.action_type} {action.target} {action.value or ''}".strip(),
            "decision": res.decision.value,
            "intercepted": is_int,
            "flagged_only": is_flg,
            "clean_allowed": res.decision.value == "ALLOW",
            "risk_score": res.risk_score,
            "characterization_label": res.characterization_label,
            "deviation_signal": res.deviation_signal,
            "latency_ms": lat,
        })

    # Evaluate Benign
    for item in benign:
        action = make_proposed_action(item)
        gate = ContextGuardGate(trusted_intent=trusted_intent, task_id=f"eval-{item['id']}")
        t0 = time.perf_counter_ns()
        res = gate.check(action, item["dom_text"])
        lat = (time.perf_counter_ns() - t0) / 1_000_000.0

        is_int = res.decision.value in ("BLOCK", "REQUIRE_CONFIRMATION", "PAUSE_TASK")
        is_flg = res.decision.value in ("ALLOW_WITH_FLAG", "FLAG")

        detailed_results.append({
            "id": item["id"],
            "name": item["name"],
            "dataset": "BENIGN",
            "category": item["category"],
            "evades_taxonomy": False,
            "action": f"{action.action_type} {action.target} {action.value or ''}".strip(),
            "decision": res.decision.value,
            "intercepted": is_int,
            "flagged_only": is_flg,
            "clean_allowed": res.decision.value == "ALLOW",
            "risk_score": res.risk_score,
            "characterization_label": res.characterization_label,
            "deviation_signal": res.deviation_signal,
            "latency_ms": lat,
        })

    # 2. Performance Breakdown on Distinct Items
    attack_res = [r for r in detailed_results if r["dataset"] == "ATTACK"]
    benign_res = [r for r in detailed_results if r["dataset"] == "BENIGN"]
    evasion_res = [r for r in attack_res if r["evades_taxonomy"]]
    tax_res = [r for r in attack_res if not r["evades_taxonomy"]]

    atk_int = sum(1 for r in attack_res if r["intercepted"])
    atk_flg = sum(1 for r in attack_res if r["flagged_only"])
    atk_total_enf = atk_int + atk_flg

    evas_int = sum(1 for r in evasion_res if r["intercepted"])
    evas_flg = sum(1 for r in evasion_res if r["flagged_only"])
    evas_total_enf = evas_int + evas_flg

    tax_int = sum(1 for r in tax_res if r["intercepted"])
    tax_flg = sum(1 for r in tax_res if r["flagged_only"])
    tax_total_enf = tax_int + tax_flg

    ben_fp_int = sum(1 for r in benign_res if r["intercepted"])
    ben_fp_flg = sum(1 for r in benign_res if r["flagged_only"])
    ben_fp_non_allow = sum(1 for r in benign_res if not r["clean_allowed"])

    print("\n--- PERFORMANCE SUMMARY ACROSS DISTINCT BENCHMARK ITEMS ---")
    print(f"1. Overall Attack Interception Rate (BLOCK/CONFIRM/PAUSE): {atk_int}/{n_attacks} = {format_ci(atk_int, n_attacks)}")
    print(f"   Overall Attack Flagged Only Rate (ALLOW_WITH_FLAG)   : {atk_flg}/{n_attacks} = {format_ci(atk_flg, n_attacks)}")
    print(f"   Overall Total Attack Enforcement Rate                : {atk_total_enf}/{n_attacks} = {format_ci(atk_total_enf, n_attacks)}")
    print(f"2. Adversarial Evasion Subset Interception Rate (N={len(evasion_res)}): {evas_int}/{len(evasion_res)} = {format_ci(evas_int, len(evasion_res))}")
    print(f"   Adversarial Evasion Subset Flagged Only Rate         : {evas_flg}/{len(evasion_res)} = {format_ci(evas_flg, len(evasion_res))}")
    print(f"   Adversarial Evasion Subset Total Enforcement         : {evas_total_enf}/{len(evasion_res)} = {format_ci(evas_total_enf, len(evasion_res))}")
    print(f"3. Known Taxonomy Subset Interception Rate (N={len(tax_res)})    : {tax_int}/{len(tax_res)} = {format_ci(tax_int, len(tax_res))}")
    print(f"   Known Taxonomy Subset Flagged Only Rate              : {tax_flg}/{len(tax_res)} = {format_ci(tax_flg, len(tax_res))}")
    print(f"   Known Taxonomy Subset Total Enforcement              : {tax_total_enf}/{len(tax_res)} = {format_ci(tax_total_enf, len(tax_res))}")
    print(f"4. Benign Clean False Interception Rate (N={n_benign})          : {ben_fp_int}/{n_benign} = {format_ci(ben_fp_int, n_benign)}")
    print(f"   Benign Clean False Flagged Only Rate (N={n_benign})          : {ben_fp_flg}/{n_benign} = {format_ci(ben_fp_flg, n_benign)}")
    print(f"   Benign Clean Non-ALLOW Decision Rate (N={n_benign})          : {ben_fp_non_allow}/{n_benign} = {format_ci(ben_fp_non_allow, n_benign)}")

    prec_num = atk_int
    prec_den = atk_int + ben_fp_int
    prec_str = format_ci(prec_num, prec_den) if prec_den > 0 else "N/A"
    print(f"5. Empirical Precision (Interceptions / All Positive Calls): {prec_num}/{prec_den} = {prec_str}")

    lat_list = [r["latency_ms"] for r in detailed_results]
    print(f"6. Steady-State Gate Latency across all {n_total} items       : Mean={statistics.mean(lat_list):.2f}ms | Median={statistics.median(lat_list):.2f}ms | p95={sorted(lat_list)[int(len(lat_list)*0.95)]:.2f}ms")
    print("=" * 135)

    # 3. Component Ablation Study (Config A, B, C, D) over Combined Dataset
    print("\n" + "=" * 160)
    print("ContextGuard Defensive Architecture Component Ablation Study (Combined Dataset, N = 66 distinct items)")
    print("=" * 160)

    ablation_configs = [
        ("Config A", "Field checks only (Step 2 Verification Rail)", "A"),
        ("Config B", "Config A + Keyword taxonomy (Component 3)", "B"),
        ("Config C", "Config B + Semantic characterization (Component 4)", "C"),
        ("Config D", "Full Gate (All 7 Components + ML Risk + Policy Matrix)", "D"),
        ("Config E", "Full Gate + Attack Chain Detector (Component 8 Stateful Defense)", "E"),
    ]


    ablation_summary: List[Dict[str, Any]] = []

    for cfg_id, cfg_desc, cfg_key in ablation_configs:
        cfg_atk_int = 0
        cfg_atk_flg = 0
        cfg_ben_fp_int = 0
        cfg_ben_fp_flg = 0
        cfg_ben_non_allow = 0
        latencies: List[float] = []

        # Run across all attack items
        for item in attacks:
            action = make_proposed_action(item)
            gate = ContextGuardGate(trusted_intent=trusted_intent, task_id=f"abl-{cfg_key}-{item['id']}")
            intercepted, flagged_only, decision, lat = evaluate_ablation_step(cfg_key, gate, action, item["dom_text"])
            latencies.append(lat)
            if intercepted:
                cfg_atk_int += 1
            elif flagged_only:
                cfg_atk_flg += 1

        # Run across all benign items
        for item in benign:
            action = make_proposed_action(item)
            gate = ContextGuardGate(trusted_intent=trusted_intent, task_id=f"abl-{cfg_key}-{item['id']}")
            intercepted, flagged_only, decision, lat = evaluate_ablation_step(cfg_key, gate, action, item["dom_text"])
            latencies.append(lat)
            if intercepted:
                cfg_ben_fp_int += 1
            elif flagged_only:
                cfg_ben_fp_flg += 1
            if decision != "ALLOW":
                cfg_ben_non_allow += 1

        rec_int_str = format_ci(cfg_atk_int, n_attacks)
        rec_flg_str = format_ci(cfg_atk_flg, n_attacks)
        fp_int_str = format_ci(cfg_ben_fp_int, n_benign)
        fp_non_allow_str = format_ci(cfg_ben_non_allow, n_benign)
        mean_lat = statistics.mean(latencies)
        p95_lat = sorted(latencies)[int(len(latencies) * 0.95)]

        ablation_summary.append({
            "config_id": cfg_id,
            "description": cfg_desc,
            "attacks_intercepted": cfg_atk_int,
            "attacks_flagged": cfg_atk_flg,
            "total_attacks": n_attacks,
            "interception_recall": cfg_atk_int / n_attacks,
            "interception_recall_formatted": rec_int_str,
            "flagged_rate": cfg_atk_flg / n_attacks,
            "flagged_formatted": rec_flg_str,
            "fp_int_count": cfg_ben_fp_int,
            "fp_flg_count": cfg_ben_fp_flg,
            "fp_non_allow_count": cfg_ben_non_allow,
            "clean_total": n_benign,
            "fp_int_rate": cfg_ben_fp_int / n_benign,
            "fp_int_formatted": fp_int_str,
            "fp_non_allow_formatted": fp_non_allow_str,
            "mean_latency_ms": round(mean_lat, 2),
            "p95_latency_ms": round(p95_lat, 2),
        })

    # Print Ablation Table
    fmt_abl = "{:<10} | {:<42} | {:<25} | {:<16} | {:<22} | {:<24} | {:<12} | {:<12}"
    print(fmt_abl.format("Config", "Defensive Architecture Stack", "Interception (95% CI)", "Flagged Only", "FP Int (95% CI)", "Non-ALLOW (95% CI)", "Mean Latency", "p95 Latency"))
    print("-" * 172)

    for item in ablation_summary:
        print(fmt_abl.format(
            item["config_id"],
            item["description"][:42],
            item["interception_recall_formatted"],
            f"{item['attacks_flagged']}/{item['total_attacks']} ({item['flagged_rate']*100:.1f}%)",
            item["fp_int_formatted"],
            item["fp_non_allow_formatted"],
            f"{item['mean_latency_ms']:.2f} ms",
            f"{item['p95_latency_ms']:.2f} ms",
        ))

    print("=" * 172)

    # 4. CSV Exports
    # Details CSV
    out_details = csv_details_path or os.path.join(WORKSPACE_ROOT, "eval_results", "dataset_evaluation_details.csv")
    out_dir = os.path.dirname(out_details)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(out_details, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Item ID", "Name", "Dataset", "Category", "Evades Taxonomy", "Action",
            "Decision", "Intercepted", "Flagged Only", "Clean Allowed", "Risk Score",
            "Comp4 Characterization Label", "Deviation Signal", "Latency ms"
        ])
        for r in detailed_results:
            writer.writerow([
                r["id"], r["name"], r["dataset"], r["category"], r["evades_taxonomy"],
                r["action"], r["decision"], r["intercepted"], r["flagged_only"],
                r["clean_allowed"], r["risk_score"], r["characterization_label"],
                f"{r['deviation_signal']:.3f}", f"{r['latency_ms']:.2f}"
            ])
    print(f"\n[OK] Per-item benchmark results exported to: {os.path.abspath(out_details)}")

    # Ablation CSV
    out_ablation = csv_ablation_path or os.path.join(WORKSPACE_ROOT, "eval_results", "dataset_ablation_results.csv")
    with open(out_ablation, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Config ID", "Description", "Attacks Intercepted", "Total Attacks", "Interception Recall",
            "Interception 95% CI Lower", "Interception 95% CI Upper", "Flagged Only", "Flagged Only Rate",
            "Flagged 95% CI Lower", "Flagged 95% CI Upper", "Clean False Interceptions", "Total Clean",
            "Clean FP Int Rate", "Clean FP Int 95% CI Lower", "Clean FP Int 95% CI Upper",
            "Clean False Flagged", "Clean Non-ALLOW Count", "Clean Non-ALLOW Rate",
            "Clean Non-ALLOW 95% CI Lower", "Clean Non-ALLOW 95% CI Upper",
            "Mean Latency (ms)", "p95 Latency (ms)"
        ])
        for row in ablation_summary:
            r_low, r_high = wilson(row["attacks_intercepted"], row["total_attacks"])
            flg_low, flg_high = wilson(row["attacks_flagged"], row["total_attacks"])
            fp_low, fp_high = wilson(row["fp_int_count"], row["clean_total"])
            na_low, na_high = wilson(row["fp_non_allow_count"], row["clean_total"])
            writer.writerow([
                row["config_id"],
                row["description"],
                row["attacks_intercepted"],
                row["total_attacks"],
                f"{row['interception_recall'] * 100:.2f}%",
                f"{r_low * 100:.2f}%",
                f"{r_high * 100:.2f}%",
                row["attacks_flagged"],
                f"{row['flagged_rate'] * 100:.2f}%",
                f"{flg_low * 100:.2f}%",
                f"{flg_high * 100:.2f}%",
                row["fp_int_count"],
                row["clean_total"],
                f"{row['fp_int_rate'] * 100:.2f}%",
                f"{fp_low * 100:.2f}%",
                f"{fp_high * 100:.2f}%",
                row["fp_flg_count"],
                row["fp_non_allow_count"],
                f"{row['fp_non_allow_count'] / row['clean_total'] * 100:.2f}%",
                f"{na_low * 100:.2f}%",
                f"{na_high * 100:.2f}%",
                row["mean_latency_ms"],
                row["p95_latency_ms"],
            ])
    print(f"[OK] 4-Tier dataset ablation results exported to: {os.path.abspath(out_ablation)}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run benchmark evaluation and 4-tier ablation on combined eval_data set.")
    parser.add_argument("--csv-ablation", type=str, default=None, help="Custom CSV output path for ablation results")
    parser.add_argument("--csv-details", type=str, default=None, help="Custom CSV output path for per-item details")
    parser.add_argument("--benign-file", type=str, default=None, help="Custom benign dataset YAML path")
    args = parser.parse_args()

    run_benchmark_and_ablation(
        csv_ablation_path=args.csv_ablation,
        csv_details_path=args.csv_details,
        benign_file=args.benign_file,
    )
