"""Evaluation helper for Gate adaptation commits on Dataset v2 dev split."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import time
from harness.case_schema import EvaluationCase
from harness.configs import evaluate_case_with_config
from analysis.metrics import compute_metrics_for_records, wilson_score_interval, format_proportion_ci
from analysis.stats import compute_per_family_breakdown

def run_dev_evaluation():
    cases = []
    for f in [Path("attacks/dev/cases.jsonl"), Path("benign/dev/cases.jsonl")]:
        with open(f, "r", encoding="utf-8") as fp:
            for line in fp:
                if line.strip():
                    cases.append(EvaluationCase.model_validate(json.loads(line)))

    records = []
    gw_cache = {}
    t0 = time.time()
    for c in cases:
        rec = evaluate_case_with_config(c, config="dual_gate", seed=42, gateway_cache=gw_cache)
        records.append(rec.model_dump())
    
    elapsed = time.time() - t0
    m = compute_metrics_for_records(records)
    bd = compute_per_family_breakdown({"dev": records})

    # Separate block vs. confirm for benign
    benign_norm = [r for r in records if r.get("case_type") == "benign" and r.get("family") != "benign_hard"]
    benign_hrd = [r for r in records if r.get("case_type") == "benign" and r.get("family") == "benign_hard"]

    norm_blocks = sum(1 for r in benign_norm if r.get("decision") == "block")
    norm_confirms = sum(1 for r in benign_norm if r.get("decision") in ("ask_human", "require_confirmation"))
    norm_tot = len(benign_norm)

    hard_blocks = sum(1 for r in benign_hrd if r.get("decision") == "block")
    hard_confirms = sum(1 for r in benign_hrd if r.get("decision") in ("ask_human", "require_confirmation"))
    hard_tot = len(benign_hrd)

    uncomp = [r for r in records if r.get("ground_truth_label") == "attack_uncompromised"]
    uncomp_blocks = sum(1 for r in uncomp if r.get("decision") == "block")
    uncomp_confirms = sum(1 for r in uncomp if r.get("decision") in ("ask_human", "require_confirmation"))

    print("=" * 80)
    print(f"DEV SPLIT EVALUATION RESULTS ({elapsed:.2f}s, {len(cases)} cases)")
    print("=" * 80)
    print(f"Compromised Recall (Overall Intercepted) : {m['compromised_formatted']}")
    print(f"Uncompromised Over-Block Rate            : {m['uncompromised_formatted']}")
    print(f"  - Uncompromised Blocks                 : {format_proportion_ci(uncomp_blocks, len(uncomp))}")
    print(f"  - Uncompromised Confirms               : {format_proportion_ci(uncomp_confirms, len(uncomp))}")
    print(f"Benign Normal False-Intercept Rate       : {m['benign_normal_formatted']}")
    print(f"  - Benign Normal Blocks                 : {format_proportion_ci(norm_blocks, norm_tot)}")
    print(f"  - Benign Normal Confirms               : {format_proportion_ci(norm_confirms, norm_tot)}")
    print(f"Benign Hard False-Intercept Rate         : {m['benign_hard_formatted']}")
    print(f"  - Benign Hard Blocks                   : {format_proportion_ci(hard_blocks, hard_tot)}")
    print(f"  - Benign Hard Confirms                 : {format_proportion_ci(hard_confirms, hard_tot)}")
    print(f"Task Completion Proxy                    : {m['task_completion_formatted']}")
    print("\nPer-Family Detection Breakdown (Compromised Attacks):")
    for fam in sorted(bd.keys()):
        print(f"  {fam:<30}: {bd[fam]['dev']['formatted']}")
    print("=" * 80)

    return m, bd

if __name__ == "__main__":
    run_dev_evaluation()
