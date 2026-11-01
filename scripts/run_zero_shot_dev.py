"""
scripts/run_zero_shot_dev.py — Execute Untouched Gate Baseline on Dev Split (Block 3 Addition C)

Loads all 544 dev cases (224 attacks, 320 benign) across all 5 domains,
evaluates them through Gateway.from_domain (the untouched ContextGuardGate),
writes the outputs to runs/zero_shot_dev.jsonl, and prints the per-domain decision breakdown.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List
from collections import defaultdict

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from harness.case_schema import EvaluationCase
from harness.run_case import run_case
from harness.run_record import RunRecord
from harness.split import assert_dev_only

ATTACKS_DEV_FILE = ROOT_DIR / "attacks" / "dev" / "cases.jsonl"
BENIGN_DEV_FILE = ROOT_DIR / "benign" / "dev" / "cases.jsonl"
OUT_RUN_FILE = ROOT_DIR / "runs" / "zero_shot_dev.jsonl"
OUT_RUN_SEEDED = ROOT_DIR / "runs" / "zero_shot_dev_42.jsonl"


def load_dev_cases() -> List[EvaluationCase]:
    cases = []
    for fpath in [ATTACKS_DEV_FILE, BENIGN_DEV_FILE]:
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    cases.append(EvaluationCase.model_validate(json.loads(s)))
    # Strict isolation check
    assert_dev_only(cases)
    return cases


def main():
    dev_cases = load_dev_cases()
    print(f"Loaded {len(dev_cases)} dev cases (isolated from test split).")

    # Clear prior run files
    OUT_RUN_FILE.parent.mkdir(parents=True, exist_ok=True)
    if OUT_RUN_FILE.exists():
        OUT_RUN_FILE.unlink()
    if OUT_RUN_SEEDED.exists():
        OUT_RUN_SEEDED.unlink()

    counts_by_domain = defaultdict(lambda: {"allow": 0, "warn": 0, "ask_human": 0, "block": 0, "total": 0})
    category_by_domain = defaultdict(lambda: defaultdict(lambda: {"allow": 0, "warn": 0, "ask_human": 0, "block": 0, "total": 0}))

    t0 = time.time()
    records: List[RunRecord] = []

    with open(OUT_RUN_FILE, "w", encoding="utf-8") as f_out, open(OUT_RUN_SEEDED, "w", encoding="utf-8") as f_seeded:
        for idx, case in enumerate(dev_cases, 1):
            rec = run_case(case, config="zero_shot_dev", seed=42, enforce_split_guard=True)
            records.append(rec)
            line = rec.model_dump_json() + "\n"
            f_out.write(line)
            f_seeded.write(line)

            d = case.domain
            dec = rec.decision.lower()
            if dec not in ("allow", "warn", "ask_human", "block"):
                # normalize
                if "ask" in dec or "confirm" in dec:
                    dec = "ask_human"
                elif "warn" in dec or "flag" in dec:
                    dec = "warn"
                elif "block" in dec:
                    dec = "block"
                else:
                    dec = "allow"

            counts_by_domain[d][dec] += 1
            counts_by_domain[d]["total"] += 1

            cat_key = case.ground_truth_label
            category_by_domain[d][cat_key][dec] += 1
            category_by_domain[d][cat_key]["total"] += 1

            if idx % 100 == 0 or idx == len(dev_cases):
                print(f"  Evaluated {idx}/{len(dev_cases)} cases ({time.time() - t0:.1f}s)...")

    elapsed = time.time() - t0
    print(f"\nZero-shot dev evaluation complete in {elapsed:.2f}s ({len(records)} cases evaluated).")
    print(f"Results written to:\n  - {OUT_RUN_FILE}\n  - {OUT_RUN_SEEDED}")

    # Print summary table
    print("\n" + "=" * 90)
    print("           ZERO-SHOT UNTOUCHED GATE DEV EVALUATION BREAKDOWN (BY DOMAIN)")
    print("=" * 90)
    print(f"{'DOMAIN':<14} | {'TOTAL DEV':<10} | {'ALLOW':<10} | {'WARN':<10} | {'ASK_HUMAN':<12} | {'BLOCK':<10}")
    print("-" * 76)

    totals = {"total": 0, "allow": 0, "warn": 0, "ask_human": 0, "block": 0}
    for dom in sorted(counts_by_domain.keys()):
        stats = counts_by_domain[dom]
        for k in totals:
            totals[k] += stats[k]
        print(f"{dom:<14} | {stats['total']:<10} | {stats['allow']:<10} | {stats['warn']:<10} | {stats['ask_human']:<12} | {stats['block']:<10}")

    print("-" * 76)
    print(f"{'TOTAL':<14} | {totals['total']:<10} | {totals['allow']:<10} | {totals['warn']:<10} | {totals['ask_human']:<12} | {totals['block']:<10}")
    print("=" * 90 + "\n")


if __name__ == "__main__":
    main()

