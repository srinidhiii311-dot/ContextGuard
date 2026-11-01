"""
scripts/run_zero_shot_dev_v2.py — Run Frozen Baseline Gate on Dataset v2 Dev Split

Evaluates all 680 dev cases (280 attacks, 400 benign) with the frozen baseline gate logic (838089b)
and outputs the results to runs/zero_shot_dev_v2.jsonl.
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
OUT_RUN_FILE = ROOT_DIR / "runs" / "zero_shot_dev_v2.jsonl"


def load_dev_cases() -> List[EvaluationCase]:
    cases = []
    for fpath in [ATTACKS_DEV_FILE, BENIGN_DEV_FILE]:
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    cases.append(EvaluationCase.model_validate(json.loads(s)))
    assert_dev_only(cases)
    return cases


def main():
    dev_cases = load_dev_cases()
    print(f"Loaded {len(dev_cases)} dev cases for Dataset v2 (isolated from test split).")

    OUT_RUN_FILE.parent.mkdir(parents=True, exist_ok=True)
    if OUT_RUN_FILE.exists():
        OUT_RUN_FILE.unlink()

    counts_by_domain = defaultdict(lambda: {"allow": 0, "warn": 0, "ask_human": 0, "block": 0, "total": 0})
    category_by_domain = defaultdict(lambda: defaultdict(lambda: {"allow": 0, "warn": 0, "ask_human": 0, "block": 0, "total": 0}))

    t0 = time.time()
    records: List[RunRecord] = []

    with open(OUT_RUN_FILE, "w", encoding="utf-8") as f_out:
        for idx, case in enumerate(dev_cases, 1):
            rec = run_case(case, config="zero_shot_dev", seed=42, enforce_split_guard=True)
            records.append(rec)
            line = rec.model_dump_json() + "\n"
            f_out.write(line)

            d = case.domain
            dec = rec.decision.lower()
            if dec not in ("allow", "warn", "ask_human", "block"):
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
    print(f"Results written to: {OUT_RUN_FILE}")

    # Print summary table
    print("\n" + "=" * 90)
    print("           DATASET V2 ZERO-SHOT BASELINE GATE DEV EVALUATION BREAKDOWN (BY DOMAIN)")
    print("=" * 90)
    header = f"{'Domain':<14} | {'Total':<6} | {'ALLOW':<8} | {'WARN':<8} | {'REQUIRE_CONF':<14} | {'BLOCK':<8}"
    print(header)
    print("-" * 90)
    for dom in sorted(counts_by_domain.keys()):
        c = counts_by_domain[dom]
        print(f"{dom:<14} | {c['total']:<6} | {c['allow']:<8} | {c['warn']:<8} | {c['ask_human']:<14} | {c['block']:<8}")
    print("-" * 90)
    tot = {k: sum(counts_by_domain[d][k] for d in counts_by_domain) for k in ["total", "allow", "warn", "ask_human", "block"]}
    print(f"{'OVERALL':<14} | {tot['total']:<6} | {tot['allow']:<8} | {tot['warn']:<8} | {tot['ask_human']:<14} | {tot['block']:<8}")
    print("=" * 90 + "\n")


if __name__ == "__main__":
    main()

