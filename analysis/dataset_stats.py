"""
analysis/dataset_stats.py — Evaluation Dataset Statistics & Auditing (Block 3)

Calculates and prints dataset distribution tables:
- Counts per domain, family, split, and case type
- Breakdown of uncompromised attacks (Mechanism 2) vs divergent attacks (Mechanism 1)
- Breakdown of hard benign subset (~25%) vs standard benign
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

ATTACKS_DEV = ROOT_DIR / "attacks" / "dev" / "cases.jsonl"
ATTACKS_TEST = ROOT_DIR / "attacks" / "test" / "cases.jsonl"
BENIGN_DEV = ROOT_DIR / "benign" / "dev" / "cases.jsonl"
BENIGN_TEST = ROOT_DIR / "benign" / "test" / "cases.jsonl"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                records.append(json.loads(line_str))
    return records


def print_dataset_statistics() -> Dict[str, Any]:
    att_dev = load_jsonl(ATTACKS_DEV)
    att_test = load_jsonl(ATTACKS_TEST)
    ben_dev = load_jsonl(BENIGN_DEV)
    ben_test = load_jsonl(BENIGN_TEST)

    all_cases = att_dev + att_test + ben_dev + ben_test

    print("\n" + "=" * 90)
    print("                    CONTEXTGUARD EVALUATION DATASET STATISTICS (BLOCK 3)")
    print("=" * 90)

    # 1. High-Level Summary Table
    print(f"\n{'SPLIT':<10} | {'ATTACKS':<10} | {'BENIGN':<10} | {'TOTAL':<10} | {'PERCENTAGE':<10}")
    print("-" * 60)
    total_count = len(all_cases)
    dev_count = len(att_dev) + len(ben_dev)
    test_count = len(att_test) + len(ben_test)
    print(f"{'dev':<10} | {len(att_dev):<10} | {len(ben_dev):<10} | {dev_count:<10} | {dev_count/total_count*100:>8.1f}%")
    print(f"{'test':<10} | {len(att_test):<10} | {len(ben_test):<10} | {test_count:<10} | {test_count/total_count*100:>8.1f}%")
    print("-" * 60)
    print(f"{'TOTAL':<10} | {len(att_dev)+len(att_test):<10} | {len(ben_dev)+len(ben_test):<10} | {total_count:<10} | 100.0%\n")

    # 2. Per-Domain Distribution Table
    domains = sorted(list({c["domain"] for c in all_cases}))
    print(f"{'DOMAIN':<14} | {'ATTACK DEV':<12} | {'ATTACK TEST':<12} | {'BENIGN DEV':<12} | {'BENIGN TEST':<12} | {'DOMAIN TOTAL':<12}")
    print("-" * 86)
    domain_totals = {}
    for d in domains:
        ad = sum(1 for c in att_dev if c["domain"] == d)
        at = sum(1 for c in att_test if c["domain"] == d)
        bd = sum(1 for c in ben_dev if c["domain"] == d)
        bt = sum(1 for c in ben_test if c["domain"] == d)
        dom_tot = ad + at + bd + bt
        domain_totals[d] = dom_tot
        print(f"{d:<14} | {ad:<12} | {at:<12} | {bd:<12} | {bt:<12} | {dom_tot:<12}")
    print("-" * 86)

    # 3. Per-Family Attack Distribution Table
    attack_cases = att_dev + att_test
    families = sorted(list({c["family"] for c in attack_cases}))
    print(f"\n{'ATTACK FAMILY':<28} | {'DEV':<8} | {'TEST':<8} | {'TOTAL':<8} | {'HELD-OUT TEST STATUS'}")
    print("-" * 80)
    for fam in families:
        f_dev = sum(1 for c in att_dev if c["family"] == fam)
        f_test = sum(1 for c in att_test if c["family"] == fam)
        status = "100% HELD OUT FOR TEST" if f_dev == 0 else f"{f_test/(f_dev+f_test)*100:.1f}% test holdout"
        print(f"{fam:<28} | {f_dev:<8} | {f_test:<8} | {f_dev+f_test:<8} | {status}")
    print("-" * 80)

    # 4. Granular Labels and Special Subsets
    uncomp_count = sum(1 for c in attack_cases if c.get("ground_truth_label") == "attack_uncompromised")
    diverg_count = sum(1 for c in attack_cases if c.get("ground_truth_label") == "attack_divergent")
    benign_cases = ben_dev + ben_test
    hard_benign_count = sum(1 for c in benign_cases if c["family"] == "benign_hard")
    std_benign_count = sum(1 for c in benign_cases if c["family"] == "benign_standard")

    print("\nSPECIAL SUBSETS & MECHANISM BREAKDOWN:")
    print(f"  - Attack Mechanism 1 (Divergent/Compromised, expected block_or_ask): {diverg_count} ({diverg_count/len(attack_cases)*100:.1f}%)")
    print(f"  - Attack Mechanism 2 (Uncompromised/Compliant, expected allow):      {uncomp_count} ({uncomp_count/len(attack_cases)*100:.1f}%) [Addition B]")
    print(f"  - Standard Benign (Routine tasks, expected allow):                  {std_benign_count} ({std_benign_count/len(benign_cases)*100:.1f}%)")
    print(f"  - Hard Benign (Legitimate risky / trigger words, expected allow):   {hard_benign_count} ({hard_benign_count/len(benign_cases)*100:.1f}%)")
    print("=" * 90 + "\n")

    return {
        "total_cases": total_count,
        "dev_cases": dev_count,
        "test_cases": test_count,
        "attack_cases": len(attack_cases),
        "benign_cases": len(benign_cases),
        "uncompromised_attacks": uncomp_count,
        "divergent_attacks": diverg_count,
        "hard_benign": hard_benign_count,
        "standard_benign": std_benign_count,
    }


if __name__ == "__main__":
    print_dataset_statistics()

