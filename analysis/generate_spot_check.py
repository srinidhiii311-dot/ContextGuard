"""
analysis/generate_spot_check.py — Deterministic Sampling of 30 Cases for Manual Audit (Block 3)
"""

from __future__ import annotations

import json
from pathlib import Path
import random
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent

ATTACKS_DEV = ROOT_DIR / "attacks" / "dev" / "cases.jsonl"
ATTACKS_TEST = ROOT_DIR / "attacks" / "test" / "cases.jsonl"
BENIGN_DEV = ROOT_DIR / "benign" / "dev" / "cases.jsonl"
BENIGN_TEST = ROOT_DIR / "benign" / "test" / "cases.jsonl"
OUT_MD = ROOT_DIR / "analysis" / "spot_check.md"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records = []
    if path.is_file():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    records.append(json.loads(s))
    return records


def sample_cases() -> None:
    att_dev = load_jsonl(ATTACKS_DEV)
    att_test = load_jsonl(ATTACKS_TEST)
    ben_dev = load_jsonl(BENIGN_DEV)
    ben_test = load_jsonl(BENIGN_TEST)

    all_cases = att_dev + att_test + ben_dev + ben_test

    rng = random.Random(42)
    # Ensure balanced representation across domains and categories:
    # 10 divergent attacks, 6 uncompromised attacks, 8 standard benign, 6 hard benign = 30 cases
    div_att = [c for c in all_cases if c.get("ground_truth_label") == "attack_divergent"]
    uncomp_att = [c for c in all_cases if c.get("ground_truth_label") == "attack_uncompromised"]
    std_ben = [c for c in all_cases if c.get("family") == "benign_standard"]
    hrd_ben = [c for c in all_cases if c.get("family") == "benign_hard"]

    sample_div = rng.sample(div_att, 10)
    sample_uncomp = rng.sample(uncomp_att, 6)
    sample_std = rng.sample(std_ben, 8)
    sample_hrd = rng.sample(hrd_ben, 6)

    sampled = sample_div + sample_uncomp + sample_std + sample_hrd
    rng.shuffle(sampled)

    lines = [
        "# ContextGuard Evaluation Dataset — 30 Case Spot Check",
        "",
        "This document contains 30 randomly sampled evaluation cases spanning all 5 mock domains,",
        "both dev/test splits, and all categories (attack divergent, attack uncompromised, standard benign, hard benign).",
        "",
        "| # | Case ID | Domain | Split | Type | Ground Truth | Expected Decision | Proposed Action |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for idx, c in enumerate(sampled, 1):
        act = c["proposed_action"]
        act_summary = f"`{act['action_type']} {act['target']}`"
        if act.get("value"):
            act_summary += f" val=`{act['value']}`"
        lines.append(
            f"| {idx} | `{c['case_id']}` | {c['domain']} | **{c['split']}** | {c['case_type']} | `{c['ground_truth_label']}` | **{c['expected_decision']}** | {act_summary} |"
        )

    lines.append("\n---\n")
    lines.append("## Detailed Case Inspections\n")

    for idx, c in enumerate(sampled, 1):
        act = c["proposed_action"]
        intent_json = json.dumps(c["locked_intent"], indent=2)
        lines.append(f"### Case {idx}: `{c['case_id']}`")
        lines.append(f"- **Domain**: {c['domain']}")
        lines.append(f"- **Split**: `{c['split']}`")
        lines.append(f"- **Category / Family**: `{c['case_type']}` / `{c['family']}` ({c['variant_id']})")
        lines.append(f"- **Ground Truth Label**: `{c['ground_truth_label']}`")
        lines.append(f"- **Expected Decision**: `{c['expected_decision']}`")
        lines.append(f"- **User Task**: {c['user_task']}")
        lines.append(f"- **Locked Intent**:\n```json\n{intent_json}\n```")
        lines.append(f"- **Proposed Action**: `{act['action_type']}` on `{act['target']}` (value: `{act.get('value')}`)")
        lines.append(f"- **Page Snapshot / Slot**: `{c['page_snapshot_ref']}`")
        lines.append(f"- **Rationale**: {c['rationale']}")
        lines.append("")

    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Sampled 30 cases into {OUT_MD}")


if __name__ == "__main__":
    sample_cases()

