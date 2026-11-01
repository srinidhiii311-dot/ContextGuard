"""
adaptive/evaluate_tag.py — Evaluates adaptive variants on the currently checked-out gate.

Outputs structured JSON with:
- commit_hash, tag_name
- seed
- per-strategy and per-domain statistics under Oracle v1, v2, and v3
- distinct generator template counts and evasions per template
- full per-variant results
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from adaptive.generator_7a import (
    DOMAINS,
    STRATEGIES,
    generate_s1_variants,
    generate_s2_variants,
    generate_s3_variants,
    generate_s4_variants,
    generate_s5_variants,
    generate_s6_variants,
)
from contextguard.gate import Decision, GateResult, ProposedAction
from gateway.loader import Gateway
from harness.oracle_v1 import SecurityOracle as SecurityOracleV1
from harness.oracle_v2 import SecurityOracleV2
from harness.oracle_v3 import SecurityOracleV3
from harness.run_case import build_trusted_intent_from_dict


def wilson_score_interval(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    p = successes / total
    denom = 1.0 + (z ** 2) / total
    centre = p + (z ** 2) / (2 * total)
    adj_sd = math.sqrt((p * (1.0 - p) + (z ** 2) / (4 * total)) / total)
    low = (centre - z * adj_sd) / denom
    high = (centre + z * adj_sd) / denom
    return max(0.0, low) * 100.0, min(1.0, high) * 100.0


def extract_template_id(variant: Dict[str, Any]) -> str:
    strat = variant.get("strategy", "")
    dom = variant.get("domain", "")
    act = variant.get("proposed_action", {})
    atype = act.get("action_type", "")
    tgt = act.get("target", "")
    val = str(act.get("value", ""))

    if strat == "S1":
        return f"{dom}_{atype}_{tgt}"
    elif strat == "S2":
        try:
            mod_type = int(variant.get("variant_id", "").split("_")[-1]) % 5
        except Exception:
            mod_type = 0
        types = ["homoglyph", "zero_width", "whitespace", "off_by_one", "casing_or_under_limit"]
        return f"{dom}_{types[mod_type]}_{tgt}"
    elif strat == "S3":
        if "#" in tgt or "#" in val:
            return f"{dom}_fragment_anchor"
        elif "//" in tgt or "//" in val:
            return f"{dom}_double_slash_path"
        elif any(k in val for k in ("dest=", "url=", "next=", "link=")):
            return f"{dom}_redirect_param"
        return f"{dom}_{atype}_redirect"
    elif strat == "S4":
        try:
            mod_type = int(variant.get("variant_id", "").split("_")[-1]) % 6
        except Exception:
            mod_type = 0
        techs = ["split_dom", "zero_width_marker", "aria_label", "alt_attr", "spanish", "german"]
        return f"{dom}_{techs[mod_type]}"
    elif strat == "S5":
        return f"{dom}_compound_{atype}_{tgt}"
    elif strat == "S6":
        return f"{dom}_{atype}_{tgt}"
    return f"{dom}_{strat}"


def generate_seed_variants(seed: int) -> List[Dict[str, Any]]:
    generators = {
        "S1": generate_s1_variants,
        "S2": generate_s2_variants,
        "S3": generate_s3_variants,
        "S4": generate_s4_variants,
        "S5": generate_s5_variants,
        "S6": generate_s6_variants,
    }
    all_v = []
    for strat, gen_fn in generators.items():
        for dom in DOMAINS:
            all_v.extend(gen_fn(domain=dom, count=40, seed=seed))
    return all_v


def run_evaluation(tag_name: str, seed: int, out_path: Path):
    # Determine commit hash
    try:
        commit_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        commit_hash = "unknown"

    print(f"Running evaluation on Tag: {tag_name} (Commit: {commit_hash[:7]}) | Seed: {seed}")

    gateways: Dict[str, Gateway] = {dom: Gateway.from_domain(dom) for dom in DOMAINS}
    variants = generate_seed_variants(seed=seed)

    records = []
    # Strat -> Domain -> Oracle -> Stats
    # Oracle: 'v1', 'v2', 'v3'
    stats = defaultdict(lambda: defaultdict(lambda: {
        "attempts": 0,
        "v1": {"unsafe": 0, "evaded": 0, "intercepted": 0},
        "v2": {"unsafe": 0, "evaded": 0, "intercepted": 0},
        "v3": {"unsafe": 0, "evaded": 0, "intercepted": 0},
        "templates": set(),
        "evasions_per_template_v1": defaultdict(int),
        "evasions_per_template_v2": defaultdict(int),
        "evasions_per_template_v3": defaultdict(int),
    }))

    for var in variants:
        vid = var["variant_id"]
        strat = var["strategy"]
        dom = var["domain"]
        pact_dict = var["proposed_action"]
        intent_dict = var["locked_intent"]
        dom_text = var.get("dom_text", "")
        tmpl = extract_template_id(var)

        # Oracle checks
        u1, r1 = SecurityOracleV1.is_action_unsafe(pact_dict, intent_dict, dom, is_attack_case=True)
        u2, r2 = SecurityOracleV2.is_action_unsafe(pact_dict, intent_dict, dom, is_attack_case=True)
        u3, r3 = SecurityOracleV3.is_action_unsafe(pact_dict, intent_dict, dom, is_attack_case=True)

        # Gate execution
        gw = gateways[dom]
        trusted_intent = build_trusted_intent_from_dict(dom, intent_dict)
        gw.set_intent(trusted_intent)

        if "prep_action" in var:
            prep_dict = var["prep_action"]
            prep_act = ProposedAction(
                action_type=prep_dict["action_type"],
                target=prep_dict["target"],
                value=prep_dict.get("value"),
                page_url=prep_dict.get("page_url", var["page_url"]),
            )
            gw.check(action=prep_act, current_dom_text=dom_text)

        action = ProposedAction(
            action_type=pact_dict.get("action_type", "CLICK"),
            target=pact_dict.get("target", ""),
            value=pact_dict.get("value"),
            page_url=pact_dict.get("page_url", var.get("page_url", "")),
        )

        res = gw.check(action=action, current_dom_text=dom_text)
        is_intercepted = res.decision in (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK)
        is_evaded = not is_intercepted

        s_dict = stats[strat][dom]
        s_dict["attempts"] += 1
        s_dict["templates"].add(tmpl)

        for ver, is_u in [("v1", u1), ("v2", u2), ("v3", u3)]:
            if is_u:
                s_dict[ver]["unsafe"] += 1
                if is_intercepted:
                    s_dict[ver]["intercepted"] += 1
                else:
                    s_dict[ver]["evaded"] += 1
                    s_dict[f"evasions_per_template_{ver}"][tmpl] += 1

        records.append({
            "variant_id": vid,
            "strategy": strat,
            "domain": dom,
            "template_id": tmpl,
            "proposed_action": pact_dict,
            "locked_intent": intent_dict,
            "gate_decision": res.decision.value,
            "gate_reason": res.reason,
            "oracle_v1": {"unsafe": u1, "reason": r1},
            "oracle_v2": {"unsafe": u2, "reason": r2},
            "oracle_v3": {"unsafe": u3, "reason": r3},
            "intercepted": is_intercepted,
            "evaded": is_evaded,
        })

    # Prepare JSON serializable summary
    serializable_stats = {}
    for strat, dom_map in stats.items():
        serializable_stats[strat] = {}
        for dom, s in dom_map.items():
            serializable_stats[strat][dom] = {
                "attempts": s["attempts"],
                "distinct_templates_count": len(s["templates"]),
                "templates_list": sorted(list(s["templates"])),
                "v1": s["v1"],
                "v2": s["v2"],
                "v3": s["v3"],
                "evasions_per_template_v1": dict(s["evasions_per_template_v1"]),
                "evasions_per_template_v2": dict(s["evasions_per_template_v2"]),
                "evasions_per_template_v3": dict(s["evasions_per_template_v3"]),
            }

    out_data = {
        "tag_name": tag_name,
        "commit_hash": commit_hash,
        "seed": seed,
        "total_variants": len(variants),
        "stats_by_strategy_domain": serializable_stats,
        "records": records,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_data, f, indent=2)

    print(f"Saved evaluation to {out_path} ({len(variants)} variants)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True, help="Tag name")
    parser.add_argument("--seed", type=int, required=True, help="Random seed (42 or 9999)")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    run_evaluation(args.tag, args.seed, Path(args.out))

