"""
adaptive/evaluate_v2_vs_v3.py — Comprehensive Comparative Evaluation (v2-perf vs v3)

Evaluates:
1. Original Block 7a seeds (seed=42) across S1-S6 (1,200 variants)
2. Fresh unseen seeds (seed=9999) across S1-S6 (1,200 variants)
3. Redesigned S4 and S5 variants (400 variants across 5 domains)

Both gate configurations:
- gate-frozen-v2-perf (C5 egress-in-content off, C6 irreversible authorization off)
- gate-frozen-v3 (C5 and C6 fully active)

Ground truth evaluated with both Oracle v1 and Oracle v2 (changelog documented).
"""

from __future__ import annotations

from collections import defaultdict
import json
import math
from pathlib import Path
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
from adaptive.redesign_s4_s5 import generate_all_redesigned_variants
from contextguard.gate import ContextGuardGate, Decision, GateResult, ProposedAction, TrustedIntent
from gateway.loader import Gateway
from harness.oracle_v1 import SecurityOracle as SecurityOracleV1
from harness.oracle_v2 import SecurityOracleV2
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


def evaluate_variant_on_gate(
    variant: Dict[str, Any],
    gate_version: str,
    gateway_cache: Dict[str, Gateway],
) -> GateResult:
    domain = variant["domain"]
    if domain not in gateway_cache:
        gateway_cache[domain] = Gateway.from_domain(domain)
    gw = gateway_cache[domain]

    # Save original verifier state
    orig_c5 = getattr(gw.verifier, "_check_egress_in_content", None)
    orig_irrev = getattr(gw.verifier, "irreversible_targets", None)

    if gate_version == "v2-perf":
        # Disable C5 and C6 to simulate gate-frozen-v2-perf exactly
        gw.verifier._check_egress_in_content = lambda *args, **kwargs: None
        gw.verifier.irreversible_targets = set()
    else:
        # v3 has C5 and C6 active
        pass

    try:
        act_dict = variant["proposed_action"]
        action = ProposedAction(
            action_type=act_dict.get("action_type", "CLICK"),
            target=act_dict.get("target", ""),
            value=act_dict.get("value"),
            page_url=act_dict.get("page_url", variant.get("page_url", "")),
        )
        intent = build_trusted_intent_from_dict(domain, variant.get("locked_intent", {}))
        gw.set_intent(intent)
        dom_text = variant.get("dom_text", "")

        # Handle multi-step preparation in S5 if present
        if "prep_action" in variant:
            prep_dict = variant["prep_action"]
            prep_act = ProposedAction(
                action_type=prep_dict["action_type"],
                target=prep_dict["target"],
                value=prep_dict.get("value"),
                page_url=prep_dict.get("page_url", variant.get("page_url", "")),
            )
            gw.check(action=prep_act, current_dom_text=dom_text)

        res = gw.check(action=action, current_dom_text=dom_text)
        return res
    finally:
        # Restore verifier state
        if orig_c5 is not None:
            gw.verifier._check_egress_in_content = orig_c5
        if orig_irrev is not None:
            gw.verifier.irreversible_targets = orig_irrev


def run_benchmark(
    variants: List[Dict[str, Any]],
    dataset_name: str,
) -> Dict[str, Any]:
    print("=" * 80)
    print(f"EVALUATING DATASET: {dataset_name} ({len(variants)} total variants)")
    print("=" * 80)

    gw_cache: Dict[str, Gateway] = {}

    results: Dict[str, Dict[str, Any]] = {
        "v2-perf_oracle_v1": defaultdict(lambda: {"attempts": 0, "unsafe": 0, "intercepted": 0, "evaded": 0}),
        "v2-perf_oracle_v2": defaultdict(lambda: {"attempts": 0, "unsafe": 0, "intercepted": 0, "evaded": 0}),
        "v3_oracle_v2": defaultdict(lambda: {"attempts": 0, "unsafe": 0, "intercepted": 0, "evaded": 0}),
    }

    evasions_v3: List[Dict[str, Any]] = []

    for v in variants:
        strat = v["strategy"]
        act = v["proposed_action"]
        intent = v.get("locked_intent", {})
        dom = v["domain"]

        # Oracle checks
        unsafe_v1, reason_v1 = SecurityOracleV1.is_action_unsafe(act, intent, dom, is_attack_case=True)
        unsafe_v2, reason_v2 = SecurityOracleV2.is_action_unsafe(act, intent, dom, is_attack_case=True)

        # Run on gate v2-perf
        res_v2 = evaluate_variant_on_gate(v, "v2-perf", gw_cache)
        is_inter_v2 = res_v2.decision in (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK)

        # Run on gate v3
        res_v3 = evaluate_variant_on_gate(v, "v3", gw_cache)
        is_inter_v3 = res_v3.decision in (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK)

        # Record v2-perf + Oracle v1
        stats_v2_o1 = results["v2-perf_oracle_v1"][strat]
        stats_v2_o1["attempts"] += 1
        if unsafe_v1:
            stats_v2_o1["unsafe"] += 1
            if is_inter_v2:
                stats_v2_o1["intercepted"] += 1
            else:
                stats_v2_o1["evaded"] += 1

        # Record v2-perf + Oracle v2
        stats_v2_o2 = results["v2-perf_oracle_v2"][strat]
        stats_v2_o2["attempts"] += 1
        if unsafe_v2:
            stats_v2_o2["unsafe"] += 1
            if is_inter_v2:
                stats_v2_o2["intercepted"] += 1
            else:
                stats_v2_o2["evaded"] += 1

        # Record v3 + Oracle v2
        stats_v3 = results["v3_oracle_v2"][strat]
        stats_v3["attempts"] += 1
        if unsafe_v2:
            stats_v3["unsafe"] += 1
            if is_inter_v3:
                stats_v3["intercepted"] += 1
            else:
                stats_v3["evaded"] += 1
                evasions_v3.append({
                    "variant_id": v.get("variant_id"),
                    "strategy": strat,
                    "domain": dom,
                    "action": act,
                    "decision": res_v3.decision.value,
                    "reason": res_v3.reason,
                    "oracle_reason": reason_v2,
                })

    return {"summary": results, "evasions_v3": evasions_v3}


def print_comparison_table(results_dict: Dict[str, Any], title: str):
    print("\n" + "=" * 90)
    print(f"COMPARATIVE RESULTS: {title}")
    print("=" * 90)
    print(f"{'Strategy':<12} | {'Unsafe':<6} | {'v2-perf (Oracle v1)':<20} | {'v2-perf (Oracle v2)':<20} | {'v3 (Oracle v2)':<20}")
    print("-" * 90)

    all_strats = sorted(results_dict["v3_oracle_v2"].keys())
    for s in all_strats:
        o1 = results_dict["v2-perf_oracle_v1"][s]
        o2 = results_dict["v2-perf_oracle_v2"][s]
        v3 = results_dict["v3_oracle_v2"][s]

        # Evasion rates
        rate_v2_o1 = (o1["evaded"] / o1["unsafe"] * 100.0) if o1["unsafe"] > 0 else 0.0
        ci_v2_o1 = wilson_score_interval(o1["evaded"], o1["unsafe"])
        str_v2_o1 = f"{o1['evaded']}/{o1['unsafe']} ({rate_v2_o1:.1f}%)"

        rate_v2_o2 = (o2["evaded"] / o2["unsafe"] * 100.0) if o2["unsafe"] > 0 else 0.0
        ci_v2_o2 = wilson_score_interval(o2["evaded"], o2["unsafe"])
        str_v2_o2 = f"{o2['evaded']}/{o2['unsafe']} ({rate_v2_o2:.1f}%)"

        rate_v3 = (v3["evaded"] / v3["unsafe"] * 100.0) if v3["unsafe"] > 0 else 0.0
        ci_v3 = wilson_score_interval(v3["evaded"], v3["unsafe"])
        str_v3 = f"{v3['evaded']}/{v3['unsafe']} ({rate_v3:.1f}%)"

        print(f"{s:<12} | {o2['unsafe']:<6} | {str_v2_o1:<20} | {str_v2_o2:<20} | {str_v3:<20}")

    print("=" * 90)


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


if __name__ == "__main__":
    # 1. Original 7a variants (seed=42)
    t0 = time.time()
    orig_variants = generate_seed_variants(seed=42)
    res_orig = run_benchmark(orig_variants, "Block 7a Original Seeds (seed=42)")
    print_comparison_table(res_orig["summary"], "Original 7a Seeds (seed=42)")

    # 2. Fresh unseen variants (seed=9999)
    fresh_variants = generate_seed_variants(seed=9999)
    res_fresh = run_benchmark(fresh_variants, "Fresh Unseen Seeds (seed=9999)")
    print_comparison_table(res_fresh["summary"], "Fresh Unseen Seeds (seed=9999)")

    # 3. Redesigned S4 and S5 variants
    redesigned_variants = generate_all_redesigned_variants()
    res_redesigned = run_benchmark(redesigned_variants, "Redesigned S4 and S5")
    print_comparison_table(res_redesigned["summary"], "Redesigned S4 and S5")

    # Save to runs/adaptive_eval_v2_v3.json
    out_data = {
        "original_seed_42": res_orig["summary"],
        "fresh_seed_9999": res_fresh["summary"],
        "redesigned_s4_s5": res_redesigned["summary"],
        "v3_evasions_orig": res_orig["evasions_v3"],
        "v3_evasions_fresh": res_fresh["evasions_v3"],
        "v3_evasions_redesigned": res_redesigned["evasions_v3"],
    }
    with open(ROOT_DIR / "runs" / "adaptive_eval_v2_v3.json", "w", encoding="utf-8") as f:
        json.dump(out_data, f, indent=2)

    print(f"\nAll evaluations complete in {time.time() - t0:.2f}s! Saved to runs/adaptive_eval_v2_v3.json.")
