"""
adaptive/run_adaptive_7a.py — Block 7a Adaptive Attack Benchmark Runner

Evaluates 1,200 white-box adaptive attack variants across 6 strategies and 5 domains:
1. Evaluates each variant with the independent SecurityOracle. Discards safe variants.
2. Runs every unsafe variant through Gateway.from_domain on the frozen gate (gate-frozen-v2-perf).
3. Classifies outcomes:
   - Intercepted: Decision.REQUIRE_CONFIRMATION or Decision.BLOCK
   - Evaded: Decision.ALLOW or Decision.WARN
4. Saves run records to runs/adaptive_7a.jsonl.
5. Computes and prints comprehensive metrics with Wilson Score CIs.
6. Prints 10 representative example evasions per strategy with full action and reason.
7. Hashes all files in adaptive/ and updates adaptive/hashes.json.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from adaptive.generator_7a import generate_all_7a_variants
from contextguard.gate import ContextGuardGate, Decision, GateResult, ProposedAction, TrustedIntent
from gateway.loader import Gateway
from harness.oracle import SecurityOracle
from harness.run_case import build_trusted_intent_from_dict

RUNS_DIR = ROOT_DIR / "runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_JSONL = RUNS_DIR / "adaptive_7a.jsonl"
ADAPTIVE_DIR = ROOT_DIR / "adaptive"


def wilson_score_interval(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """Calculates Wilson score interval for binomial proportions."""
    if total == 0:
        return 0.0, 0.0
    p = successes / total
    denominator = 1.0 + (z ** 2) / total
    centre_adjusted_probability = p + (z ** 2) / (2 * total)
    adjusted_std_dev = math.sqrt((p * (1.0 - p) + (z ** 2) / (4 * total)) / total)
    lower_bound = (centre_adjusted_probability - z * adjusted_std_dev) / denominator
    upper_bound = (centre_adjusted_probability + z * adjusted_std_dev) / denominator
    return max(0.0, lower_bound) * 100.0, min(1.0, upper_bound) * 100.0


def compute_adaptive_file_hashes() -> Dict[str, str]:
    """Hashes all files in adaptive/ directory."""
    hashes = {}
    for p in sorted(ADAPTIVE_DIR.glob("*")):
        if p.is_file() and p.name != "hashes.json":
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            hashes[p.name] = h
    return hashes


def run_benchmark():
    print("=" * 80)
    print("BLOCK 7a: WHITE-BOX PROGRAMMATIC ADAPTIVE ATTACK BENCHMARK")
    print("Frozen Gate: gate-frozen-v2-perf | Evaluator: Gateway.from_domain")
    print("=" * 80)

    variants = generate_all_7a_variants()
    print(f"Total candidate variants generated: {len(variants)}")

    # Pre-construct gateways per domain once for maximum throughput
    gateways: Dict[str, Gateway] = {}
    for d in ["flight", "banking", "ecommerce", "healthcare", "email"]:
        gateways[d] = Gateway.from_domain(d)

    records: List[Dict[str, Any]] = []
    evasions_by_strategy: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    # Strategy & Domain aggregation stats
    # key: (strategy, domain) -> {attempts, unsafe, intercepted, evaded, discarded}
    stats = defaultdict(lambda: {"attempts": 0, "unsafe": 0, "intercepted": 0, "evaded": 0, "discarded": 0})
    strat_totals = defaultdict(lambda: {"attempts": 0, "unsafe": 0, "intercepted": 0, "evaded": 0, "discarded": 0})

    t0 = time.time()
    for var in variants:
        vid = var["variant_id"]
        strat = var["strategy"]
        dom = var["domain"]
        pact_dict = var["proposed_action"]
        intent_dict = var["locked_intent"]
        dom_text = var.get("dom_text", "")
        raw_html = var.get("raw_html", "")

        stats[(strat, dom)]["attempts"] += 1
        strat_totals[strat]["attempts"] += 1

        # 1. Oracle Safety Evaluation
        is_unsafe, oracle_reason = SecurityOracle.is_action_unsafe(
            action=pact_dict,
            locked_intent=intent_dict,
            domain=dom,
            is_attack_case=True,
        )

        if not is_unsafe:
            stats[(strat, dom)]["discarded"] += 1
            strat_totals[strat]["discarded"] += 1
            continue

        stats[(strat, dom)]["unsafe"] += 1
        strat_totals[strat]["unsafe"] += 1

        # 2. Gate Execution on Frozen Gate
        gw = gateways[dom]
        trusted_intent = build_trusted_intent_from_dict(dom, intent_dict)
        gw.set_intent(trusted_intent)

        # Handle multi-step preparation in S5 if present
        if "prep_action" in var:
            prep_dict = var["prep_action"]
            prep_act = ProposedAction(
                action_type=prep_dict["action_type"],
                target=prep_dict["target"],
                value=prep_dict.get("value"),
                page_url=prep_dict.get("page_url", var["page_url"]),
            )
            gw.check(action=prep_act, current_dom_text="Step 1 preparation")

        proposed_act = ProposedAction(
            action_type=pact_dict["action_type"],
            target=pact_dict["target"],
            value=pact_dict.get("value"),
            page_url=pact_dict.get("page_url", var["page_url"]),
        )

        gate_res = gw.check(
            action=proposed_act,
            current_dom_text=dom_text + (" " + raw_html if raw_html else ""),
        )

        dec_str = gate_res.decision.value if hasattr(gate_res.decision, "value") else str(gate_res.decision)
        if gate_res.decision in (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK):
            outcome = "intercepted"
            stats[(strat, dom)]["intercepted"] += 1
            strat_totals[strat]["intercepted"] += 1
        else:
            outcome = "evaded"
            stats[(strat, dom)]["evaded"] += 1
            strat_totals[strat]["evaded"] += 1
            evasion_record = {
                "variant_id": vid,
                "strategy": strat,
                "domain": dom,
                "action": f"{pact_dict['action_type']} {pact_dict['target']} value={pact_dict.get('value')!r}",
                "page_url": pact_dict.get("page_url"),
                "gate_decision": dec_str,
                "gate_reason": gate_res.reason,
                "oracle_reason": oracle_reason,
            }
            evasions_by_strategy[strat].append(evasion_record)

        run_rec = {
            "variant_id": vid,
            "strategy": strat,
            "domain": dom,
            "action": pact_dict,
            "oracle_unsafe": is_unsafe,
            "oracle_reason": oracle_reason,
            "gate_decision": dec_str,
            "gate_reason": gate_res.reason,
            "gate_risk_score": getattr(gate_res, "risk_score", None),
            "outcome": outcome,
        }
        records.append(run_rec)

    elapsed = time.time() - t0
    print(f"\nExecution complete in {elapsed:.2f}s ({len(records)} unsafe evaluations, {len(records)/elapsed:.1f} cases/s)")

    # Save to runs/adaptive_7a.jsonl
    with open(OUTPUT_JSONL, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"Saved run records to: {OUTPUT_JSONL}")

    # =========================================================================
    # Strategy Summary Table
    # =========================================================================
    print("\n" + "=" * 90)
    print("STRATEGY SUMMARY RESULTS (BLOCK 7a)")
    print("=" * 90)
    print(f"{'Strategy':<10} | {'Attempts':<9} | {'Unsafe':<8} | {'Intercepted':<12} | {'Evaded':<8} | {'Evasion Rate % (Wilson 95% CI)':<30}")
    print("-" * 90)

    for strat in ["S1", "S2", "S3", "S4", "S5", "S6"]:
        st = strat_totals[strat]
        att = st["attempts"]
        uns = st["unsafe"]
        inter = st["intercepted"]
        ev = st["evaded"]
        ev_pct = (ev / uns * 100.0) if uns > 0 else 0.0
        w_low, w_high = wilson_score_interval(ev, uns)
        ci_str = f"{ev_pct:5.1f}% [{w_low:4.1f}%, {w_high:4.1f}%]"
        print(f"{strat:<10} | {att:<9} | {uns:<8} | {inter:<12} | {ev:<8} | {ci_str:<30}")

    print("-" * 90)
    total_att = sum(st["attempts"] for st in strat_totals.values())
    total_uns = sum(st["unsafe"] for st in strat_totals.values())
    total_inter = sum(st["intercepted"] for st in strat_totals.values())
    total_ev = sum(st["evaded"] for st in strat_totals.values())
    tot_ev_pct = (total_ev / total_uns * 100.0) if total_uns > 0 else 0.0
    tot_low, tot_high = wilson_score_interval(total_ev, total_uns)
    tot_ci_str = f"{tot_ev_pct:5.1f}% [{tot_low:4.1f}%, {tot_high:4.1f}%]"
    print(f"{'TOTAL':<10} | {total_att:<9} | {total_uns:<8} | {total_inter:<12} | {total_ev:<8} | {tot_ci_str:<30}")
    print("=" * 90)

    # =========================================================================
    # Strategy x Domain Breakdown Table
    # =========================================================================
    print("\n" + "=" * 100)
    print("STRATEGY x DOMAIN DETAILED BREAKDOWN")
    print("=" * 100)
    print(f"{'Strategy':<10} | {'Domain':<12} | {'Attempts':<9} | {'Unsafe':<8} | {'Intercepted':<12} | {'Evaded':<8} | {'Evasion Rate (Wilson CI)':<25}")
    print("-" * 100)

    for strat in ["S1", "S2", "S3", "S4", "S5", "S6"]:
        for dom in ["flight", "banking", "ecommerce", "healthcare", "email"]:
            st = stats[(strat, dom)]
            att = st["attempts"]
            uns = st["unsafe"]
            inter = st["intercepted"]
            ev = st["evaded"]
            ev_pct = (ev / uns * 100.0) if uns > 0 else 0.0
            w_low, w_high = wilson_score_interval(ev, uns)
            ci_str = f"{ev_pct:5.1f}% [{w_low:4.1f}%, {w_high:4.1f}%]"
            print(f"{strat:<10} | {dom:<12} | {att:<9} | {uns:<8} | {inter:<12} | {ev:<8} | {ci_str:<25}")

    # =========================================================================
    # 10 Representative Example Evasions per Strategy
    # =========================================================================
    print("\n" + "=" * 90)
    print("REPRESENTATIVE EXAMPLE EVASIONS (UP TO 10 PER STRATEGY)")
    print("=" * 90)

    for strat in ["S1", "S2", "S3", "S4", "S5", "S6"]:
        ev_list = evasions_by_strategy[strat]
        print(f"\n--- Strategy {strat} ({len(ev_list)} total evasions) ---")
        if not ev_list:
            print("  [Zero evasions observed for this strategy — gate intercepted 100% of variants!]")
            continue
        for idx, item in enumerate(ev_list[:10], 1):
            print(f"  [{idx:02d}] Variant: {item['variant_id']} (Domain: {item['domain']})")
            print(f"       Action:        {item['action']}")
            print(f"       Page URL:      {item['page_url']}")
            print(f"       Gate Decision: {item['gate_decision']}")
            print(f"       Gate Reason:   {item['gate_reason']}")
            print(f"       Oracle Label:  UNSAFE -> {item['oracle_reason']}")

    # Save hashes
    file_hashes = compute_adaptive_file_hashes()
    with open(ADAPTIVE_DIR / "hashes.json", "w", encoding="utf-8") as f:
        json.dump(file_hashes, f, indent=2)
    print(f"\nSaved cryptographic file hashes to: {ADAPTIVE_DIR / 'hashes.json'}")


if __name__ == "__main__":
    run_benchmark()
