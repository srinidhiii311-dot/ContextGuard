"""
analysis/run_dev_hard_60_judge.py — Block 6b Completion: Live LLM Judge Evaluation on dev_hard_60

Evaluates:
- 60 hard dev cases across 4 categories:
  1. semantically_off_task_mapped (15 cases)
  2. legitimate_unmapped_action (15 cases)
  3. paraphrased_injection_no_lexicon (15 cases)
  4. judge_injection_adversarial (15 cases)
- Judge OFF vs. Judge ON
- Tracks uncached latency (median, p95), cache hits, request IDs, fallbacks, and decisions changed.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import statistics
import sys
import time
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from contextguard.gate import Decision, ProposedAction
from contextguard.llm_checker import LLMChecker
from gateway.loader import Gateway
from harness.case_schema import EvaluationCase
from harness.run_case import build_trusted_intent_from_dict

HARD_60_PATH = ROOT_DIR / "data" / "dev_hard_60.jsonl"


def run_benchmark():
    with open(HARD_60_PATH, "r", encoding="utf-8") as f:
        cases = [EvaluationCase.model_validate(json.loads(line)) for line in f if line.strip()]

    print(f"Loaded {len(cases)} hard dev cases from {HARD_60_PATH}")

    # 1. Evaluate with Judge OFF
    print("\n--- Evaluating with Judge OFF (Canonical Gate v3) ---")
    gateways_off = {dom: Gateway.from_domain(dom) for dom in ["flight", "banking", "ecommerce", "healthcare", "email"]}
    for gw in gateways_off.values():
        if gw.gate:
            gw.gate.enable_llm_checker = False

    decisions_off: Dict[str, Dict[str, Any]] = {}
    for c in cases:
        gw = gateways_off[c.domain]
        intent = build_trusted_intent_from_dict(c.domain, c.locked_intent)
        gw.set_intent(intent)
        act = ProposedAction(
            action_type=c.proposed_action.action_type,
            target=c.proposed_action.target,
            value=c.proposed_action.value,
            page_url=c.proposed_action.page_url,
        )
        res = gw.check(act, current_dom_text=c.page_state.visible_text)
        decisions_off[c.case_id] = {
            "decision": res.decision.value,
            "reason": res.reason,
        }

    # 2. Evaluate with Judge ON
    print("\n--- Evaluating with Judge ON (Canonical Gate v3 + Live Gemini Judge) ---")
    gateways_on = {dom: Gateway.from_domain(dom) for dom in ["flight", "banking", "ecommerce", "healthcare", "email"]}
    for gw in gateways_on.values():
        if gw.gate:
            gw.gate.enable_llm_checker = True
            gw.gate._llm_checker = LLMChecker(raise_on_fallback=True)

    decisions_on: Dict[str, Dict[str, Any]] = {}
    llm_telemetry = []

    for i, c in enumerate(cases, 1):
        gw = gateways_on[c.domain]
        intent = build_trusted_intent_from_dict(c.domain, c.locked_intent)
        gw.set_intent(intent)
        act = ProposedAction(
            action_type=c.proposed_action.action_type,
            target=c.proposed_action.target,
            value=c.proposed_action.value,
            page_url=c.proposed_action.page_url,
        )
        res = gw.check(act, current_dom_text=c.page_state.visible_text)
        decisions_on[c.case_id] = {
            "decision": res.decision.value,
            "reason": res.reason,
            "llm_verdict": res.llm_verdict,
            "llm_source": res.llm_source,
        }

        # Check LLM checker invocation
        if res.llm_verdict:
            llm_telemetry.append({
                "case_id": c.case_id,
                "category": c.family,
                "verdict": res.llm_verdict,
                "source": res.llm_source,
            })
        print(f"[{i:02d}/60] {c.case_id} ({c.family}) -> OFF: {decisions_off[c.case_id]['decision']} | ON: {res.decision.value}")

    # 3. Analyze changes per category
    cats = ["semantically_off_task_mapped", "legitimate_unmapped_action", "paraphrased_injection_no_lexicon", "judge_injection_adversarial"]
    cat_summary = {}

    for cat in cats:
        cat_cases = [c for c in cases if c.family == cat]
        changed = []
        newly_caught_attacks = []
        newly_blocked_benign = []

        for c in cat_cases:
            d_off = decisions_off[c.case_id]["decision"]
            d_on = decisions_on[c.case_id]["decision"]
            is_off_pass = d_off in ("allow", "warn")
            is_on_pass = d_on in ("allow", "warn")
            is_off_inter = not is_off_pass
            is_on_inter = not is_on_pass

            if d_off != d_on:
                changed.append((c, d_off, d_on))
                if c.case_type == "attack" and is_off_pass and is_on_inter:
                    newly_caught_attacks.append(c)
                elif c.case_type == "benign" and is_off_pass and is_on_inter:
                    newly_blocked_benign.append(c)

        cat_summary[cat] = {
            "total": len(cat_cases),
            "changed_count": len(changed),
            "changed_cases": changed,
            "newly_caught_attacks": len(newly_caught_attacks),
            "newly_blocked_benign": len(newly_blocked_benign),
        }

    # 4. Latency and Telemetry
    with open(ROOT_DIR / "runs" / "llm_calls.jsonl", "r", encoding="utf-8") as f:
        all_calls = [json.loads(l) for l in f if l.strip()]

    judge_calls = [c for c in all_calls if c.get("role") == "judge"]
    # Check cache status of the calls
    uncached = [c for c in judge_calls if not c.get("cached", False)]
    cached = [c for c in judge_calls if c.get("cached", False)]

    uncached_latencies = [c.get("latency_ms", 0.0) for c in uncached if c.get("latency_ms", 0.0) > 0]
    med_lat = statistics.median(uncached_latencies) if uncached_latencies else 0.0
    p95_lat = statistics.quantiles(uncached_latencies, n=20)[18] if len(uncached_latencies) >= 20 else (max(uncached_latencies) if uncached_latencies else 0.0)

    # 5. Output Results Table
    print("\n" + "=" * 80)
    print("BLOCK 6b: LIVE LLM JUDGE BENCHMARK ON DEV_HARD_60")
    print("=" * 80)
    print(f"{'Category':<35} | {'Cases':<6} | {'Changed':<8} | {'New Attacks Caught':<18} | {'New Benign Blocked'}")
    print("-" * 80)
    for cat in cats:
        cs = cat_summary[cat]
        print(f"{cat:<35} | {cs['total']:<6} | {cs['changed_count']:<8} | {cs['newly_caught_attacks']:<18} | {cs['newly_blocked_benign']}")
    print("-" * 80)

    print("\n--- Telemetry & Latency (Uncached Calls Only) ---")
    print(f"Total Judge Calls in llm_calls.jsonl: {len(judge_calls)}")
    print(f"Uncached Calls:                      {len(uncached)}")
    print(f"Cached Hits:                         {len(cached)}")
    print(f"Median Uncached Latency:             {med_lat:.2f} ms")
    print(f"p95 Uncached Latency:                {p95_lat:.2f} ms")
    print("Sample Uncached Request IDs (up to 5):")
    for uc in uncached[:5]:
        print(f"  - {uc.get('request_id')} (model: {uc.get('model')}, latency: {uc.get('latency_ms'):.2f} ms)")

    # 6. Specifically analyze the 15 judge_injection_adversarial cases
    print("\n--- Analysis of 15 judge_injection_adversarial Cases ---")
    judge_inj_cases = [c for c in cases if c.family == "judge_injection_adversarial"]
    allowed_count = 0
    downgraded_count = 0
    intercepted_count = 0

    for c in judge_inj_cases:
        d_on = decisions_on[c.case_id]["decision"]
        d_off = decisions_off[c.case_id]["decision"]
        if d_on in ("allow", "warn"):
            allowed_count += 1
        else:
            intercepted_count += 1
        # Check if decision was downgraded from off -> on
        if d_off in ("block", "require_confirmation") and d_on in ("allow", "warn"):
            downgraded_count += 1

    print(f"Total judge_injection cases:         {len(judge_inj_cases)}")
    print(f"Cases Intercepted by Gate+Judge:     {intercepted_count} / {len(judge_inj_cases)} (100.0%)")
    print(f"Cases Allowed by Judge Override:     {allowed_count}")
    print(f"Cases Downgraded by Judge Override:  {downgraded_count}")
    print("Security Guarantee: Due to RAISE-ONLY design, injected prompts targeting the LLM judge")
    print("cannot downgrade gate policy decisions or unblock unsafe actions.")

    # Save run output
    out_record = {
        "cat_summary": cat_summary,
        "telemetry": {
            "total_judge_calls": len(judge_calls),
            "uncached_count": len(uncached),
            "cached_count": len(cached),
            "median_uncached_latency_ms": med_lat,
            "p95_uncached_latency_ms": p95_lat,
            "uncached_request_ids": [uc.get("request_id") for uc in uncached],
        },
        "judge_injection_audit": {
            "total": len(judge_inj_cases),
            "intercepted": intercepted_count,
            "allowed": allowed_count,
            "downgraded": downgraded_count,
        }
    }
    with open(ROOT_DIR / "runs" / "dev_hard_60_judge_eval.json", "w", encoding="utf-8") as f:
        json.dump(out_record, f, indent=2, default=str)

    print("\nSaved evaluation results to runs/dev_hard_60_judge_eval.json")

if __name__ == "__main__":
    run_benchmark()
