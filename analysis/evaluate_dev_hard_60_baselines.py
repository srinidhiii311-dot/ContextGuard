"""
analysis/evaluate_dev_hard_60_baselines.py — Block 8e Item 2: All Baselines on dev_hard_60 by Category

Evaluates on dev_hard_60 (60 cases across 4 categories):
  1. Regex-Only Filter
  2. LLM-Judge-Only Gate
  3. Tool-Allowlist Gate
  4. ContextGuard Gate (Canonical Config D)
  5. ContextGuard Gate + LLM Judge (Config H)

Categories (15 cases each):
  - semantically_off_task_mapped (Attack)
  - legitimate_unmapped_action (Benign)
  - paraphrased_injection_no_lexicon (Attack)
  - judge_injection_adversarial (Attack)
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from contextguard.gate import Decision, ProposedAction
from contextguard.llm_checker import LLMChecker, build_judge_prompt
from gateway.loader import Gateway
from harness.case_schema import EvaluationCase
from harness.configs import TAXONOMY_REGEX
from harness.oracle_v3 import DOMAIN_ALLOWLISTS
from harness.run_case import build_trusted_intent_from_dict
from llm.client import LLMClient


def load_dev_hard_cases() -> List[EvaluationCase]:
    hard_path = ROOT_DIR / "data" / "dev_hard_60.jsonl"
    cases = []
    with open(hard_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            cases.append(EvaluationCase.model_validate(json.loads(line.strip())))
    return cases


def load_manifests() -> Dict[str, Dict[str, Any]]:
    manifests = {}
    for dom in ["flight", "banking", "ecommerce", "healthcare", "email"]:
        mpath = ROOT_DIR / "sandboxes" / dom / "manifest.json"
        if mpath.exists():
            with open(mpath, "r", encoding="utf-8") as f:
                data = json.load(f)
                allowed_actions = set()
                for a in data.get("allowed_actions", []):
                    allowed_actions.add((a["action_type"].upper(), a["target"].lower()))
                manifests[dom] = {
                    "base_url": data.get("base_url", ""),
                    "allowed_actions": allowed_actions,
                }
    return manifests


def eval_regex(case: EvaluationCase) -> str:
    text_to_scan = (
        f"{case.page_state.visible_text or ''} "
        f"{case.page_state.raw_html or ''} "
        f"{case.proposed_action.source_text or ''} "
        f"{case.proposed_action.value or ''} "
        f"{case.proposed_action.target or ''}"
    )
    hit = bool(TAXONOMY_REGEX.search(text_to_scan))
    return "BLOCK" if hit else "ALLOW"


def eval_judge_only(case: EvaluationCase, client: LLMClient) -> str:
    action_dict = {
        "type": case.proposed_action.action_type,
        "target": case.proposed_action.target,
        "value": case.proposed_action.value,
        "url": case.proposed_action.page_url,
    }
    prompt = build_judge_prompt(case.locked_intent, action_dict)
    resp = client.call(role="judge", prompt=prompt, use_cache=True)
    try:
        clean = resp.content.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:].strip()
        data = json.loads(clean)
        consistent = data.get("consistent", True)
    except Exception:
        consistent = True
    return "ALLOW" if consistent else "BLOCK"


def eval_allowlist(case: EvaluationCase, manifests: Dict[str, Dict[str, Any]]) -> str:
    dom = case.domain
    act_type = case.proposed_action.action_type.upper()
    target = case.proposed_action.target

    m = manifests.get(dom, {})
    allowed_acts = m.get("allowed_actions", set())
    domain_allowlist = DOMAIN_ALLOWLISTS.get(dom, set())

    allowed = False
    if act_type == "NAVIGATE":
        target_lower = target.lower()
        if any(h in target_lower for h in domain_allowlist) or target.startswith("/"):
            allowed = True
    else:
        if (act_type, target.lower()) in allowed_acts or ("*", target.lower()) in allowed_acts:
            allowed = True
    return "ALLOW" if allowed else "BLOCK"


def eval_canonical_gate(case: EvaluationCase, gw: Gateway) -> str:
    p_act = ProposedAction(
        action_type=case.proposed_action.action_type,
        target=case.proposed_action.target,
        value=case.proposed_action.value,
        page_url=case.proposed_action.page_url,
        source_text=case.proposed_action.source_text,
    )
    res = gw.check(p_act, current_dom_text=case.page_state.visible_text)
    if res.decision in (Decision.BLOCK, Decision.REQUIRE_CONFIRMATION):
        return "BLOCK"
    return "ALLOW"


def eval_gate_judge(case: EvaluationCase, gw_judge: Gateway) -> Tuple[str, bool]:
    p_act = ProposedAction(
        action_type=case.proposed_action.action_type,
        target=case.proposed_action.target,
        value=case.proposed_action.value,
        page_url=case.proposed_action.page_url,
        source_text=case.proposed_action.source_text,
        raw_html=case.page_state.raw_html,
    )
    res = gw_judge.check(p_act, current_dom_text=case.page_state.visible_text)
    called_judge = bool(res.llm_verdict and not res.llm_verdict.get("error"))
    dec = "BLOCK" if res.decision in (Decision.BLOCK, Decision.REQUIRE_CONFIRMATION) else "ALLOW"
    return dec, called_judge


def main():
    cases = load_dev_hard_cases()
    manifests = load_manifests()
    client = LLMClient()

    categories = [
        "semantically_off_task_mapped",
        "legitimate_unmapped_action",
        "paraphrased_injection_no_lexicon",
        "judge_injection_adversarial",
    ]

    # Pre-instantiate gateways
    gateways_canonical = {dom: Gateway.from_domain(dom) for dom in ["flight", "banking", "ecommerce", "healthcare", "email"]}
    gateways_judge = {}
    for dom in ["flight", "banking", "ecommerce", "healthcare", "email"]:
        gw = Gateway.from_domain(dom)
        gw.gate.enable_llm_checker = True
        gw.gate._llm_checker = LLMChecker(raise_on_fallback=False)
        gateways_judge[dom] = gw

    results_by_cat = {cat: {} for cat in categories}
    systems = ["Regex-Only", "LLM-Judge-Only", "Tool-Allowlist", "ContextGuard Gate (v3.1)", "ContextGuard Gate + Judge (Config H)"]
    for cat in categories:
        for sys_name in systems:
            results_by_cat[cat][sys_name] = {"total": 0, "intercepted": 0, "allowed": 0, "reached_judge": 0}

    for c in cases:
        cat = c.family
        t_intent = build_trusted_intent_from_dict(c.domain, c.locked_intent)

        # Regex
        r_dec = eval_regex(c)
        results_by_cat[cat]["Regex-Only"]["total"] += 1
        if r_dec == "BLOCK": results_by_cat[cat]["Regex-Only"]["intercepted"] += 1
        else: results_by_cat[cat]["Regex-Only"]["allowed"] += 1

        # LLM Judge Only
        j_dec = eval_judge_only(c, client)
        results_by_cat[cat]["LLM-Judge-Only"]["total"] += 1
        if j_dec == "BLOCK": results_by_cat[cat]["LLM-Judge-Only"]["intercepted"] += 1
        else: results_by_cat[cat]["LLM-Judge-Only"]["allowed"] += 1

        # Tool Allowlist
        a_dec = eval_allowlist(c, manifests)
        results_by_cat[cat]["Tool-Allowlist"]["total"] += 1
        if a_dec == "BLOCK": results_by_cat[cat]["Tool-Allowlist"]["intercepted"] += 1
        else: results_by_cat[cat]["Tool-Allowlist"]["allowed"] += 1

        # Canonical Gate
        gw = gateways_canonical[c.domain]
        gw.set_intent(t_intent)
        g_dec = eval_canonical_gate(c, gw)
        results_by_cat[cat]["ContextGuard Gate (v3.1)"]["total"] += 1
        if g_dec == "BLOCK": results_by_cat[cat]["ContextGuard Gate (v3.1)"]["intercepted"] += 1
        else: results_by_cat[cat]["ContextGuard Gate (v3.1)"]["allowed"] += 1

        # Gate + Judge
        gw_j = gateways_judge[c.domain]
        gw_j.set_intent(t_intent)
        gj_dec, called_j = eval_gate_judge(c, gw_j)
        results_by_cat[cat]["ContextGuard Gate + Judge (Config H)"]["total"] += 1
        if gj_dec == "BLOCK": results_by_cat[cat]["ContextGuard Gate + Judge (Config H)"]["intercepted"] += 1
        else: results_by_cat[cat]["ContextGuard Gate + Judge (Config H)"]["allowed"] += 1
        if called_j: results_by_cat[cat]["ContextGuard Gate + Judge (Config H)"]["reached_judge"] += 1

    print("=" * 105)
    print("                    DEV_HARD_60 BASELINES & ARCHITECTURES BREAKDOWN")
    print("=" * 105)
    print(f"{'Category (N=15)':<36} | {'System':<34} | {'Intercepted':<12} | {'Outcome':<14}")
    print("-" * 105)

    for cat in categories:
        is_attack = (cat != "legitimate_unmapped_action")
        target_metric = "Recall" if is_attack else "Over-block"
        print(f"[{cat.upper()}] (Type: {'Attack' if is_attack else 'Benign'})")
        for sys_name in systems:
            d = results_by_cat[cat][sys_name]
            inter = d["intercepted"]
            tot = d["total"]
            pct = inter / tot * 100.0
            rj_str = f" (reached judge: {d['reached_judge']})" if "Judge" in sys_name and d["reached_judge"] > 0 else ""
            print(f"  {'':<34} | {sys_name:<34} | {inter:>2}/{tot} ({pct:5.1f}%) | {target_metric}: {inter:>2}/{tot}{rj_str}")
        print("-" * 105)

    # Save output to runs/dev_hard_60_baselines.json
    out_file = ROOT_DIR / "runs" / "dev_hard_60_baselines.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results_by_cat, f, indent=2)
    print(f"\nSaved raw results to {out_file}")


if __name__ == "__main__":
    main()

