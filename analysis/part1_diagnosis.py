"""
analysis/part1_diagnosis.py — Comprehensive Diagnostic Audit for Block 4b (Part 1)
"""

from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from harness.case_schema import EvaluationCase
from gateway.loader import Gateway
from contextguard.gate import ProposedAction, TrustedIntent
from harness.run_case import build_trusted_intent_from_dict

# 1. Load run files
dual_gate_runs = {}
with open(ROOT_DIR / "runs" / "dual_gate_42.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        dual_gate_runs[r["task_id"]] = r

taxonomy_runs = {}
with open(ROOT_DIR / "runs" / "taxonomy_only_42.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        taxonomy_runs[r["task_id"]] = r

llm_runs = {}
with open(ROOT_DIR / "runs" / "dual_gate_llm_42.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        llm_runs[r["task_id"]] = r

# 2. Load EvaluationCases for dev split
dev_cases_by_id = {}
for p in [ROOT_DIR / "attacks" / "dev" / "cases.jsonl", ROOT_DIR / "benign" / "dev" / "cases.jsonl"]:
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            c = EvaluationCase.model_validate(json.loads(line))
            dev_cases_by_id[c.case_id] = c


def is_intercepted(dec: str) -> bool:
    return dec.lower() in ("block", "ask_human", "require_confirmation", "pause_task")


# ==============================================================================
# Part 1.1: The 76 Compromised Dev Attacks Missed by dual_gate but Caught by taxonomy_only
# ==============================================================================
missed_76_ids = []
for cid, r_dual in dual_gate_runs.items():
    r_tax = taxonomy_runs.get(cid)
    if not r_tax:
        continue
    c = dev_cases_by_id[cid]
    if c.case_type == "attack" and c.ground_truth_label != "attack_uncompromised":
        # Compromised attack
        tax_stopped = is_intercepted(r_tax["decision"])
        dual_stopped = is_intercepted(r_dual["decision"])
        if tax_stopped and not dual_stopped:
            missed_76_ids.append(cid)

print(f"Total compromised attacks missed by dual_gate but caught by taxonomy_only: {len(missed_76_ids)}")

# Analysis of the 76 misses
by_domain = Counter()
by_family = Counter()
by_action_type = Counter()
by_field_deviation = Counter()
detailed_misses = []

for cid in missed_76_ids:
    c = dev_cases_by_id[cid]
    by_domain[c.domain] += 1
    by_family[c.family] += 1
    atype = c.proposed_action.action_type
    by_action_type[atype] += 1

    # Check whether proposed value deviates from locked_intent on a mapped field
    # Build gateway to inspect mapped fields
    gw = Gateway.from_domain(c.domain)
    target_clean = c.proposed_action.target.lstrip("#.").replace("-", "_").lower()
    val = str(c.proposed_action.value or "").strip()

    # Check mapped fields in verifier
    mapped = False
    deviates = False
    if gw.gate and gw.gate.verifier:
        for tgt_k, mapping in gw.gate.verifier.target_mappings.items():
            if tgt_k.lower() in target_clean or target_clean in tgt_k.lower():
                mapped = True
                intent_f = mapping.get("intent_field")
                if intent_f:
                    exp_val = str(c.locked_intent.get(intent_f, "")).strip()
                    if exp_val and val.lower() != exp_val.lower():
                        deviates = True
                break

    if not mapped:
        field_status = "unmapped_target"
    elif deviates:
        field_status = "mapped_deviates"
    else:
        field_status = "mapped_matches_or_empty"
    by_field_deviation[field_status] += 1

    # Run single case through gate to capture exact risk assessment components
    intent = build_trusted_intent_from_dict(c.domain, c.locked_intent)
    gw_eval = Gateway.from_domain(c.domain, trusted_intent=intent)
    p_act = ProposedAction(
        action_type=c.proposed_action.action_type,
        target=c.proposed_action.target,
        value=c.proposed_action.value,
        page_url=c.proposed_action.page_url,
        source_text=c.proposed_action.source_text,
        raw_html=c.page_state.raw_html,
    )
    res = gw_eval.check(p_act, current_dom_text=c.page_state.visible_text)
    detailed_misses.append({
        "case_id": c.case_id,
        "domain": c.domain,
        "family": c.family,
        "action_type": c.proposed_action.action_type,
        "target": c.proposed_action.target,
        "value": c.proposed_action.value,
        "field_status": field_status,
        "decision": res.decision.value,
        "reason": res.reason,
        "risk_score": res.risk_score,
        "risk_tier": res.risk_tier,
        "confidence": res.confidence,
        "deviation_signal": res.deviation_signal,
        "marker_hit": res.marker_hit,
        "factors": res.factor_breakdown,
    })

print("\n--- Summary Breakdown of the 76 Misses ---")
print("By Domain:", dict(by_domain))
print("By Family:", dict(by_family))
print("By Proposed Action Type:", dict(by_action_type))
print("By Field Deviation Status:", dict(by_field_deviation))

# Save 10 detailed misses to JSON
with open(ROOT_DIR / "analysis" / "sample_10_misses.json", "w", encoding="utf-8") as f:
    json.dump(detailed_misses[:10], f, indent=2)


# ==============================================================================
# Part 1.2: The 20 benign_hard Intercepts
# ==============================================================================
benign_hard_intercepts = []
for cid, r_dual in dual_gate_runs.items():
    c = dev_cases_by_id[cid]
    if c.case_type == "benign" and c.family == "benign_hard":
        if is_intercepted(r_dual["decision"]):
            # Check if action matched intent
            target_clean = c.proposed_action.target.lstrip("#.").replace("-", "_").lower()
            val = str(c.proposed_action.value or "").strip()
            # Run gate to see fired rule and components
            intent = build_trusted_intent_from_dict(c.domain, c.locked_intent)
            gw_eval = Gateway.from_domain(c.domain, trusted_intent=intent)
            p_act = ProposedAction(
                action_type=c.proposed_action.action_type,
                target=c.proposed_action.target,
                value=c.proposed_action.value,
                page_url=c.proposed_action.page_url,
                source_text=c.proposed_action.source_text,
                raw_html=c.page_state.raw_html,
            )
            res = gw_eval.check(p_act, current_dom_text=c.page_state.visible_text)
            
            # Check match against locked intent
            matches_intent = False
            for k, v in c.locked_intent.items():
                if str(v).lower() == val.lower() and val:
                    matches_intent = True
                    break

            benign_hard_intercepts.append({
                "case_id": c.case_id,
                "domain": c.domain,
                "decision": r_dual["decision"],
                "reason": res.reason,
                "action_type": c.proposed_action.action_type,
                "target": c.proposed_action.target,
                "value": c.proposed_action.value,
                "matches_intent": matches_intent,
                "risk_score": res.risk_score,
                "risk_tier": res.risk_tier,
            })

print(f"\nTotal benign_hard intercepts: {len(benign_hard_intercepts)}")
with open(ROOT_DIR / "analysis" / "benign_hard_20_intercepts.json", "w", encoding="utf-8") as f:
    json.dump(benign_hard_intercepts, f, indent=2)


# ==============================================================================
# Part 1.3: Action-Type Mix and Family Detection Analysis
# ==============================================================================
family_action_mix = defaultdict(Counter)
family_action_detection = defaultdict(lambda: defaultdict(lambda: {"total": 0, "detected": 0}))

for cid, c in dev_cases_by_id.items():
    if c.case_type == "attack" and c.ground_truth_label != "attack_uncompromised":
        fam = c.family
        atype = c.proposed_action.action_type
        family_action_mix[fam][atype] += 1
        
        is_det = is_intercepted(dual_gate_runs[cid]["decision"])
        family_action_detection[fam][atype]["total"] += 1
        if is_det:
            family_action_detection[fam][atype]["detected"] += 1

print("\n--- Action Type Mix per Family ---")
for fam, acts in family_action_mix.items():
    print(f"Family '{fam}': {dict(acts)}")


# ==============================================================================
# Part 1.4: LLM Checker Audit on the 95 Invoked Cases
# ==============================================================================
llm_invoked_cases = []
for cid, r_llm in llm_runs.items():
    call = r_llm.get("llm_call")
    if call:
        r_dual = dual_gate_runs[cid]
        c = dev_cases_by_id[cid]
        llm_invoked_cases.append({
            "task_id": cid,
            "case_type": c.case_type,
            "ground_truth_label": c.ground_truth_label,
            "provider": call.get("provider"),
            "model": call.get("model"),
            "request_id": call.get("request_id"),
            "latency_ms": call.get("latency_ms"),
            "dual_gate_decision": r_dual["decision"],
            "llm_gate_decision": r_llm["decision"],
            "decision_changed": r_dual["decision"] != r_llm["decision"],
        })

print(f"\nTotal LLM invoked cases: {len(llm_invoked_cases)}")
changed_decisions = sum(1 for x in llm_invoked_cases if x["decision_changed"])
print(f"Verdicts different from rule decision: {changed_decisions}")
with open(ROOT_DIR / "analysis" / "llm_95_invocations.json", "w", encoding="utf-8") as f:
    json.dump(llm_invoked_cases, f, indent=2)

print("\nDiagnosis computation complete. Artifacts written to analysis/")

