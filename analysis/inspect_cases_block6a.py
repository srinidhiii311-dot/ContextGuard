import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness.case_schema import EvaluationCase
from harness.configs import evaluate_case_with_config
from gateway.loader import Gateway

gw_cache = {}

out_f = open("analysis/inspect_cases_output.txt", "w", encoding="utf-8")

def log(msg=""):
    print(msg)
    out_f.write(msg + "\n")

log("=" * 80)
log("1. DETAILED ANALYSIS OF THE 30 MISSED COMPROMISED ATTACKS")
log("=" * 80)

missed = []
with open("attacks/dev/cases.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        c = EvaluationCase.model_validate(json.loads(line))
        if c.ground_truth_label == "attack_divergent":
            rec = evaluate_case_with_config(c, config="dual_gate", seed=42, gateway_cache=gw_cache)
            if rec.decision in ("allow", "allow_with_flag", "warn", "flag"):
                gw = gw_cache.get(f"full_{c.domain}")
                mapped = False
                if gw and gw.gate and gw.gate._verifier:
                    tgt_clean = (c.proposed_action.target or "").strip().lower()
                    bare = tgt_clean.lstrip("#.")
                    mapped = (
                        tgt_clean in gw.gate._verifier.target_mappings
                        or bare in gw.gate._verifier.target_mappings
                        or any(tgt_clean in m.get("target_selectors", []) for m in gw.gate._verifier.target_mappings.values())
                    )
                missed.append((c, rec, mapped))

for idx, (c, rec, mapped) in enumerate(missed, 1):
    act = c.proposed_action
    log(f"\n[{idx}/30] Case ID: {c.case_id} | Family: {c.family} | Domain: {c.domain}")
    log(f"  User Task       : {c.user_task}")
    log(f"  Locked Intent   : {c.locked_intent}")
    log(f"  Proposed Action : type={act.action_type}, target={act.target}, value={act.value}, url={act.page_url}")
    log(f"  Target Mapped?  : {mapped}")
    log(f"  Gate Decision   : {rec.decision}")
    log(f"  Rationale       : {c.rationale}")

log("\n" + "=" * 80)
log("2. DETAILED ANALYSIS OF THE 10 BENIGN NORMAL INTERCEPTS")
log("=" * 80)

benign_intercepts = []
with open("benign/dev/cases.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        c = EvaluationCase.model_validate(json.loads(line))
        if c.family != "benign_hard":
            rec = evaluate_case_with_config(c, config="dual_gate", seed=42, gateway_cache=gw_cache)
            if rec.decision in ("block", "ask_human", "require_confirmation", "pause_task"):
                benign_intercepts.append((c, rec))

for idx, (c, rec) in enumerate(benign_intercepts, 1):
    act = c.proposed_action
    log(f"\n[{idx}/10] Case ID: {c.case_id} | Domain: {c.domain} | Decision: {rec.decision}")
    log(f"  User Task       : {c.user_task}")
    log(f"  Locked Intent   : {c.locked_intent}")
    log(f"  Proposed Action : type={act.action_type}, target={act.target}, value={act.value}, url={act.page_url}")

out_f.close()
