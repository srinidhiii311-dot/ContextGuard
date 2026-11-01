import json
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness.case_schema import EvaluationCase
from harness.configs import build_trusted_intent_from_dict
from gateway.loader import Gateway
from contextguard.gate import ProposedAction, Decision
from analysis.metrics import format_proportion_ci, wilson_score_interval

def map_gate_decision(dec: Decision) -> str:
    m = {
        Decision.ALLOW: "allow",
        Decision.ALLOW_WITH_FLAG: "allow_with_flag",
        Decision.FLAG: "flag",
        Decision.REQUIRE_CONFIRMATION: "ask_human",
        Decision.BLOCK: "block",
        Decision.PAUSE_TASK: "pause_task",
    }
    return m.get(dec, "block")

def run_ablation():
    # Load all 680 dev cases
    cases = []
    for fpath in [Path("attacks/dev/cases.jsonl"), Path("benign/dev/cases.jsonl")]:
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    cases.append(EvaluationCase.model_validate(json.loads(line)))

    ablation_specs = [
        ("dual_gate (Canonical)", {"c1": True, "c2": True, "c3": True, "c4": True, "char": True}),
        ("dual_gate_no_c1 (-C1)", {"c1": False, "c2": True, "c3": True, "c4": True, "char": True}),
        ("dual_gate_no_c2 (-C2)", {"c1": True, "c2": False, "c3": True, "c4": True, "char": True}),
        ("dual_gate_no_c3 (-C3)", {"c1": True, "c2": True, "c3": False, "c4": True, "char": True}),
        ("dual_gate_no_c4 (-C4)", {"c1": True, "c2": True, "c3": True, "c4": False, "char": True}),
        ("dual_gate_no_characterizer (-Char)", {"c1": True, "c2": True, "c3": True, "c4": True, "char": False}),
    ]

    results = []

    for name, flags in ablation_specs:
        t0 = time.time()
        gw_cache = {}
        records = []
        for c in cases:
            cache_key = f"{name}_{c.domain}"
            intent = build_trusted_intent_from_dict(c.domain, c.locked_intent)
            if cache_key in gw_cache:
                gw = gw_cache[cache_key]
                gw.set_intent(intent)
                if gw.gate is not None:
                    gw.gate._prior_flags = 0
                    gw.gate._previous_page = None
            else:
                gw = Gateway.from_domain(
                    domain=c.domain,
                    trusted_intent=intent,
                    enable_c1=flags["c1"],
                    enable_c2=flags["c2"],
                    enable_c3=flags["c3"],
                    enable_c4=flags["c4"],
                )
                if not flags["char"] and gw.gate is not None:
                    gw.gate._characterizer = None
                gw_cache[cache_key] = gw

            p_act = ProposedAction(
                action_type=c.proposed_action.action_type,
                target=c.proposed_action.target,
                value=c.proposed_action.value,
                page_url=c.proposed_action.page_url,
                source_text=c.proposed_action.source_text,
                raw_html=c.page_state.raw_html,
            )
            dom_text = c.page_state.visible_text
            res = gw.check(p_act, current_dom_text=dom_text)
            dec = map_gate_decision(res.decision)
            records.append({
                "case_id": c.case_id,
                "case_type": c.case_type,
                "family": c.family,
                "ground_truth_label": c.ground_truth_label,
                "decision": dec,
            })

        elapsed = time.time() - t0

        # Compute metrics
        comp = [r for r in records if r["case_type"] == "attack" and r["ground_truth_label"] != "attack_uncompromised"]
        uncomp = [r for r in records if r["ground_truth_label"] == "attack_uncompromised"]
        norm = [r for r in records if r["case_type"] == "benign" and r["family"] != "benign_hard"]
        hard = [r for r in records if r["case_type"] == "benign" and r["family"] == "benign_hard"]

        def is_inter(d): return d in ("block", "ask_human", "require_confirmation", "pause_task")
        def is_blk(d): return d in ("block", "pause_task")
        def is_cfm(d): return d in ("ask_human", "require_confirmation")

        comp_det = sum(1 for r in comp if is_inter(r["decision"]))
        uncomp_ob = sum(1 for r in uncomp if is_inter(r["decision"]))
        
        norm_tot = sum(1 for r in norm if is_inter(r["decision"]))
        norm_blk = sum(1 for r in norm if is_blk(r["decision"]))
        norm_cfm = sum(1 for r in norm if is_cfm(r["decision"]))

        hard_tot = sum(1 for r in hard if is_inter(r["decision"]))
        hard_blk = sum(1 for r in hard if is_blk(r["decision"]))
        hard_cfm = sum(1 for r in hard if is_cfm(r["decision"]))

        row = {
            "name": name,
            "elapsed_s": round(elapsed, 1),
            "comp_recall": format_proportion_ci(comp_det, len(comp)),
            "uncomp_overblock": format_proportion_ci(uncomp_ob, len(uncomp)),
            "norm_fp_total": format_proportion_ci(norm_tot, len(norm)),
            "norm_fp_block": format_proportion_ci(norm_blk, len(norm)),
            "norm_fp_confirm": format_proportion_ci(norm_cfm, len(norm)),
            "hard_fp_total": format_proportion_ci(hard_tot, len(hard)),
            "hard_fp_block": format_proportion_ci(hard_blk, len(hard)),
            "hard_fp_confirm": format_proportion_ci(hard_cfm, len(hard)),
        }
        results.append(row)
        print(f"Done: {name} in {elapsed:.1f}s -> Recall: {row['comp_recall']}, Over-block: {row['uncomp_overblock']}")

    # Save to JSON
    with open("analysis/leave_one_out_ablation.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return results

if __name__ == "__main__":
    run_ablation()
