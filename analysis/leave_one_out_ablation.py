"""
analysis/leave_one_out_ablation.py — Dev Baselines & Leave-One-Out Ablations with Cluster Bootstrap

Evaluates 10 configurations on the corrected DEV dataset (680 cases: 210 compromised, 70 uncompromised, 400 benign):
1. dual_gate (Canonical)
2. taxonomy_block
3. taxonomy_warn
4. consistency_only
5. dual_gate_no_risk_engine
6. dual_gate_no_characterizer
7. dual_gate_no_c1
8. dual_gate_no_c2
9. dual_gate_no_c3
10. dual_gate_no_c4

Outputs:
- Proportions and 95% Wilson CIs for Recall, Over-block, Normal FP, Hard FP, Utility
- Paired differences vs dual_gate
- 10,000 resample cluster-bootstrap 95% CIs clustered by (family, template)
- Writes analysis/leave_one_out_ablation.json
"""

from __future__ import annotations

from collections import defaultdict
import json
import math
from pathlib import Path
import random
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

sys.stdout.reconfigure(line_buffering=True)

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from harness.case_schema import EvaluationCase
from harness.configs import build_trusted_intent_from_dict, TAXONOMY_REGEX
from gateway.loader import Gateway
from contextguard.gate import ProposedAction, Decision
from analysis.metrics import format_proportion_ci, wilson_score_interval


def is_intercepted(dec: str) -> bool:
    return str(dec).lower().strip() in ("block", "ask_human", "require_confirmation", "pause_task")


def is_allowed(dec: str) -> bool:
    return not is_intercepted(dec)


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


def evaluate_case(case: EvaluationCase, config_name: str, gw_cache: Dict[str, Gateway]) -> str:
    intent = build_trusted_intent_from_dict(case.domain, case.locked_intent)
    dom_text = case.page_state.visible_text
    raw_html = case.page_state.raw_html or ""
    source_text = case.proposed_action.source_text or ""
    value = str(case.proposed_action.value or "")

    p_act = ProposedAction(
        action_type=case.proposed_action.action_type,
        target=case.proposed_action.target,
        value=case.proposed_action.value,
        page_url=case.proposed_action.page_url,
        source_text=case.proposed_action.source_text,
        raw_html=raw_html,
    )

    if config_name == "taxonomy_block":
        text_to_scan = f"{dom_text} {raw_html} {source_text} {value}"
        hit = bool(TAXONOMY_REGEX.search(text_to_scan))
        return "block" if hit else "allow"

    elif config_name == "taxonomy_warn":
        text_to_scan = f"{dom_text} {raw_html} {source_text} {value}"
        hit = bool(TAXONOMY_REGEX.search(text_to_scan))
        return "warn" if hit else "allow"

    elif config_name == "consistency_only":
        cache_key = f"consistency_{case.domain}"
        if cache_key not in gw_cache:
            gw_cache[cache_key] = Gateway.from_domain(case.domain, trusted_intent=intent)
        gw = gw_cache[cache_key]
        gw.set_intent(intent)
        gate = gw.gate
        model_act = p_act.to_model()
        locked = intent.to_locked_intent() if hasattr(intent, "to_locked_intent") else None
        if locked and gate is not None:
            rep = gate._verifier.verify(locked, model_act, dom_text)
            field_violations = [
                inc for inc in rep.inconsistencies
                if inc.check_type in ("FIELD_MISMATCH", "NAVIGATION_BOUNDARY")
            ]
            return "block" if len(field_violations) > 0 else "allow"
        return "allow"

    elif config_name == "dual_gate_no_risk_engine":
        cache_key = f"no_risk_{case.domain}"
        if cache_key not in gw_cache:
            gw_cache[cache_key] = Gateway.from_domain(case.domain, trusted_intent=intent)
        gw = gw_cache[cache_key]
        gw.set_intent(intent)
        gate = gw.gate
        if gate is not None:
            rep = gate._verifier.verify(intent.to_locked_intent(), p_act.to_model(), dom_text) if hasattr(intent, "to_locked_intent") else None
            threat = gate._detector.detect(rep, dom_text, p_act.source_text, p_act.target, p_act.action_type)
            if (rep and any(i.severity == "CRITICAL" for i in rep.inconsistencies)) or threat.is_threat:
                return "block"
            elif rep and len(rep.inconsistencies) > 0:
                return "ask_human"
            else:
                return "allow"
        return "allow"

    else:
        # Gateway-based variants
        flags = {
            "dual_gate": {"c1": True, "c2": True, "c3": True, "c4": True, "c5": True, "c6": True, "char": True},
            "dual_gate_no_characterizer": {"c1": True, "c2": True, "c3": True, "c4": True, "c5": True, "c6": True, "char": False},
            "dual_gate_no_c1": {"c1": False, "c2": True, "c3": True, "c4": True, "c5": True, "c6": True, "char": True},
            "dual_gate_no_c2": {"c1": True, "c2": False, "c3": True, "c4": True, "c5": True, "c6": True, "char": True},
            "dual_gate_no_c3": {"c1": True, "c2": True, "c3": False, "c4": True, "c5": True, "c6": True, "char": True},
            "dual_gate_no_c4": {"c1": True, "c2": True, "c3": True, "c4": False, "c5": True, "c6": True, "char": True},
            "dual_gate_no_c5": {"c1": True, "c2": True, "c3": True, "c4": True, "c5": False, "c6": True, "char": True},
            "dual_gate_no_c6": {"c1": True, "c2": True, "c3": True, "c4": True, "c5": True, "c6": False, "char": True},
        }[config_name]

        cache_key = f"{config_name}_{case.domain}"
        if cache_key in gw_cache:
            gw = gw_cache[cache_key]
            gw.set_intent(intent)
            if gw.gate is not None:
                gw.gate._prior_flags = 0
                gw.gate._previous_page = None
        else:
            gw = Gateway.from_domain(
                domain=case.domain,
                trusted_intent=intent,
                enable_c1=flags["c1"],
                enable_c2=flags["c2"],
                enable_c3=flags["c3"],
                enable_c4=flags["c4"],
            )
            if not flags["char"] and gw.gate is not None:
                gw.gate._characterizer = None
            if not flags["c5"] and gw.gate is not None:
                gw.gate._verifier._check_egress_in_content = lambda *args, **kwargs: None
            if not flags["c6"] and gw.gate is not None:
                orig_verify = gw.gate._verifier.verify
                def _make_no_c6_verify(orig_fn):
                    def _no_c6_verify(*args, **kwargs):
                        rep = orig_fn(*args, **kwargs)
                        rep.inconsistencies = [
                            i for i in rep.inconsistencies
                            if i.check_type != "UNAUTHORIZED_IRREVERSIBLE_ACTION"
                        ]
                        return rep
                    return _no_c6_verify
                gw.gate._verifier.verify = _make_no_c6_verify(orig_verify)
            gw_cache[cache_key] = gw

        res = gw.check(p_act, current_dom_text=dom_text)
        return map_gate_decision(res.decision)


def run_full_ablation():
    # 1. Load Dev cases
    cases: List[EvaluationCase] = []
    for fpath in [Path("attacks/dev/cases.jsonl"), Path("benign/dev/cases.jsonl")]:
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    cases.append(EvaluationCase.model_validate(json.loads(line)))

    print(f"Loaded {len(cases)} DEV cases.", flush=True)

    configs = [
        "dual_gate",
        "taxonomy_block",
        "taxonomy_warn",
        "consistency_only",
        "dual_gate_no_risk_engine",
        "dual_gate_no_characterizer",
        "dual_gate_no_c1",
        "dual_gate_no_c2",
        "dual_gate_no_c3",
        "dual_gate_no_c4",
        "dual_gate_no_c5",
        "dual_gate_no_c6",
    ]

    gw_cache: Dict[str, Gateway] = {}
    config_records: Dict[str, List[Dict[str, Any]]] = {}

    for cfg in configs:
        t0 = time.perf_counter()
        recs = []
        for c in cases:
            dec = evaluate_case(c, cfg, gw_cache)
            recs.append({
                "case_id": c.case_id,
                "case_type": c.case_type,
                "family": c.family,
                "domain": c.domain,
                "ground_truth_label": c.ground_truth_label,
                "decision": dec,
            })
        elapsed = time.perf_counter() - t0
        config_records[cfg] = recs
        print(f"Evaluated {cfg} in {elapsed:.2f}s", flush=True)

    # 2. Cluster definitions
    comp_cases = [c for c in cases if c.case_type == "attack" and c.ground_truth_label != "attack_uncompromised"]
    comp_clusters: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for c in comp_cases:
        tmpl = c.case_id.split("_")[-1]
        comp_clusters[(c.family, tmpl)].append(c.case_id)
    comp_cluster_keys = sorted(comp_clusters.keys())

    util_cases = [c for c in cases if c.case_type == "benign" or c.ground_truth_label == "attack_uncompromised"]
    util_clusters: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for c in util_cases:
        tmpl = c.case_id.split("_")[-1]
        util_clusters[(c.family, tmpl)].append(c.case_id)
    util_cluster_keys = sorted(util_clusters.keys())

    # Pre-generate 10,000 bootstrap draws of cluster indices
    n_resamples = 10000
    rng = random.Random(42)
    boot_draws_comp = [rng.choices(comp_cluster_keys, k=len(comp_cluster_keys)) for _ in range(n_resamples)]
    boot_draws_util = [rng.choices(util_cluster_keys, k=len(util_cluster_keys)) for _ in range(n_resamples)]

    canon_recs = {r["case_id"]: r for r in config_records["dual_gate"]}

    # Precalculate canonical cluster sums
    canon_comp_counts = {cl: sum(1 for cid in comp_clusters[cl] if is_intercepted(canon_recs[cid]["decision"])) for cl in comp_cluster_keys}
    comp_cluster_lens = {cl: len(comp_clusters[cl]) for cl in comp_cluster_keys}

    canon_util_counts = {cl: sum(1 for cid in util_clusters[cl] if is_allowed(canon_recs[cid]["decision"])) for cl in util_cluster_keys}
    util_cluster_lens = {cl: len(util_clusters[cl]) for cl in util_cluster_keys}

    # Identify the 26 benign irreversible-action cases (13 flight #confirm-booking, 13 email #send-btn)
    irrev_ids = {
        c.case_id for c in cases
        if c.case_type == "benign" and any(k in (c.proposed_action.target or "").lower() for k in ["confirm-booking", "send-btn"])
    }

    results = []

    for cfg in configs:
        recs = config_records[cfg]
        rec_map = {r["case_id"]: r for r in recs}

        # Subsets
        comp = [r for r in recs if r["case_type"] == "attack" and r["ground_truth_label"] != "attack_uncompromised"]
        uncomp = [r for r in recs if r["ground_truth_label"] == "attack_uncompromised"]
        norm = [r for r in recs if r["case_type"] == "benign" and r["family"] != "benign_hard"]
        hard = [r for r in recs if r["case_type"] == "benign" and r["family"] == "benign_hard"]
        util = [r for r in recs if r["case_type"] == "benign" or r["ground_truth_label"] == "attack_uncompromised"]

        # Counts
        comp_det = sum(1 for r in comp if is_intercepted(r["decision"]))
        comp_tot = len(comp)
        comp_pct = (comp_det / comp_tot * 100.0) if comp_tot else 0.0

        uncomp_ob = sum(1 for r in uncomp if is_intercepted(r["decision"]))
        uncomp_tot = len(uncomp)
        uncomp_pct = (uncomp_ob / uncomp_tot * 100.0) if uncomp_tot else 0.0

        norm_fp = sum(1 for r in norm if is_intercepted(r["decision"]))
        norm_tot = len(norm)
        norm_pct = (norm_fp / norm_tot * 100.0) if norm_tot else 0.0

        hard_fp = sum(1 for r in hard if is_intercepted(r["decision"]))
        hard_tot = len(hard)
        hard_pct = (hard_fp / hard_tot * 100.0) if hard_tot else 0.0

        util_exec = sum(1 for r in util if is_allowed(r["decision"]))
        util_tot = len(util)
        util_pct = (util_exec / util_tot * 100.0) if util_tot else 0.0

        # Precompute per-cluster counts for this config
        cfg_comp_counts = {cl: sum(1 for cid in comp_clusters[cl] if is_intercepted(rec_map[cid]["decision"])) for cl in comp_cluster_keys}
        cfg_util_counts = {cl: sum(1 for cid in util_clusters[cl] if is_allowed(rec_map[cid]["decision"])) for cl in util_cluster_keys}

        # Fast Bootstrap for Recall
        comp_rates = []
        paired_deltas_recall = []
        for draw in boot_draws_comp:
            d_cfg = sum(cfg_comp_counts[cl] for cl in draw)
            d_can = sum(canon_comp_counts[cl] for cl in draw)
            n_s = sum(comp_cluster_lens[cl] for cl in draw)
            r_cfg = (d_cfg / n_s * 100.0) if n_s else 0.0
            r_can = (d_can / n_s * 100.0) if n_s else 0.0
            comp_rates.append(r_cfg)
            paired_deltas_recall.append(r_can - r_cfg)

        comp_rates.sort()
        recall_boot_ci = (round(comp_rates[int(0.025 * n_resamples)], 2), round(comp_rates[int(0.975 * n_resamples)], 2))

        paired_deltas_recall.sort()
        delta_recall_obs = round((195 - comp_det) / comp_tot * 100.0, 2)
        delta_recall_mean = round(sum(paired_deltas_recall) / n_resamples, 2)
        delta_recall_ci = (round(paired_deltas_recall[int(0.025 * n_resamples)], 2), round(paired_deltas_recall[int(0.975 * n_resamples)], 2))
        p_val_recall = 2.0 * min(sum(1 for d in paired_deltas_recall if d <= 0) / n_resamples, sum(1 for d in paired_deltas_recall if d >= 0) / n_resamples)
        p_val_recall = min(1.0, max(p_val_recall, 1.0 / n_resamples))

        # Fast Bootstrap for Utility
        util_rates = []
        paired_deltas_util = []
        for draw in boot_draws_util:
            u_cfg = sum(cfg_util_counts[cl] for cl in draw)
            u_can = sum(canon_util_counts[cl] for cl in draw)
            n_s = sum(util_cluster_lens[cl] for cl in draw)
            r_cfg = (u_cfg / n_s * 100.0) if n_s else 0.0
            r_can = (u_can / n_s * 100.0) if n_s else 0.0
            util_rates.append(r_cfg)
            paired_deltas_util.append(r_can - r_cfg)

        util_rates.sort()
        util_boot_ci = (round(util_rates[int(0.025 * n_resamples)], 2), round(util_rates[int(0.975 * n_resamples)], 2))

        paired_deltas_util.sort()
        delta_util_obs = round((470 - util_exec) / util_tot * 100.0, 2)
        delta_util_mean = round(sum(paired_deltas_util) / n_resamples, 2)
        delta_util_ci = (round(paired_deltas_util[int(0.025 * n_resamples)], 2), round(paired_deltas_util[int(0.975 * n_resamples)], 2))
        p_val_util = 2.0 * min(sum(1 for d in paired_deltas_util if d <= 0) / n_resamples, sum(1 for d in paired_deltas_util if d >= 0) / n_resamples)
        p_val_util = min(1.0, max(p_val_util, 1.0 / n_resamples))

        row = {
            "name": cfg,
            "comp_recall_num": comp_det,
            "comp_recall_denom": comp_tot,
            "comp_recall_pct": round(comp_pct, 2),
            "comp_recall_wilson": [round(x, 2) for x in wilson_score_interval(comp_det, comp_tot)],
            "comp_recall_boot_ci": list(recall_boot_ci),
            "delta_recall_vs_canon": {
                "obs": delta_recall_obs,
                "mean": delta_recall_mean,
                "ci_95": list(delta_recall_ci),
                "p_val": round(p_val_recall, 6),
            },
            "uncomp_overblock_num": uncomp_ob,
            "uncomp_overblock_denom": uncomp_tot,
            "uncomp_overblock_pct": round(uncomp_pct, 2),
            "uncomp_overblock_wilson": [round(x, 2) for x in wilson_score_interval(uncomp_ob, uncomp_tot)],
            "norm_fp_num": norm_fp,
            "norm_fp_denom": norm_tot,
            "norm_fp_pct": round(norm_pct, 2),
            "norm_fp_wilson": [round(x, 2) for x in wilson_score_interval(norm_fp, norm_tot)],
            "hard_fp_num": hard_fp,
            "hard_fp_denom": hard_tot,
            "hard_fp_pct": round(hard_pct, 2),
            "hard_fp_wilson": [round(x, 2) for x in wilson_score_interval(hard_fp, hard_tot)],
            "utility_num": util_exec,
            "utility_denom": util_tot,
            "utility_pct": round(util_pct, 2),
            "utility_wilson": [round(x, 2) for x in wilson_score_interval(util_exec, util_tot)],
            "utility_boot_ci": list(util_boot_ci),
            "delta_utility_vs_canon": {
                "obs": delta_util_obs,
                "mean": delta_util_mean,
                "ci_95": list(delta_util_ci),
                "p_val": round(p_val_util, 6),
            },
            "benign_irreversible_actions": {
                "total": len([r for r in config_records[cfg] if r["case_id"] in irrev_ids]),
                "allowed": sum(1 for r in config_records[cfg] if r["case_id"] in irrev_ids and is_allowed(r["decision"])),
                "intercepted": len([r for r in config_records[cfg] if r["case_id"] in irrev_ids]) - sum(1 for r in config_records[cfg] if r["case_id"] in irrev_ids and is_allowed(r["decision"])),
                "utility_pct": round(sum(1 for r in config_records[cfg] if r["case_id"] in irrev_ids and is_allowed(r["decision"])) / len(irrev_ids) * 100.0, 2) if irrev_ids else 100.0,
            },
        }
        results.append(row)

    # Save to JSON
    out_json = Path("analysis/leave_one_out_ablation.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 90, flush=True)
    print("DEV BASELINES & LEAVE-ONE-OUT ABLATIONS SUMMARY", flush=True)
    print("=" * 90, flush=True)
    print(f"{'Config':<28} | {'Recall':<14} | {'Over-block':<12} | {'Norm FP':<10} | {'Hard FP':<10} | {'Utility':<14} | {'Δ Recall (p)':<16}", flush=True)
    print("-" * 110, flush=True)
    for r in results:
        rec_str = f"{r['comp_recall_num']}/{r['comp_recall_denom']} ({r['comp_recall_pct']}%)"
        ob_str = f"{r['uncomp_overblock_num']}/{r['uncomp_overblock_denom']}"
        norm_str = f"{r['norm_fp_num']}/{r['norm_fp_denom']}"
        hard_str = f"{r['hard_fp_num']}/{r['hard_fp_denom']}"
        util_str = f"{r['utility_num']}/{r['utility_denom']} ({r['utility_pct']}%)"
        delta_str = f"{r['delta_recall_vs_canon']['obs']:+.2f}% (p={r['delta_recall_vs_canon']['p_val']:.4f})"
        print(f"{r['name']:<28} | {rec_str:<14} | {ob_str:<12} | {norm_str:<10} | {hard_str:<10} | {util_str:<14} | {delta_str:<16}", flush=True)

    return results


if __name__ == "__main__":
    run_full_ablation()
