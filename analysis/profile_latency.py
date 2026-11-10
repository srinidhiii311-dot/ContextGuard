import json
import os
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from harness.case_schema import EvaluationCase
from harness.configs import build_trusted_intent_from_dict
from gateway.loader import Gateway
from contextguard.gate import ProposedAction

def run_latency_profiling(n_cases=200):
    # Load 200 dev cases (100 attacks, 100 benign)
    cases = []
    with open(ROOT_DIR / "attacks" / "dev" / "cases.jsonl", "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if idx >= 100:
                break
            if line.strip():
                cases.append(EvaluationCase.model_validate(json.loads(line)))

    with open(ROOT_DIR / "benign" / "dev" / "cases.jsonl", "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if idx >= 100:
                break
            if line.strip():
                cases.append(EvaluationCase.model_validate(json.loads(line)))

    print(f"Loaded {len(cases)} cases for profiling.")

    # 1. Profile with audit logging ENABLED
    timings = {
        "hmac_ms": [],
        "dom_scan_ms": [],
        "threat_ms": [],
        "risk_engine_ms": [],
        "audit_ms": [],
        "total_ms": [],
    }

    gw_cache = {}
    for c in cases:
        intent = build_trusted_intent_from_dict(c.domain, c.locked_intent)
        gw_key = f"prof_{c.domain}"
        if gw_key in gw_cache:
            gw = gw_cache[gw_key]
            gw.set_intent(intent)
        else:
            gw = Gateway.from_domain(c.domain, trusted_intent=intent)
            gw_cache[gw_key] = gw

        p_act = ProposedAction(
            action_type=c.proposed_action.action_type,
            target=c.proposed_action.target,
            value=c.proposed_action.value,
            page_url=c.proposed_action.page_url,
            source_text=c.proposed_action.source_text,
            raw_html=c.page_state.raw_html,
        )
        dom_text = c.page_state.visible_text

        t_start = time.perf_counter()
        res = gw.check(p_act, current_dom_text=dom_text)
        t_tot = (time.perf_counter() - t_start) * 1000.0

        proc = res.processing_ms
        timings["hmac_ms"].append(proc.get("hmac_ms", 0.05)) # negligible HMAC time
        timings["dom_scan_ms"].append(proc.get("dom_scan_ms", proc.get("context_capture_ms", 0.5)))
        timings["threat_ms"].append(proc.get("threat_detection_ms", 0.0))
        timings["risk_engine_ms"].append(proc.get("risk_assessment_ms", 0.0))
        timings["audit_ms"].append(proc.get("audit_log_ms", 0.0))
        timings["total_ms"].append(t_tot)

    def p50(arr):
        s = sorted(arr)
        return s[len(s) // 2] if s else 0.0

    def p95(arr):
        s = sorted(arr)
        return s[int(0.95 * len(s))] if s else 0.0

    # 2. Profile with audit logging DISABLED
    # To disable audit logging, pass /dev/null or dummy in-memory logger
    no_audit_totals = []
    gw_cache_no_audit = {}
    null_audit_path = ROOT_DIR / "runs" / "null_audit.jsonl"
    for c in cases:
        intent = build_trusted_intent_from_dict(c.domain, c.locked_intent)
        gw_key = f"prof_no_audit_{c.domain}"
        if gw_key in gw_cache_no_audit:
            gw = gw_cache_no_audit[gw_key]
            gw.set_intent(intent)
        else:
            gw = Gateway.from_domain(c.domain, trusted_intent=intent, audit_log_path=null_audit_path)
            # Patch audit logger to no-op
            if gw.gate is not None:
                gw.gate._log_decision_to_audit = lambda action, result, session=None, **kwargs: {"prev_hash": "0"*64, "entry_hash": "0"*64, "index": 0}
            gw_cache_no_audit[gw_key] = gw

        p_act = ProposedAction(
            action_type=c.proposed_action.action_type,
            target=c.proposed_action.target,
            value=c.proposed_action.value,
            page_url=c.proposed_action.page_url,
            source_text=c.proposed_action.source_text,
            raw_html=c.page_state.raw_html,
        )
        dom_text = c.page_state.visible_text

        t_start = time.perf_counter()
        res = gw.check(p_act, current_dom_text=dom_text)
        t_tot = (time.perf_counter() - t_start) * 1000.0
        no_audit_totals.append(t_tot)

    # Clean up null audit file if created
    if null_audit_path.exists():
        try:
            null_audit_path.unlink()
        except Exception:
            pass

    # Calculate time shares
    mean_tot = sum(timings["total_ms"]) / len(timings["total_ms"])
    # If processing_ms doesn't record internal breakdowns down to audit/hmac, measure directly:
    print(f"\n--- Latency Breakdown (over {n_cases} cases) ---")
    print(f"Audit Logging Enabled  : p50 = {p50(timings['total_ms']):.2f} ms | p95 = {p95(timings['total_ms']):.2f} ms | mean = {mean_tot:.2f} ms")
    print(f"Audit Logging Disabled : p50 = {p50(no_audit_totals):.2f} ms | p95 = {p95(no_audit_totals):.2f} ms | mean = {sum(no_audit_totals)/len(no_audit_totals):.2f} ms")

    delta_audit = max(0.0, mean_tot - (sum(no_audit_totals) / len(no_audit_totals)))
    audit_share = (delta_audit / mean_tot * 100.0) if mean_tot > 0 else 0.0

    profile_results = {
        "n_cases": n_cases,
        "with_audit": {
            "p50_ms": round(p50(timings["total_ms"]), 2),
            "p95_ms": round(p95(timings["total_ms"]), 2),
            "mean_ms": round(mean_tot, 2),
        },
        "without_audit": {
            "p50_ms": round(p50(no_audit_totals), 2),
            "p95_ms": round(p95(no_audit_totals), 2),
            "mean_ms": round(sum(no_audit_totals) / len(no_audit_totals), 2),
        },
        "time_shares": {
            "audit_write_and_anchor_pct": round(audit_share, 1),
            "threat_pipeline_pct": round((sum(timings["threat_ms"]) / len(timings["threat_ms"]) / mean_tot * 100.0) if mean_tot > 0 else 0.0, 1),
            "risk_engine_pct": round((sum(timings["risk_engine_ms"]) / len(timings["risk_engine_ms"]) / mean_tot * 100.0) if mean_tot > 0 else 0.0, 1),
        }
    }

    with open(ROOT_DIR / "analysis" / "latency_profile.json", "w", encoding="utf-8") as f:
        json.dump(profile_results, f, indent=2)

    return profile_results

if __name__ == "__main__":
    run_latency_profiling()

