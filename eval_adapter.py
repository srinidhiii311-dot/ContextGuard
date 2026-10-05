"""eval_adapter.py — Unified evaluation adapter connecting datasets to ContextGuardGate.

Implements evaluate(item, config) supporting single-step (schema v1) and multi-step (schema v2) items.
Configs:
- A_rules_only: Field verification rail only
- B_keywords: Config A + Keyword taxonomy (Component 3)
- C_component4: Config B + Semantic deviation characterization (Component 4)
- D_full: Full gate (all 7 components + ML Risk Engine + Declarative Policy)
- H_llm: Config D + LLM Semantic Consistency Checker (Grey-zone Raiser)
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from contextguard.gate import ContextGuardGate, Decision, ProposedAction, TrustedIntent
from contextguard.llm_checker import LLMChecker, provider_from_env

DECISION_SEVERITY = {
    "BLOCK": 4,
    "PAUSE_TASK": 3,
    "REQUIRE_CONFIRMATION": 2,
    "ALLOW_WITH_FLAG": 1,
    "FLAG": 1,
    "ALLOW": 0,
}

CONFIG_MAP = {
    "A_rules_only": "A",
    "B_keywords": "B",
    "C_component4": "C",
    "D_full": "D",
    "H_llm": "H",
}


def _extract_steps(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    if "steps" in item and isinstance(item["steps"], list) and len(item["steps"]) > 0:
        return item["steps"]
    # Schema v1 single-step
    act = item.get("action", {})
    return [{
        "action": act,
        "dom_text": item.get("dom_text", item.get("text", "")),
        "raw_html": item.get("raw_html", ""),
    }]


def _build_action(act_dict: Dict[str, Any], default_url: str = "http://127.0.0.1:8000/search") -> ProposedAction:
    if isinstance(act_dict, ProposedAction):
        return act_dict
    atype = act_dict.get("action_type", act_dict.get("type", "CLICK")).upper()
    target = act_dict.get("target", act_dict.get("selector", "#btn"))
    val = act_dict.get("value")
    url = act_dict.get("page_url", act_dict.get("url", default_url))
    return ProposedAction(
        action_type=atype,
        target=target,
        value=str(val) if val is not None else None,
        page_url=url,
    )


def _build_intent(item: Dict[str, Any]) -> TrustedIntent:
    intent_data = item.get("intent") or item.get("trusted_intent")
    if isinstance(intent_data, TrustedIntent):
        return intent_data
    if isinstance(intent_data, dict):
        return TrustedIntent.from_dict(intent_data)
    return TrustedIntent(
        origin="Chennai",
        destination="Delhi",
        cabin_class="Economy",
        passenger_count=1,
    )


def evaluate(item: Dict[str, Any], config: str) -> Dict[str, Any]:
    """Run ONE item (all its steps, in order) through the gate under `config`.
    Return the decision of the first step that stops, else the strongest decision seen.
    """
    cfg_code = CONFIG_MAP.get(config, config)
    trusted_intent = _build_intent(item)
    task_id = f"eval-{item.get('id', 'item')}-{config}"

    llm_checker = None
    if cfg_code == "H":
        llm_checker = LLMChecker(provider_from_env())

    gate = ContextGuardGate(
        trusted_intent=trusted_intent,
        task_id=task_id,
        enable_llm_checker=(cfg_code == "H"),
        llm_checker=llm_checker,
    )

    steps = _extract_steps(item)
    strongest_decision = "ALLOW"
    strongest_score = 0
    total_latency_ms = 0.0
    fired_reasons: List[str] = []

    for step_idx, step in enumerate(steps):
        act_dict = step.get("action", {})
        dom_text = step.get("dom_text", step.get("text", ""))
        action = _build_action(act_dict)

        t0 = time.perf_counter_ns()
        if cfg_code == "A":
            model_action = action.to_model()
            locked_intent = gate.trusted_intent.to_locked_intent()
            rep = gate._verifier.verify(locked_intent, model_action, dom_text)
            field_violations = [
                inc for inc in rep.inconsistencies
                if inc.check_type in ("FIELD_MISMATCH", "NAVIGATION_BOUNDARY")
            ]
            intercepted = len(field_violations) > 0
            dec_str = "BLOCK" if intercepted else "ALLOW"
            score = 65 if intercepted else 10
            reason = field_violations[0].description if intercepted else ""

        elif cfg_code == "B":
            model_action = action.to_model()
            locked_intent = gate.trusted_intent.to_locked_intent()
            rep = gate._verifier.verify(locked_intent, model_action, dom_text)
            field_violations = [
                inc for inc in rep.inconsistencies
                if inc.check_type in ("FIELD_MISMATCH", "NAVIGATION_BOUNDARY")
            ]
            det = gate._detector.detect(
                consistency_report=rep,
                dom_text=dom_text,
                justification_text=action.source_text,
                action_target=action.target,
                action_type=action.action_type,
            )
            kw_hit = (
                det.is_threat
                and det.confidence >= gate._detector.confidence_threshold
                and det.attack_type is not None
            )
            intercepted = len(field_violations) > 0 or kw_hit
            dec_str = "BLOCK" if intercepted else "ALLOW"
            score = 75 if intercepted else 10
            reason = det.attack_type if kw_hit else (field_violations[0].description if field_violations else "")

        elif cfg_code == "C":
            model_action = action.to_model()
            locked_intent = gate.trusted_intent.to_locked_intent()
            rep = gate._verifier.verify(locked_intent, model_action, dom_text)
            field_violations = [
                inc for inc in rep.inconsistencies
                if inc.check_type in ("FIELD_MISMATCH", "NAVIGATION_BOUNDARY")
            ]
            pipe_res = gate._run_threat_pipeline(rep, dom_text, action)
            c4_hit = pipe_res.is_threat and (
                pipe_res.characterization_label is not None
                or (pipe_res.confidence >= gate._detector.confidence_threshold and pipe_res.attack_type is not None)
            )
            marker_hit = any(inc.check_type in ("INJECTION_MARKER", "PROCESS_INTEGRITY") for inc in rep.inconsistencies)
            intercepted = len(field_violations) > 0 or c4_hit or marker_hit
            dec_str = "BLOCK" if intercepted else "ALLOW"
            score = 80 if intercepted else 10
            reason = pipe_res.characterization_label or pipe_res.attack_type or "threat"

        else:
            # Config D or H
            res = gate.check(action, dom_text)
            dec_str = res.decision.value
            score = res.risk_score
            reason = res.reason

        lat_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        total_latency_ms += lat_ms
        if reason:
            fired_reasons.append(reason)

        # Update strongest decision seen
        if DECISION_SEVERITY.get(dec_str, 0) > DECISION_SEVERITY.get(strongest_decision, 0):
            strongest_decision = dec_str
            strongest_score = score

        # Check if first stopping step
        if dec_str in ("BLOCK", "REQUIRE_CONFIRMATION", "PAUSE_TASK"):
            return {
                "decision": dec_str,
                "score": score,
                "stop_step": step_idx + 1,
                "fired": "; ".join(fired_reasons) if fired_reasons else None,
                "latency_ms": round(total_latency_ms, 2),
            }

    return {
        "decision": strongest_decision,
        "score": strongest_score,
        "stop_step": None,
        "fired": "; ".join(fired_reasons) if fired_reasons else None,
        "latency_ms": round(total_latency_ms, 2),
    }
