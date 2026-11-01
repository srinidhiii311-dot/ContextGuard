"""
harness/configs.py — Gateway Configuration Definitions & Evaluation Adapters (Block 5)

Explicit definitions and adapters for defensive configurations:
1. no_gateway (B0): Passthrough baseline allowing all actions without inspection.
2. taxonomy_only (B1): Static keyword and regex taxonomy matching without consistency checks or ML risk engine.
3. consistency_only (B2/A): Intent parameter and navigation boundary consistency verification only.
4. dual_gate (D): Canonical Full Gate (Consistency + Taxonomy + Characterizer + Risk Engine + Policy Engine).
5. dual_gate_llm (H): Canonical Gate + LLM Semantic Consistency Reviewer (Grey-Zone Raiser).
Ablations:
6. dual_gate_no_characterizer: Full gate bypassing Component 4 (lexical characterizer).
7. dual_gate_no_risk_engine: Full gate with unweighted heuristic risk mapping.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from contextguard.consistency_checker import ContextConsistencyVerifier
from contextguard.gate import ContextGuardGate, Decision, GateResult, ProposedAction, TrustedIntent
from contextguard.llm_checker import LLMChecker
from contextguard.threat_detector import ThreatDetector
from gateway.loader import Gateway
from harness.case_schema import EvaluationCase
from harness.run_case import build_trusted_intent_from_dict, map_gate_decision
from harness.run_record import LLMCallRecord, RunRecord

# Traditional keyword / attack taxonomy pattern for taxonomy_only baseline
TAXONOMY_REGEX = re.compile(
    r"(ignore\s+previous\s+instructions|system\s+override|data-attack-type|attacker\.example|"
    r"display\s*:\s*none|evil-pay|override\s+previous|new\s+instructions|disregard|"
    r"javascript\s*:|hidden\s*=\s*['\"]true['\"]|opacity\s*:\s*0|font-size\s*:\s*0|"
    r"transfer\s+all|send\s+to\s+attacker|forward\s+all)",
    re.IGNORECASE,
)


@dataclass
class GatewayConfigSpec:
    """Explicit configuration metadata and feature flags."""
    name: str
    code: str
    description: str
    flags: Dict[str, bool] = field(default_factory=dict)


CONFIG_SPECS: Dict[str, GatewayConfigSpec] = {
    "no_gateway": GatewayConfigSpec(
        name="no_gateway",
        code="B0",
        description="Passthrough baseline with no safety inspection.",
        flags={
            "enable_verifier": False,
            "enable_taxonomy": False,
            "enable_characterizer": False,
            "enable_risk_engine": False,
            "enable_policy_engine": False,
            "enable_llm_checker": False,
        },
    ),
    "taxonomy_only": GatewayConfigSpec(
        name="taxonomy_only",
        code="B1",
        description="Static keyword and attack taxonomy regex matching only.",
        flags={
            "enable_verifier": False,
            "enable_taxonomy": True,
            "enable_characterizer": False,
            "enable_risk_engine": False,
            "enable_policy_engine": False,
            "enable_llm_checker": False,
        },
    ),
    "consistency_only": GatewayConfigSpec(
        name="consistency_only",
        code="B2",
        description="Intent parameter consistency and boundary verification only.",
        flags={
            "enable_verifier": True,
            "enable_taxonomy": False,
            "enable_characterizer": False,
            "enable_risk_engine": False,
            "enable_policy_engine": False,
            "enable_llm_checker": False,
        },
    ),
    "dual_gate": GatewayConfigSpec(
        name="dual_gate",
        code="D",
        description="Canonical full gate (Verifier + Taxonomy + Characterizer + Risk Engine + Policy).",
        flags={
            "enable_verifier": True,
            "enable_taxonomy": True,
            "enable_characterizer": True,
            "enable_risk_engine": True,
            "enable_policy_engine": True,
            "enable_llm_checker": False,
        },
    ),
    "dual_gate_llm": GatewayConfigSpec(
        name="dual_gate_llm",
        code="H",
        description="Canonical full gate with LLM semantic consistency reviewer in grey zone.",
        flags={
            "enable_verifier": True,
            "enable_taxonomy": True,
            "enable_characterizer": True,
            "enable_risk_engine": True,
            "enable_policy_engine": True,
            "enable_llm_checker": True,
        },
    ),
    "dual_gate_no_characterizer": GatewayConfigSpec(
        name="dual_gate_no_characterizer",
        code="Abl_NoChar",
        description="Ablation: Full gate without Component 4 threat characterization.",
        flags={
            "enable_verifier": True,
            "enable_taxonomy": True,
            "enable_characterizer": False,
            "enable_risk_engine": True,
            "enable_policy_engine": True,
            "enable_llm_checker": False,
        },
    ),
    "dual_gate_no_risk_engine": GatewayConfigSpec(
        name="dual_gate_no_risk_engine",
        code="Abl_NoRisk",
        description="Ablation: Full gate with direct rule matching bypassing weighted ML risk scoring.",
        flags={
            "enable_verifier": True,
            "enable_taxonomy": True,
            "enable_characterizer": True,
            "enable_risk_engine": False,
            "enable_policy_engine": True,
            "enable_llm_checker": False,
        },
    ),
}

# Aliases
CONFIG_ALIASES = {
    "b0": "no_gateway",
    "b1": "taxonomy_only",
    "b2": "consistency_only",
    "d": "dual_gate",
    "h": "dual_gate_llm",
    "full_gate": "dual_gate",
    "zero_shot_dev": "dual_gate",
}


def normalize_config_name(name: str) -> str:
    cleaned = name.lower().strip()
    return CONFIG_ALIASES.get(cleaned, cleaned)


def evaluate_case_with_config(
    case: EvaluationCase,
    config: str,
    seed: int = 42,
    gateway_cache: Optional[Dict[str, Any]] = None,
) -> RunRecord:
    """
    Evaluates an EvaluationCase under the specified gateway configuration.
    Returns a validated RunRecord.
    """
    cfg_name = normalize_config_name(config)
    spec = CONFIG_SPECS.get(cfg_name)
    if not spec:
        raise ValueError(f"Unknown configuration '{config}'. Available: {list(CONFIG_SPECS.keys())}")

    intent = build_trusted_intent_from_dict(case.domain, case.locked_intent)
    dom_text = case.page_state.visible_text
    raw_html = case.page_state.raw_html

    p_act = ProposedAction(
        action_type=case.proposed_action.action_type,
        target=case.proposed_action.target,
        value=case.proposed_action.value,
        page_url=case.proposed_action.page_url,
        source_text=case.proposed_action.source_text,
        raw_html=raw_html,
    )

    t_start = time.perf_counter()
    decision = "allow"
    llm_record: Optional[LLMCallRecord] = None
    fallback_cnt = 0

    if cfg_name == "no_gateway":
        # Baseline 0: Passthrough
        decision = "allow"

    elif cfg_name == "taxonomy_only":
        # Baseline 1: Taxonomy / Regex matching only
        text_to_scan = f"{dom_text} {raw_html or ''} {case.proposed_action.source_text or ''} {case.proposed_action.value or ''}"
        hit = bool(TAXONOMY_REGEX.search(text_to_scan))
        decision = "block" if hit else "allow"

    elif cfg_name == "consistency_only":
        # Baseline 2: Context consistency verification only
        # Check against locked intent via verifier
        cache_key = f"verifier_{case.domain}"
        if gateway_cache is not None and cache_key in gateway_cache:
            gw = gateway_cache[cache_key]
            gw.set_intent(intent)
        else:
            gw = Gateway.from_domain(case.domain, trusted_intent=intent)
            if gateway_cache is not None:
                gateway_cache[cache_key] = gw

        gate = gw.gate
        model_act = p_act.to_model()
        locked = intent.to_locked_intent() if hasattr(intent, "to_locked_intent") else None
        if locked and gate is not None:
            rep = gate._verifier.verify(locked, model_act, dom_text)
            field_violations = [
                inc for inc in rep.inconsistencies
                if inc.check_type in ("FIELD_MISMATCH", "NAVIGATION_BOUNDARY")
            ]
            decision = "block" if len(field_violations) > 0 else "allow"
        else:
            # Fallback naive field check
            t_low = case.proposed_action.target.lower()
            val = str(case.proposed_action.value or "").strip().lower()
            mismatch = False
            for k, v in case.locked_intent.items():
                if k.lower() in t_low and val and str(v).lower() != val:
                    mismatch = True
                    break
            decision = "block" if mismatch else "allow"

    elif cfg_name == "dual_gate":
        # Canonical Full Gate
        cache_key = f"full_{case.domain}"
        if gateway_cache is not None and cache_key in gateway_cache:
            gw = gateway_cache[cache_key]
            gw.set_intent(intent)
        else:
            gw = Gateway.from_domain(case.domain, trusted_intent=intent)
            if gateway_cache is not None:
                gateway_cache[cache_key] = gw

        gate_res = gw.check(p_act, current_dom_text=dom_text)
        decision = map_gate_decision(gate_res.decision)

    elif cfg_name == "dual_gate_llm":
        # Canonical Gate + LLM Checker
        cache_key = f"llm_{case.domain}"
        if gateway_cache is not None and cache_key in gateway_cache:
            gw = gateway_cache[cache_key]
            gw.set_intent(intent)
        else:
            gw = Gateway.from_domain(case.domain, trusted_intent=intent)
            if gw.gate is not None:
                gw.gate.enable_llm_checker = True
                if gw.gate._llm_checker is None:
                    gw.gate._llm_checker = LLMChecker(raise_on_fallback=True)
            if gateway_cache is not None:
                gateway_cache[cache_key] = gw

        gate_res = gw.check(p_act, current_dom_text=dom_text)
        decision = map_gate_decision(gate_res.decision)
        if gate_res.llm_verdict:
            src = gate_res.llm_source or "offline"
            if src == "fallback" or gate_res.llm_verdict.get("error"):
                fallback_cnt = 1
                raise RuntimeError(
                    f"LLM Checker call fell back or failed in config {cfg_name}: "
                    f"{gate_res.llm_verdict.get('error')}"
                )
            llm_record = LLMCallRecord(
                provider=src,
                model=str(gate_res.llm_verdict.get("model") or src),
                request_id=str(gate_res.llm_verdict.get("request_id") or f"chk_{case.case_id}"),
                tokens_in=int(gate_res.llm_verdict.get("tokens_in", 0)),
                tokens_out=int(gate_res.llm_verdict.get("tokens_out", 0)),
                latency_ms=float(gate_res.llm_verdict.get("latency_ms", 0.0)),
            )

    elif cfg_name == "dual_gate_no_characterizer":
        # Ablation: without characterizer
        cache_key = f"no_char_{case.domain}"
        if gateway_cache is not None and cache_key in gateway_cache:
            gw = gateway_cache[cache_key]
            gw.set_intent(intent)
        else:
            gw = Gateway.from_domain(case.domain, trusted_intent=intent)
            if gw.gate is not None:
                gw.gate._characterizer = None
            if gateway_cache is not None:
                gateway_cache[cache_key] = gw

        gate_res = gw.check(p_act, current_dom_text=dom_text)
        decision = map_gate_decision(gate_res.decision)

    elif cfg_name == "dual_gate_no_risk_engine":
        # Ablation: without ML risk engine
        cache_key = f"no_risk_{case.domain}"
        if gateway_cache is not None and cache_key in gateway_cache:
            gw = gateway_cache[cache_key]
            gw.set_intent(intent)
        else:
            gw = Gateway.from_domain(case.domain, trusted_intent=intent)
            if gateway_cache is not None:
                gateway_cache[cache_key] = gw

        # Direct consistency/threat rule evaluation
        gate = gw.gate
        if gate is not None:
            rep = gate._verifier.verify(intent.to_locked_intent(), p_act.to_model(), dom_text) if hasattr(intent, "to_locked_intent") else None
            threat = gate._detector.detect(rep, dom_text, p_act.source_text, p_act.target, p_act.action_type)
            if (rep and any(i.severity == "CRITICAL" for i in rep.inconsistencies)) or threat.is_threat:
                decision = "block"
            elif rep and len(rep.inconsistencies) > 0:
                decision = "ask_human"
            else:
                decision = "allow"
        else:
            decision = "allow"

    latency_ms = (time.perf_counter() - t_start) * 1000.0

    return RunRecord(
        run_id=f"run_{case.case_id}_{cfg_name}_{seed}",
        task_id=case.case_id,
        domain=case.domain,
        config=cfg_name,
        seed=seed,
        case_type=case.case_type,
        family=case.family,
        split=case.split,
        proposed_action=case.proposed_action.model_dump(),
        decision=decision,
        ground_truth_label=case.ground_truth_label,
        latency_ms=round(latency_ms, 2),
        llm_call=llm_record,
        fallback_count=fallback_cnt,
    )
