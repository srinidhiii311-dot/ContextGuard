"""
harness/configs.py — Gateway Configuration Definitions & Evaluation Adapters (Block 5 & Block 8e)

Explicit definitions and adapters for all defensive configurations, baselines, and ablations:
Core Architectures & Baselines:
1. no_gateway (B0): Passthrough baseline allowing all actions without inspection.
2. taxonomy_block (B1_block): Static keyword and regex taxonomy matching; hit results in BLOCK.
3. taxonomy_warn (B1_warn): Static keyword and regex taxonomy matching; hit produces WARN only.
4. consistency_only (B2): Intent parameter and navigation boundary consistency verification only.
5. regex_only: Pure static regex scanner across DOM and action parameters without entity binding.
6. llm_judge_only: Direct LLM consistency evaluation (gemini-3.5-flash-lite) with no rule engine floor.
7. tool_allowlist: Static action and target allowlist from sandbox manifests without value inspection.
8. dual_gate (D): Canonical Full Gate (Consistency + Taxonomy + Characterizer + Risk Engine + Policy).
9. dual_gate_llm (H): Canonical Gate + LLM Semantic Consistency Reviewer in grey zone (30 <= score < 60).

Component Ablations:
10. dual_gate_no_characterizer: Full gate bypassing Component 4 lexical characterizer.
11. dual_gate_no_risk_engine: Full gate with direct rule matching bypassing weighted ML risk scoring.
12. dual_gate_no_c1: Full gate without C1 In-Context Injection Defense.
13. dual_gate_no_c2: Full gate without C2 Semantic Intent Alignment.
14. dual_gate_no_c3: Full gate without C3 DOM Structural Invariants.
15. dual_gate_no_c4: Full gate without C4 Behavioral Anomaly Detection & False-Positive Filter.
16. dual_gate_no_c5: Full gate without C5 Data Egress & Exfiltration Filter.
17. dual_gate_no_c6: Full gate without C6 Irreversible Action Authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from contextguard.consistency_checker import ContextConsistencyVerifier
from contextguard.gate import ContextGuardGate, Decision, GateResult, ProposedAction, TrustedIntent
from contextguard.llm_checker import LLMChecker, build_judge_prompt
from contextguard.threat_detector import ThreatDetector
from gateway.loader import Gateway
from harness.case_schema import EvaluationCase
from harness.oracle_v3 import DOMAIN_ALLOWLISTS
from harness.run_case import build_trusted_intent_from_dict, map_gate_decision
from harness.run_record import LLMCallRecord, RunRecord
from llm.client import LLMClient

# Traditional keyword / attack taxonomy pattern for taxonomy matching
TAXONOMY_REGEX = re.compile(
    r"(ignore\s+previous\s+instructions|system\s+override|data-attack-type|attacker\.example|"
    r"display\s*:\s*none|evil-pay|override\s+previous|new\s+instructions|disregard|"
    r"javascript\s*:|hidden\s*=\s*['\"]true['\"]|opacity\s*:\s*0|font-size\s*:\s*0|"
    r"transfer\s+all|send\s+to\s+attacker|forward\s+all)",
    re.IGNORECASE,
)

_MANIFESTS_CACHE: Optional[Dict[str, Dict[str, Any]]] = None
_JUDGE_CLIENT: Optional[LLMClient] = None


def get_sandbox_manifests() -> Dict[str, Dict[str, Any]]:
    global _MANIFESTS_CACHE
    if _MANIFESTS_CACHE is None:
        manifests = {}
        for dom in ["flight", "banking", "ecommerce", "healthcare", "email"]:
            mpath = Path(__file__).resolve().parent.parent / "sandboxes" / dom / "manifest.json"
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
        _MANIFESTS_CACHE = manifests
    return _MANIFESTS_CACHE


def get_judge_client() -> LLMClient:
    global _JUDGE_CLIENT
    if _JUDGE_CLIENT is None:
        _JUDGE_CLIENT = LLMClient()
    return _JUDGE_CLIENT


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
    "taxonomy_block": GatewayConfigSpec(
        name="taxonomy_block",
        code="B1_block",
        description="Static attack taxonomy regex matching where a match produces an outright block.",
        flags={
            "enable_verifier": False,
            "enable_taxonomy": True,
            "enable_characterizer": False,
            "enable_risk_engine": False,
            "enable_policy_engine": False,
            "enable_llm_checker": False,
        },
    ),
    "taxonomy_warn": GatewayConfigSpec(
        name="taxonomy_warn",
        code="B1_warn",
        description="Static attack taxonomy regex matching where a match produces a warning only.",
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
    "regex_only": GatewayConfigSpec(
        name="regex_only",
        code="Baseline_Regex",
        description="Pure static regex scanner across DOM and action text without entity binding.",
        flags={"regex_only": True},
    ),
    "llm_judge_only": GatewayConfigSpec(
        name="llm_judge_only",
        code="Baseline_Judge",
        description="Direct LLM consistency evaluation (gemini-3.5-flash-lite) with no rule engine.",
        flags={"llm_judge_only": True},
    ),
    "tool_allowlist": GatewayConfigSpec(
        name="tool_allowlist",
        code="Baseline_Allowlist",
        description="Static action and target allowlist from sandbox manifests without value inspection.",
        flags={"tool_allowlist": True},
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
    "dual_gate_no_c1": GatewayConfigSpec(
        name="dual_gate_no_c1",
        code="Abl_NoC1",
        description="Ablation: Full gate without C1 In-Context Injection Defense.",
        flags={"c1": False},
    ),
    "dual_gate_no_c2": GatewayConfigSpec(
        name="dual_gate_no_c2",
        code="Abl_NoC2",
        description="Ablation: Full gate without C2 Semantic Intent Alignment.",
        flags={"c2": False},
    ),
    "dual_gate_no_c3": GatewayConfigSpec(
        name="dual_gate_no_c3",
        code="Abl_NoC3",
        description="Ablation: Full gate without C3 DOM Structural Invariant Enforcement.",
        flags={"c3": False},
    ),
    "dual_gate_no_c4": GatewayConfigSpec(
        name="dual_gate_no_c4",
        code="Abl_NoC4",
        description="Ablation: Full gate without C4 Behavioral Anomaly Detection & False-Positive Filter.",
        flags={"c4": False},
    ),
    "dual_gate_no_c5": GatewayConfigSpec(
        name="dual_gate_no_c5",
        code="Abl_NoC5",
        description="Ablation: Full gate without C5 Data Egress & Exfiltration Filter.",
        flags={"c5": False},
    ),
    "dual_gate_no_c6": GatewayConfigSpec(
        name="dual_gate_no_c6",
        code="Abl_NoC6",
        description="Ablation: Full gate without C6 Irreversible Action Authorization.",
        flags={"c6": False},
    ),
}

# Unified aliases
CONFIG_ALIASES = {
    "b0": "no_gateway",
    "b1": "taxonomy_block",
    "taxonomy_only": "taxonomy_block",
    "b1_warn": "taxonomy_warn",
    "b1_block": "taxonomy_block",
    "b2": "consistency_only",
    "d": "dual_gate",
    "h": "dual_gate_llm",
    "full_gate": "dual_gate",
    "zero_shot_dev": "dual_gate",
    "c1": "dual_gate_no_c1",
    "c2": "dual_gate_no_c2",
    "c3": "dual_gate_no_c3",
    "c4": "dual_gate_no_c4",
    "c5": "dual_gate_no_c5",
    "c6": "dual_gate_no_c6",
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

    elif cfg_name == "taxonomy_block":
        # Baseline 1: Taxonomy / Regex matching only (Block on hit)
        text_to_scan = f"{dom_text} {raw_html or ''} {case.proposed_action.source_text or ''} {case.proposed_action.value or ''}"
        hit = bool(TAXONOMY_REGEX.search(text_to_scan))
        decision = "block" if hit else "allow"

    elif cfg_name == "taxonomy_warn":
        # Baseline 1b: Taxonomy matching with warning only
        text_to_scan = f"{dom_text} {raw_html or ''} {case.proposed_action.source_text or ''} {case.proposed_action.value or ''}"
        hit = bool(TAXONOMY_REGEX.search(text_to_scan))
        decision = "warn" if hit else "allow"

    elif cfg_name == "consistency_only":
        # Baseline 2: Context consistency verification only
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
            t_low = case.proposed_action.target.lower()
            val = str(case.proposed_action.value or "").strip().lower()
            mismatch = False
            for k, v in case.locked_intent.items():
                if k.lower() in t_low and val and str(v).lower() != val:
                    mismatch = True
                    break
            decision = "block" if mismatch else "allow"

    elif cfg_name == "regex_only":
        # Pure Regex Filter baseline
        text_to_scan = (
            f"{dom_text or ''} "
            f"{raw_html or ''} "
            f"{case.proposed_action.source_text or ''} "
            f"{case.proposed_action.value or ''} "
            f"{case.proposed_action.target or ''}"
        )
        hit = bool(TAXONOMY_REGEX.search(text_to_scan))
        decision = "block" if hit else "allow"

    elif cfg_name == "tool_allowlist":
        # Manifest Tool-Allowlist baseline
        manifests = get_sandbox_manifests()
        m = manifests.get(case.domain, {})
        allowed_acts = m.get("allowed_actions", set())
        domain_allowlist = DOMAIN_ALLOWLISTS.get(case.domain, set())
        act_type = case.proposed_action.action_type.upper()
        target = case.proposed_action.target

        allowed = False
        if act_type == "NAVIGATE":
            target_lower = target.lower()
            if any(h in target_lower for h in domain_allowlist) or target.startswith("/"):
                allowed = True
        else:
            if (act_type, target.lower()) in allowed_acts or ("*", target.lower()) in allowed_acts:
                allowed = True
        decision = "allow" if allowed else "block"

    elif cfg_name == "llm_judge_only":
        # LLM-Judge-Only baseline (gemini-3.5-flash-lite, no rule engine floor)
        action_dict = {
            "type": case.proposed_action.action_type,
            "target": case.proposed_action.target,
            "value": case.proposed_action.value,
            "url": case.proposed_action.page_url,
        }
        prompt = build_judge_prompt(case.locked_intent, action_dict)
        client = get_judge_client()
        try:
            resp = client.call(role="judge", prompt=prompt, use_cache=True, split=case.split)
            clean = resp.content.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:].strip()
            data = json.loads(clean)
            consistent = data.get("consistent", True)
            decision = "allow" if consistent else "require_confirmation"
            llm_record = LLMCallRecord(
                provider=resp.provider,
                model=resp.model,
                request_id=resp.request_id,
                tokens_in=resp.tokens_in,
                tokens_out=resp.tokens_out,
                latency_ms=resp.latency_ms,
            )
        except Exception as e:
            Path("runs").mkdir(parents=True, exist_ok=True)
            with open("runs/api_failures.log", "a", encoding="utf-8") as f_err:
                f_err.write(f"LLM Judge failure on {case.case_id}: {type(e).__name__}: {e}\n")
            raise RuntimeError(f"LLM API failure in {cfg_name} on {case.case_id}: {type(e).__name__}: {e}")

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
        # Canonical Gate + LLM Checker (Config H)
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
                err_msg = str(gate_res.llm_verdict.get("error"))
                Path("runs").mkdir(parents=True, exist_ok=True)
                with open("runs/api_failures.log", "a", encoding="utf-8") as f_err:
                    f_err.write(f"LLM Checker failure on {case.case_id}: {err_msg}\n")
                raise RuntimeError(
                    f"LLM Checker call fell back or failed in config {cfg_name}: {err_msg}"
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

    elif cfg_name in ("dual_gate_no_c1", "dual_gate_no_c2", "dual_gate_no_c3", "dual_gate_no_c4", "dual_gate_no_c5", "dual_gate_no_c6"):
        # Component C1-C6 leave-one-out ablations
        flags = {
            "dual_gate_no_c1": {"c1": False, "c2": True, "c3": True, "c4": True, "c5": True, "c6": True},
            "dual_gate_no_c2": {"c1": True, "c2": False, "c3": True, "c4": True, "c5": True, "c6": True},
            "dual_gate_no_c3": {"c1": True, "c2": True, "c3": False, "c4": True, "c5": True, "c6": True},
            "dual_gate_no_c4": {"c1": True, "c2": True, "c3": True, "c4": False, "c5": True, "c6": True},
            "dual_gate_no_c5": {"c1": True, "c2": True, "c3": True, "c4": True, "c5": False, "c6": True},
            "dual_gate_no_c6": {"c1": True, "c2": True, "c3": True, "c4": True, "c5": True, "c6": False},
        }[cfg_name]

        cache_key = f"{cfg_name}_{case.domain}"
        if gateway_cache is not None and cache_key in gateway_cache:
            gw = gateway_cache[cache_key]
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
            if gateway_cache is not None:
                gateway_cache[cache_key] = gw

        gate_res = gw.check(p_act, current_dom_text=dom_text)
        decision = map_gate_decision(gate_res.decision)

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
