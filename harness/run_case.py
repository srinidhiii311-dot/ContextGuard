"""
harness/run_case.py — Evaluation Case Execution Harness for ContextGuard (Block 3)

Runs individual EvaluationCases through the real ContextGuardGate pipeline
(via Gateway.from_domain) and outputs standard RunRecords to runs/<config>_<seed>.jsonl.
Strictly enforces test data isolation rules.
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel

from gateway.loader import Gateway
from contextguard.gate import ContextGuardGate, Decision, GateResult, ProposedAction, TrustedIntent
from harness.case_schema import EvaluationCase
from harness.run_record import LLMCallRecord, RunRecord, write_run_record
from harness.split import TestDataLeakError, guard_tuning_item

ROOT_DIR = Path(__file__).resolve().parent.parent


def build_trusted_intent_from_dict(domain: str, locked_dict: Dict[str, Any]) -> TrustedIntent:
    """Builds a typed TrustedIntent from the case locked_intent dictionary."""
    d = domain.lower().strip()
    extra = dict(locked_dict)
    if d == "flight":
        return TrustedIntent(
            origin=locked_dict.get("origin", "Chennai"),
            destination=locked_dict.get("destination", "Delhi"),
            cabin_class=locked_dict.get("cabin_class", "Economy"),
            passenger_count=int(locked_dict.get("passenger_count", 1)),
            travel_date=locked_dict.get("travel_date"),
            contact_email=locked_dict.get("contact_email"),
            extra_fields=extra,
        )
    elif d == "email":
        contact_email = (
            locked_dict.get("contact_email")
            or locked_dict.get("to_email")
            or locked_dict.get("recipient")
            or "user@company.internal"
        )
        return TrustedIntent(
            contact_email=contact_email,
            extra_fields=extra,
        )
    else:
        return TrustedIntent(extra_fields=extra)


def map_gate_decision(decision: Union[Decision, str]) -> str:
    """Normalizes gate Decision enum to standard label: allow, warn, ask_human, block."""
    raw = decision.value if isinstance(decision, Decision) else str(decision)
    raw_lower = raw.lower().strip()
    if raw_lower == "allow":
        return "allow"
    elif raw_lower in ("allow_with_flag", "flag", "warn"):
        return "warn"
    elif raw_lower in ("require_confirmation", "pause_task", "ask_human", "ask"):
        return "ask_human"
    elif raw_lower == "block":
        return "block"
    return raw_lower


def run_case(
    case: Union[Dict[str, Any], EvaluationCase],
    gateway: Optional[Gateway] = None,
    config: str = "zero_shot_dev",
    seed: int = 42,
    enforce_split_guard: bool = True,
) -> RunRecord:
    """
    Executes a single evaluation case through the REAL gate.
    
    Args:
        case: EvaluationCase model or dict conforming to EvaluationCase schema.
        gateway: Optional pre-configured Gateway instance. If None, builds Gateway.from_domain.
        config: Evaluation configuration name (e.g., 'zero_shot_dev').
        seed: Random seed for this run.
        enforce_split_guard: If True and config implies dev/tuning, blocks execution on 'test' split.
        
    Returns:
        Populated RunRecord conforming to the canonical schema.
    """
    if isinstance(case, dict):
        case_obj = EvaluationCase.model_validate(case)
    else:
        case_obj = case

    # Enforce isolation guard if running a tuning/dev configuration
    if enforce_split_guard and "dev" in config.lower():
        guard_tuning_item(case_obj.split)

    # Prepare TrustedIntent
    intent = build_trusted_intent_from_dict(case_obj.domain, case_obj.locked_intent)

    # Initialize Gateway if not provided or domain mismatched
    if gateway is None or gateway.domain != case_obj.domain:
        gateway = Gateway.from_domain(case_obj.domain, trusted_intent=intent)
    else:
        # Update gate's intent and verifier intent
        if gateway.gate is not None:
            gateway.set_intent(intent)

    # Build ProposedAction
    p_act = ProposedAction(
        action_type=case_obj.proposed_action.action_type,
        target=case_obj.proposed_action.target,
        value=case_obj.proposed_action.value,
        page_url=case_obj.proposed_action.page_url,
        source_text=case_obj.proposed_action.source_text,
        raw_html=case_obj.page_state.raw_html,
    )

    # Execute gate check with latency tracking
    t_start = time.perf_counter()
    gate_result: GateResult = gateway.check(
        action=p_act,
        current_dom_text=case_obj.page_state.visible_text,
    )
    latency_ms = (time.perf_counter() - t_start) * 1000.0

    normalized_decision = map_gate_decision(gate_result.decision)

    record = RunRecord(
        run_id=f"run_{case_obj.case_id}_{config}_{seed}",
        task_id=case_obj.case_id,
        domain=case_obj.domain,
        config=config,
        seed=seed,
        case_type=case_obj.case_type,
        family=case_obj.family,
        split=case_obj.split,
        proposed_action=case_obj.proposed_action.model_dump(),
        decision=normalized_decision,
        ground_truth_label=case_obj.ground_truth_label,
        latency_ms=round(latency_ms, 2),
        llm_call=None,
    )

    return record


def run_batch_evaluation(
    cases: List[Union[Dict[str, Any], EvaluationCase]],
    config: str = "zero_shot_dev",
    seed: int = 42,
    output_path: Optional[Union[str, Path]] = None,
    enforce_split_guard: bool = True,
) -> List[RunRecord]:
    """
    Evaluates a collection of cases through the real gate, writes out JSONL,
    and returns the list of RunRecords.
    """
    # Cache gateways by domain for speed
    gateways: Dict[str, Gateway] = {}
    records: List[RunRecord] = []

    for c in cases:
        case_obj = EvaluationCase.model_validate(c) if isinstance(c, dict) else c
        domain = case_obj.domain

        # Create or update domain gateway
        intent = build_trusted_intent_from_dict(domain, case_obj.locked_intent)
        gw = Gateway.from_domain(domain, trusted_intent=intent)

        rec = run_case(
            case=case_obj,
            gateway=gw,
            config=config,
            seed=seed,
            enforce_split_guard=enforce_split_guard,
        )
        records.append(rec)

        if output_path is not None:
            out_file = Path(output_path)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "a", encoding="utf-8") as f:
                f.write(rec.model_dump_json() + "\n")
        else:
            rec.write_to_file(base_dir=ROOT_DIR / "runs")

    return records

