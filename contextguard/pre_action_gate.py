"""
contextguard/pre_action_gate.py — Pre-Action Safety Gate

Evaluates an intended agent action BEFORE browser execution.
Interprets action sensitivity, reversibility, task entity consistency,
and workflow stage. Halts or pauses consequential actions before mutation occurs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from backend.database.db import ContextGuardRuntimeDAO
from contextguard.gate import ContextGuardGate, Decision, ProposedAction, TrustedIntent
from contextguard.task_context import TrustedTaskContext


@dataclass
class PreCheckResult:
    decision:           str             # ALLOW | PAUSE | BLOCK | WARN
    reason:             str
    risk_score:         int             # 0 to 100
    action_sensitivity: float           # 0.0 to 1.0
    is_consequential:   bool
    requires_operator:  bool            = False
    mismatch_detail:    Optional[str]   = None
    latency_ms:         float           = 0.0
    matched_rules:      List[str]       = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision":           self.decision,
            "reason":             self.reason,
            "risk_score":         self.risk_score,
            "action_sensitivity": self.action_sensitivity,
            "is_consequential":   self.is_consequential,
            "requires_operator":  self.requires_operator,
            "mismatch_detail":    self.mismatch_detail,
            "matched_rules":      self.matched_rules,
        }


class PreActionGate:
    """Synchronous pre-action safety gateway.
    Consolidates runtime action verification with the canonical 11-layer ContextGuardGate pipeline,
    ensuring 100% defense parity between live interactive agent sessions and benchmarked evaluation.
    """

    def __init__(
        self,
        base_domain: str = "127.0.0.1:8000",
        warn_threshold: float = 30.0,
        pause_threshold: float = 60.0,
        block_threshold: float = 85.0,
    ) -> None:
        self.base_domain = base_domain
        self.warn_threshold = warn_threshold
        self.pause_threshold = pause_threshold
        self.block_threshold = block_threshold
        self._canonical_gates: Dict[str, ContextGuardGate] = {}

    def _get_or_create_gate(self, session_id: str, task_context: Any) -> ContextGuardGate:
        if session_id not in self._canonical_gates:
            domain = getattr(task_context, "domain", None)
            if not domain and isinstance(task_context, dict):
                domain = task_context.get("domain")

            if domain and domain.lower().strip() != "flight":
                d = domain.lower().strip()
                if isinstance(task_context, TrustedIntent):
                    intent = task_context
                elif isinstance(task_context, dict):
                    data = {k: v for k, v in task_context.items() if k not in ("domain", "task_id", "session_id")}
                    if "to_email" in data and "contact_email" not in data:
                        data["contact_email"] = data["to_email"]
                    intent = TrustedIntent.from_dict(data)
                elif hasattr(task_context, "to_dict"):
                    data = task_context.to_dict()
                    data = {k: v for k, v in data.items() if k not in ("domain", "task_id", "session_id")}
                    if "to_email" in data and "contact_email" not in data:
                        data["contact_email"] = data["to_email"]
                    intent = TrustedIntent.from_dict(data)
                elif hasattr(task_context, "extra_fields"):
                    intent = TrustedIntent(extra_fields=getattr(task_context, "extra_fields"))
                else:
                    attrs = {k: getattr(task_context, k) for k in dir(task_context) if not k.startswith("_") and not callable(getattr(task_context, k))}
                    attrs.pop("domain", None)
                    if "to_email" in attrs and "contact_email" not in attrs:
                        attrs["contact_email"] = attrs["to_email"]
                    intent = TrustedIntent.from_dict(attrs)

                from gateway.loader import Gateway
                gw = Gateway.from_domain(d, trusted_intent=intent, task_id=session_id)
                self._canonical_gates[session_id] = gw.gate
            else:
                # Flight domain requires origin, destination, cabin_class, passengers
                origin = task_context.get("origin") if isinstance(task_context, dict) else getattr(task_context, "origin", None)
                dest = task_context.get("destination") if isinstance(task_context, dict) else getattr(task_context, "destination", None)
                cabin = task_context.get("cabin_class") if isinstance(task_context, dict) else getattr(task_context, "cabin_class", None)
                if isinstance(task_context, dict):
                    pax = task_context.get("passengers") if task_context.get("passengers") is not None else task_context.get("passenger_count")
                else:
                    pax = getattr(task_context, "passengers", None) if getattr(task_context, "passengers", None) is not None else getattr(task_context, "passenger_count", None)

                if not origin:
                    raise ValueError(f"Required intent field 'origin' is missing for session '{session_id}'.")
                if not dest:
                    raise ValueError(f"Required intent field 'destination' is missing for session '{session_id}'.")
                if not cabin:
                    raise ValueError(f"Required intent field 'cabin_class' is missing for session '{session_id}'.")
                if pax is None:
                    raise ValueError(f"Required intent field 'passengers' is missing for session '{session_id}'.")
                intent = TrustedIntent(
                    origin=str(origin).strip(),
                    destination=str(dest).strip(),
                    cabin_class=str(cabin).strip(),
                    passenger_count=int(pax),
                )
                from gateway.loader import Gateway
                gw = Gateway.from_domain("flight", trusted_intent=intent, task_id=session_id)
                self._canonical_gates[session_id] = gw.gate
        return self._canonical_gates[session_id]

    def evaluate_action(
        self,
        session_id: str,
        step_number: int,
        task_context: TrustedTaskContext,
        action: Dict[str, Any],
        current_url: str,
        current_page_name: str,
        page_text: str,
    ) -> PreCheckResult:
        """
        Runs pre-action security checks.
        """
        atype = str(action.get("type", "")).upper()
        target = str(action.get("selector", action.get("target", ""))).lower()
        val = action.get("value", None)
        val_str = str(val) if val is not None else ""

        risk_score = 10
        reasons: List[str] = []
        action_sensitivity = 0.1
        is_consequential = False
        mismatch_detail = None

        # 1. Action Sensitivity & Consequentiality Assessment
        if any(term in target for term in ("pay", "checkout", "cvv", "ssn", "password", "commit")) or ("card" in target and "flight" not in target):
            action_sensitivity = 0.95
            is_consequential = True
        elif atype == "NAVIGATE" or "href" in target or "http" in target:
            action_sensitivity = 0.85
            is_consequential = True
        elif atype in ("SUBMIT", "CLICK") and ("confirm" in target or "book" in target):
            action_sensitivity = 0.80
            is_consequential = True
        elif atype == "SELECT" or atype == "TYPE":
            action_sensitivity = 0.35

        # 2. Navigation Boundary & External Domain Check
        if atype == "NAVIGATE" or (val_str and val_str.startswith("http")):
            dest_url = val_str or target
            netloc = urlparse(dest_url).netloc
            if netloc and self.base_domain not in netloc and "localhost" not in netloc:
                risk_score += 85
                action_sensitivity = 1.0
                reasons.append(f"Action targets external untrusted domain '{netloc}'")

        # 3. Task Entity Consistency Check (for form input/selection actions)
        is_input_action = atype in ("TYPE", "SELECT", "INPUT", "FILL") or (
            atype == "CLICK" and not any(k in target for k in ("btn", "button", "submit", "continue", "review", "confirm", "card"))
        )

        # Check Cabin Class
        if is_input_action and ("cabin" in target or "class" in target) and hasattr(task_context, "check_entity_mismatch"):
            mismatch = task_context.check_entity_mismatch("cabin_class", val_str)
            if mismatch:
                risk_score += 70
                mismatch_detail = mismatch
                reasons.append(mismatch)

        # Check Passenger Count
        if is_input_action and ("passenger" in target or "count" in target or "pcount" in target) and hasattr(task_context, "check_entity_mismatch"):
            mismatch = task_context.check_entity_mismatch("passengers", val_str)
            if mismatch:
                risk_score += 70
                mismatch_detail = mismatch
                reasons.append(mismatch)

        # Check Origin & Destination
        if is_input_action and ("origin" in target or target in ("#from", "input#from")) and hasattr(task_context, "check_entity_mismatch"):
            mismatch = task_context.check_entity_mismatch("origin", val_str)
            if mismatch:
                risk_score += 65
                mismatch_detail = mismatch
                reasons.append(mismatch)

        if is_input_action and ("dest" in target or target in ("#to", "input#to", "[name='to']")) and hasattr(task_context, "check_entity_mismatch"):
            mismatch = task_context.check_entity_mismatch("destination", val_str)
            if mismatch:
                risk_score += 65
                mismatch_detail = mismatch
                reasons.append(mismatch)

        # 4. Premature Commit / Workflow Stage Integrity
        if ("confirm" in target or "pay" in target) and current_page_name in ("search", "results"):
            risk_score += 60
            is_consequential = True
            reasons.append(f"Premature booking commit attempted from '{current_page_name}' page")

        # Clamp risk score
        risk_score = min(100, max(0, risk_score))

        # 5. Canonical 11-Layer ContextGuardGate Verification
        canonical_gate = self._get_or_create_gate(session_id, task_context)
        proposed = ProposedAction(
            action_type=atype,
            target=target,
            value=val_str if val is not None else None,
            page_url=current_url,
            source_text=action.get("source_text"),
            raw_html=action.get("raw_html"),
        )
        canonical_res = canonical_gate.check(proposed, page_text)
        try:
            matched_rules = [
                inc.check_type for inc in canonical_gate._verifier.verify(
                    canonical_gate.trusted_intent.to_locked_intent(), proposed.to_model(), page_text
                ).inconsistencies
            ]
        except Exception:
            matched_rules = []

        canonical_dec_map = {
            Decision.BLOCK: "BLOCK",
            Decision.PAUSE_TASK: "PAUSE",
            Decision.REQUIRE_CONFIRMATION: "PAUSE",
            Decision.ALLOW_WITH_FLAG: "WARN",
            Decision.FLAG: "WARN",
            Decision.ALLOW: "ALLOW",
        }
        decision = canonical_dec_map.get(canonical_res.decision, "ALLOW")
        risk_score = canonical_res.risk_score
        if canonical_res.reason and canonical_res.reason not in reasons:
            reasons.insert(0, canonical_res.reason)
        reason = "; ".join(reasons) if reasons else "Action aligns with task context"
        requires_operator = decision in ("BLOCK", "PAUSE")

        # Record to database
        ContextGuardRuntimeDAO.record_policy_decision(
            session_id=session_id,
            step_number=step_number,
            phase="PRE_ACTION",
            decision=decision,
            reason=reason,
            risk_score=risk_score,
            action_sensitivity=action_sensitivity,
            enforced_action=f"{atype} {target}"[:100],
        )

        return PreCheckResult(
            decision=decision,
            reason=reason,
            risk_score=risk_score,
            action_sensitivity=action_sensitivity,
            is_consequential=is_consequential,
            requires_operator=requires_operator,
            mismatch_detail=mismatch_detail,
            matched_rules=matched_rules,
        )
