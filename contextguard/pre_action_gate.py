"""
contextguard/pre_action_gate.py — Pre-Action Safety Gate

Evaluates an intended agent action BEFORE browser execution.
Interprets action sensitivity, reversibility, task entity consistency,
and workflow stage. Halts or pauses consequential actions before mutation occurs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from backend.database.db import ContextGuardRuntimeDAO
from contextguard.task_context import TrustedTaskContext


@dataclass
class PreCheckResult:
    decision:           str             # ALLOW | PAUSE | BLOCK
    reason:             str
    risk_score:         int             # 0 to 100
    action_sensitivity: float           # 0.0 to 1.0
    is_consequential:   bool
    requires_operator:  bool            = False
    mismatch_detail:    Optional[str]   = None
    latency_ms:         float           = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision":           self.decision,
            "reason":             self.reason,
            "risk_score":         self.risk_score,
            "action_sensitivity": self.action_sensitivity,
            "is_consequential":   self.is_consequential,
            "requires_operator":  self.requires_operator,
            "mismatch_detail":    self.mismatch_detail,
        }


class PreActionGate:
    """Synchronous gate verifying intended actions before execution."""

    def __init__(
        self,
        base_domain: str = "127.0.0.1:8000",
        pause_threshold: float = 75.0,
        block_threshold: float = 90.0,
    ) -> None:
        self.base_domain = base_domain
        self.pause_threshold = pause_threshold
        self.block_threshold = block_threshold

    def evaluate_action(
        self,
        session_id: str,
        step_number: int,
        task_context: TrustedTaskContext,
        action: Dict[str, Any],
        current_url: str,
        current_page_name: str,
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

        # 3. Task Entity Consistency Check
        # Check Cabin Class
        if "cabin" in target or "class" in target:
            mismatch = task_context.check_entity_mismatch("cabin_class", val_str)
            if mismatch:
                risk_score += 70
                mismatch_detail = mismatch
                reasons.append(mismatch)

        # Check Passenger Count
        if "passenger" in target or "count" in target or "pcount" in target:
            mismatch = task_context.check_entity_mismatch("passengers", val_str)
            if mismatch:
                risk_score += 70
                mismatch_detail = mismatch
                reasons.append(mismatch)

        # Check Origin & Destination
        if "origin" in target or "from" in target:
            mismatch = task_context.check_entity_mismatch("origin", val_str)
            if mismatch:
                risk_score += 65
                mismatch_detail = mismatch
                reasons.append(mismatch)

        if "dest" in target or "to" in target:
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

        # 5. Policy Enforcement
        if risk_score >= self.block_threshold or (is_consequential and risk_score >= 80):
            decision = "BLOCK"
            reason = "; ".join(reasons) if reasons else "High-risk unauthorized action halted before execution"
            requires_operator = True
        elif risk_score >= self.pause_threshold or (is_consequential and risk_score >= 60):
            decision = "PAUSE"
            reason = "; ".join(reasons) if reasons else "Consequential action requires operator confirmation"
            requires_operator = True
        elif risk_score >= 40:
            decision = "WARN"
            reason = "; ".join(reasons) if reasons else "Action flagged with elevated risk but allowed"
            requires_operator = False
        else:
            decision = "ALLOW"
            reason = "Action aligns with task context"
            requires_operator = False

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
        )
