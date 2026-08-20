"""
Decision data models for ContextGuard.

A DecisionResult is the authoritative output of the decision engine.
The browser service reads the 'executable' flag; only ALLOW and WARN
decisions are executable. BLOCK and REQUIRE_APPROVAL are never executed
without an explicit human approval record.

Critical policy violations always override the numeric risk score to ensure
fail-closed behaviour: even a low-scoring action is blocked if a policy
demands it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class DecisionType(str, Enum):
    """
    Four-valued decision output.

    Priority order (highest first): BLOCK > REQUIRE_APPROVAL > WARN > ALLOW.
    The decision engine always applies the highest-priority applicable decision.
    """
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class RiskLevel(str, Enum):
    """
    Human-readable risk band derived from the numeric risk score.

    0–24   → LOW
    25–49  → MEDIUM
    50–69  → HIGH
    70–100 → CRITICAL
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Decision result
# ---------------------------------------------------------------------------

class DecisionResult(BaseModel):
    """
    The complete output of a ContextGuard evaluation.

    'executable' is True only for ALLOW and WARN decisions.
    'approval_required' is True only for REQUIRE_APPROVAL decisions.
    Critical policy violations set 'executable' to False regardless of score.
    """
    decision: DecisionType = Field(..., description="Final gate decision")
    risk_score: int = Field(..., ge=0, le=100, description="Numeric risk score 0–100")
    risk_level: RiskLevel = Field(..., description="Risk band")
    reasons: List[str] = Field(default_factory=list, description="Human-readable decision reasons")
    matched_policies: List[str] = Field(default_factory=list, description="Policy IDs that fired")
    risk_factors: List[str] = Field(default_factory=list, description="Individual risk contributions")
    tainted: bool = Field(False, description="Whether the action is influenced by untrusted content")
    taint_explanation: Optional[str] = Field(None, description="How taint reached this action")
    executable: bool = Field(False, description="Whether the browser may execute this action")
    approval_required: bool = Field(False, description="Whether human approval is needed")
    action_id: str = Field(..., description="ID of the evaluated action")
    approval_id: Optional[str] = Field(None, description="ID of the created approval request, if any")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the decision"
    )

    @classmethod
    def from_risk_score(
        cls,
        score: int,
        action_id: str,
        reasons: Optional[List[str]] = None,
        matched_policies: Optional[List[str]] = None,
        risk_factors: Optional[List[str]] = None,
        tainted: bool = False,
        taint_explanation: Optional[str] = None,
        force_decision: Optional[DecisionType] = None,
    ) -> "DecisionResult":
        """
        Build a DecisionResult from a numeric score.

        If force_decision is provided it overrides the score-derived decision —
        this is used when a critical policy fires regardless of score.
        """
        score = max(0, min(100, score))
        risk_level = _score_to_level(score)

        if force_decision is not None:
            decision = force_decision
        elif score >= 70:
            decision = DecisionType.BLOCK
        elif score >= 50:
            decision = DecisionType.REQUIRE_APPROVAL
        elif score >= 25:
            decision = DecisionType.WARN
        else:
            decision = DecisionType.ALLOW

        executable = decision in (DecisionType.ALLOW, DecisionType.WARN)
        approval_required = decision == DecisionType.REQUIRE_APPROVAL

        return cls(
            decision=decision,
            risk_score=score,
            risk_level=risk_level,
            reasons=reasons or [],
            matched_policies=matched_policies or [],
            risk_factors=risk_factors or [],
            tainted=tainted,
            taint_explanation=taint_explanation,
            executable=executable,
            approval_required=approval_required,
            action_id=action_id,
        )


def _score_to_level(score: int) -> RiskLevel:
    """Map a numeric score to a risk level band."""
    if score >= 70:
        return RiskLevel.CRITICAL
    elif score >= 50:
        return RiskLevel.HIGH
    elif score >= 25:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW


class ApprovalRequest(BaseModel):
    """Represents a pending human-approval request for a REQUIRE_APPROVAL action."""
    approval_id: str = Field(..., description="Unique approval request ID")
    action_id: str = Field(..., description="The exact action ID that needs approval")
    session_id: str = Field(..., description="Session the action belongs to")
    agent_id: str = Field(..., description="Agent that proposed the action")
    action_type: str = Field(..., description="Type of browser action")
    target_url: Optional[str] = Field(None)
    target_selector: Optional[str] = Field(None)
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str = Field(...)
    reasons: List[str] = Field(default_factory=list)
    matched_policies: List[str] = Field(default_factory=list)
    status: str = Field("pending", description="pending | approved | rejected | expired")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = Field(None)
    resolved_by: Optional[str] = Field(None)


class ApprovalResponse(BaseModel):
    """Response returned when resolving an approval request."""
    approval_id: str
    action_id: str
    status: str
    message: str
    executable: bool
