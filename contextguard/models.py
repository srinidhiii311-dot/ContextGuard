"""
contextguard/models.py — Core Pydantic Contracts and Data Schemas

Defines the formal data contracts connecting all seven components of ContextGuard:
1. Runtime Context Monitor (ContextSnapshot)
2. Consistency Verification (ConsistencyReport, InconsistencyItem)
3. Threat Detection (ThreatDetectionResult)
4. Threat Characterization (ThreatDetectionResult with characterization_label)
5. Risk Assessment Engine (RiskAssessmentResult)
6. Declarative Policy Engine (PolicyDecisionResult)
7. Response Enforcement & Audit Logging (AuditRecord)
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# -----------------------------------------------------------------------------
# Decision & Policy Tiers
# -----------------------------------------------------------------------------

class PolicyDecision(str, Enum):
    ALLOW                = "ALLOW"
    ALLOW_WITH_FLAG      = "ALLOW_WITH_FLAG"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"
    BLOCK                = "BLOCK"
    PAUSE_TASK           = "PAUSE_TASK"


def normalize_decision(value: Any) -> PolicyDecision:
    """
    Normalizes string aliases or enum representations to canonical PolicyDecision.
    Maps legacy/test aliases (e.g. 'WARN' -> ALLOW_WITH_FLAG, 'PAUSE' -> PAUSE_TASK).
    """
    if isinstance(value, PolicyDecision):
        return value
    val_str = str(getattr(value, "value", value)).upper().strip()
    alias_map = {
        "ALLOW": PolicyDecision.ALLOW,
        "WARN": PolicyDecision.ALLOW_WITH_FLAG,
        "FLAG": PolicyDecision.ALLOW_WITH_FLAG,
        "ALLOW_WITH_FLAG": PolicyDecision.ALLOW_WITH_FLAG,
        "REQUIRE_CONFIRMATION": PolicyDecision.REQUIRE_CONFIRMATION,
        "PAUSE": PolicyDecision.PAUSE_TASK,
        "PAUSE_TASK": PolicyDecision.PAUSE_TASK,
        "BLOCK": PolicyDecision.BLOCK,
    }
    if val_str in alias_map:
        return alias_map[val_str]
    raise ValueError(f"Unknown or unmappable decision value: {value!r}")


class RiskTier(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# -----------------------------------------------------------------------------
# 0. Immutable Ground Truth: Locked Intent
# -----------------------------------------------------------------------------

class LockedIntent(BaseModel):
    """
    Parsed once from the user's natural language instruction and frozen.
    No webpage content or runtime event is allowed to modify this.
    """
    model_config = ConfigDict(frozen=True)

    origin: str = Field(..., description="Departure city or airport")
    destination: str = Field(..., description="Arrival city or airport")
    cabin_class: str = Field(default="Economy", description="Requested cabin class")
    passenger_count: int = Field(default=1, description="Number of passengers")
    max_price: Optional[int] = Field(default=None, description="Max budget constraint")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


# -----------------------------------------------------------------------------
# 1. Runtime Context Monitor Contracts
# -----------------------------------------------------------------------------

class ProposedAction(BaseModel):
    """Action proposed by the agent controller prior to browser execution."""
    action_type: str = Field(..., description="CLICK, TYPE, SELECT, SUBMIT, NAVIGATE")
    target: str = Field(..., description="Target selector, element name, or URL")
    value: Optional[str] = Field(default=None, description="Proposed input or selection value")
    source_text: Optional[str] = Field(default=None, description="DOM text agent cites as justification")
    page_url: str = Field(default="", description="Current URL before action")


class ContextSnapshot(BaseModel):
    """Objective snapshot of page state + proposed action captured before execution."""
    snapshot_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = Field(..., description="Associated task identifier")
    step_number: int = Field(default=0, description="Step sequence number")
    page_url: str = Field(..., description="Live page URL")
    dom_text: str = Field(..., description="Extracted visible text from DOM")
    visible_form_state: Dict[str, Any] = Field(default_factory=dict)
    proposed_action: ProposedAction = Field(...)
    timestamp: float = Field(default_factory=time.time)


# -----------------------------------------------------------------------------
# 2. Context Consistency Verification Contracts (Verification Rail)
# -----------------------------------------------------------------------------

class InconsistencyItem(BaseModel):
    """Specific mismatch or violation found during verification."""
    check_type: str = Field(..., description="FIELD_MISMATCH | NAVIGATION_BOUNDARY | INJECTION_MARKER")
    field_name: Optional[str] = None
    expected_value: Optional[str] = None
    observed_value: Optional[str] = None
    severity: float = Field(default=0.5, ge=0.0, le=1.0, description="Inconsistency severity score")
    detail: str = ""


class ConsistencyReport(BaseModel):
    """
    Output of Step 2 (Consistency Verification).
    Provides the direct data rail into Step 5 (Risk Assessment).
    """
    is_consistent: bool = Field(..., description="True if no inconsistencies detected")
    consistency_score: float = Field(default=1.0, ge=0.0, le=1.0, description="1.0 = fully consistent, 0.0 = completely diverged")
    inconsistency_severity: float = Field(default=0.0, ge=0.0, le=1.0, description="Max or aggregated severity of inconsistencies")
    inconsistencies: List[InconsistencyItem] = Field(default_factory=list)
    marker_presence: bool = Field(default=False, description="True if known injection marker was detected")
    marker_hit: Optional[str] = Field(default=None, description="Matched injection marker keyword/phrase")


# -----------------------------------------------------------------------------
# 3 & 4. Threat Detection & Characterization Contracts
# -----------------------------------------------------------------------------

class ThreatDetectionResult(BaseModel):
    """
    Output of either Step 3 (Known Detection) or Step 4 (Unknown Characterization).
    """
    is_threat: bool = Field(default=False)
    is_known_path: bool = Field(default=True, description="True = Step 3 taxonomy match; False = Step 4 characterization")
    attack_type: Optional[str] = Field(default=None, description="Known attack type (null for unknown path)")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Classification confidence (known path)")
    characterization_label: Optional[str] = Field(default=None, description="Constrained bucket label (unknown path)")
    deviation_signal: float = Field(default=0.0, description="Raw deviation magnitude (e.g. embedding distance)")
    normalized_deviation: float = Field(default=0.0, ge=0.0, le=1.0, description="Bounded normalized deviation signal")


# -----------------------------------------------------------------------------
# 5. Risk Assessment Engine Contracts
# -----------------------------------------------------------------------------

class RiskFactorBreakdown(BaseModel):
    threat_signal_contribution: float = 0.0
    inconsistency_contribution: float = 0.0
    action_sensitivity_contribution: float = 0.0
    marker_contribution: float = 0.0


class RiskAssessmentResult(BaseModel):
    """Continuous 0–100 risk score and associated risk tier."""
    risk_score: int = Field(..., ge=0, le=100, description="Continuous risk score computed from weights")
    risk_tier: RiskTier = Field(..., description="Mapped policy tier: LOW, MEDIUM, HIGH, CRITICAL")
    factors: RiskFactorBreakdown = Field(default_factory=RiskFactorBreakdown)
    action_sensitivity: float = Field(default=0.3, ge=0.0, le=1.0)
    booking_critical: bool = Field(default=False)


# -----------------------------------------------------------------------------
# 6. Policy Engine Contracts
# -----------------------------------------------------------------------------

class PolicyDecisionResult(BaseModel):
    """Graduated response selected by evaluating policy_rules.yaml."""
    decision: PolicyDecision = Field(...)
    reason: str = Field(..., description="Human-readable justification for the decision")
    escalated_from_prior_flags: bool = Field(default=False)
    requires_human_confirmation: bool = Field(default=False)


# -----------------------------------------------------------------------------
# 7. Traceable Audit Trail Contract
# -----------------------------------------------------------------------------

class AuditRecord(BaseModel):
    """
    Complete traceable causal chain for a single proposed action tick.
    Persisted to append-only audit_log table and streamed over WebSocket.
    """
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str
    step_number: int
    timestamp: float = Field(default_factory=time.time)
    proposed_action: ProposedAction
    context_snapshot_id: str
    consistency_report: ConsistencyReport
    threat_detection: ThreatDetectionResult
    risk_assessment: RiskAssessmentResult
    policy_decision: PolicyDecisionResult
    enforced_outcome: str = Field(..., description="EXECUTED | BLOCKED | PENDING_CONFIRMATION | TASK_PAUSED")
    processing_latency_ms: Dict[str, float] = Field(default_factory=dict, description="Latency breakdown per component")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
