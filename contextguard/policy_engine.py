"""
contextguard/policy_engine.py — Configurable Policy & Decision Engine

Separates ML prediction from policy enforcement:
- Uses configurable thresholds (ALLOW, WARN, PAUSE, BLOCK)
- Takes into account action sensitivity, consequentiality, and prior flag escalation
- Escalates high-sensitivity consequential actions (e.g. payment, sensitive data entry)
  if risk is elevated (>= 50)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


from contextguard.models import PolicyDecision


@dataclass
class PolicyDecisionResult:
    decision:                   Any             # PolicyDecision or str with .value
    reason:                     str
    risk_score:                 int             = 0
    model_confidence:           float           = 0.5
    requires_human_confirmation: bool           = False
    escalated_from_prior_flags:  bool           = False
    action_sensitivity:         float           = 0.0

    def to_dict(self) -> Dict[str, Any]:
        dec_val = getattr(self.decision, "value", str(self.decision))
        return {
            "decision":                   dec_val,
            "reason":                     self.reason,
            "risk_score":                 self.risk_score,
            "model_confidence":           self.model_confidence,
            "requires_human_confirmation": self.requires_human_confirmation,
            "escalated_from_prior_flags":  self.escalated_from_prior_flags,
            "action_sensitivity":         self.action_sensitivity,
        }


class PolicyEngine:
    """Evaluates configurable policy rules against continuous risk score and context."""

    def __init__(
        self,
        allow_threshold: float = 35.0,
        warn_threshold: float = 60.0,
        pause_threshold: float = 80.0,
        escalation_threshold: int = 2,
    ) -> None:
        self.allow_threshold = float(allow_threshold)
        self.warn_threshold = float(warn_threshold)
        self.pause_threshold = float(pause_threshold)
        self.escalation_threshold = escalation_threshold

    def update_thresholds(
        self,
        allow: Optional[float] = None,
        warn: Optional[float] = None,
        pause: Optional[float] = None,
    ) -> None:
        if allow is not None:
            self.allow_threshold = float(allow)
        if warn is not None:
            self.warn_threshold = float(warn)
        if pause is not None:
            self.pause_threshold = float(pause)

    def evaluate(
        self,
        risk_score: Optional[int] = None,
        model_confidence: float = 0.5,
        action_sensitivity: float = 0.0,
        is_consequential: bool = False,
        prior_flags: int = 0,
        context_reasons: Optional[str] = None,
        risk_assessment: Optional[Any] = None,
        booking_critical: bool = False,
        action_target: Optional[str] = None,
        action_type: Optional[str] = None,
        **kwargs: Any,
    ) -> PolicyDecisionResult:
        """
        Maps (Risk Score, Confidence, Sensitivity, Prior Flags) -> Graduated Decision.
        Decisions: ALLOW, ALLOW_WITH_FLAG, REQUIRE_CONFIRMATION / PAUSE_TASK, BLOCK.
        """
        is_escalated = prior_flags >= self.escalation_threshold
        requires_human = False
        reasons = [context_reasons] if context_reasons else []

        if risk_assessment is not None:
            if hasattr(risk_assessment, "risk_score"):
                risk_score = risk_assessment.risk_score
            elif isinstance(risk_assessment, dict):
                risk_score = risk_assessment.get("risk_score", 0)
            if hasattr(risk_assessment, "action_sensitivity"):
                action_sensitivity = risk_assessment.action_sensitivity
            elif isinstance(risk_assessment, dict):
                action_sensitivity = risk_assessment.get("action_sensitivity", action_sensitivity)

            if booking_critical:
                is_consequential = True

            tier_str = "LOW"
            if hasattr(risk_assessment, "risk_tier"):
                tier_val = getattr(risk_assessment.risk_tier, "value", str(risk_assessment.risk_tier))
                tier_str = str(tier_val).upper()
            elif risk_score >= 80:
                tier_str = "CRITICAL"
            elif risk_score >= 60:
                tier_str = "HIGH"
            elif risk_score >= 35:
                tier_str = "MEDIUM"
            else:
                tier_str = "LOW"

            matrix = {
                False: {  # Non-escalated base matrix
                    "LOW": {True: "ALLOW", False: "ALLOW"},
                    "MEDIUM": {True: "REQUIRE_CONFIRMATION", False: "ALLOW_WITH_FLAG"},
                    "HIGH": {True: "BLOCK", False: "REQUIRE_CONFIRMATION"},
                    "CRITICAL": {True: "BLOCK", False: "BLOCK"},
                },
                True: {   # Escalated matrix (prior_flags >= threshold)
                    "LOW": {True: "ALLOW_WITH_FLAG", False: "ALLOW"},
                    "MEDIUM": {True: "BLOCK", False: "REQUIRE_CONFIRMATION"},
                    "HIGH": {True: "PAUSE_TASK", False: "BLOCK"},
                    "CRITICAL": {True: "PAUSE_TASK", False: "BLOCK"},
                }
            }

            dec_str = matrix[is_escalated].get(tier_str, {}).get(bool(booking_critical or is_consequential), "ALLOW")
            decision_map = {
                "ALLOW": PolicyDecision.ALLOW,
                "ALLOW_WITH_FLAG": PolicyDecision.ALLOW_WITH_FLAG,
                "REQUIRE_CONFIRMATION": PolicyDecision.REQUIRE_CONFIRMATION,
                "BLOCK": PolicyDecision.BLOCK,
                "PAUSE_TASK": PolicyDecision.PAUSE_TASK,
            }
            decision = decision_map.get(dec_str, PolicyDecision.ALLOW)
            requires_human = decision in (PolicyDecision.REQUIRE_CONFIRMATION, PolicyDecision.PAUSE_TASK)

            reasons.append(f"Risk tier: {tier_str} (score {risk_score}), booking_critical={booking_critical} -> {dec_str}")
            final_reason = "; ".join(reasons)
        else:
            if risk_score is None:
                risk_score = 0

            if booking_critical:
                is_consequential = True

            # Configurable threshold-based evaluation with consequential action escalation
            if is_consequential and action_sensitivity >= 0.80 and risk_score >= 50:
                decision = PolicyDecision.REQUIRE_CONFIRMATION
                requires_human = True
                reasons.append(
                    f"High-sensitivity consequential action (sensitivity={action_sensitivity:.2f}) "
                    f"with elevated risk ({risk_score}/100) paused for operator confirmation"
                )
            elif risk_score >= self.pause_threshold:
                if is_escalated or risk_score >= 90:
                    decision = PolicyDecision.BLOCK
                    reasons.append(f"Critical risk score ({risk_score}/100 >= {self.pause_threshold})")
                else:
                    decision = PolicyDecision.PAUSE_TASK
                    requires_human = True
                    reasons.append(f"High risk score ({risk_score}/100 >= {self.pause_threshold}) requiring confirmation")
            elif risk_score >= self.warn_threshold or (is_escalated and risk_score >= self.allow_threshold):
                decision = PolicyDecision.ALLOW_WITH_FLAG
                reasons.append(f"Moderate risk score ({risk_score}/100) flagged for monitoring")
            else:
                decision = PolicyDecision.ALLOW
                reasons.append("Risk score within normal baseline bounds")

            final_reason = "; ".join(reasons) if reasons else f"Policy evaluation complete (Score: {risk_score})"

        return PolicyDecisionResult(
            decision=decision,
            reason=final_reason,
            risk_score=risk_score,
            model_confidence=model_confidence,
            requires_human_confirmation=requires_human,
            escalated_from_prior_flags=is_escalated,
            action_sensitivity=action_sensitivity,
        )


policy_engine = PolicyEngine()
