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


@dataclass
class PolicyDecisionResult:
    decision:                   str             # ALLOW | WARN | PAUSE | BLOCK
    reason:                     str
    risk_score:                 int
    model_confidence:           float
    requires_human_confirmation: bool
    escalated_from_prior_flags:  bool
    action_sensitivity:         float           = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision":                   self.decision,
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
        risk_score: int,
        model_confidence: float = 0.5,
        action_sensitivity: float = 0.0,
        is_consequential: bool = False,
        prior_flags: int = 0,
        context_reasons: Optional[str] = None,
    ) -> PolicyDecisionResult:
        """
        Maps (Risk Score, Confidence, Sensitivity, Prior Flags) -> Graduated Decision.
        Decisions: ALLOW, WARN, PAUSE, BLOCK.
        """
        is_escalated = prior_flags >= self.escalation_threshold
        requires_human = False

        reasons = [context_reasons] if context_reasons else []

        # High-impact sensitive action escalation (e.g. payment, external nav)
        if is_consequential and action_sensitivity >= 0.80 and risk_score >= 50:
            decision = "PAUSE"
            requires_human = True
            reasons.append(
                f"High-sensitivity consequential action (sensitivity={action_sensitivity:.2f}) "
                f"with elevated risk ({risk_score}/100) paused for operator confirmation"
            )
        elif risk_score >= self.pause_threshold:
            if is_escalated or risk_score >= 90:
                decision = "BLOCK"
                reasons.append(f"Critical risk score ({risk_score}/100 >= {self.pause_threshold})")
            else:
                decision = "PAUSE"
                requires_human = True
                reasons.append(f"High risk score ({risk_score}/100 >= {self.pause_threshold}) requiring confirmation")
        elif risk_score >= self.warn_threshold or (is_escalated and risk_score >= self.allow_threshold):
            decision = "WARN"
            reasons.append(f"Moderate risk score ({risk_score}/100) flagged for monitoring")
        else:
            decision = "ALLOW"
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
