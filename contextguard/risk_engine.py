"""
contextguard/risk_engine.py — Phase 5, Checkpoint 5.3

Maps inconsistencies from the consistency checker into a 0–100 risk score
and a SAFE / SUSPICIOUS / HIGH_RISK status.

Weighted rules (MVP rule-based engine)
---------------------------------------
The weights are conservative and additive, capped at 100.
A rule-based engine is the MVP; LLM-based semantic comparison
is stated future work (per ROADMAP Phase 5 notes).

Score bands
-----------
0–29   SAFE        — normal booking flow, no anomalies
30–59  SUSPICIOUS  — one or more soft anomalies, monitor closely
60–100 HIGH_RISK   — critical finding (injection, foreign domain, mismatch)
                     → triggers intervention if enabled

Threat type mapping (for security_events table)
------------------------------------------------
injection_keywords      → PROMPT_INJECTION
hidden_content          → HIDDEN_CONTENT_ATTACK
dom_manipulation        → DOM_MANIPULATION_ATTACK
large_dom_change        → CONTEXT_MANIPULATION
cabin_class_mismatch    → PARAMETER_TAMPERING
destination_mismatch    → PARAMETER_TAMPERING
origin_mismatch         → PARAMETER_TAMPERING
passenger_count_mismatch→ PARAMETER_TAMPERING
premature_submit        → PLAN_INJECTION
foreign_navigation      → NAVIGATION_ATTACK
malicious_domain        → NAVIGATION_ATTACK
action_on_injected_page → COMPOUND_ATTACK
url_regression          → NAVIGATION_ATTACK
page_order_violation    → PLAN_INJECTION
unexpected_domain       → NAVIGATION_ATTACK
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from contextguard.consistency_checker import ConsistencyReport

# -------------------------------------------------------------------
# Status thresholds
# -------------------------------------------------------------------
SAFE_THRESHOLD      = 30
SUSPICIOUS_THRESHOLD= 60

# -------------------------------------------------------------------
# Threat type lookup
# -------------------------------------------------------------------
_THREAT_MAP: Dict[str, str] = {
    "injection_keywords":       "PROMPT_INJECTION",
    "hidden_content":           "HIDDEN_CONTENT_ATTACK",
    "dom_manipulation":         "DOM_MANIPULATION_ATTACK",
    "large_dom_change":         "CONTEXT_MANIPULATION",
    "medium_dom_change":        "CONTEXT_MANIPULATION",
    "cabin_class_mismatch":     "PARAMETER_TAMPERING",
    "destination_mismatch":     "PARAMETER_TAMPERING",
    "origin_mismatch":          "PARAMETER_TAMPERING",
    "passenger_count_mismatch": "PARAMETER_TAMPERING",
    "premature_submit":         "PLAN_INJECTION",
    "foreign_navigation":       "NAVIGATION_ATTACK",
    "malicious_domain":         "NAVIGATION_ATTACK",
    "action_on_injected_page":  "COMPOUND_ATTACK",
    "url_regression":           "NAVIGATION_ATTACK",
    "page_order_violation":     "PLAN_INJECTION",
    "unexpected_domain":        "NAVIGATION_ATTACK",
}

# Critical finding types that always push score to HIGH_RISK
_CRITICAL_FINDINGS = {
    "injection_keywords",
    "malicious_domain",
    "foreign_navigation",
    "action_on_injected_page",
    "destination_mismatch",
    "origin_mismatch",
}


@dataclass
class RiskResult:
    risk_score:   int
    status:       str              # SAFE | SUSPICIOUS | HIGH_RISK
    threat_types: List[str]        = field(default_factory=list)
    top_finding:  Optional[str]    = None
    details:      List[Dict]       = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score":   self.risk_score,
            "status":       self.status,
            "threat_types": self.threat_types,
            "top_finding":  self.top_finding,
            "details":      self.details,
        }


class RiskEngine:
    """
    Checkpoint 5.3 — maps ConsistencyReport → RiskResult.

    Note: This is a rule-based MVP.  LLM-based semantic comparison
    is the stated next iteration (see ROADMAP Phase 5).
    """

    def evaluate(
        self,
        report:    ConsistencyReport,
        base_score: int = 0,
    ) -> RiskResult:
        score         = base_score
        threat_types  = []
        top_finding   = None
        top_delta     = 0
        details       = []

        for inc in report.inconsistencies:
            score      += inc.risk_delta
            threat_type = _THREAT_MAP.get(inc.finding_type, "UNKNOWN")

            if threat_type not in threat_types:
                threat_types.append(threat_type)

            if inc.risk_delta > top_delta:
                top_delta   = inc.risk_delta
                top_finding = inc.description

            details.append({
                "source":       inc.source,
                "finding_type": inc.finding_type,
                "threat_type":  threat_type,
                "risk_delta":   inc.risk_delta,
                "description":  inc.description[:120],
            })

            # Critical findings force score into HIGH_RISK zone
            if inc.finding_type in _CRITICAL_FINDINGS:
                score = max(score, SUSPICIOUS_THRESHOLD + 1)

        score = min(score, 100)

        if score >= SUSPICIOUS_THRESHOLD:
            status = "HIGH_RISK"
        elif score >= SAFE_THRESHOLD:
            status = "SUSPICIOUS"
        else:
            status = "SAFE"

        return RiskResult(
            risk_score   = score,
            status       = status,
            threat_types = threat_types,
            top_finding  = top_finding,
            details      = details,
        )


risk_engine = RiskEngine()


# ---------------------------------------------------------------------------
# ContextGuard Component 5: Continuous Multi-Factor Risk Assessment Engine
# Specification Reference: Section 3 (Step 7), FR14, FR15, FR16
# ---------------------------------------------------------------------------

from pathlib import Path
import yaml
from contextguard.models import (
    ConsistencyReport as NewConsistencyReport,
    RiskAssessmentResult,
    RiskFactorBreakdown,
    RiskTier,
    ThreatDetectionResult,
)

CONFIG_DIR = Path(__file__).parent / "config"


class ContextGuardRiskAssessmentEngine:
    """
    Computes continuous 0-100 risk score combining:
    - Classification confidence (or normalized deviation signal for unknown path)
    - Inconsistency severity (from Step 2 Verification Rail)
    - Action sensitivity (from protected_fields.yaml)
    - Marker presence (from Step 2 Verification Rail)
    Weights are externally configured via risk_weights.yaml (FR15).
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        cfg_file = config_path or (CONFIG_DIR / "risk_weights.yaml")
        if not cfg_file.exists():
            raise FileNotFoundError(f"Missing risk weights config: {cfg_file}")

        data = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
        w = data.get("weights", {})
        self.w_conf: float = float(w.get("weight_classification_confidence", 0.25))
        self.w_inconsist: float = float(w.get("weight_inconsistency_severity", 0.30))
        self.w_action: float = float(w.get("weight_action_sensitivity", 0.25))
        self.w_marker: float = float(w.get("weight_marker_presence", 0.20))

        self.tiers_config = data.get("risk_tiers", {})

    def assess(
        self,
        threat_result: ThreatDetectionResult,
        consistency_report: NewConsistencyReport,
        action_sensitivity: float,
        booking_critical: bool,
    ) -> RiskAssessmentResult:
        """
        Combines threat signal, consistency severity, action sensitivity, and marker presence.
        Returns continuous RiskAssessmentResult with mapped RiskTier.
        """
        # Threat signal: confidence for known path, normalized deviation for unknown path
        if threat_result.is_known_path:
            threat_signal = threat_result.confidence if threat_result.is_threat else 0.0
        else:
            threat_signal = threat_result.normalized_deviation if threat_result.is_threat else 0.0

        inconsistency_severity = consistency_report.inconsistency_severity if not consistency_report.is_consistent else 0.0
        marker_indicator = 1.0 if consistency_report.marker_presence else 0.0
        sensitivity = max(0.0, min(1.0, action_sensitivity))

        # Multi-factor weighted contributions
        c_threat = self.w_conf * threat_signal
        c_inconsist = self.w_inconsist * inconsistency_severity
        c_action = self.w_action * sensitivity
        c_marker = self.w_marker * marker_indicator

        raw_score = 100.0 * (c_threat + c_inconsist + c_action + c_marker)
        risk_score = int(round(max(0.0, min(100.0, raw_score))))

        # Map to RiskTier
        risk_tier = self._map_to_tier(risk_score)

        return RiskAssessmentResult(
            risk_score=risk_score,
            risk_tier=risk_tier,
            factors=RiskFactorBreakdown(
                threat_signal_contribution=round(c_threat * 100, 2),
                inconsistency_contribution=round(c_inconsist * 100, 2),
                action_sensitivity_contribution=round(c_action * 100, 2),
                marker_contribution=round(c_marker * 100, 2),
            ),
            action_sensitivity=sensitivity,
            booking_critical=booking_critical,
        )

    def _map_to_tier(self, score: int) -> RiskTier:
        for tier_name in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            tier_info = self.tiers_config.get(tier_name, {})
            min_s = tier_info.get("min_score", 0)
            max_s = tier_info.get("max_score", 100)
            if min_s <= score <= max_s:
                return RiskTier(tier_name)
        if score >= 85:
            return RiskTier.CRITICAL
        elif score >= 60:
            return RiskTier.HIGH
        elif score >= 30:
            return RiskTier.MEDIUM
        return RiskTier.LOW

