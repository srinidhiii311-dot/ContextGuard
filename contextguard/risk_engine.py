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
        """
        Compute final risk score from the consistency report.

        base_score: carry-over from previous steps in the same task
        (allows the score to accumulate across a multi-step run).
        """
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
