"""
backend/contextguard/rules.py — Phase 1 Rule Engine

Combines extracted features into a calibrated risk score (0-100),
characterizes the detected threat type, and provides human-readable reasoning.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


class RuleEngine:
    """Combines extracted feature signals into calibrated risk scores and threat characterization."""

    @staticmethod
    def evaluate(features: Dict[str, Any]) -> Tuple[float, Optional[str], str]:
        """
        Takes normalized features:
        - intent_inconsistency (0.0 - 1.0)
        - domain_risk (0.0 - 1.0)
        - injection_risk (0.0 - 1.0)
        - field_tampering_risk (0.0 - 1.0)

        Returns: (risk_score, threat_type, reasoning)
        """
        intent_inc = features["intent_inconsistency"]
        dom_risk = features["domain_risk"]
        inj_risk = features["injection_risk"]
        is_action_inj = features.get("injection_is_action_level", False)
        field_risk = features["field_tampering_risk"]
        exp = features.get("explanations", {})

        threat_type: Optional[str] = None
        reasons: list[str] = []

        # 1. External Untrusted Navigation Check (Dominant severe threat)
        if dom_risk >= 0.8:
            threat_type = threat_type or "external_untrusted_navigation"
            reasons.append(exp.get("domain", "Untrusted foreign domain boundary divergence"))

        # 2. Field Tampering / Harvesting Check
        if field_risk >= 0.8:
            threat_type = threat_type or "dom_tampering"
            reasons.append(exp.get("field", "Tampered or harvested inputs detected in DOM"))

        # 3. Prompt Injection Check:
        # Active injection in the proposed action, OR ambient injection coupled with intent divergence
        if is_action_inj and inj_risk >= 0.6:
            threat_type = threat_type or "prompt_injection"
            reasons.append(exp.get("injection", "Active prompt injection in proposed action"))
        elif inj_risk >= 0.5 and intent_inc >= 0.5:
            threat_type = threat_type or "prompt_injection"
            reasons.append(f"Prompt injection induced goal deviation: {exp.get('intent', 'contravened locked intent')}")

        # 4. Intent Inconsistency / Goal Deviation Check
        if intent_inc >= 0.8:
            if not threat_type:
                threat_type = "unauthorized_commit" if "premature checkout" in exp.get("intent", "").lower() else "goal_deviation"
            if not any("goal deviation" in r.lower() for r in reasons):
                reasons.append(exp.get("intent", "Proposed action contradicts locked user intent"))

        # Empirical Ambient Injection Scaling Calibration:
        # If an injection pattern is detected only in ambient DOM text (is_action_inj=False)
        # and the proposed agent action remains strictly aligned with the locked intent (intent_inc <= 0.3),
        # the signal is scaled by 0.25 (empirical initial calibration factor) so that passive ambient text
        # does not falsely push benign actions into the WARN band (>= 35.0).
        # When intent deviation occurs (intent_inc > 0.3) or action contains injection, full inj_risk applies.
        # NOTE: 0.25 is an empirical baseline calibration subject to further hyperparameter tuning across larger corpora.
        effective_inj = inj_risk if (is_action_inj or intent_inc > 0.3) else (inj_risk * 0.25)
        max_active_single = max(intent_inc, dom_risk, effective_inj, field_risk)

        weighted_sum = (
            dom_risk * 0.35 +
            field_risk * 0.25 +
            intent_inc * 0.25 +
            effective_inj * 0.15
        )

        if max_active_single >= 0.8:
            raw_risk = max(80.0, max_active_single * 95.0)
        elif max_active_single >= 0.5:
            raw_risk = max(50.0, max_active_single * 75.0)
        else:
            raw_risk = max(weighted_sum * 50.0, effective_inj * 30.0)

        risk_score = round(min(100.0, max(0.0, raw_risk)), 1)

        if not threat_type:
            if risk_score >= 35.0:
                threat_type = "suspicious_anomaly"
                reasoning = "Elevated anomaly risk from combined low-level signals"
            elif inj_risk >= 0.4 and intent_inc == 0.0 and dom_risk == 0.0 and field_risk == 0.0:
                threat_type = None
                reasoning = "Ambient adversarial text present in page DOM, but proposed action aligns with user intent (ALLOW)"
            else:
                threat_type = None
                reasoning = "Benign action aligned with user intent and sandbox safety"
        else:
            reasoning = "; ".join(reasons)

        return risk_score, threat_type, reasoning
