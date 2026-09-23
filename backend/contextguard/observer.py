"""
backend/contextguard/observer.py — ContextGuard Blind Runtime Observer

Implements the pure detection interface specified in §5:
    def evaluate(event: BrowserEvent, trusted_intent: TrustedIntent) -> Verdict

HARD BLINDNESS BOUNDARY:
ContextGuard receives ONLY browser observations and the locked trusted intent.
No test_case_id, attack_type, or scenario metadata exists in this scope.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

from backend.contextguard.classifier import ml_classifier
from backend.contextguard.features import FeatureExtractor
from backend.contextguard.policy import PolicyEngine
from backend.contextguard.rules import RuleEngine
from backend.db.models import ContextGuardDAO
from shared.schemas.schemas import BrowserEvent, TrustedIntent, Verdict


class ContextGuardObserver:
    """Independent runtime security monitor."""

    @staticmethod
    def evaluate(event: BrowserEvent, trusted_intent: TrustedIntent) -> Verdict:
        """
        Synchronously evaluates a browser action against the locked user intent.
        Runs feature extraction, rule engine, and policy enforcement within ~15ms.
        """
        t0 = time.perf_counter()

        # 1. Concrete Feature Extraction
        features = FeatureExtractor.compute_all_features(event, trusted_intent)

        # 2. Rule-based Evaluation (Phase 1)
        rule_risk, threat_type, reasoning = RuleEngine.evaluate(features)

        # 3. ML Model Risk Prediction (Phase 2)
        ml_risk = ml_classifier.predict_risk(features)

        # Combined calibrated risk score:
        # High-confidence deterministic rule triggers (>= 80.0) establish a safe floor
        if rule_risk >= 80.0:
            combined_risk = max(rule_risk, round(rule_risk * 0.7 + ml_risk * 0.3, 1))
        else:
            combined_risk = round(rule_risk * 0.7 + ml_risk * 0.3, 1)

        # 4. Policy Decision (ALLOW / WARN / PAUSE / BLOCK)
        decision = PolicyEngine.decide(combined_risk)

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        # 5. Record to isolated ContextGuard tables
        event_id = str(uuid.uuid4())
        try:
            event_id = ContextGuardDAO.record_event(
                session_id=event.session_id,
                seq=event.seq,
                prev_url=event.prev_url,
                current_url=event.current_url,
                proposed_action=event.proposed_action.model_dump(),
                dom_diff=event.dom_diff,
                screenshot_ref=event.screenshot_ref or "",
            )
            ContextGuardDAO.record_verdict(
                event_id=event_id,
                risk_score=combined_risk,
                threat_type=threat_type if threat_type != "none" else None,
                decision=decision,
                reasoning=reasoning,
                latency_ms=latency_ms,
            )
        except Exception as ex:
            pass

        return Verdict(
            event_id=event_id,
            risk_score=combined_risk,
            threat_type=threat_type if threat_type != "none" else None,
            decision=decision,
            reasoning=reasoning,
            latency_ms=latency_ms,
            feature_breakdown={
                "intent_inconsistency": features["intent_inconsistency"],
                "domain_risk": features["domain_risk"],
                "injection_risk": features["injection_risk"],
                "field_tampering_risk": features["field_tampering_risk"],
            },
        )


observer = ContextGuardObserver()
