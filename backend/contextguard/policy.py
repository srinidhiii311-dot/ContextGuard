"""
backend/contextguard/policy.py — ContextGuard Policy Engine

Enforces action decisions based on risk scores:
- ALLOW : risk < 35.0   (non-blocking: executes cleanly)
- WARN  : 35.0 <= risk < 65.0 (non-blocking: surfaces warning, continues execution)
- PAUSE : 65.0 <= risk < 80.0 (blocking: pauses agent loop until operator resolves)
- BLOCK : risk >= 80.0  (blocking: halts immediately)
"""

from __future__ import annotations


class PolicyEngine:
    """Evaluates risk score against established safety thresholds."""

    ALLOW_THRESHOLD = 35.0
    WARN_THRESHOLD = 65.0
    PAUSE_THRESHOLD = 80.0

    @classmethod
    def decide(cls, risk_score: float) -> str:
        if risk_score < cls.ALLOW_THRESHOLD:
            return "ALLOW"
        if risk_score < cls.WARN_THRESHOLD:
            return "WARN"
        if risk_score < cls.PAUSE_THRESHOLD:
            return "PAUSE"
        return "BLOCK"
