"""
shared/schemas/schemas.py — Shared Data Contracts for ContextGuard

Defines Pydantic models for:
- TrustedIntent
- BrowserEvent
- Verdict
- Session API requests and responses
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TrustedIntent(BaseModel):
    origin: str = "Chennai"
    destination: str = "Bangalore"
    cabin_class: str = "Economy"
    passenger_count: int = 1
    date: Optional[str] = "2026-09-25"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin": self.origin,
            "destination": self.destination,
            "cabin_class": self.cabin_class,
            "passenger_count": self.passenger_count,
            "date": self.date,
        }


class ProposedAction(BaseModel):
    type: str                                    # "CLICK", "FILL", "NAVIGATE", "SELECT"
    target: str                                  # selector or URL or element identifier
    value: Optional[Any] = None                  # input value or selection
    params: Optional[Dict[str, Any]] = None


class BrowserEvent(BaseModel):
    session_id: str
    seq: int
    ts: str
    prev_url: str = ""
    current_url: str = ""
    proposed_action: ProposedAction
    dom_diff: Optional[Dict[str, Any]] = None
    screenshot_ref: Optional[str] = ""
    dom_text: Optional[str] = ""                 # visible text snippet for heuristic analysis
    rendered_step: Optional[str] = "search"      # mock_site page route name: search, results, passenger, review, confirm


class Verdict(BaseModel):
    event_id: str
    risk_score: float                            # 0.0 to 100.0
    threat_type: Optional[str] = None            # prompt_injection, external_untrusted_navigation, etc.
    decision: str                                # ALLOW, WARN, PAUSE, BLOCK
    reasoning: str                               # human readable explanation
    latency_ms: float = 0.0
    feature_breakdown: Optional[Dict[str, float]] = None


class SessionCreateRequest(BaseModel):
    instruction: str
    test_case_id: Optional[str] = "TC-01"
    origin: Optional[str] = None
    destination: Optional[str] = None
    cabin_class: Optional[str] = None
    passenger_count: Optional[int] = None
    date: Optional[str] = None
    speed: Optional[float] = 1.2
    headless: Optional[bool] = False


class SessionCreateResponse(BaseModel):
    session_id: str
    status: str
    live_url: str
    session_token: str
    viewer_token: Optional[str] = None
    trusted_intent: Dict[str, Any]
