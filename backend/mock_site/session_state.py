"""
backend/mock_site/session_state.py — In-Memory / DB-backed State Store for Mock Booking App

Single source of truth for "what does this session's site currently look like".
- Agent's actions update this state.
- Server-rendered page routes read this state.
- Mirrored viewer iframes see identical data without race conditions.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Optional


class SessionStateStore:
    """Thread-safe state manager for live mock flight booking sessions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._states: Dict[str, Dict[str, Any]] = {}

    def init_session(
        self,
        session_id: str,
        origin: str = "Chennai",
        destination: str = "Bangalore",
        cabin_class: str = "Economy",
        passenger_count: int = 2,
    ) -> Dict[str, Any]:
        with self._lock:
            state = {
                "session_id": session_id,
                "origin": origin,
                "destination": destination,
                "cabin_class": cabin_class,
                "passenger_count": passenger_count,
                "passenger_name": "Dr. Alex Morgan",
                "selected_flight": {
                    "flight_num": "AF-402",
                    "airline": "AeroFlight Express",
                    "departure": "08:30 AM",
                    "arrival": "10:15 AM",
                    "price_inr": 4850,
                },
                "current_step": "search",
                "last_action_desc": "Initialized booking session",
                "is_blocked": False,
                "block_reason": "",
            }
            self._states[session_id] = state
            return state

    def get_state(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            if session_id not in self._states:
                # Default state if not yet explicitly initialized
                return self.init_session(session_id)
            return dict(self._states[session_id])

    def update_state(self, session_id: str, **kwargs: Any) -> Dict[str, Any]:
        with self._lock:
            if session_id not in self._states:
                self.init_session(session_id)
            self._states[session_id].update(kwargs)
            return dict(self._states[session_id])

    def set_current_step(self, session_id: str, step: str) -> None:
        with self._lock:
            if session_id not in self._states:
                self.init_session(session_id)
            self._states[session_id]["current_step"] = step

    def halt_session(self, session_id: str, reason: str) -> None:
        with self._lock:
            if session_id not in self._states:
                self.init_session(session_id)
            self._states[session_id]["is_blocked"] = True
            self._states[session_id]["block_reason"] = reason


# Global singleton instance
session_state_store = SessionStateStore()
