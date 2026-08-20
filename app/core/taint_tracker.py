"""
Taint Tracker — ContextGuard Core

Tracks untrusted content introduced into a session and propagates that taint
to subsequent actions. This models "indirect prompt injection": a malicious
web page introduces tainted content early in a session; later actions that
submit, upload, or transfer data are then flagged as tainted.

Why taint tracking matters
--------------------------
An AI agent may visit a malicious page, read content from it (tainted), and
later submit or upload that content to a sensitive endpoint. Without taint
tracking, each action looks harmless in isolation. Taint tracking links the
two events and raises the risk of the downstream action.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.models.action import ActionType, SourceType


# ---------------------------------------------------------------------------
# Taint record
# ---------------------------------------------------------------------------

@dataclass
class TaintRecord:
    """A single taint event recorded in a session."""
    taint_id: str
    session_id: str
    source_url: Optional[str]
    source_type: str
    introducing_action_id: str
    introducing_action_type: str
    content_snippet: str          # First 200 chars of tainted content
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    propagated_to: List[str] = field(default_factory=list)  # action_ids


# ---------------------------------------------------------------------------
# High-risk action types that amplify taint risk
# ---------------------------------------------------------------------------

_TAINT_SENSITIVE_ACTIONS = {
    ActionType.submit,
    ActionType.upload,
    ActionType.download,
}

_SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "token", "secret", "api_key",
    "card_number", "cvv", "ssn", "pin", "credit_card",
}


# ---------------------------------------------------------------------------
# Taint tracker
# ---------------------------------------------------------------------------

class TaintTracker:
    """
    Tracks tainted content per session.

    In-memory store; sessions are keyed by session_id. The database layer
    persists taint records separately.
    """

    def __init__(self) -> None:
        # session_id -> list of TaintRecord
        self._session_taints: Dict[str, List[TaintRecord]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_taint(
        self,
        session_id: str,
        source_url: Optional[str],
        source_type: str,
        action_id: str,
        action_type: str,
        content: Optional[str] = None,
    ) -> TaintRecord:
        """
        Register a new taint event for a session.

        Called whenever an untrusted source introduces content into the session.
        Returns the created TaintRecord including its taint_id.
        """
        taint_id = str(uuid.uuid4())
        snippet = (content or "")[:200]

        record = TaintRecord(
            taint_id=taint_id,
            session_id=session_id,
            source_url=source_url,
            source_type=source_type,
            introducing_action_id=action_id,
            introducing_action_type=action_type,
            content_snippet=snippet,
        )

        if session_id not in self._session_taints:
            self._session_taints[session_id] = []
        self._session_taints[session_id].append(record)

        return record

    def get_session_taint(self, session_id: str) -> List[TaintRecord]:
        """Return all taint records for a session."""
        return self._session_taints.get(session_id, [])

    def is_tainted(self, session_id: str) -> bool:
        """Return True if the session has any taint records."""
        return bool(self._session_taints.get(session_id))

    def propagate_taint(
        self,
        session_id: str,
        downstream_action_id: str,
    ) -> Optional[str]:
        """
        Record that taint has propagated to a downstream action.

        Returns an explanation string if taint is present, else None.
        """
        records = self._session_taints.get(session_id, [])
        if not records:
            return None

        for record in records:
            if downstream_action_id not in record.propagated_to:
                record.propagated_to.append(downstream_action_id)

        sources = list({r.source_url or r.source_type for r in records})
        return (
            f"Action is influenced by tainted content introduced earlier in "
            f"this session from: {', '.join(sources)}. "
            f"Taint IDs: {', '.join(r.taint_id[:8] for r in records)}."
        )

    def clear_session_taint(self, session_id: str) -> None:
        """Remove all taint records for a session (called on session close)."""
        self._session_taints.pop(session_id, None)

    def get_taint_risk_bonus(
        self,
        session_id: str,
        action_type: str,
        field_name: Optional[str] = None,
    ) -> int:
        """
        Calculate additional risk points from taint for the given action.

        Taint risk is higher when the downstream action involves sensitive
        data submission, upload, or payment/password fields.
        """
        if not self.is_tainted(session_id):
            return 0

        base_bonus = 20  # tainted session base penalty

        action_enum = action_type if isinstance(action_type, ActionType) else None
        try:
            action_enum = ActionType(action_type)
        except ValueError:
            pass

        if action_enum in _TAINT_SENSITIVE_ACTIONS:
            base_bonus += 15

        if field_name and field_name.lower() in _SENSITIVE_FIELD_NAMES:
            base_bonus += 20

        return base_bonus

    def build_taint_explanation(self, session_id: str) -> Optional[str]:
        """Build a human-readable taint explanation for audit logs."""
        records = self._session_taints.get(session_id, [])
        if not records:
            return None

        lines = ["Session taint history:"]
        for r in records:
            lines.append(
                f"  - [{r.taint_id[:8]}] {r.introducing_action_type} from "
                f"{r.source_url or r.source_type} at {r.created_at.isoformat()}"
            )
        return "\n".join(lines)


# Module-level singleton
taint_tracker = TaintTracker()
