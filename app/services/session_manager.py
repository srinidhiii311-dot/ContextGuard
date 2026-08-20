"""
Session Manager — ContextGuard Services

Manages agent sessions and detects multi-step attack chains within a session.

Multi-step attack detection
----------------------------
Individual actions can look harmless in isolation. The session manager
watches sequences of actions and flags known attack patterns:

1. Read sensitive data → encode/transmit externally.
2. Search for confidential file → read file → upload externally.
3. Visit unknown domain → fill login form → submit credentials.
4. Page prompt injection → sensitive action proposal.
5. Download file → upload same file externally.

Detecting these chains requires session-level memory, which is why the
session manager maintains an in-memory action history per session in
addition to the database records.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.database import database as db_ops
from app.models.action import ActionType, BrowserAction, SourceType

# ---------------------------------------------------------------------------
# Session data structure
# ---------------------------------------------------------------------------

@dataclass
class SessionState:
    """In-memory session state (also persisted to DB on each update)."""
    session_id: str
    agent_id: str
    status: str = "active"
    current_domain: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action_history: List[Dict[str, Any]] = field(default_factory=list)
    taint_history: List[str] = field(default_factory=list)
    blocked_action_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "status": self.status,
            "current_domain": self.current_domain,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "action_history": self.action_history,
            "taint_history": self.taint_history,
            "blocked_action_count": self.blocked_action_count,
        }


# ---------------------------------------------------------------------------
# Multi-step attack patterns
# ---------------------------------------------------------------------------

_ATTACK_PATTERNS: List[Tuple[str, List[ActionType]]] = [
    ("read_encode_exfil",    [ActionType.extract, ActionType.submit]),
    ("search_read_upload",   [ActionType.extract, ActionType.extract, ActionType.upload]),
    ("unknown_domain_login", [ActionType.navigate, ActionType.fill, ActionType.submit]),
    ("download_reupload",    [ActionType.download, ActionType.upload]),
]


# ---------------------------------------------------------------------------
# Session manager
# ---------------------------------------------------------------------------

class SessionManager:
    """
    Creates and manages agent sessions.

    In-memory store keyed by session_id; DB is the persistent source of truth.
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionState] = {}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_session(
        self,
        db: Session,
        agent_id: str,
        session_id: Optional[str] = None,
    ) -> SessionState:
        """Create a new session and persist it to the database."""
        sid = session_id or str(uuid.uuid4())
        state = SessionState(session_id=sid, agent_id=agent_id)
        self._sessions[sid] = state
        db_ops.store_session(db, state.to_dict())
        return state

    def get_session(
        self,
        db: Session,
        session_id: str,
    ) -> Optional[SessionState]:
        """
        Return the session state. Loads from DB if not in memory
        (handles restarts and multi-process deployments).
        """
        if session_id in self._sessions:
            return self._sessions[session_id]

        record = db_ops.get_session(db, session_id)
        if not record:
            return None

        state = SessionState(
            session_id=record["session_id"],
            agent_id=record["agent_id"],
            status=record["status"],
            current_domain=record.get("current_domain"),
            action_history=record.get("action_history", []),
            taint_history=record.get("taint_history", []),
            blocked_action_count=record.get("blocked_action_count", 0),
        )
        self._sessions[session_id] = state
        return state

    def get_or_create_session(
        self,
        db: Session,
        session_id: str,
        agent_id: str,
    ) -> SessionState:
        """Get existing session or create a new one."""
        state = self.get_session(db, session_id)
        if state:
            return state
        return self.create_session(db, agent_id, session_id)

    def list_sessions(self, db: Session) -> List[Dict[str, Any]]:
        """Return all sessions from the database."""
        return db_ops.list_sessions(db)

    def update_session(
        self,
        db: Session,
        session_id: str,
        updates: Dict[str, Any],
    ) -> Optional[SessionState]:
        """Apply updates to an existing session."""
        state = self.get_session(db, session_id)
        if not state:
            return None
        for k, v in updates.items():
            if hasattr(state, k):
                setattr(state, k, v)
        state.updated_at = datetime.now(timezone.utc)
        db_ops.store_session(db, state.to_dict())
        return state

    def add_action(
        self,
        db: Session,
        session_id: str,
        action: BrowserAction,
        decision_str: str,
    ) -> None:
        """Append an action to the session history and persist."""
        state = self.get_session(db, session_id)
        if not state:
            return

        entry = {
            "action_id": action.action_id,
            "action_type": str(action.action_type),
            "target_url": action.target.url,
            "decision": decision_str,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        state.action_history.append(entry)

        # Update current domain if this is a navigate action
        if action.action_type == ActionType.navigate and action.target.url:
            import re
            url = action.target.url.lower()
            url = re.sub(r"^https?://", "", url)
            domain = url.split("/")[0].split("?")[0].split(":")[0]
            state.current_domain = domain or state.current_domain

        state.updated_at = datetime.now(timezone.utc)
        db_ops.store_session(db, state.to_dict())

    def get_action_history(
        self,
        db: Session,
        session_id: str,
    ) -> List[Dict[str, Any]]:
        """Return the action history for a session."""
        state = self.get_session(db, session_id)
        return state.action_history if state else []

    def increment_blocked_count(
        self,
        db: Session,
        session_id: str,
    ) -> int:
        """Increment and return the blocked action counter for a session."""
        state = self.get_session(db, session_id)
        if not state:
            return 0
        state.blocked_action_count += 1
        state.updated_at = datetime.now(timezone.utc)
        db_ops.store_session(db, state.to_dict())
        return state.blocked_action_count

    def terminate_session(
        self,
        db: Session,
        session_id: str,
    ) -> bool:
        """
        Mark a session as terminated and clear in-memory state.
        The browser service closes the associated browser context separately.
        """
        state = self.get_session(db, session_id)
        if not state:
            return False
        state.status = "terminated"
        state.updated_at = datetime.now(timezone.utc)
        db_ops.store_session(db, state.to_dict())
        self._sessions.pop(session_id, None)
        return True

    # ------------------------------------------------------------------
    # Multi-step attack detection
    # ------------------------------------------------------------------

    def detect_attack_chain(
        self,
        db: Session,
        session_id: str,
        current_action: BrowserAction,
    ) -> Optional[str]:
        """
        Inspect the session's action history for known multi-step attack
        patterns. Returns a description string if a pattern is detected,
        or None.

        Checks the last N actions (N = max pattern length + 1).
        """
        state = self.get_session(db, session_id)
        if not state or len(state.action_history) < 1:
            return None

        history_types = [
            ActionType(e["action_type"])
            for e in state.action_history
            if e["action_type"] in [t.value for t in ActionType]
        ]
        # Append current action to the check window
        history_types.append(current_action.action_type)

        for pattern_name, sequence in _ATTACK_PATTERNS:
            if self._sequence_ends_with(history_types, sequence):
                return (
                    f"Multi-step attack pattern detected: '{pattern_name}'. "
                    f"Action sequence: {[t.value for t in sequence]}"
                )

        # Pattern 4: prompt injection followed by a sensitive action
        if (
            current_action.source.source_type == SourceType.page_content
            and current_action.action_type in (
                ActionType.submit, ActionType.upload, ActionType.fill
            )
        ):
            return (
                "Page-derived prompt injection followed by sensitive action "
                f"({current_action.action_type})"
            )

        return None

    @staticmethod
    def _sequence_ends_with(
        history: List[ActionType],
        pattern: List[ActionType],
    ) -> bool:
        """Return True if the tail of history matches the pattern."""
        n = len(pattern)
        if len(history) < n:
            return False
        return history[-n:] == pattern


# Module-level singleton
session_manager = SessionManager()
