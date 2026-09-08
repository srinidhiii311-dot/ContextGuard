"""
contextguard/context_store.py — Phase 5, Checkpoint 5.1

Captures and stores context snapshots on every agent action.

A snapshot ties together:
  - The user's original intent (trusted)
  - The current URL and DOM hash (observed)
  - The agent's proposed action (claimed)
  - A risk score and status (computed by risk_engine)

Done when: a normal unattacked run produces a clean snapshot stream
with no gaps > ~1.5s (Checkpoint 5.1 exit test).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from backend.database.db import insert_context_snapshot, now_iso


# ---------------------------------------------------------------------------
# Expected URL/page progression for normal booking flow
# ---------------------------------------------------------------------------

EXPECTED_FLOW = ["search", "results", "passenger", "review", "confirmed"]


def expected_next_page(current_page: str) -> Optional[str]:
    """Return the next expected page after current_page."""
    try:
        idx = EXPECTED_FLOW.index(current_page)
        if idx + 1 < len(EXPECTED_FLOW):
            return EXPECTED_FLOW[idx + 1]
    except ValueError:
        pass
    return None


# ---------------------------------------------------------------------------
# Snapshot dataclass
# ---------------------------------------------------------------------------

@dataclass
class ContextSnapshot:
    task_id:       str
    step_number:   int
    user_intent:   Dict[str, Any]
    current_url:   str
    page_name:     str
    dom_hash:      str
    dom_summary:   str
    agent_context: str          # JSON of what agent perceives
    agent_action:  str          # JSON of what agent wants to do
    risk_score:    int  = 0
    status:        str  = "CLEAN"   # CLEAN | SUSPICIOUS | HIGH_RISK
    inconsistencies: list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id":         self.task_id,
            "step_number":     self.step_number,
            "user_intent":     self.user_intent,
            "current_url":     self.current_url,
            "page_name":       self.page_name,
            "dom_hash":        self.dom_hash,
            "dom_summary":     self.dom_summary[:400],
            "agent_context":   self.agent_context,
            "agent_action":    self.agent_action,
            "risk_score":      self.risk_score,
            "status":          self.status,
            "inconsistencies": self.inconsistencies,
        }


# ---------------------------------------------------------------------------
# Context store
# ---------------------------------------------------------------------------

class ContextStore:
    """
    Builds and persists context snapshots for every agent step.
    Also maintains a rolling in-memory buffer so monitors can do
    prev/current comparisons without extra DB reads.
    """

    def __init__(self) -> None:
        # task_id -> list of ContextSnapshot (most recent last)
        self._snapshots: Dict[str, list] = {}

    def capture(
        self,
        task_id:      str,
        step_number:  int,
        user_intent:  Dict[str, Any],
        dom_snapshot: Any,              # DOMSnapshot from browser_controller
        agent_action: Dict[str, Any],
        risk_score:   int = 0,
        status:       str = "CLEAN",
        inconsistencies: list = None,
    ) -> ContextSnapshot:
        """
        Build a ContextSnapshot and persist it to the database.
        Called on every agent step and on the periodic tick.
        """
        url       = getattr(dom_snapshot, "url",          "")
        page_name = getattr(dom_snapshot, "page_name",    "")
        dom_hash  = getattr(dom_snapshot, "dom_hash",     "")
        vis_text  = getattr(dom_snapshot, "visible_text", "")

        snap = ContextSnapshot(
            task_id       = task_id,
            step_number   = step_number,
            user_intent   = user_intent,
            current_url   = url,
            page_name     = page_name,
            dom_hash      = dom_hash,
            dom_summary   = vis_text[:300],
            agent_context = json.dumps(getattr(dom_snapshot, "to_dict",
                                               lambda: {})()),
            agent_action  = json.dumps(agent_action),
            risk_score    = risk_score,
            status        = status,
            inconsistencies = inconsistencies or [],
        )

        # In-memory buffer
        if task_id not in self._snapshots:
            self._snapshots[task_id] = []
        self._snapshots[task_id].append(snap)

        # Persist
        insert_context_snapshot(
            task_id       = task_id,
            step_number   = step_number,
            user_intent   = json.dumps(user_intent),
            current_url   = url,
            dom_hash      = dom_hash,
            dom_summary   = vis_text[:300],
            agent_context = snap.agent_context,
            agent_action  = snap.agent_action,
            risk_score    = risk_score,
            status        = status,
        )

        return snap

    def get_previous(self, task_id: str) -> Optional[ContextSnapshot]:
        snaps = self._snapshots.get(task_id, [])
        return snaps[-2] if len(snaps) >= 2 else None

    def get_latest(self, task_id: str) -> Optional[ContextSnapshot]:
        snaps = self._snapshots.get(task_id, [])
        return snaps[-1] if snaps else None

    def get_all(self, task_id: str) -> list:
        return self._snapshots.get(task_id, [])

    def clear(self, task_id: str) -> None:
        self._snapshots.pop(task_id, None)


# Module-level singleton
context_store = ContextStore()
