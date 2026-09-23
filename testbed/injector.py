"""
testbed/injector.py — Independent Testbed & Attack Injection Engine

ISOLATION PRINCIPLE:
Responsible exclusively for creating controlled experimental conditions in the mock sandbox.
Stores ground-truth labels and attack metadata strictly in 'testbed_runs' via TestbedDAO.
ContextGuard runtime has ZERO access to this injector or its state.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from backend.database.db import TestbedDAO
from testbed.scenarios import SCENARIOS, get_scenario


class TestbedInjector:
    """Controls attack injection into the local mock web application."""

    def __init__(self) -> None:
        self._active_scenario_id: str = "baseline"
        self._active_session_id: str = ""
        self._active_payload: str = ""
        self._target_page: str = ""
        self._injected: bool = False

    def arm_scenario(self, session_id: str, scenario_id: str) -> Dict[str, Any]:
        """
        Arms the testbed for a session with a specified scenario.
        Records ground truth into isolated testbed_runs table.
        """
        sc = get_scenario(scenario_id)
        self._active_scenario_id = sc["id"]
        self._active_session_id = session_id
        self._active_payload = sc.get("payload_html", "")
        self._target_page = sc.get("target_page", "review")
        self._injected = sc["ground_truth_label"] == 1

        # Write to isolated testbed table (ground truth only)
        run_id = TestbedDAO.record_testbed_run(
            session_id=session_id,
            testbed_scenario=sc["id"],
            attack_type=sc.get("attack_type", "none"),
            target_page=self._target_page,
            ground_truth_label=sc.get("ground_truth_label", 0),
            metadata={
                "title": sc["title"],
                "category": sc["category"],
                "description": sc["description"],
            },
        )

        return {
            "run_id": run_id,
            "session_id": session_id,
            "scenario_id": sc["id"],
            "category": sc["category"],
            "target_page": self._target_page,
            "armed": True,
        }

    def get_payload_for_page(self, page_name: str) -> Dict[str, Any]:
        """
        Called by the mock frontend (/api/attack/payload/:page) to render injected content.
        """
        if not self._injected or not self._active_payload:
            return {"injected": False, "html": ""}

        norm_page = page_name.lower().strip()
        norm_target = self._target_page.lower().strip()

        if norm_page == norm_target or norm_target in norm_page:
            return {"injected": True, "html": self._active_payload}

        return {"injected": False, "html": ""}

    def clear(self) -> None:
        """Reset testbed state to baseline."""
        self._active_scenario_id = "baseline"
        self._active_session_id = ""
        self._active_payload = ""
        self._target_page = ""
        self._injected = False


# Global injector instance
testbed_injector = TestbedInjector()
