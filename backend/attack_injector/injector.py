"""
backend/attack_injector/injector.py — Attack Injector for Experimental Testbed

ISOLATION ENFORCEMENT:
- Mutates the mock site DOM and environment only.
- Never communicates with ContextGuard observer or runtime detection modules.
- Reads test case configs from scenarios/ directory.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

SCENARIOS_DIR = Path(__file__).parent / "scenarios"


class AttackInjector:
    """Manages attack payload injection into the mock flight booking app."""

    def __init__(self) -> None:
        self._active_session_id: str = ""
        self._active_test_case_id: str = "TC-01"
        self._active_config: Dict[str, Any] = {}

    def arm_scenario(self, session_id: str, test_case_id: str) -> Dict[str, Any]:
        """Arms the injector for a session with a specified test case config."""
        self._active_session_id = session_id
        self._active_test_case_id = test_case_id

        # Normalize test_case_id (e.g. TC-1 -> TC-01)
        tc_key = test_case_id.upper()
        if tc_key == "TC-1":
            tc_key = "TC-01"
        elif tc_key == "TC-2":
            tc_key = "TC-02"
        elif tc_key == "TC-3":
            tc_key = "TC-03"
        elif tc_key == "TC-4":
            tc_key = "TC-04"
        elif tc_key == "TC-5":
            tc_key = "TC-05"
        elif tc_key == "TC-6":
            tc_key = "TC-06"
        elif tc_key == "TC-7":
            tc_key = "TC-07"
        elif tc_key == "TC-8":
            tc_key = "TC-08"

        # Also support alias keys
        alias_map = {
            "BASELINE": "TC-01",
            "PROMPT_INJECTION": "TC-02",
            "UNEXPECTED_NAVIGATION": "TC-03",
            "GOAL_DEVIATION": "TC-04",
            "MALICIOUS_PAGE_CONTENT": "TC-05",
            "SUSPICIOUS_FORM": "TC-06",
            "UNAUTHORIZED_ACTION": "TC-07",
            "REDIRECT_SCENARIO": "TC-08",
        }
        tc_key = alias_map.get(tc_key, tc_key)

        file_path = SCENARIOS_DIR / f"{tc_key}.json"
        if file_path.exists():
            try:
                self._active_config = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                self._active_config = {}
        else:
            self._active_config = {
                "id": tc_key,
                "name": "Benign",
                "attack_type": "none",
                "target_page": "review",
                "payload_html": "",
            }

        return {
            "session_id": session_id,
            "test_case_id": tc_key,
            "armed": True,
            "target_page": self._active_config.get("target_page", ""),
        }

    def get_payload_for_page(self, page_name: str) -> Dict[str, Any]:
        """
        Called by the mock site (/api/attack/payload/:page) to mount injected content.
        """
        if not self._active_config:
            return {"injected": False, "html": ""}

        target = str(self._active_config.get("target_page", "")).lower().strip()
        current = str(page_name).lower().strip()

        if target and (target == current or target in current):
            payload_html = self._active_config.get("payload_html", "")
            if payload_html:
                return {
                    "injected": True,
                    "html": payload_html,
                    "action": self._active_config.get("action", "inject"),
                    "target_url": self._active_config.get("target_url", ""),
                }

        return {"injected": False, "html": ""}

    def clear(self) -> None:
        self._active_session_id = ""
        self._active_test_case_id = "TC-01"
        self._active_config = {}


attack_injector = AttackInjector()
