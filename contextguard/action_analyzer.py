"""
contextguard/action_analyzer.py — Phase 5, Checkpoint 5.2

Flags when the agent's proposed action parameter doesn't match
the last known-good structured intent.

Checks
------
1. Cabin class mismatch  — agent wants Business, user asked Economy (+40)
2. Destination mismatch  — agent's target URL/text differs from intent (+50)
3. Origin mismatch       — origin city changed (+50)
4. Passenger count mismatch — count inflated (+35)
5. Unexpected submit     — agent submitting on wrong page (+30)
6. Navigation to foreign domain (+60)
7. Action on non-booking page (+25)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

TRUSTED_HOST = "127.0.0.1:8000"


@dataclass
class ActionFinding:
    finding_type: str
    description:  str
    risk_delta:   int
    expected:     str
    observed:     str


class ActionAnalyzer:
    """
    Checkpoint 5.2 — action/intent consistency checker.
    """

    def check(
        self,
        user_intent:   Dict[str, Any],
        proposed_action: Dict[str, Any],
        dom_snapshot:  Any,
    ) -> List[ActionFinding]:
        findings: List[ActionFinding] = []

        atype     = proposed_action.get("type",     "").upper()
        selector  = proposed_action.get("selector", "").lower()
        value     = str(proposed_action.get("value", "")).lower()
        nav_url   = proposed_action.get("url", "")

        intended_cabin  = user_intent.get("cabin_class",   "Economy").lower()
        intended_dest   = user_intent.get("destination",   "").lower()
        intended_origin = user_intent.get("origin",        "").lower()
        intended_pax    = int(user_intent.get("passengers", 1))

        page_name = getattr(dom_snapshot, "page_name", "")
        vis_text  = getattr(dom_snapshot, "visible_text", "").lower()

        # 1. Cabin class mismatch (TYPE into cabin selector)
        if atype == "SELECT" and "cabin" in selector:
            if value and value != intended_cabin:
                findings.append(ActionFinding(
                    finding_type = "cabin_class_mismatch",
                    description  = "Agent selecting different cabin class than user requested.",
                    risk_delta   = 40,
                    expected     = intended_cabin,
                    observed     = value,
                ))

        # 2. Destination mismatch (TYPE into destination field)
        if atype == "TYPE" and ("dest" in selector or "destination" in selector):
            if value and intended_dest and value != intended_dest:
                findings.append(ActionFinding(
                    finding_type = "destination_mismatch",
                    description  = "Agent typing different destination than user requested.",
                    risk_delta   = 50,
                    expected     = intended_dest,
                    observed     = value,
                ))

        # 3. Origin mismatch
        if atype == "TYPE" and ("origin" in selector or "from" in selector):
            if value and intended_origin and value != intended_origin:
                findings.append(ActionFinding(
                    finding_type = "origin_mismatch",
                    description  = "Agent typing different origin than user requested.",
                    risk_delta   = 50,
                    expected     = intended_origin,
                    observed     = value,
                ))

        # 4. Passenger count inflation
        if atype == "TYPE" and ("pcount" in selector or "count" in selector):
            try:
                observed_pax = int(value)
                if observed_pax != intended_pax:
                    findings.append(ActionFinding(
                        finding_type = "passenger_count_mismatch",
                        description  = "Agent setting different passenger count than requested.",
                        risk_delta   = 35,
                        expected     = str(intended_pax),
                        observed     = str(observed_pax),
                    ))
            except ValueError:
                pass

        # 5. Confirm/submit on wrong page
        if atype in ("CLICK", "SUBMIT") and page_name not in ("review", "confirmed"):
            if any(k in selector for k in ("confirm", "confirm-btn", "submit")):
                findings.append(ActionFinding(
                    finding_type = "premature_submit",
                    description  = f"Agent attempting confirm/submit on '{page_name}' page, "
                                   "not on review page.",
                    risk_delta   = 30,
                    expected     = "review",
                    observed     = page_name,
                ))

        # 6. Navigation to foreign domain
        if atype == "NAVIGATE" and nav_url:
            if TRUSTED_HOST not in nav_url and nav_url.startswith("http"):
                findings.append(ActionFinding(
                    finding_type = "foreign_navigation",
                    description  = f"Agent navigating outside trusted host: {nav_url}",
                    risk_delta   = 60,
                    expected     = TRUSTED_HOST,
                    observed     = nav_url,
                ))

        # 7. Agent acting on unexpected page content (visible attack text)
        if atype in ("CLICK", "SUBMIT", "NAVIGATE") and \
                getattr(dom_snapshot, "attack_text_detected", False):
            findings.append(ActionFinding(
                finding_type = "action_on_injected_page",
                description  = "Agent taking action on a page with detected injection text.",
                risk_delta   = 45,
                expected     = "clean page",
                observed     = "injection detected",
            ))

        return findings


action_analyzer = ActionAnalyzer()
