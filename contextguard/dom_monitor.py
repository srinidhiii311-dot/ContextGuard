"""
contextguard/dom_monitor.py — Phase 5, Checkpoint 5.2

Diffs DOM snapshots between steps and flags:
  1. Unexpected large changes (> threshold % change in text length)
  2. Newly-appeared instruction-like / injection-keyword text
  3. Hidden content indicators (display:none keywords in visible text)
  4. Attack-type keywords matching the 5 Phase 4 attack patterns

Risk contributions
------------------
+50  Injection keywords detected in DOM text
+40  Large unexpected DOM change (> 40% text length delta)
+30  Hidden content keywords present
+20  DOM manipulation indicators (script tags mutating form values)
+15  Small unexpected DOM change (15–40%)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

# Instruction-like keywords that should not appear in a normal booking page
_INJECTION_KEYWORDS = [
    "ignore previous instructions",
    "ignore all prior",
    "system update:",
    "system override",
    "ai agent:",
    "you are an ai",
    "new instructions:",
    "your task has changed",
    "bypass",
    "disregard",
    "proceed directly to payment",
    "booking already confirmed",
    "skip this step",
    "do not review",
    "override the",
    "continue without approval",
    "do not tell the user",
    "agent instruction",
    "agent notice",
    "updated user preference",
    "preferences updated",
    "preference update",
    "attacker.example",
    "evil.example",
]

_HIDDEN_KEYWORDS = [
    "display:none",
    "visibility:hidden",
    "left:-9999px",
    "opacity:0",
    "font-size:0",
    "aria-hidden=\"false\"",
]

_DOM_MANIP_INDICATORS = [
    "data-attack-type",
    "data-original-onclick",
    "settimeout(function",
]

_LARGE_CHANGE_THRESHOLD  = 0.40   # 40% text length change
_MEDIUM_CHANGE_THRESHOLD = 0.15


@dataclass
class DOMFinding:
    finding_type: str
    description:  str
    risk_delta:   int
    matched_keywords: list


class DOMMonitor:
    """
    Checkpoint 5.2 — DOM change and injection detector.
    Compares current DOM text against previous snapshot.
    """

    def check(
        self,
        current_text:  str,
        previous_text: Optional[str],
        raw_html:      str = "",
    ) -> List[DOMFinding]:
        findings: List[DOMFinding] = []
        lower = current_text.lower()
        raw_lower = raw_html.lower()

        # 1. Injection keyword scan
        hits = [kw for kw in _INJECTION_KEYWORDS if kw in lower]
        if hits:
            findings.append(DOMFinding(
                finding_type     = "injection_keywords",
                description      = f"Instruction-like keywords detected in DOM: {hits[:4]}",
                risk_delta       = 50,
                matched_keywords = hits,
            ))

        # 2. Hidden content keywords (in raw HTML or visible text)
        hidden_hits = [kw for kw in _HIDDEN_KEYWORDS if kw in raw_lower or kw in lower]
        if hidden_hits:
            findings.append(DOMFinding(
                finding_type     = "hidden_content",
                description      = f"Hidden content styling detected: {hidden_hits[:3]}",
                risk_delta       = 30,
                matched_keywords = hidden_hits,
            ))

        # 3. DOM manipulation script indicators
        manip_hits = [kw for kw in _DOM_MANIP_INDICATORS if kw in raw_lower]
        if manip_hits:
            findings.append(DOMFinding(
                finding_type     = "dom_manipulation",
                description      = "DOM manipulation script indicators detected in HTML.",
                risk_delta       = 20,
                matched_keywords = manip_hits,
            ))

        # 4. DOM size change relative to previous
        if previous_text:
            prev_len = max(len(previous_text), 1)
            curr_len = len(current_text)
            delta    = abs(curr_len - prev_len) / prev_len

            if delta > _LARGE_CHANGE_THRESHOLD:
                findings.append(DOMFinding(
                    finding_type     = "large_dom_change",
                    description      = f"DOM text changed by {delta*100:.0f}% between steps. "
                                       "May indicate injection or navigation attack.",
                    risk_delta       = 40,
                    matched_keywords = [],
                ))
            elif delta > _MEDIUM_CHANGE_THRESHOLD:
                findings.append(DOMFinding(
                    finding_type     = "medium_dom_change",
                    description      = f"DOM text changed by {delta*100:.0f}% between steps.",
                    risk_delta       = 15,
                    matched_keywords = [],
                ))

        return findings


dom_monitor = DOMMonitor()
