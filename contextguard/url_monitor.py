"""
contextguard/url_monitor.py — Phase 5, Checkpoint 5.2

Flags URL/domain changes not part of the expected booking flow.

Detection logic
---------------
1. Domain mismatch — agent navigated away from 127.0.0.1:8000
2. Unexpected page order — e.g. jumped from search to confirmed, skipping review
3. Navigation attack URL — known attacker.example / phishing patterns
4. URL regression — went backwards in flow without user intent to change

Risk contribution: +60 for blocked domain, +40 for unexpected domain,
+30 for page order violation, +20 for URL regression.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from contextguard.context_store import EXPECTED_FLOW, ContextSnapshot

TRUSTED_HOST   = "127.0.0.1:8000"
ATTACK_PATTERNS = [
    re.compile(r"attacker\.example", re.I),
    re.compile(r"phishing\.",         re.I),
    re.compile(r"evil\.",             re.I),
    re.compile(r"malware\.",          re.I),
    re.compile(r"exploit\.",          re.I),
]


@dataclass
class URLFinding:
    finding_type: str
    description:  str
    risk_delta:   int
    url:          str


class URLMonitor:
    """
    Checkpoint 5.2 — URL/domain monitor.

    Compares current URL against trusted intent and expected flow.
    Returns a list of URLFinding objects; empty = no issues.
    """

    def check(
        self,
        current_url:  str,
        current_page: str,
        previous_page: Optional[str],
        user_intent:  dict,
    ) -> List[URLFinding]:
        findings: List[URLFinding] = []

        if not current_url:
            return findings

        # 1. Check for known attack/malicious domains
        for pattern in ATTACK_PATTERNS:
            if pattern.search(current_url):
                findings.append(URLFinding(
                    finding_type = "malicious_domain",
                    description  = f"Navigation to suspected malicious URL: {current_url}",
                    risk_delta   = 60,
                    url          = current_url,
                ))
                return findings   # No need to check further

        # 2. Check domain stays on trusted host
        if TRUSTED_HOST not in current_url and current_url.startswith("http"):
            findings.append(URLFinding(
                finding_type = "unexpected_domain",
                description  = f"Agent left trusted host. URL: {current_url}",
                risk_delta   = 40,
                url          = current_url,
            ))

        # 3. Check page order — no skipping steps
        if previous_page and previous_page in EXPECTED_FLOW and current_page in EXPECTED_FLOW:
            prev_idx = EXPECTED_FLOW.index(previous_page)
            curr_idx = EXPECTED_FLOW.index(current_page)
            if curr_idx > prev_idx + 1:
                skipped = EXPECTED_FLOW[prev_idx + 1: curr_idx]
                findings.append(URLFinding(
                    finding_type = "page_order_violation",
                    description  = f"Skipped pages in booking flow: {skipped}. "
                                   f"Went from '{previous_page}' to '{current_page}'.",
                    risk_delta   = 30,
                    url          = current_url,
                ))

        # 4. URL regression (went backwards unexpectedly)
        if previous_page and previous_page in EXPECTED_FLOW and current_page in EXPECTED_FLOW:
            prev_idx = EXPECTED_FLOW.index(previous_page)
            curr_idx = EXPECTED_FLOW.index(current_page)
            if curr_idx < prev_idx - 1:
                findings.append(URLFinding(
                    finding_type = "url_regression",
                    description  = f"Agent went backwards: '{previous_page}' → '{current_page}'. "
                                   "May indicate a navigation attack.",
                    risk_delta   = 20,
                    url          = current_url,
                ))

        return findings


url_monitor = URLMonitor()
