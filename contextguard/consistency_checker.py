"""
contextguard/consistency_checker.py — Phase 5, Checkpoint 5.3

Combines outputs from all three monitors into a structured
Inconsistency list: what changed, expected vs actual.

This is the single object the risk_engine reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from contextguard.action_analyzer import ActionFinding, action_analyzer
from contextguard.dom_monitor import DOMFinding, dom_monitor
from contextguard.url_monitor import URLFinding, url_monitor


@dataclass
class Inconsistency:
    """One detected problem from any monitor."""
    source:       str    # "url_monitor" | "dom_monitor" | "action_analyzer"
    finding_type: str
    description:  str
    risk_delta:   int
    expected:     str = ""
    observed:     str = ""
    keywords:     list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source":       self.source,
            "finding_type": self.finding_type,
            "description":  self.description,
            "risk_delta":   self.risk_delta,
            "expected":     self.expected,
            "observed":     self.observed,
            "keywords":     self.keywords,
        }


@dataclass
class ConsistencyReport:
    """Full output of one consistency check pass."""
    task_id:          str
    step_number:      int
    inconsistencies:  List[Inconsistency] = field(default_factory=list)
    total_risk_delta: int = 0
    clean:            bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id":         self.task_id,
            "step_number":     self.step_number,
            "inconsistencies": [i.to_dict() for i in self.inconsistencies],
            "total_risk_delta":self.total_risk_delta,
            "clean":           self.clean,
        }


class ConsistencyChecker:
    """
    Checkpoint 5.3 — orchestrates all monitors and returns a ConsistencyReport.
    """

    def check(
        self,
        task_id:         str,
        step_number:     int,
        user_intent:     Dict[str, Any],
        dom_snapshot:    Any,
        proposed_action: Dict[str, Any],
        previous_page:   Optional[str] = None,
        previous_text:   Optional[str] = None,
        raw_html:        str = "",
    ) -> ConsistencyReport:
        report = ConsistencyReport(task_id=task_id, step_number=step_number)

        current_url  = getattr(dom_snapshot, "url",          "")
        current_page = getattr(dom_snapshot, "page_name",    "")
        current_text = getattr(dom_snapshot, "visible_text", "")

        # --- URL monitor ---
        for f in url_monitor.check(current_url, current_page,
                                   previous_page, user_intent):
            report.inconsistencies.append(Inconsistency(
                source       = "url_monitor",
                finding_type = f.finding_type,
                description  = f.description,
                risk_delta   = f.risk_delta,
                observed     = f.url,
            ))

        # --- DOM monitor ---
        for f in dom_monitor.check(current_text, previous_text, raw_html):
            report.inconsistencies.append(Inconsistency(
                source       = "dom_monitor",
                finding_type = f.finding_type,
                description  = f.description,
                risk_delta   = f.risk_delta,
                keywords     = f.matched_keywords,
            ))

        # --- Action analyzer ---
        for f in action_analyzer.check(user_intent, proposed_action, dom_snapshot):
            report.inconsistencies.append(Inconsistency(
                source       = "action_analyzer",
                finding_type = f.finding_type,
                description  = f.description,
                risk_delta   = f.risk_delta,
                expected     = f.expected,
                observed     = f.observed,
            ))

        report.total_risk_delta = sum(i.risk_delta for i in report.inconsistencies)
        report.clean            = len(report.inconsistencies) == 0
        return report


consistency_checker = ConsistencyChecker()
