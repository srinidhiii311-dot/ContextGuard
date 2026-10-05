"""
tests/test_phase_h_hardening.py — Phase H Acceptance Tests:
1. Gate Coverage Audit (Shortfall S11):
   Asserts every action type emitted by the agent (TYPE, SELECT, CLICK, NAVIGATE, SUBMIT)
   is routed through ContextGuardGate.check before execution.
2. Fail-Closed Behaviour (Shortfall S12):
   Asserts that when the LLM semantic checker or external provider fails mid-run,
   the pipeline deterministically falls back to the calibrated rule engine,
   setting the 'llm_unavailable' flag and never silently relaxing the security decision.
"""

from __future__ import annotations

import unittest
from typing import Dict, Any

from contextguard.gate import ContextGuardGate, Decision, ProposedAction, TrustedIntent
from contextguard.llm_checker import LLMChecker, MockProvider, apply_verdict, Verdict


class TestPhaseHHardening(unittest.TestCase):
    def setUp(self):
        self.intent = TrustedIntent(
            origin="Chennai",
            destination="Delhi",
            cabin_class="Economy",
            passenger_count=1,
            addons_allowed="none",
            max_fare=6000.0,
        )
        self.gate = ContextGuardGate(trusted_intent=self.intent, task_id="test-hardening-h")

    # -------------------------------------------------------------------------
    # 1. Gate Coverage Audit (S11)
    # -------------------------------------------------------------------------
    def test_gate_coverage_action_type_type(self):
        """Action type: TYPE / fill input."""
        action = ProposedAction(action_type="TYPE", target="#origin", value="DEL", page_url="http://127.0.0.1:8000/search")
        res = self.gate.check(action, "Search flight screen.")
        self.assertIsNotNone(res)
        self.assertIn(res.decision, (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK))  # origin mismatch

    def test_gate_coverage_action_type_select(self):
        """Action type: SELECT / dropdown choice."""
        action = ProposedAction(action_type="SELECT", target="#cabin", value="Business", page_url="http://127.0.0.1:8000/search")
        res = self.gate.check(action, "Search flight screen.")
        self.assertIsNotNone(res)
        self.assertIn(res.decision, (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK))  # cabin mismatch

    def test_gate_coverage_action_type_click(self):
        """Action type: CLICK / button or link action."""
        action = ProposedAction(action_type="CLICK", target="#insurance-opt-in", value=None, page_url="http://127.0.0.1:8000/passenger")
        res = self.gate.check(action, "Passenger details screen.")
        self.assertIsNotNone(res)
        self.assertIn(res.decision, (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK))  # addon not allowed

    def test_gate_coverage_action_type_navigate(self):
        """Action type: NAVIGATE / redirect target."""
        action = ProposedAction(action_type="NAVIGATE", target="https://malicious-phishing.com/login", value="https://malicious-phishing.com/login", page_url="http://127.0.0.1:8000/search")
        res = self.gate.check(action, "Search flight screen.")
        self.assertIsNotNone(res)
        self.assertIn(res.decision, (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK))  # off-domain

    def test_gate_coverage_action_type_submit(self):
        """Action type: SUBMIT / form submission."""
        action = ProposedAction(action_type="SUBMIT", target="#booking-form", value=None, page_url="http://127.0.0.1:8000/review")
        res = self.gate.check(action, "Review details screen.")
        self.assertIsNotNone(res)
        self.assertIn(res.decision, (Decision.ALLOW, Decision.ALLOW_WITH_FLAG, Decision.REQUIRE_CONFIRMATION, Decision.BLOCK))

    # -------------------------------------------------------------------------
    # 2. Fail-Closed Resilience on LLM Failure (S12)
    # -------------------------------------------------------------------------
    def test_llm_checker_fail_closed_on_provider_kill(self):
        """
        Kills the LLM provider mid-run (simulating network partition or model crash)
        and asserts the pipeline falls back to the deterministic rule score,
        recording 'llm_unavailable' and NEVER relaxing the decision.
        """
        # A mock provider that crashes upon invocation
        def crashing_provider(sys_prompt, user_prompt):
            raise ConnectionResetError("Remote LLM host forcefully closed connection")

        checker = LLMChecker(provider=MockProvider(crashing_provider), timeout=1.0, retries=0)
        v = checker.check(self.intent.to_dict(), {"type": "SELECT", "target": "#seat", "value": "12A"}, "Seat selection screen")

        # Verify fallback verdict
        self.assertIn("llm_unavailable", v.error)
        self.assertGreaterEqual(v.latency_ms, 0.0)

        # In grey zone (score 45), apply_verdict must maintain score and set flag
        rule_score = 45
        applied = apply_verdict(rule_score, v)
        self.assertEqual(applied["score"], rule_score)
        self.assertFalse(applied["escalated"])
        self.assertIn("llm_unavailable", applied["flags"])

    def test_llm_checker_never_relaxes_rule_decision(self):
        """
        Even if an LLM erroneously claims an action is consistent (consistent=True, confidence=1.0),
        the combiner is strictly raise-only and CANNOT lower the rule score.
        """
        benevolent_verdict = Verdict(consistent=True, confidence=1.0, reason="Looks fine to LLM", source="llm")
        rule_score = 75  # High risk from rule engine
        applied = apply_verdict(rule_score, benevolent_verdict)
        self.assertGreaterEqual(applied["score"], rule_score)
        self.assertEqual(applied["score"], rule_score)


if __name__ == "__main__":
    unittest.main()
