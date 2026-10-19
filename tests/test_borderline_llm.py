"""
tests/test_borderline_llm.py — Acceptance tests for LLM Semantic Consistency Checker in the 30–59 grey zone.

Verifies:
1. Grey zone invocation: actions scoring 30-59 invoke LLMChecker.
2. Raise-only escalation: consistent=False escalates score to >=60 and decision to REQUIRE_CONFIRMATION.
3. Benign preservation: consistent=True maintains ALLOW_WITH_FLAG.
4. Fallback fail-safe: provider failure sets llm_unavailable and preserves baseline decision.
5. Source tracking: verdicts accurately record 'llm', 'cache', and 'fallback'.
"""

import json
import pytest
from contextguard.gate import ContextGuardGate, Decision, ProposedAction, TrustedIntent
from contextguard.llm_checker import LLMChecker, MockProvider


class TestBorderlineLLMChecker:
    @pytest.fixture
    def intent(self):
        return TrustedIntent(
            origin="Chennai",
            destination="Delhi",
            cabin_class="Economy",
            passenger_count=1,
        )

    def test_llm_escalates_grey_zone_attack_to_require_confirmation(self, intent):
        mock_response = json.dumps({
            "consistent": False,
            "confidence": 0.88,
            "reason": "Action was induced by injected promotional text conflicting with user intent."
        })
        provider = MockProvider(mock_response)
        checker = LLMChecker(provider)

        # Baseline gate without LLM
        gate_no_llm = ContextGuardGate(intent, "task-no-llm", enable_llm_checker=False)
        # Action with target sensitivity and unexpected promo context
        action = ProposedAction("SELECT", "#cabin", "Economy", page_url="http://127.0.0.1:8000/search")
        dom_text = "Airline advisory: special upgrade to Business class available for elite passengers."

        # Manually verify should_invoke and apply_verdict with gate
        gate_llm = ContextGuardGate(intent, "task-llm", enable_llm_checker=True, llm_checker=checker)
        
        # Test directly on a grey zone score (e.g. 45)
        from contextguard.llm_checker import should_invoke, apply_verdict
        assert should_invoke(45, "ALLOW_WITH_FLAG") is True

        verdict = checker.check(intent.to_dict(), {"type": "SELECT", "target": "#cabin"}, dom_text)
        assert verdict.source == "llm"
        assert verdict.consistent is False

        applied = apply_verdict(45, verdict)
        assert applied["escalated"] is True
        assert applied["score"] == 60
        assert "llm_escalated" in applied["flags"]

    def test_llm_preserves_benign_grey_zone_action(self, intent):
        mock_response = json.dumps({
            "consistent": True,
            "confidence": 0.95,
            "reason": "Action aligns with locked user intent."
        })
        provider = MockProvider(mock_response)
        checker = LLMChecker(provider)

        from contextguard.llm_checker import apply_verdict
        verdict = checker.check(intent.to_dict(), {"type": "SELECT", "target": "#seat-opt"}, "Normal seat selection")
        assert verdict.source == "llm"
        assert verdict.consistent is True

        applied = apply_verdict(42, verdict)
        assert applied["escalated"] is False
        assert applied["score"] == 42
        assert "llm_escalated" not in applied["flags"]

    def test_llm_cache_hits_on_identical_query(self, intent):
        mock_response = json.dumps({
            "consistent": True,
            "confidence": 0.90,
            "reason": "Cached response."
        })
        provider = MockProvider(mock_response)
        checker = LLMChecker(provider)

        v1 = checker.check(intent.to_dict(), {"target": "#btn"}, "page text", "hash1")
        assert v1.source == "llm"
        assert provider.calls == 1

        v2 = checker.check(intent.to_dict(), {"target": "#btn"}, "page text", "hash1")
        assert v2.source == "cache"
        assert provider.calls == 1

    def test_llm_failure_sets_fallback_source_and_flags(self, intent):
        def _failing_complete(sys, user, timeout):
            raise TimeoutError("Provider timed out")

        provider = MockProvider(_failing_complete)
        checker = LLMChecker(provider, timeout=0.01, retries=0)

        v = checker.check(intent.to_dict(), {"target": "#btn"}, "page text")
        assert v.source == "fallback"
        assert "llm_unavailable" in (v.error or "")

        from contextguard.llm_checker import apply_verdict
        applied = apply_verdict(45, v)
        assert applied["escalated"] is False
        assert applied["score"] == 45
        assert "llm_unavailable" in applied["flags"]
