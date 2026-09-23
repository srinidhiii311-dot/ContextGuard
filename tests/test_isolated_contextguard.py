"""
tests/test_isolated_contextguard.py — Comprehensive Verification Suite

Validates the complete ContextGuard architectural redesign:
1. Testbed-Detector Isolation Boundary
2. Pre-Action Safety Gate Verification
3. Post-Action State Difference Engine
4. Feature Extractor & ML Model Inference
5. Configurable Policy Engine Decisions
6. Offline Evaluation DAO
"""

import os
import sys
import unittest
from pathlib import Path

# Ensure root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.database.db import ContextGuardRuntimeDAO, EvaluationDAO, TestbedDAO, init_db
from contextguard.ml.feature_extractor import feature_extractor
from contextguard.ml.risk_model import risk_predictor
from contextguard.policy_engine import policy_engine
from contextguard.pre_action_gate import PreActionGate
from contextguard.state_collector import BrowserState
from contextguard.state_difference import StateDifferenceEngine
from contextguard.task_context import TrustedTaskContext
from testbed.injector import testbed_injector
from testbed.scenarios import SCENARIOS, list_scenarios


class TestContextGuardArchitecture(unittest.TestCase):

    def setUp(self):
        init_db()
        self.task_context = TrustedTaskContext(
            task_id="test-task-101",
            raw_instruction="Book 2 economy tickets from Chennai to Bangalore for 25 September 2026",
            origin="Chennai",
            destination="Bangalore",
            date="2026-09-25",
            passengers=2,
            cabin_class="Economy",
        )

    def test_01_testbed_detector_isolation(self):
        """Verify strict software isolation between ContextGuard runtime and Testbed ground truth."""
        # TestbedDAO records ground truth
        session_id = "test-sess-iso"
        run_id = TestbedDAO.record_testbed_run(
            session_id=session_id,
            testbed_scenario="prompt_injection",
            attack_type="cabin_override",
            target_page="search",
            ground_truth_label=1,
            metadata={"test": "isolation"},
        )
        self.assertTrue(run_id)

        # Verify ContextGuardRuntimeDAO has NO method for testbed_runs
        self.assertFalse(hasattr(ContextGuardRuntimeDAO, "record_testbed_run"))
        self.assertFalse(hasattr(ContextGuardRuntimeDAO, "get_testbed_run"))

        # Verify task context has NO attack metadata
        intent_dict = self.task_context.to_dict()
        self.assertNotIn("attack_type", intent_dict)
        self.assertNotIn("scenario", intent_dict)
        self.assertNotIn("test_case", intent_dict)
        self.assertNotIn("ground_truth", intent_dict)

    def test_02_pre_action_gate_catches_tamper_before_execution(self):
        """Verify Pre-Action Gate blocks or pauses consequential/tampered actions before execution."""
        gate = PreActionGate()

        # Benign action aligning with intent -> ALLOW
        benign_act = {"type": "SELECT", "selector": "#cabin", "value": "Economy"}
        res1 = gate.evaluate_action(
            session_id="sess-pre",
            step_number=1,
            task_context=self.task_context,
            action=benign_act,
            current_url="http://127.0.0.1:8000/app",
            current_page_name="search",
        )
        self.assertEqual(res1.decision, "ALLOW")
        self.assertLess(res1.risk_score, 40)

        # Injected Cabin Class Mismatch -> BLOCK or PAUSE
        tamper_act = {"type": "SELECT", "selector": "#cabin", "value": "Business"}
        res2 = gate.evaluate_action(
            session_id="sess-pre",
            step_number=2,
            task_context=self.task_context,
            action=tamper_act,
            current_url="http://127.0.0.1:8000/app",
            current_page_name="search",
        )
        self.assertIn(res2.decision, ("BLOCK", "PAUSE"))
        self.assertGreaterEqual(res2.risk_score, 70)
        self.assertIn("Cabin class mismatch", res2.reason)

        # Unauthorized Instant Checkout from search page -> BLOCK
        unauth_act = {"type": "CLICK", "selector": "#instant-pay-btn", "value": "Pay ₹50,000"}
        res3 = gate.evaluate_action(
            session_id="sess-pre",
            step_number=3,
            task_context=self.task_context,
            action=unauth_act,
            current_url="http://127.0.0.1:8000/app",
            current_page_name="search",
        )
        self.assertIn(res3.decision, ("BLOCK", "PAUSE"))
        self.assertTrue(res3.is_consequential)

    def test_03_post_action_state_difference_engine(self):
        """Verify State Difference Engine captures DOM mutations, URL changes, and sensitive fields."""
        diff_engine = StateDifferenceEngine()

        s0 = BrowserState(
            state_id="s0",
            session_id="sess-diff",
            step_number=0,
            timestamp=100.0,
            url="http://127.0.0.1:8000/app/#search",
            domain="127.0.0.1:8000",
            page_title="Flight Search",
            dom_hash="hash0",
            text_length=200,
            visible_text="Book flights from Chennai to Bangalore",
            forms=[{"id": "search-form"}],
            inputs=[{"name": "origin"}, {"name": "destination"}],
            buttons=["Search Flights"],
        )

        s1_external = BrowserState(
            state_id="s1",
            session_id="sess-diff",
            step_number=1,
            timestamp=101.0,
            url="http://untrusted-external-payment.org/verify",
            domain="untrusted-external-payment.org",
            page_title="External Payment",
            dom_hash="hash1",
            text_length=350,
            visible_text="Submit credit card payment to external gateway",
            forms=[{"id": "pay-form"}],
            inputs=[{"name": "credit_card_number"}, {"name": "card_cvv"}],
            buttons=["Pay Now"],
        )

        diff = diff_engine.analyze_transition(
            session_id="sess-diff",
            step_number=1,
            prev_state=s0,
            curr_state=s1_external,
            task_context=self.task_context,
        )

        self.assertTrue(diff.url_changed)
        self.assertTrue(diff.domain_changed)
        self.assertTrue(diff.is_external_domain)
        self.assertTrue(diff.sensitive_field_detected)

    def test_04_feature_extractor_and_ml_risk_model(self):
        """Verify feature extraction vector and ML risk prediction inference."""
        diff_engine = StateDifferenceEngine()
        s0 = BrowserState(
            state_id="s0", session_id="sess-ml", step_number=0, timestamp=1.0,
            url="http://127.0.0.1:8000/app/#search", domain="127.0.0.1:8000",
            page_title="Search", dom_hash="h0", text_length=150,
            visible_text="Flight search Chennai to Bangalore", forms=[], inputs=[], buttons=[]
        )
        s1 = BrowserState(
            state_id="s1", session_id="sess-ml", step_number=1, timestamp=2.0,
            url="http://127.0.0.1:8000/app/#results", domain="127.0.0.1:8000",
            page_title="Results", dom_hash="h1", text_length=450,
            visible_text="Flights from Chennai to Bangalore available on 25 September IndiGo Air India",
            forms=[], inputs=[], buttons=["Select"]
        )
        diff = diff_engine.analyze_transition("sess-ml", 1, s0, s1, self.task_context)

        feats = feature_extractor.extract_features(
            diff=diff,
            action={"type": "CLICK", "selector": "#search-btn", "value": "Search Flights"},
            task_context=self.task_context,
            current_page_name="results",
        )
        self.assertEqual(len(feats), 18)

        risk_score, confidence, top_contrib = risk_predictor.predict(feats)
        self.assertIsInstance(risk_score, int)
        self.assertGreaterEqual(risk_score, 0)
        self.assertLessEqual(risk_score, 100)
        self.assertGreaterEqual(confidence, 0.5)
        self.assertLessEqual(confidence, 1.0)

    def test_05_configurable_policy_engine(self):
        """Verify policy engine decisions under configurable thresholds."""
        policy = policy_engine
        policy.update_thresholds(allow=35.0, warn=60.0, pause=80.0)

        dec_low = policy.evaluate(risk_score=20, model_confidence=0.9)
        self.assertEqual(dec_low.decision, "ALLOW")

        dec_med = policy.evaluate(risk_score=65, model_confidence=0.7)
        self.assertEqual(dec_med.decision, "WARN")

        dec_high = policy.evaluate(risk_score=85, model_confidence=0.85)
        self.assertEqual(dec_high.decision, "PAUSE")

        # Consequential payment with moderate risk escalates to PAUSE
        dec_sens = policy.evaluate(risk_score=55, action_sensitivity=0.9, is_consequential=True)
        self.assertEqual(dec_sens.decision, "PAUSE")
        self.assertTrue(dec_sens.requires_human_confirmation)

    def test_06_testbed_scenarios_suite(self):
        """Verify that all 8 scenarios (1 baseline + 7 adversarial) are registered."""
        scenarios = list_scenarios()
        self.assertEqual(len(scenarios), 8)

        benign = [s for s in scenarios if s["ground_truth_label"] == 0]
        adversarial = [s for s in scenarios if s["ground_truth_label"] == 1]
        self.assertEqual(len(benign), 1)
        self.assertEqual(len(adversarial), 7)


if __name__ == "__main__":
    unittest.main()
