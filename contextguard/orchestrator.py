"""
contextguard/orchestrator.py — ContextGuard Runtime Orchestrator

Master controller for ContextGuard continuous monitoring:
1. Locks TrustedTaskContext
2. Executes Pre-Action Gate before consequential actions
3. Executes Post-Action State Difference Engine, Feature Extraction, ML Risk Prediction, and Policy Evaluation
4. Broadcasts real-time events to connected WebSockets
5. Enforces Testbed-Detector Isolation: NEVER receives testbed metadata!
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from backend.database.db import ContextGuardRuntimeDAO
from backend.websocket.manager import ws_manager
from contextguard.ml.feature_extractor import feature_extractor
from contextguard.ml.risk_model import risk_predictor
from contextguard.policy_engine import policy_engine
from contextguard.pre_action_gate import PreActionGate, PreCheckResult
from contextguard.state_collector import BrowserState, StateCollector
from contextguard.state_difference import StateDifferenceEngine
from contextguard.task_context import TrustedTaskContext


class ContextGuardSession:
    """Represents an active monitoring session for a web agent execution."""

    def __init__(
        self,
        session_id: str,
        task_context: TrustedTaskContext,
        base_domain: str = "127.0.0.1:8000",
        stabilization_delay_sec: float = 0.3,
    ) -> None:
        self.session_id = session_id
        self.task_context = task_context
        self.base_domain = base_domain
        self.step = 0
        self.prior_flags = 0
        self.cumulative_anomalies = 0

        # Components
        self.state_collector = StateCollector(stabilization_delay_sec=stabilization_delay_sec)
        self.pre_action_gate = PreActionGate(base_domain=base_domain)
        self.difference_engine = StateDifferenceEngine(base_domain=base_domain)
        self.policy_engine = policy_engine

        self.previous_state: Optional[BrowserState] = None
        self.latest_state: Optional[BrowserState] = None
        self.latest_risk_score: int = 0
        self.latest_confidence: float = 0.5
        self.latest_decision: str = "ALLOW"

    def precheck_action(
        self,
        action: Dict[str, Any],
        current_url: str = "",
        current_page_name: str = "search",
    ) -> PreCheckResult:
        """
        Step A: Pre-Action Safety Gate.
        Inspects intended action against current state and locked task context before execution.
        """
        self.step += 1
        t0 = time.perf_counter()

        res = self.pre_action_gate.evaluate_action(
            session_id=self.session_id,
            step_number=self.step,
            task_context=self.task_context,
            action=action,
            current_url=current_url,
            current_page_name=current_page_name,
        )

        latency_ms = (time.perf_counter() - t0) * 1000
        res.latency_ms = round(latency_ms, 2)

        # Record action in runtime DAO
        action_id = ContextGuardRuntimeDAO.record_agent_action(
            session_id=self.session_id,
            step_number=self.step,
            action_type=str(action.get("type", "")),
            selector=str(action.get("selector", action.get("target", ""))),
            value=action.get("value", None),
            action_sensitivity=res.action_sensitivity,
        )

        # Broadcast live HUD event
        self._broadcast_event({
            "phase": "PRE_ACTION",
            "step": self.step,
            "decision": res.decision,
            "risk_score": res.risk_score,
            "action": action,
            "reason": res.reason,
            "latency_ms": round(latency_ms, 2),
            "is_consequential": res.is_consequential,
        })

        if res.decision in ("WARN", "PAUSE"):
            self.prior_flags += 1

        return res

    def observe_post_action(
        self,
        current_state: BrowserState,
        action: Optional[Dict[str, Any]] = None,
        current_page_name: str = "search",
    ) -> Dict[str, Any]:
        """
        Step B: Post-Action Observation & State Difference Engine.
        Captures state transition, extracts features, predicts risk with ML, evaluates policy.
        """
        t_start = time.perf_counter()

        # 1. State difference
        t0 = time.perf_counter()
        diff = self.difference_engine.analyze_transition(
            session_id=self.session_id,
            step_number=self.step,
            prev_state=self.previous_state,
            curr_state=current_state,
            task_context=self.task_context,
        )
        diff_latency_ms = (time.perf_counter() - t0) * 1000

        # 2. Feature extraction
        t0 = time.perf_counter()
        features = feature_extractor.extract_features(
            diff=diff,
            action=action,
            task_context=self.task_context,
            current_page_name=current_page_name,
            cumulative_anomalies=self.cumulative_anomalies,
        )
        feat_latency_ms = (time.perf_counter() - t0) * 1000

        # 3. ML Risk Model inference
        t0 = time.perf_counter()
        risk_score, confidence, top_features = risk_predictor.predict(features)
        ml_latency_ms = (time.perf_counter() - t0) * 1000

        # Track anomalies
        if risk_score >= self.policy_engine.warn_threshold or diff.is_external_domain or diff.sensitive_field_detected:
            self.cumulative_anomalies += 1

        # Record ML prediction in DB
        pred_id = ContextGuardRuntimeDAO.record_model_prediction(
            session_id=self.session_id,
            step_number=self.step,
            phase="POST_ACTION",
            risk_score=risk_score,
            model_confidence=confidence,
            contributing_features=top_features,
            latency_ms=ml_latency_ms,
        )

        # 4. Policy evaluation
        action_sens = features.get("action_sensitivity", 0.0)
        is_consequential = action_sens >= 0.75
        policy_res = self.policy_engine.evaluate(
            risk_score=risk_score,
            model_confidence=confidence,
            action_sensitivity=action_sens,
            is_consequential=is_consequential,
            prior_flags=self.prior_flags,
        )

        # Record policy decision in DB
        dec_id = ContextGuardRuntimeDAO.record_policy_decision(
            session_id=self.session_id,
            step_number=self.step,
            phase="POST_ACTION",
            decision=policy_res.decision,
            reason=policy_res.reason,
            risk_score=risk_score,
            action_sensitivity=action_sens,
            enforced_action=f"POST_OBSERVE step {self.step}",
        )

        total_latency_ms = (time.perf_counter() - t_start) * 1000

        # Update session state pointers
        self.previous_state = self.latest_state
        self.latest_state = current_state
        self.latest_risk_score = risk_score
        self.latest_confidence = confidence
        self.latest_decision = policy_res.decision

        result = {
            "session_id": self.session_id,
            "step_number": self.step,
            "decision": policy_res.decision,
            "risk_score": risk_score,
            "model_confidence": confidence,
            "reason": policy_res.reason,
            "top_contributing_features": top_features,
            "transition_summary": diff.to_dict(),
            "latencies": {
                "diff_ms": round(diff_latency_ms, 2),
                "feature_extraction_ms": round(feat_latency_ms, 2),
                "ml_inference_ms": round(ml_latency_ms, 2),
                "total_post_action_ms": round(total_latency_ms, 2),
            },
        }

        # Broadcast post-action event
        self._broadcast_event({
            "phase": "POST_ACTION",
            "step": self.step,
            "decision": policy_res.decision,
            "risk_score": risk_score,
            "model_confidence": confidence,
            "reason": policy_res.reason,
            "current_url": current_state.url,
            "top_features": top_features,
            "latency_ms": round(total_latency_ms, 2),
        })

        return result

    def _broadcast_event(self, event_data: Dict[str, Any]) -> None:
        try:
            ws_manager.broadcast_sync({
                "type": "contextguard_live_event",
                "session_id": self.session_id,
                "data": event_data,
            })
        except Exception:
            pass


# Active sessions registry
_ACTIVE_SESSIONS: Dict[str, ContextGuardSession] = {}


def get_session(session_id: str) -> Optional[ContextGuardSession]:
    return _ACTIVE_SESSIONS.get(session_id)


def register_session(session: ContextGuardSession) -> None:
    _ACTIVE_SESSIONS[session.session_id] = session


def clear_sessions() -> None:
    _ACTIVE_SESSIONS.clear()
