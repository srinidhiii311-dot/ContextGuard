"""
contextguard/intervention.py — Phase 5, Checkpoint 5.4

Intervention hook that plugs into agent_controller.py.

When the risk score crosses the threshold, this hook signals the agent
to PAUSE before the next action executes.  The dashboard shows the alert
and exposes a "Resume agent" button.

This is the core ContextGuard guarantee: a Prompt Injection attack that
previously fooled the baseline agent now gets paused before the wrong
action is taken (Phase 4 exit test → Phase 5.4 pass criterion).

Integration
-----------
Pass `intervention_hook=contextguard_hook` when constructing AgentController:

    from contextguard.intervention import build_intervention_hook
    hook = build_intervention_hook(task_id, user_intent)
    ctrl = AgentController(intervention_hook=hook)
    await ctrl.run(task_id, instruction)
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional

from backend.database.db import insert_security_event
from backend.websocket.manager import ws_manager
from contextguard.consistency_checker import consistency_checker
from contextguard.context_store import context_store
from contextguard.risk_engine import RiskEngine, risk_engine

# Risk threshold above which the agent is paused
INTERVENTION_THRESHOLD = 60   # HIGH_RISK zone


def build_intervention_hook(
    task_id:    str,
    user_intent: Dict[str, Any],
    threshold:  int = INTERVENTION_THRESHOLD,
    enabled:    bool = True,
) -> Callable:
    """
    Factory that returns an async callable compatible with AgentController's
    intervention_hook parameter.

    The hook is called before every agent action:
        allowed = await hook(state, snapshot, action)

    Returns True to allow the action, False to block it.
    """
    # Per-task risk accumulator (score carries over between steps)
    _task_risk = {"score": 0}

    async def hook(state: Any, snapshot: Any, action: Dict[str, Any]) -> bool:
        if not enabled:
            return True

        # Get previous snapshot for DOM diff
        prev = context_store.get_previous(task_id)
        prev_text = getattr(prev, "dom_summary", None) if prev else None
        prev_page = getattr(prev, "page_name",   None) if prev else None

        # Run consistency check
        report = consistency_checker.check(
            task_id         = task_id,
            step_number     = state.step,
            user_intent     = user_intent,
            dom_snapshot    = snapshot,
            proposed_action = action,
            previous_page   = prev_page,
            previous_text   = prev_text,
        )

        # Evaluate risk (accumulative)
        result = risk_engine.evaluate(report, base_score=_task_risk["score"])
        _task_risk["score"] = result.risk_score

        # Capture context snapshot
        context_store.capture(
            task_id         = task_id,
            step_number     = state.step,
            user_intent     = user_intent,
            dom_snapshot    = snapshot,
            agent_action    = action,
            risk_score      = result.risk_score,
            status          = result.status,
            inconsistencies = [i.to_dict() for i in report.inconsistencies],
        )

        # Persist security event if anomalous
        if not report.clean:
            for threat in result.threat_types:
                insert_security_event(
                    task_id    = task_id,
                    threat_type= threat,
                    details    = json.dumps(result.details[:3]),
                    risk_score = result.risk_score,
                    status     = result.status,
                )

        # Broadcast to dashboard
        ws_manager.broadcast_sync({
            "type":         "contextguard_scan",
            "task_id":      task_id,
            "step":         state.step,
            "risk_score":   result.risk_score,
            "status":       result.status,
            "threat_types": result.threat_types,
            "top_finding":  result.top_finding,
            "action":       action.get("type"),
            "page":         getattr(snapshot, "page_name", ""),
            "clean":        report.clean,
        })

        # --- Intervention decision ---
        if result.risk_score >= threshold:
            # Broadcast PAUSE event to dashboard
            ws_manager.broadcast_sync({
                "type":       "agent_paused",
                "task_id":    task_id,
                "step":       state.step,
                "risk_score": result.risk_score,
                "status":     result.status,
                "reason":     result.top_finding or "Risk threshold exceeded",
                "action_blocked": action,
            })
            return False   # BLOCK the action

        return True   # ALLOW the action

    return hook
