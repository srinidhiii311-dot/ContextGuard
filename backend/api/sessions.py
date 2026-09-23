"""
backend/api/sessions.py — Session Endpoints & Operator Resolution Controls

Endpoints:
- POST /api/sessions            : Create and launch session
- GET  /api/sessions/{id}       : Full session detail + event/verdict timeline
- POST /api/sessions/{id}/resume: Operator approves paused action
- POST /api/sessions/{id}/deny  : Operator denies paused action
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.browser_agent.agent import resolve_pause
from backend.db.models import ContextGuardDAO, OperatorActionDAO, SessionControllerDAO
from backend.events.bus import event_bus
from backend.session_controller.controller import session_controller
from shared.schemas.schemas import SessionCreateRequest, SessionCreateResponse

router = APIRouter(prefix="/api/sessions", tags=["Sessions"])


class PauseResolutionRequest(BaseModel):
    actor: str = Field(default="Human Operator", description="Operator identity or role")
    notes: Optional[str] = Field(default=None, description="Operator justification or audit notes")


@router.post("", response_model=SessionCreateResponse, status_code=201)
def create_session_endpoint(payload: SessionCreateRequest) -> SessionCreateResponse:
    """Launches an autonomous agent session with locked intent and isolated testbed."""
    return session_controller.launch_session(payload)


@router.get("/{session_id}")
def get_session_detail_endpoint(session_id: str) -> Dict[str, Any]:
    """Returns session detail and complete event/verdict timeline for audit replay."""
    session = SessionControllerDAO.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    events = ContextGuardDAO.get_session_events_and_verdicts(session_id)
    return {
        "session": session,
        "events": events,
    }


@router.post("/{session_id}/resume")
def resume_session_endpoint(
    session_id: str,
    payload: Optional[PauseResolutionRequest] = None,
) -> Dict[str, Any]:
    """Human operator approves a PAUSED consequential action to proceed."""
    success = resolve_pause(session_id, "resume")
    if not success:
        raise HTTPException(status_code=400, detail="Session is not currently waiting in PAUSED state")

    req = payload or PauseResolutionRequest()
    actor_name = req.actor or "Human Operator"
    notes_text = req.notes or "Operator clearance granted"

    # Record Operator Override in persistent audit trail
    existing_events = ContextGuardDAO.get_session_events_and_verdicts(session_id)
    next_seq = (max((e.get("seq", 0) for e in existing_events), default=0)) + 1

    event_id = ContextGuardDAO.record_event(
        session_id=session_id,
        seq=next_seq,
        prev_url=existing_events[-1].get("current_url", "") if existing_events else "",
        current_url=f"http://127.0.0.1:8000/api/sessions/{session_id}/resume",
        proposed_action={
            "type": "OPERATOR_OVERRIDE",
            "target": "HUMAN_OPERATOR",
            "value": "RESUME",
            "actor": actor_name,
            "action": "APPROVED",
            "notes": notes_text,
        },
        dom_diff={"resolution": "Operator clearance granted", "action": "resume", "actor": actor_name, "notes": notes_text},
        screenshot_ref="",
    )
    reasoning_str = f"Human operator [{actor_name}] reviewed paused consequential action and granted approval to proceed: {notes_text}"
    ContextGuardDAO.record_verdict(
        event_id=event_id,
        risk_score=0.0,
        threat_type="operator_override",
        decision="ALLOW",
        reasoning=reasoning_str,
        latency_ms=0.0,
    )

    # Broadcast override audit event to live listener
    event_bus.broadcast_sync(session_id, {
        "seq": next_seq,
        "type": "operator_override",
        "action_desc": f"Operator Approved Action Resume ({actor_name})",
        "risk_score": 0.0,
        "threat_type": "operator_override",
        "decision": "ALLOW",
        "reasoning": reasoning_str,
        "latency_ms": 0.0,
    })

    # Record in decoupled operator_actions table
    OperatorActionDAO.record_action(
        session_id=session_id,
        actor=actor_name,
        action_taken="RESUME",
        prior_decision="PAUSE",
        notes=notes_text,
    )

    return {"status": "resumed", "session_id": session_id, "audit_event_id": event_id, "actor": actor_name}


@router.post("/{session_id}/deny")
def deny_session_endpoint(
    session_id: str,
    payload: Optional[PauseResolutionRequest] = None,
) -> Dict[str, Any]:
    """Human operator denies a PAUSED action, halting the session with a BLOCK verdict."""
    success = resolve_pause(session_id, "deny")
    if not success:
        raise HTTPException(status_code=400, detail="Session is not currently waiting in PAUSED state")

    req = payload or PauseResolutionRequest()
    actor_name = req.actor or "Human Operator"
    notes_text = req.notes or "Operator denial enforced"

    # Record Operator Denial in persistent audit trail
    existing_events = ContextGuardDAO.get_session_events_and_verdicts(session_id)
    next_seq = (max((e.get("seq", 0) for e in existing_events), default=0)) + 1

    event_id = ContextGuardDAO.record_event(
        session_id=session_id,
        seq=next_seq,
        prev_url=existing_events[-1].get("current_url", "") if existing_events else "",
        current_url=f"http://127.0.0.1:8000/api/sessions/{session_id}/deny",
        proposed_action={
            "type": "OPERATOR_OVERRIDE",
            "target": "HUMAN_OPERATOR",
            "value": "DENY",
            "actor": actor_name,
            "action": "DENIED",
            "notes": notes_text,
        },
        dom_diff={"resolution": "Operator denial enforced", "action": "deny", "actor": actor_name, "notes": notes_text},
        screenshot_ref="",
    )
    reasoning_str = f"Human operator [{actor_name}] reviewed paused consequential action and denied execution: {notes_text}"
    ContextGuardDAO.record_verdict(
        event_id=event_id,
        risk_score=100.0,
        threat_type="operator_override",
        decision="BLOCK",
        reasoning=reasoning_str,
        latency_ms=0.0,
    )

    # Broadcast override audit event to live listener
    event_bus.broadcast_sync(session_id, {
        "seq": next_seq,
        "type": "operator_override",
        "action_desc": f"Operator Denied Action ({actor_name})",
        "risk_score": 100.0,
        "threat_type": "operator_override",
        "decision": "BLOCK",
        "reasoning": reasoning_str,
        "latency_ms": 0.0,
    })

    # Record in decoupled operator_actions table
    OperatorActionDAO.record_action(
        session_id=session_id,
        actor=actor_name,
        action_taken="DENY",
        prior_decision="PAUSE",
        notes=notes_text,
    )

    return {"status": "denied", "session_id": session_id, "audit_event_id": event_id, "actor": actor_name}
