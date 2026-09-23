"""
backend/api/v1_pipeline.py — Synchronous Security Pipeline Endpoints (Phase 2)

Exposes the synchronous ContextGuard pre-action gate over REST and WebSockets:
  - POST /v1/task/init       : Locks immutable TrustedIntent from instruction (FR1, FR2)
  - POST /v1/action/verify   : Synchronously verifies proposed action (<500ms NFR1, FR6, FR7, FR10, FR19)
  - GET  /v1/task/{id}/status: Returns current gate metrics, counters, and locked intent
  - GET  /v1/task/{id}/audit : Returns complete traceable audit trail (FR21, FR23)
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from agent.task_parser import parse_task
from backend.database.db import get_audit_log, get_conn, insert_task, now_iso
from backend.websocket.manager import ws_manager
from contextguard.gate import ContextGuardGate, Decision, ProposedAction, TrustedIntent

router = APIRouter(prefix="/v1", tags=["ContextGuard Core Pipeline"])

# In-memory session registry mapping task_id -> ContextGuardGate
_ACTIVE_GATES: Dict[str, ContextGuardGate] = {}


def get_gate(task_id: str) -> Optional[ContextGuardGate]:
    """Retrieve the active gate instance for a task."""
    return _ACTIVE_GATES.get(task_id)


def register_gate(task_id: str, gate: ContextGuardGate) -> None:
    """Register or replace a gate instance for a task."""
    _ACTIVE_GATES[task_id] = gate


def clear_gates() -> None:
    """Clear all active in-memory gate instances."""
    _ACTIVE_GATES.clear()


# ===========================================================================
# Request & Response Schemas
# ===========================================================================

class TaskInitRequest(BaseModel):
    task_id: Optional[str] = Field(
        None,
        description="Optional task UUID. A new UUID will be generated if not provided.",
        json_schema_extra={"example": "task-demo-001"},
    )
    instruction: str = Field(
        ...,
        description="Natural-language instruction given by the user.",
        json_schema_extra={"example": "Book an economy flight from Chennai to Delhi for 1 passenger"},
    )
    origin: Optional[str] = Field(None, description="Explicit origin override")
    destination: Optional[str] = Field(None, description="Explicit destination override")
    cabin_class: Optional[str] = Field("Economy", description="Explicit cabin class override")
    passenger_count: Optional[int] = Field(1, description="Explicit passenger count override")


class TaskInitResponse(BaseModel):
    task_id: str
    status: str = "LOCKED"
    trusted_intent: Dict[str, Any]
    created_at: str


class ActionVerifyRequest(BaseModel):
    task_id: str = Field(..., description="ID of the locked task session.")
    action: Dict[str, Any] = Field(
        ...,
        description="Agent tool call containing at least 'type'/'action_type' and 'target'/'selector'.",
        json_schema_extra={"example": {"type": "CLICK", "target": "confirm_booking_button", "value": None}},
    )
    dom_snapshot: str = Field(
        ...,
        description="Raw or visible text DOM snapshot of the active browser page.",
    )
    page_url: Optional[str] = Field("", description="Active page URL in the browser.")


class ActionVerifyResponse(BaseModel):
    audit_id: str
    task_id: str
    step_number: int
    decision: str
    allowed: bool
    risk_score: int
    risk_tier: str
    attack_type: Optional[str] = None
    characterization_label: Optional[str] = None
    confidence: float = 0.0
    deviation_signal: float = 0.0
    reason: str
    factor_breakdown: Dict[str, Any]
    processing_ms: Dict[str, float]
    total_latency_ms: float


class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    total_checks: int
    allow_count: int
    flag_count: int
    block_count: int
    prior_flags: int
    trusted_intent: Optional[Dict[str, Any]] = None


# ===========================================================================
# Endpoints
# ===========================================================================

@router.post("/task/init", response_model=TaskInitResponse, status_code=201)
def init_task(payload: TaskInitRequest) -> TaskInitResponse:
    """
    Step 2.1 (FR1, FR2):
    Accepts user instruction, parses into immutable TrustedIntent,
    and locks it inside the synchronous ContextGuardGate instance.
    """
    task_id = payload.task_id or str(uuid.uuid4())

    # If explicit origin and destination are not provided, parse via task_parser
    if not (payload.origin and payload.destination):
        parsed = parse_task(payload.instruction)
        intent = TrustedIntent.from_parsed(parsed)
    else:
        intent = TrustedIntent(
            origin=payload.origin.strip(),
            destination=payload.destination.strip(),
            cabin_class=(payload.cabin_class or "Economy").strip(),
            passenger_count=payload.passenger_count or 1,
        )

    # Callback to push live decision payloads to connected WebSockets (NFR3, FR22)
    def _on_gate_decision(record: Dict[str, Any]) -> None:
        ws_manager.broadcast_sync({
            "type": "live_overlay_event",
            "task_id": task_id,
            "record": record,
        })

    # Instantiate the synchronous gate with all 7 components
    gate = ContextGuardGate(
        trusted_intent=intent,
        task_id=task_id,
        on_decision=_on_gate_decision,
    )
    register_gate(task_id, gate)

    # Persist initial task record
    created_at = now_iso()
    try:
        insert_task(task_id, payload.instruction)
    except Exception:
        pass  # If task already exists in DB, keep going

    return TaskInitResponse(
        task_id=task_id,
        status="LOCKED",
        trusted_intent=intent.to_dict(),
        created_at=created_at,
    )


@router.post("/action/verify", response_model=ActionVerifyResponse)
def verify_action(payload: ActionVerifyRequest) -> ActionVerifyResponse:
    """
    Step 2.1 & 2.2 (FR6, FR7, FR10, FR19, NFR1 <500ms):
    Synchronous security pipeline gate. Evaluates proposed action against
    the locked intent, runs threat detection & risk matrix, and applies policy.
    """
    gate = get_gate(payload.task_id)
    if not gate:
        # Fallback: attempt to reconstruct gate from SQLite if task exists
        conn = get_conn()
        row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (payload.task_id,)).fetchone()
        conn.close()
        if row:
            parsed = parse_task(row["instruction"] or "")
            intent = TrustedIntent.from_parsed(parsed)
            gate = ContextGuardGate(trusted_intent=intent, task_id=payload.task_id)
            register_gate(payload.task_id, gate)
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Active task session '{payload.task_id}' not found. Please call /v1/task/init first.",
            )

    t_start = time.perf_counter()

    # Translate dictionary action to ProposedAction
    proposed = ProposedAction.from_dict(
        action=payload.action,
        page_url=payload.page_url or "",
        source_text=payload.dom_snapshot[:500],
    )

    # Execute all 7 pipeline components synchronously
    gate_result = gate.check(
        action=proposed,
        current_dom_text=payload.dom_snapshot,
    )

    total_latency_ms = (time.perf_counter() - t_start) * 1000

    # Also broadcast quick decision summary to WebSocket
    ws_manager.broadcast_sync({
        "type": "gate_decision",
        "task_id": payload.task_id,
        "step_number": gate_result.step_number,
        "decision": gate_result.decision.value,
        "allowed": gate_result.allowed,
        "risk_score": gate_result.risk_score,
        "risk_tier": gate_result.risk_tier,
        "attack_type": gate_result.attack_type,
        "characterization_label": gate_result.characterization_label,
        "latency_ms": round(total_latency_ms, 2),
        "audit_id": gate_result.audit_id,
    })

    return ActionVerifyResponse(
        audit_id=gate_result.audit_id,
        task_id=payload.task_id,
        step_number=gate_result.step_number,
        decision=gate_result.decision.value,
        allowed=gate_result.allowed,
        risk_score=gate_result.risk_score,
        risk_tier=gate_result.risk_tier,
        attack_type=gate_result.attack_type,
        characterization_label=gate_result.characterization_label,
        confidence=round(gate_result.confidence, 4),
        deviation_signal=round(gate_result.deviation_signal, 4),
        reason=gate_result.reason,
        factor_breakdown=gate_result.factor_breakdown,
        processing_ms=gate_result.processing_ms,
        total_latency_ms=round(total_latency_ms, 2),
    )


@router.get("/task/{task_id}/status", response_model=TaskStatusResponse)
def get_task_status(task_id: str) -> TaskStatusResponse:
    """Returns runtime execution counters and locked intent for a task."""
    gate = get_gate(task_id)
    if not gate:
        raise HTTPException(status_code=404, detail=f"Task session '{task_id}' not found.")

    summary = gate.summary
    return TaskStatusResponse(
        task_id=task_id,
        status="ACTIVE",
        total_checks=summary["total_checks"],
        allow_count=summary["allow_count"],
        flag_count=summary["flag_count"],
        block_count=summary["block_count"],
        prior_flags=summary["prior_flags"],
        trusted_intent=gate.trusted_intent.to_dict(),
    )


@router.get("/task/{task_id}/audit")
def get_task_audit_trail(
    task_id: str,
    limit: int = Query(100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """Returns traceable append-only audit trail records for a task (FR21, FR23)."""
    return get_audit_log(task_id=task_id, limit=limit)
