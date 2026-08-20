"""
ContextGuard — Runtime Safety Gateway for Web Agents

FastAPI application entry point. All browser actions proposed by an AI agent
must pass through ContextGuard before execution. This module wires together
the decision engine, session manager, approval service, audit logger, and
browser service behind a clean REST API.

Required execution path:
  Agent → POST /api/actions/execute → DecisionEngine → BrowserService

The agent has no direct path to Playwright.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.decision_engine import decision_engine
from app.core.taint_tracker import taint_tracker
from app.database.database import (
    get_audit_logs,
    get_dashboard_stats,
    get_db,
    get_pending_approvals,
    init_db,
    list_sessions,
    store_action,
    store_decision,
    get_session as db_get_session,
)
from app.models.action import (
    ActionEvaluateRequest,
    ActionExecuteRequest,
    BrowserAction,
)
from app.models.decision import DecisionResult, DecisionType
from app.services.approval_service import approval_service
from app.services.audit_logger import audit_logger
from app.services.browser_service import browser_service
from app.services.session_manager import session_manager
import app.database.database as _db_module

# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: initialise database tables then start the browser (best-effort).
    Browser startup failures are non-fatal — the safety gateway still operates
    in evaluation-only mode without a live browser.
    Shutdown: stop the browser gracefully.
    """
    _db_module.init_db()
    try:
        await browser_service.start_browser()
    except Exception:
        # Chromium not installed or unavailable — continue without live browser.
        pass
    yield
    try:
        await browser_service.stop_browser()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(
    title="ContextGuard",
    description="Runtime Safety Gateway for Web Agents in High-Risk Browser Actions",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ---------------------------------------------------------------------------
# Helper: persist action + decision
# ---------------------------------------------------------------------------

def _persist_action_and_decision(
    db: Session,
    action: BrowserAction,
    decision: DecisionResult,
    execution_status: str,
) -> None:
    """Store the action, decision, and audit log atomically."""
    store_action(db, {
        "action_id": action.action_id,
        "session_id": action.session_id,
        "agent_id": action.agent_id,
        "action_type": str(action.action_type),
        "target_url": action.target.url,
        "target_selector": action.target.selector,
        "element_type": action.target.element_type,
        "field_name": action.target.field_name,
        "payload": action.payload,
        "source_type": str(action.source.source_type),
        "tainted": decision.tainted,
        "timestamp": action.timestamp,
    })
    store_decision(db, {
        "action_id": action.action_id,
        "session_id": action.session_id,
        "decision": str(decision.decision),
        "risk_score": decision.risk_score,
        "risk_level": str(decision.risk_level),
        "reasons": decision.reasons,
        "matched_policies": decision.matched_policies,
        "risk_factors": decision.risk_factors,
        "tainted": decision.tainted,
        "taint_explanation": decision.taint_explanation,
        "executable": decision.executable,
        "approval_required": decision.approval_required,
        "timestamp": decision.timestamp,
    })
    audit_logger.log(db, action, decision, execution_status)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, summary="Dashboard")
async def dashboard(request: Request):
    """Render the ContextGuard cybersecurity dashboard."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/health", summary="Health check")
async def health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Return application health and database connectivity status."""
    # Call via module reference so tests can monkey-patch check_db_health.
    db_status = _db_module.check_db_health()
    try:
        stats = get_dashboard_stats(db) if db_status == "ok" else {}
    except Exception as exc:
        stats = {}
        db_status = f"error: {exc}"

    return {
        "status": "ok",
        "service": "ContextGuard",
        "version": "1.0.0",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

class CreateSessionRequest(BaseModel):
    agent_id: str
    session_id: Optional[str] = None


@app.post("/api/sessions", status_code=201, summary="Create session")
async def create_session(
    body: CreateSessionRequest,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Create a new agent session."""
    state = session_manager.create_session(db, body.agent_id, body.session_id)
    return {
        "session_id": state.session_id,
        "agent_id": state.agent_id,
        "status": state.status,
        "created_at": state.created_at.isoformat(),
    }


@app.get("/api/sessions", summary="List sessions")
async def list_all_sessions(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Return all sessions."""
    return session_manager.list_sessions(db)


@app.get("/api/sessions/{session_id}", summary="Session details")
async def get_session(
    session_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Return session details and action history."""
    record = db_get_session(db, session_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return record


@app.post("/api/sessions/{session_id}/terminate", summary="Terminate session")
async def terminate_session(
    session_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Terminate a session and close its browser context."""
    ok = session_manager.terminate_session(db, session_id)
    await browser_service.close_context(session_id)
    taint_tracker.clear_session_taint(session_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return {"session_id": session_id, "status": "terminated"}


# ---------------------------------------------------------------------------
# Actions — evaluate
# ---------------------------------------------------------------------------

@app.post("/api/actions/evaluate", summary="Evaluate action (no execution)")
async def evaluate_action(
    body: ActionEvaluateRequest,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Evaluate a proposed browser action without executing it.
    Returns the full DecisionResult including risk score, reasons, and policies.
    """
    action = body.action

    # Ensure session exists
    session_manager.get_or_create_session(db, action.session_id, action.agent_id)

    # Get blocked count for this session
    state = session_manager.get_session(db, action.session_id)
    blocked_count = state.blocked_action_count if state else 0

    # Evaluate
    dec = decision_engine.evaluate(action, blocked_count)

    # Check for multi-step attack
    chain = session_manager.detect_attack_chain(db, action.session_id, action)
    if chain:
        dec.reasons.append(f"Multi-step attack chain: {chain}")
        if dec.decision not in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
            dec = DecisionResult(
                decision=DecisionType.REQUIRE_APPROVAL,
                risk_score=max(dec.risk_score, 60),
                risk_level=dec.risk_level,
                reasons=dec.reasons,
                matched_policies=dec.matched_policies + ["CG-CHAIN-DETECT"],
                risk_factors=dec.risk_factors + ["multi_step_attack_chain"],
                tainted=dec.tainted,
                taint_explanation=dec.taint_explanation,
                executable=False,
                approval_required=True,
                action_id=action.action_id,
            )

    # Create approval request if needed
    if dec.decision == DecisionType.REQUIRE_APPROVAL:
        approval = approval_service.create_approval(
            db=db,
            action_id=action.action_id,
            session_id=action.session_id,
            agent_id=action.agent_id,
            action_type=str(action.action_type),
            decision=dec,
            target_url=action.target.url,
            target_selector=action.target.selector,
        )
        dec.approval_id = approval.approval_id

    # Increment blocked count
    if dec.decision == DecisionType.BLOCK:
        session_manager.increment_blocked_count(db, action.session_id)

    # Record action in session history
    session_manager.add_action(db, action.session_id, action, str(dec.decision))

    # Persist
    execution_status = (
        "blocked" if dec.decision == DecisionType.BLOCK
        else "pending_approval" if dec.decision == DecisionType.REQUIRE_APPROVAL
        else "not_executed"
    )
    _persist_action_and_decision(db, action, dec, execution_status)

    return dec.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Actions — execute
# ---------------------------------------------------------------------------

@app.post("/api/actions/execute", summary="Evaluate and execute action")
async def execute_action(
    body: ActionExecuteRequest,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Evaluate a browser action and execute it only if ContextGuard permits.

    BLOCK → rejected, never executed.
    REQUIRE_APPROVAL → rejected until human approves via /api/approvals/{id}/approve.
    ALLOW / WARN → executed.
    """
    action = body.action

    session_manager.get_or_create_session(db, action.session_id, action.agent_id)
    state = session_manager.get_session(db, action.session_id)
    blocked_count = state.blocked_action_count if state else 0

    dec = decision_engine.evaluate(action, blocked_count)

    # Multi-step chain detection
    chain = session_manager.detect_attack_chain(db, action.session_id, action)
    if chain:
        dec.reasons.append(f"Multi-step attack chain: {chain}")
        if dec.decision not in (DecisionType.BLOCK, DecisionType.REQUIRE_APPROVAL):
            dec = DecisionResult(
                decision=DecisionType.REQUIRE_APPROVAL,
                risk_score=max(dec.risk_score, 60),
                risk_level=dec.risk_level,
                reasons=dec.reasons,
                matched_policies=dec.matched_policies + ["CG-CHAIN-DETECT"],
                risk_factors=dec.risk_factors + ["multi_step_attack_chain"],
                tainted=dec.tainted,
                taint_explanation=dec.taint_explanation,
                executable=False,
                approval_required=True,
                action_id=action.action_id,
            )

    # Check for pre-existing approval (for REQUIRE_APPROVAL actions)
    approved = approval_service.is_approved(db, action.action_id)

    if dec.decision == DecisionType.REQUIRE_APPROVAL and not approved:
        approval = approval_service.create_approval(
            db=db,
            action_id=action.action_id,
            session_id=action.session_id,
            agent_id=action.agent_id,
            action_type=str(action.action_type),
            decision=dec,
            target_url=action.target.url,
            target_selector=action.target.selector,
        )
        dec.approval_id = approval.approval_id

    if dec.decision == DecisionType.BLOCK:
        session_manager.increment_blocked_count(db, action.session_id)

    session_manager.add_action(db, action.session_id, action, str(dec.decision))

    # Attempt browser execution
    execution_result = None
    execution_status = "not_executed"

    if dec.executable or approved:
        try:
            execution_result = await browser_service.execute_action(action, dec, approved)
            execution_status = "executed"
        except Exception as exc:
            execution_status = "execution_error"
            _persist_action_and_decision(db, action, dec, execution_status)
            raise HTTPException(status_code=500, detail=f"Browser execution error: {exc}")
    else:
        execution_status = (
            "blocked" if dec.decision == DecisionType.BLOCK
            else "pending_approval"
        )

    _persist_action_and_decision(db, action, dec, execution_status)

    response = dec.model_dump(mode="json")
    response["execution_status"] = execution_status
    if execution_result:
        response["execution_result"] = execution_result
    return response


# ---------------------------------------------------------------------------
# Actions — list evaluated
# ---------------------------------------------------------------------------

@app.get("/api/actions", summary="List evaluated actions")
async def list_actions(
    session_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Return evaluated actions, optionally filtered by session."""
    from app.database.database import get_actions
    return get_actions(db, session_id=session_id, limit=limit)


# ---------------------------------------------------------------------------
# Audit logs
# ---------------------------------------------------------------------------

@app.get("/api/audit", summary="Audit logs")
async def get_audit(
    session_id: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Return audit logs with optional filtering by session and decision."""
    return get_audit_logs(db, session_id=session_id, decision_filter=decision, limit=limit)


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------

@app.get("/api/approvals", summary="Pending approvals")
async def list_approvals(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Return all pending approval requests."""
    return approval_service.get_pending_approvals(db)


@app.post("/api/approvals/{approval_id}/approve", summary="Approve action")
async def approve(
    approval_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Approve an exact action by approval ID.
    Approval is valid only for the single action tied to this approval_id.
    """
    result = approval_service.approve_action(db, approval_id)
    if result.status == "not_found":
        raise HTTPException(status_code=404, detail="Approval request not found")
    return result.model_dump()


@app.post("/api/approvals/{approval_id}/reject", summary="Reject action")
async def reject(
    approval_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Reject an action. Rejection permanently prevents execution."""
    result = approval_service.reject_action(db, approval_id)
    if result.status == "not_found":
        raise HTTPException(status_code=404, detail="Approval request not found")
    return result.model_dump()


# ---------------------------------------------------------------------------
# Dashboard stats API (used by frontend JS)
# ---------------------------------------------------------------------------

@app.get("/api/stats", summary="Dashboard statistics")
async def get_stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Return real-time dashboard statistics calculated from the database."""
    return get_dashboard_stats(db)
