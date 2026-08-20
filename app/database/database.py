"""
Database layer — ContextGuard

Uses SQLAlchemy Core with SQLite (contextguard.db by default).
All business logic is kept out of this module; it provides only
storage and retrieval primitives plus dashboard aggregation queries.

Why sensitive data is masked
-----------------------------
Passwords, tokens, card numbers and similar values must never appear in
plaintext in the database. The audit logger masks them before calling
store_audit_log(); this module stores whatever string it receives, so the
masking responsibility sits at the boundary closest to the raw data.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Column, DateTime, Float, Integer, String, Text, Boolean,
    create_engine, text,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ---------------------------------------------------------------------------
# Database location
# ---------------------------------------------------------------------------

_DB_PATH = Path(__file__).parent.parent.parent / "contextguard.db"
_DB_URL = f"sqlite:///{_DB_PATH}"

engine = create_engine(_DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ---------------------------------------------------------------------------
# ORM base and models
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class SessionRecord(Base):
    __tablename__ = "sessions"

    session_id = Column(String, primary_key=True, index=True)
    agent_id = Column(String, nullable=False)
    status = Column(String, default="active")
    current_domain = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    action_history = Column(Text, default="[]")   # JSON list of action_ids
    taint_history = Column(Text, default="[]")    # JSON list of taint records
    blocked_action_count = Column(Integer, default=0)


class ActionRecord(Base):
    __tablename__ = "actions"

    action_id = Column(String, primary_key=True, index=True)
    session_id = Column(String, index=True, nullable=False)
    agent_id = Column(String, nullable=False)
    action_type = Column(String, nullable=False)
    target_url = Column(String, nullable=True)
    target_selector = Column(String, nullable=True)
    element_type = Column(String, nullable=True)
    field_name = Column(String, nullable=True)
    payload = Column(Text, default="{}")          # masked JSON
    source_type = Column(String, nullable=True)
    tainted = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class DecisionRecord(Base):
    __tablename__ = "decisions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action_id = Column(String, index=True, nullable=False)
    session_id = Column(String, index=True, nullable=False)
    decision = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String, nullable=False)
    reasons = Column(Text, default="[]")           # JSON list
    matched_policies = Column(Text, default="[]")  # JSON list
    risk_factors = Column(Text, default="[]")      # JSON list
    tainted = Column(Boolean, default=False)
    taint_explanation = Column(Text, nullable=True)
    executable = Column(Boolean, default=False)
    approval_required = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ApprovalRecord(Base):
    __tablename__ = "approvals"

    approval_id = Column(String, primary_key=True, index=True)
    action_id = Column(String, index=True, nullable=False)
    session_id = Column(String, index=True, nullable=False)
    agent_id = Column(String, nullable=False)
    action_type = Column(String, nullable=False)
    target_url = Column(String, nullable=True)
    target_selector = Column(String, nullable=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String, nullable=False)
    reasons = Column(Text, default="[]")
    matched_policies = Column(Text, default="[]")
    status = Column(String, default="pending")     # pending|approved|rejected|expired
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String, nullable=True)


class AuditLogRecord(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action_id = Column(String, index=True, nullable=False)
    session_id = Column(String, index=True, nullable=False)
    agent_id = Column(String, nullable=False)
    action_type = Column(String, nullable=False)
    target_url = Column(String, nullable=True)
    target_selector = Column(String, nullable=True)
    source_type = Column(String, nullable=True)
    taint_status = Column(Boolean, default=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String, nullable=False)
    decision = Column(String, nullable=False)
    reasons = Column(Text, default="[]")
    matched_policies = Column(Text, default="[]")
    execution_status = Column(String, default="not_executed")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class PolicyRecord(Base):
    __tablename__ = "policies"

    policy_id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    action_type = Column(String, nullable=True)
    severity = Column(String, default="medium")
    decision = Column(String, default="WARN")
    enabled = Column(Boolean, default=True)


# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------

def init_db(bind=None) -> None:
    """
    Create all tables if they do not exist.

    Pass a custom ``bind`` (engine) to initialise a separate database,
    for example an in-memory SQLite engine used by the test suite.
    All ORM models are defined in this module and registered on ``Base``,
    so every table is created in a single call.
    """
    target = bind if bind is not None else engine
    # Explicitly reference every model class so their table metadata is
    # registered on Base before create_all is called.  Importing them at
    # the top of this module is sufficient, but listing them here makes the
    # dependency explicit and guards against future refactors.
    _ = (
        SessionRecord,
        ActionRecord,
        DecisionRecord,
        ApprovalRecord,
        AuditLogRecord,
        PolicyRecord,
    )
    Base.metadata.create_all(bind=target)


def check_db_health(bind=None) -> str:
    """
    Verify that the required tables exist and are queryable.

    Returns ``"ok"`` on success or an error string on failure.
    Only call this *after* ``init_db()`` has been called.
    """
    target = bind if bind is not None else engine
    try:
        with target.connect() as conn:
            # Query each critical table to confirm existence.
            for table in ("sessions", "actions", "decisions", "approvals", "audit_logs"):
                conn.execute(text(f"SELECT 1 FROM {table} LIMIT 1"))
        return "ok"
    except Exception as exc:
        return f"error: {exc}"


def get_db() -> Session:
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Session storage
# ---------------------------------------------------------------------------

def store_session(db: Session, session_data: Dict[str, Any]) -> None:
    """Insert or update a session record."""
    existing = db.get(SessionRecord, session_data["session_id"])
    if existing:
        existing.status = session_data.get("status", existing.status)
        existing.current_domain = session_data.get("current_domain", existing.current_domain)
        existing.updated_at = datetime.now(timezone.utc)
        existing.blocked_action_count = session_data.get(
            "blocked_action_count", existing.blocked_action_count
        )
        existing.action_history = json.dumps(session_data.get("action_history", []))
        existing.taint_history = json.dumps(session_data.get("taint_history", []))
    else:
        record = SessionRecord(
            session_id=session_data["session_id"],
            agent_id=session_data.get("agent_id", "unknown"),
            status=session_data.get("status", "active"),
            current_domain=session_data.get("current_domain"),
            created_at=session_data.get("created_at", datetime.now(timezone.utc)),
            updated_at=datetime.now(timezone.utc),
            action_history=json.dumps(session_data.get("action_history", [])),
            taint_history=json.dumps(session_data.get("taint_history", [])),
            blocked_action_count=session_data.get("blocked_action_count", 0),
        )
        db.add(record)
    db.commit()


def get_session(db: Session, session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a session by ID."""
    record = db.get(SessionRecord, session_id)
    if not record:
        return None
    return _session_to_dict(record)


def list_sessions(db: Session) -> List[Dict[str, Any]]:
    """Return all sessions."""
    records = db.query(SessionRecord).order_by(SessionRecord.created_at.desc()).all()
    return [_session_to_dict(r) for r in records]


def _session_to_dict(r: SessionRecord) -> Dict[str, Any]:
    return {
        "session_id": r.session_id,
        "agent_id": r.agent_id,
        "status": r.status,
        "current_domain": r.current_domain,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        "action_history": json.loads(r.action_history or "[]"),
        "taint_history": json.loads(r.taint_history or "[]"),
        "blocked_action_count": r.blocked_action_count or 0,
    }


# ---------------------------------------------------------------------------
# Action storage
# ---------------------------------------------------------------------------

def store_action(db: Session, action_data: Dict[str, Any]) -> None:
    """Insert an action record."""
    record = ActionRecord(
        action_id=action_data["action_id"],
        session_id=action_data["session_id"],
        agent_id=action_data.get("agent_id", "unknown"),
        action_type=action_data["action_type"],
        target_url=action_data.get("target_url"),
        target_selector=action_data.get("target_selector"),
        element_type=action_data.get("element_type"),
        field_name=action_data.get("field_name"),
        payload=json.dumps(action_data.get("payload", {})),
        source_type=action_data.get("source_type"),
        tainted=action_data.get("tainted", False),
        timestamp=action_data.get("timestamp", datetime.now(timezone.utc)),
    )
    db.merge(record)
    db.commit()


def get_actions(
    db: Session,
    session_id: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Return actions, optionally filtered by session."""
    q = db.query(ActionRecord).order_by(ActionRecord.timestamp.desc())
    if session_id:
        q = q.filter(ActionRecord.session_id == session_id)
    return [_action_to_dict(r) for r in q.limit(limit).all()]


def _action_to_dict(r: ActionRecord) -> Dict[str, Any]:
    return {
        "action_id": r.action_id,
        "session_id": r.session_id,
        "agent_id": r.agent_id,
        "action_type": r.action_type,
        "target_url": r.target_url,
        "target_selector": r.target_selector,
        "element_type": r.element_type,
        "field_name": r.field_name,
        "payload": json.loads(r.payload or "{}"),
        "source_type": r.source_type,
        "tainted": r.tainted,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
    }


# ---------------------------------------------------------------------------
# Decision storage
# ---------------------------------------------------------------------------

def store_decision(db: Session, decision_data: Dict[str, Any]) -> None:
    """Insert a decision record."""
    record = DecisionRecord(
        action_id=decision_data["action_id"],
        session_id=decision_data["session_id"],
        decision=decision_data["decision"],
        risk_score=decision_data["risk_score"],
        risk_level=decision_data["risk_level"],
        reasons=json.dumps(decision_data.get("reasons", [])),
        matched_policies=json.dumps(decision_data.get("matched_policies", [])),
        risk_factors=json.dumps(decision_data.get("risk_factors", [])),
        tainted=decision_data.get("tainted", False),
        taint_explanation=decision_data.get("taint_explanation"),
        executable=decision_data.get("executable", False),
        approval_required=decision_data.get("approval_required", False),
        timestamp=decision_data.get("timestamp", datetime.now(timezone.utc)),
    )
    db.add(record)
    db.commit()


# ---------------------------------------------------------------------------
# Approval storage
# ---------------------------------------------------------------------------

def store_approval(db: Session, approval_data: Dict[str, Any]) -> None:
    """Insert an approval record."""
    record = ApprovalRecord(
        approval_id=approval_data["approval_id"],
        action_id=approval_data["action_id"],
        session_id=approval_data["session_id"],
        agent_id=approval_data.get("agent_id", "unknown"),
        action_type=approval_data["action_type"],
        target_url=approval_data.get("target_url"),
        target_selector=approval_data.get("target_selector"),
        risk_score=approval_data["risk_score"],
        risk_level=approval_data["risk_level"],
        reasons=json.dumps(approval_data.get("reasons", [])),
        matched_policies=json.dumps(approval_data.get("matched_policies", [])),
        status=approval_data.get("status", "pending"),
        created_at=approval_data.get("created_at", datetime.now(timezone.utc)),
    )
    db.merge(record)
    db.commit()


def update_approval(db: Session, approval_id: str, update_data: Dict[str, Any]) -> bool:
    """Update an approval record. Returns True if found."""
    record = db.get(ApprovalRecord, approval_id)
    if not record:
        return False
    for k, v in update_data.items():
        if hasattr(record, k):
            setattr(record, k, v)
    db.commit()
    return True


def get_approval(db: Session, approval_id: str) -> Optional[Dict[str, Any]]:
    record = db.get(ApprovalRecord, approval_id)
    return _approval_to_dict(record) if record else None


def get_pending_approvals(db: Session) -> List[Dict[str, Any]]:
    records = (
        db.query(ApprovalRecord)
        .filter(ApprovalRecord.status == "pending")
        .order_by(ApprovalRecord.created_at.asc())
        .all()
    )
    return [_approval_to_dict(r) for r in records]


def _approval_to_dict(r: ApprovalRecord) -> Dict[str, Any]:
    return {
        "approval_id": r.approval_id,
        "action_id": r.action_id,
        "session_id": r.session_id,
        "agent_id": r.agent_id,
        "action_type": r.action_type,
        "target_url": r.target_url,
        "target_selector": r.target_selector,
        "risk_score": r.risk_score,
        "risk_level": r.risk_level,
        "reasons": json.loads(r.reasons or "[]"),
        "matched_policies": json.loads(r.matched_policies or "[]"),
        "status": r.status,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
        "resolved_by": r.resolved_by,
    }


# ---------------------------------------------------------------------------
# Audit log storage
# ---------------------------------------------------------------------------

def store_audit_log(db: Session, log_data: Dict[str, Any]) -> None:
    """Insert an audit log entry. Sensitive values must already be masked."""
    record = AuditLogRecord(
        action_id=log_data["action_id"],
        session_id=log_data["session_id"],
        agent_id=log_data.get("agent_id", "unknown"),
        action_type=log_data["action_type"],
        target_url=log_data.get("target_url"),
        target_selector=log_data.get("target_selector"),
        source_type=log_data.get("source_type"),
        taint_status=log_data.get("taint_status", False),
        risk_score=log_data.get("risk_score", 0),
        risk_level=log_data.get("risk_level", "LOW"),
        decision=log_data["decision"],
        reasons=json.dumps(log_data.get("reasons", [])),
        matched_policies=json.dumps(log_data.get("matched_policies", [])),
        execution_status=log_data.get("execution_status", "not_executed"),
        timestamp=log_data.get("timestamp", datetime.now(timezone.utc)),
    )
    db.add(record)
    db.commit()


def get_audit_logs(
    db: Session,
    session_id: Optional[str] = None,
    decision_filter: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    q = db.query(AuditLogRecord).order_by(AuditLogRecord.timestamp.desc())
    if session_id:
        q = q.filter(AuditLogRecord.session_id == session_id)
    if decision_filter:
        q = q.filter(AuditLogRecord.decision == decision_filter.upper())
    return [_audit_to_dict(r) for r in q.limit(limit).all()]


def _audit_to_dict(r: AuditLogRecord) -> Dict[str, Any]:
    return {
        "id": r.id,
        "action_id": r.action_id,
        "session_id": r.session_id,
        "agent_id": r.agent_id,
        "action_type": r.action_type,
        "target_url": r.target_url,
        "target_selector": r.target_selector,
        "source_type": r.source_type,
        "taint_status": r.taint_status,
        "risk_score": r.risk_score,
        "risk_level": r.risk_level,
        "decision": r.decision,
        "reasons": json.loads(r.reasons or "[]"),
        "matched_policies": json.loads(r.matched_policies or "[]"),
        "execution_status": r.execution_status,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
    }


# ---------------------------------------------------------------------------
# Dashboard aggregation queries
# ---------------------------------------------------------------------------

def get_dashboard_stats(db: Session) -> Dict[str, Any]:
    """
    Calculate all dashboard metrics from the database.
    Values are never hardcoded — they reflect the live database state.
    """
    total = db.query(DecisionRecord).count()
    allowed = db.query(DecisionRecord).filter(DecisionRecord.decision == "ALLOW").count()
    warned = db.query(DecisionRecord).filter(DecisionRecord.decision == "WARN").count()
    blocked = db.query(DecisionRecord).filter(DecisionRecord.decision == "BLOCK").count()
    pending_approvals = (
        db.query(ApprovalRecord).filter(ApprovalRecord.status == "pending").count()
    )
    active_sessions = (
        db.query(SessionRecord).filter(SessionRecord.status == "active").count()
    )

    # Average risk score
    result = db.execute(
        text("SELECT AVG(risk_score) FROM decisions")
    ).scalar()
    avg_risk = round(float(result), 1) if result else 0.0

    return {
        "total_actions": total,
        "allowed": allowed,
        "warned": warned,
        "blocked": blocked,
        "pending_approvals": pending_approvals,
        "active_sessions": active_sessions,
        "average_risk_score": avg_risk,
    }
