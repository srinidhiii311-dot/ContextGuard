"""
Approval Service — ContextGuard Services

Manages the human-approval workflow for REQUIRE_APPROVAL decisions.

Why the approval workflow protects high-impact actions
-------------------------------------------------------
Payment submissions, password interactions, and file uploads can have
irreversible real-world consequences. Requiring explicit human sign-off
before execution ensures that a compromised or misbehaving agent cannot
autonomously complete sensitive operations. Approving one action does not
grant blanket permission — every action with REQUIRE_APPROVAL generates its
own unique approval request tied to the exact action_id.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.database import database as db_ops
from app.models.decision import ApprovalRequest, ApprovalResponse, DecisionResult

# Approvals older than this are automatically expired
_EXPIRY_MINUTES = 30


class ApprovalService:
    """
    Creates, resolves, and queries approval requests.

    Approval is tied to the exact action_id and session_id. Approving one
    request does NOT automatically permit future similar actions.
    """

    def create_approval(
        self,
        db: Session,
        action_id: str,
        session_id: str,
        agent_id: str,
        action_type: str,
        decision: DecisionResult,
        target_url: Optional[str] = None,
        target_selector: Optional[str] = None,
    ) -> ApprovalRequest:
        """
        Create a new pending approval request.

        Returns the ApprovalRequest model so the decision result can
        include the approval_id in its response.
        """
        approval_id = str(uuid.uuid4())
        request = ApprovalRequest(
            approval_id=approval_id,
            action_id=action_id,
            session_id=session_id,
            agent_id=agent_id,
            action_type=action_type,
            target_url=target_url,
            target_selector=target_selector,
            risk_score=decision.risk_score,
            risk_level=str(decision.risk_level),
            reasons=decision.reasons,
            matched_policies=decision.matched_policies,
            status="pending",
            created_at=datetime.now(timezone.utc),
        )

        db_ops.store_approval(db, request.model_dump())
        return request

    def get_pending_approvals(self, db: Session) -> List[Dict]:
        """Return all approvals with status='pending'."""
        self.expire_old_approvals(db)
        return db_ops.get_pending_approvals(db)

    def get_approval(self, db: Session, approval_id: str) -> Optional[Dict]:
        """Return a single approval record by ID."""
        return db_ops.get_approval(db, approval_id)

    def approve_action(
        self,
        db: Session,
        approval_id: str,
        resolved_by: str = "human_operator",
    ) -> ApprovalResponse:
        """
        Approve an exact action.

        Only the action tied to this approval_id is permitted. Future
        actions of the same type still require their own approval.
        """
        record = db_ops.get_approval(db, approval_id)
        if not record:
            return ApprovalResponse(
                approval_id=approval_id,
                action_id="unknown",
                status="not_found",
                message="Approval request not found",
                executable=False,
            )

        if record["status"] != "pending":
            return ApprovalResponse(
                approval_id=approval_id,
                action_id=record["action_id"],
                status=record["status"],
                message=f"Approval is already '{record['status']}'",
                executable=record["status"] == "approved",
            )

        db_ops.update_approval(db, approval_id, {
            "status": "approved",
            "resolved_at": datetime.now(timezone.utc),
            "resolved_by": resolved_by,
        })

        return ApprovalResponse(
            approval_id=approval_id,
            action_id=record["action_id"],
            status="approved",
            message="Action approved. This approval is valid only for this exact action.",
            executable=True,
        )

    def reject_action(
        self,
        db: Session,
        approval_id: str,
        resolved_by: str = "human_operator",
    ) -> ApprovalResponse:
        """
        Reject an approval request. Rejection prevents execution permanently.
        """
        record = db_ops.get_approval(db, approval_id)
        if not record:
            return ApprovalResponse(
                approval_id=approval_id,
                action_id="unknown",
                status="not_found",
                message="Approval request not found",
                executable=False,
            )

        if record["status"] != "pending":
            return ApprovalResponse(
                approval_id=approval_id,
                action_id=record["action_id"],
                status=record["status"],
                message=f"Approval is already '{record['status']}'",
                executable=False,
            )

        db_ops.update_approval(db, approval_id, {
            "status": "rejected",
            "resolved_at": datetime.now(timezone.utc),
            "resolved_by": resolved_by,
        })

        return ApprovalResponse(
            approval_id=approval_id,
            action_id=record["action_id"],
            status="rejected",
            message="Action rejected. Execution is permanently prevented for this request.",
            executable=False,
        )

    def is_approved(self, db: Session, action_id: str) -> bool:
        """
        Check whether a specific action_id has an approved record.

        Approving one action does NOT approve other actions.
        """
        from app.database.database import ApprovalRecord
        record = (
            db.query(ApprovalRecord)
            .filter(
                ApprovalRecord.action_id == action_id,
                ApprovalRecord.status == "approved",
            )
            .first()
        )
        return record is not None

    def expire_old_approvals(self, db: Session) -> int:
        """
        Mark approvals older than _EXPIRY_MINUTES as expired.
        Returns the number of records expired.
        """
        from app.database.database import ApprovalRecord
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=_EXPIRY_MINUTES)
        records = (
            db.query(ApprovalRecord)
            .filter(
                ApprovalRecord.status == "pending",
                ApprovalRecord.created_at < cutoff,
            )
            .all()
        )
        for r in records:
            r.status = "expired"
            r.resolved_at = datetime.now(timezone.utc)
            r.resolved_by = "system_expiry"
        db.commit()
        return len(records)


# Module-level singleton
approval_service = ApprovalService()
