"""
Audit Logger — ContextGuard Services

Logs every evaluated action with its decision, risk score, and outcome.
Sensitive field values are masked before storage so that passwords, tokens,
payment card numbers and similar data never appear in plaintext in the audit
trail.

Why sensitive data is masked
-----------------------------
Audit logs are often accessible to a wider audience than source code. Storing
plaintext secrets in logs creates a secondary exfiltration surface. Masking
at the boundary — before any storage call — ensures that even if the audit
database is compromised, no credential or payment data is exposed.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.database.database import store_audit_log
from app.models.action import BrowserAction
from app.models.decision import DecisionResult

# ---------------------------------------------------------------------------
# Sensitive key patterns — values matching these keys are masked
# ---------------------------------------------------------------------------

_SENSITIVE_KEY_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"^password$", r"^passwd$", r"^pass$", r"^pin$",
        r"^token$", r"^access_token$", r"^refresh_token$", r"^id_token$",
        r"^api_key$", r"^apikey$", r"^secret$", r"^private_key$",
        r"^cookie$", r"^session_token$",
        r"^card_number$", r"^credit_card$", r"^cvv$", r"^cvc$",
        r"^expiry$", r"^expiration$",
        r"^ssn$", r"^social_security$", r"^national_id$",
        r"^bank_account$", r"^routing_number$",
        r"^authorization$", r"^bearer$",
    ]
]

_MASK = "***MASKED***"


def mask_sensitive_value(key: str, value: Any) -> Any:
    """
    Return the masked sentinel if the key matches a sensitive pattern.
    Non-sensitive keys are returned unchanged.
    """
    for pattern in _SENSITIVE_KEY_PATTERNS:
        if pattern.match(str(key)):
            return _MASK
    return value


def mask_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a copy of the payload with sensitive values replaced by the mask.
    Nested dicts are recursively masked.
    """
    masked: Dict[str, Any] = {}
    for k, v in payload.items():
        if isinstance(v, dict):
            masked[k] = mask_payload(v)
        else:
            masked[k] = mask_sensitive_value(k, v)
    return masked


def mask_content(content: Optional[str]) -> Optional[str]:
    """
    Redact inline sensitive data patterns from free-text content.
    Catches patterns like 'password=abc123' or 'token: xyz'.
    """
    if not content:
        return content
    # Redact key=value and key: value patterns
    content = re.sub(
        r"(password|passwd|token|api_key|secret|cvv|card_number|ssn)"
        r"(\s*[:=]\s*)(\S+)",
        r"\1\2***MASKED***",
        content,
        flags=re.IGNORECASE,
    )
    return content


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Writes structured, masked audit entries to the database.

    An audit entry is written for every evaluated action regardless of
    whether it was executed. This ensures a complete chain of custody.
    """

    def log(
        self,
        db: Session,
        action: BrowserAction,
        decision: DecisionResult,
        execution_status: str = "not_executed",
    ) -> None:
        """
        Write a masked audit log entry.

        Parameters
        ----------
        db:               Active database session.
        action:           The proposed browser action (payload is masked here).
        decision:         The ContextGuard decision result.
        execution_status: 'executed', 'not_executed', 'blocked', 'pending_approval'.
        """
        masked_payload = mask_payload(action.payload)
        masked_content = mask_content(action.source.content)

        log_entry: Dict[str, Any] = {
            "action_id": action.action_id,
            "session_id": action.session_id,
            "agent_id": action.agent_id,
            "action_type": str(action.action_type),
            "target_url": action.target.url,
            "target_selector": action.target.selector,
            "source_type": str(action.source.source_type),
            "taint_status": decision.tainted,
            "risk_score": decision.risk_score,
            "risk_level": str(decision.risk_level),
            "decision": str(decision.decision),
            "reasons": decision.reasons,
            "matched_policies": decision.matched_policies,
            "execution_status": execution_status,
            "timestamp": datetime.now(timezone.utc),
            # Masked payload stored for forensic reference only
            "masked_payload": json.dumps(masked_payload),
        }

        store_audit_log(db, log_entry)

    def log_execution_result(
        self,
        db: Session,
        action_id: str,
        session_id: str,
        success: bool,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Append an execution outcome to the latest audit log for an action.
        Because SQLite doesn't support partial updates elegantly here, we
        insert a lightweight follow-up record.
        """
        outcome = "executed_success" if success else "executed_failure"
        log_entry: Dict[str, Any] = {
            "action_id": action_id,
            "session_id": session_id,
            "agent_id": "system",
            "action_type": "execution_result",
            "decision": "ALLOW",
            "risk_score": 0,
            "risk_level": "LOW",
            "reasons": [error_message] if error_message else [],
            "matched_policies": [],
            "execution_status": outcome,
            "timestamp": datetime.now(timezone.utc),
        }
        store_audit_log(db, log_entry)


# Module-level singleton
audit_logger = AuditLogger()
