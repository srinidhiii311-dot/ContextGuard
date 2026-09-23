"""
backend/api/audit.py — Audit Records Endpoints

Serves paginated list of all recorded sessions for the Audit Ledger page.
"""

from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter, Query

from backend.db.models import ReportingDAO

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get("")
def get_audit_records_endpoint(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """Returns paginated sessions with timestamp, instruction, locked intent, final decision, and peak risk."""
    return ReportingDAO.get_audit_list(limit=limit, offset=offset)
