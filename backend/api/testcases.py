"""
backend/api/testcases.py — Test Case Catalog Endpoints

Serves test case options for the Page 1 instruction picker.
Contains id, name, description, attack_type — NEVER returns injector configs to the frontend.
"""

from __future__ import annotations

from typing import Any, Dict, List
from fastapi import APIRouter

from backend.db.models import TestbedDAO

router = APIRouter(prefix="/api/testcases", tags=["Test Cases"])


@router.get("")
def list_test_cases_endpoint() -> List[Dict[str, Any]]:
    """Returns catalog of test cases (id, name, description, attack_type) for Instruction page picker."""
    return TestbedDAO.list_test_cases()
