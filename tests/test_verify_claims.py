"""
tests/test_verify_claims.py — Claims Ledger & Document Consistency Tests (Gap 3)

Validates that:
1. scripts/verify_claims.py passes cleanly on current repository state.
2. Changing one number in the paper or document causes the script to fail (negative test).
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from scripts.verify_claims import (
    audit_claims,
    load_claims,
    verify_claims_against_csv,
    verify_documents_against_ledger,
)

ROOT = Path(__file__).resolve().parent.parent


def test_verify_claims_passes_on_current_state():
    errors = audit_claims()
    assert not errors, f"Claims verification failed with errors: {errors}"


def test_verify_claims_negative_test_fails_on_tampered_paper():
    """Negative test (Gap 3): Proves that changing one number in the paper causes verification to fail."""
    claims = load_claims()
    assert len(claims) > 0

    paper_path = ROOT / "ContextGuard_Research_Paper.md"
    original_text = paper_path.read_text(encoding="utf-8")

    # Tamper with 91.7% -> 99.9% in memory
    tampered_text = original_text.replace("91.7%", "99.9%")
    assert "99.9%" in tampered_text

    with patch.object(Path, "read_text", return_value=tampered_text):
        errors = verify_documents_against_ledger(claims)
        assert len(errors) > 0, "Expected verify_documents_against_ledger to FAIL when paper number is tampered!"
        assert any("Document Mismatch" in err for err in errors), f"Expected Document Mismatch error, got: {errors}"
