"""
tests/test_gate_auth_hardening.py — Tests for Gate API Auth Hardening (Item 1).

Requirements:
- Missing Authorization header or empty bearer token -> 401.
- Invalid, tampered, expired, or task-mismatched token -> 403.
- Routes /action/verify, /task/{task_id}/status, and /task/{task_id}/audit must enforce require_gate_token.
- Mandatory auth: GATE_AUTH_ENABLED bypass removed entirely.
"""

import base64
import hashlib
import hmac
import os
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

import backend.api.gate_auth as ga
from backend.api.v1_pipeline import router


TEST_SECRET = "test-gate-api-secret-min-32-chars-hardening-xx"


@pytest.fixture(autouse=True)
def auth_env():
    """Ensure GATE_API_SECRET is set for testing."""
    with patch.dict(os.environ, {"GATE_API_SECRET": TEST_SECRET}):
        yield


def _make_dummy_request(headers: dict = None, path_params: dict = None):
    req = MagicMock()
    req.headers = headers or {}
    req.path_params = path_params or {}
    return req


# ---------------------------------------------------------------------------
# 1. Missing Authorization header or empty bearer token -> 401
# ---------------------------------------------------------------------------

def test_missing_authorization_header_returns_401():
    req = _make_dummy_request()
    with pytest.raises(HTTPException) as exc_info:
        ga.require_gate_token(req, authorization=None, x_task_id="task-1")
    assert exc_info.value.status_code == 401
    assert "Bearer" in exc_info.value.headers.get("WWW-Authenticate", "")


def test_empty_bearer_token_returns_401():
    req = _make_dummy_request()
    for empty_auth in ["Bearer ", "Bearer", "Bearer   "]:
        with pytest.raises(HTTPException) as exc_info:
            ga.require_gate_token(req, authorization=empty_auth, x_task_id="task-1")
        assert exc_info.value.status_code == 401
        assert "Bearer" in exc_info.value.headers.get("WWW-Authenticate", "")


# ---------------------------------------------------------------------------
# 2. Invalid, tampered, expired, or task-mismatched token -> 403
# ---------------------------------------------------------------------------

def test_invalid_token_returns_403():
    req = _make_dummy_request()
    with pytest.raises(HTTPException) as exc_info:
        ga.require_gate_token(req, authorization="Bearer totally-invalid-token", x_task_id="task-1")
    assert exc_info.value.status_code == 403


def test_tampered_token_returns_403():
    req = _make_dummy_request()
    token = ga.issue_session_token("task-1")
    padded = token + "=" * (-len(token) % 4)
    raw = bytearray(base64.urlsafe_b64decode(padded))
    sep_idx = raw.rfind(b"|")
    if sep_idx != -1 and sep_idx + 4 < len(raw):
        raw[sep_idx + 4] ^= 0xFF
    tampered = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()

    with pytest.raises(HTTPException) as exc_info:
        ga.require_gate_token(req, authorization=f"Bearer {tampered}", x_task_id="task-1")
    assert exc_info.value.status_code == 403


def test_expired_token_returns_403():
    req = _make_dummy_request()
    import secrets as _sec
    nonce = _sec.token_hex(16)
    expiry = int(time.time()) - 100
    msg = f"task-1:{nonce}:{expiry}"
    sig = hmac.new(TEST_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    payload = f"{msg}|{sig}".encode()
    expired_token = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()

    with pytest.raises(HTTPException) as exc_info:
        ga.require_gate_token(req, authorization=f"Bearer {expired_token}", x_task_id="task-1")
    assert exc_info.value.status_code == 403


def test_task_mismatched_token_returns_403():
    req = _make_dummy_request()
    token_for_task_a = ga.issue_session_token("task-A")
    with pytest.raises(HTTPException) as exc_info:
        ga.require_gate_token(req, authorization=f"Bearer {token_for_task_a}", x_task_id="task-B")
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# 3. Route dependency coverage: /action/verify, /task/{task_id}/status, /task/{task_id}/audit
# ---------------------------------------------------------------------------

def test_routes_have_require_gate_token_dependency():
    """Verify all three routes declare require_gate_token as a dependency."""
    routes_to_check = [
        "/action/verify",
        "/task/{task_id}/status",
        "/task/{task_id}/audit",
    ]

    for path in routes_to_check:
        matching = [
            r for r in router.routes
            if getattr(r, "path", None) == f"/v1{path}" or getattr(r, "path", None) == path
        ]
        assert matching, f"Route {path} not found in router"
        route = matching[0]

        # Check in route dependencies or endpoint signature
        all_deps = [d.call for d in route.dependant.dependencies]
        assert ga.require_gate_token in all_deps, (
            f"Route {path} must declare Depends(require_gate_token)"
        )


def test_path_param_task_id_extracted_and_verified_for_status_and_audit():
    """
    For /task/{task_id}/status and /task/{task_id}/audit, the token can be
    verified against request.path_params['task_id'].
    """
    token_status = ga.issue_session_token("task-status-123")
    req = _make_dummy_request(path_params={"task_id": "task-status-123"})
    result = ga.require_gate_token(req, authorization=f"Bearer {token_status}", x_task_id=None)
    assert result == "task-status-123"

    # Mismatch with path_param must return 403
    with pytest.raises(HTTPException) as exc_info:
        ga.require_gate_token(req, authorization=f"Bearer {token_status}", x_task_id="different-task")
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# 4. Mandatory auth: GATE_AUTH_ENABLED bypass removed entirely
# ---------------------------------------------------------------------------

def test_gate_auth_enabled_env_cannot_bypass_auth():
    """Setting GATE_AUTH_ENABLED=false must NOT bypass authentication."""
    with patch.dict(os.environ, {"GATE_AUTH_ENABLED": "false"}):
        req = _make_dummy_request()
        with pytest.raises(HTTPException) as exc_info:
            ga.require_gate_token(req, authorization=None, x_task_id="task-1")
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# 5. strip_internals round-trip on ActionVerifyResponse (no TestClient)
# ---------------------------------------------------------------------------

def test_action_verify_response_strip_internals_round_trip():
    """
    Build a full ActionVerifyResponse, run model_dump() through strip_internals,
    construct ActionVerifyResponse from the result, and assert it succeeds and
    that none of the four internal fields appear in model_dump(exclude_none=True).
    """
    from backend.api.gate_auth import strip_internals
    from backend.api.v1_pipeline import ActionVerifyResponse

    full_resp = ActionVerifyResponse(
        audit_id="audit-123",
        task_id="task-456",
        step_number=1,
        decision="ALLOW",
        allowed=True,
        risk_score=15,
        risk_tier="LOW",
        attack_type=None,
        characterization_label=None,
        confidence=0.95,
        deviation_signal=0.1,
        reason="Action is consistent",
        factor_breakdown={"threat_signal": 0.0},
        processing_ms={"total": 5.0},
        total_latency_ms=12.5,
    )

    stripped = strip_internals(full_resp.model_dump())
    # Constructing ActionVerifyResponse from stripped dict must succeed without ValidationError
    stripped_resp = ActionVerifyResponse(**stripped)
    assert stripped_resp.audit_id == "audit-123"
    assert stripped_resp.decision == "ALLOW"
    assert stripped_resp.allowed is True

    dumped = stripped_resp.model_dump(exclude_none=True)
    for field in ("risk_score", "risk_tier", "factor_breakdown", "processing_ms"):
        assert field not in dumped, f"Internal field '{field}' must not appear in model_dump(exclude_none=True)"


# ---------------------------------------------------------------------------
# 6. High-volume token reliability & tampering regression (no TestClient)
# ---------------------------------------------------------------------------

def test_issue_and_verify_5000_tokens_zero_failures():
    """
    Issue and verify 5000 tokens for varied task IDs and assert 0 failures.
    Catches intermittent signature delimiter collision bugs.
    """
    import uuid

    task_id_patterns = [
        "simple-task",
        "task_with_underscores_123",
        "flight-search-chennai-to-delhi-001",
        "ecommerce.order.checkout.999",
        "banking:transfer-internal",
        "email_inbox_clean_sweep",
        "healthcare_patient_record_lookup",
        "t",
        "very-long-task-id-" + "x" * 64,
    ]

    failures = []
    for i in range(5000):
        base_tid = task_id_patterns[i % len(task_id_patterns)]
        task_id = f"{base_tid}-{i}-{uuid.uuid4().hex[:8]}"
        token = ga.issue_session_token(task_id)
        if not ga.verify_session_token(token, task_id):
            failures.append((i, task_id, token))

    assert len(failures) == 0, f"Expected 0 verification failures across 5000 tokens, got {len(failures)}"


def test_tampered_signature_fails_verification():
    """Verify that any tampering with the signature portion causes verify_session_token to fail."""
    task_id = "test-tamper-target"
    token = ga.issue_session_token(task_id)

    # Decode payload
    padded = token + "=" * (-len(token) % 4)
    raw = bytearray(base64.urlsafe_b64decode(padded))

    # Signature starts after the "|" delimiter
    sep_idx = raw.rfind(b"|")
    assert sep_idx != -1

    # Tamper with the first character of the signature
    raw_tampered = bytearray(raw)
    raw_tampered[sep_idx + 1] = ord("0") if raw_tampered[sep_idx + 1] != ord("0") else ord("1")
    tampered_token = base64.urlsafe_b64encode(bytes(raw_tampered)).rstrip(b"=").decode()
    assert ga.verify_session_token(tampered_token, task_id) is False

    # Tamper with the last character of the signature
    raw_tampered_last = bytearray(raw)
    raw_tampered_last[-1] = ord("a") if raw_tampered_last[-1] != ord("a") else ord("b")
    tampered_token_last = base64.urlsafe_b64encode(bytes(raw_tampered_last)).rstrip(b"=").decode()
    assert ga.verify_session_token(tampered_token_last, task_id) is False

    # Truncate signature
    truncated_raw = raw[:sep_idx + 10]
    truncated_token = base64.urlsafe_b64encode(bytes(truncated_raw)).rstrip(b"=").decode()
    assert ga.verify_session_token(truncated_token, task_id) is False
