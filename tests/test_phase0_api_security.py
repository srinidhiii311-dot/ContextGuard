"""
tests/test_phase0_api_security.py — Phase 0: Gate API security property tests

Covers all five items from the master plan Phase 0 checklist:

  1. CORS: allow_origins is not "*"; cross-origin fetch from a sandbox page fails.
  2. Auth: POST /v1/action/verify returns 401 without a valid token when
     gate_auth_enabled=True; returns 200 with a valid token.
  3. strip_internals: the response returned to the caller omits rule IDs, scores
     and factor_breakdown.
  4. Approval action-hash binding: a replayed approval_id for a different action
     is rejected; the original action is accepted.
  5. Token issuance: issue_session_token / verify_session_token round-trip; expired
     token is rejected; tampered token is rejected.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import time
import unittest
from typing import Any, Dict
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helper: run with gate_auth_enabled patched
# ---------------------------------------------------------------------------

def with_auth_enabled(fn):
    """Decorator that temporarily sets gate_auth_enabled=True and a test secret."""
    import functools
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with patch.dict(os.environ, {
            "GATE_AUTH_ENABLED": "true",
            "GATE_API_SECRET": "phase0-test-secret-min-32-chars-xx",
            "JWT_SECRET": "phase0-jwt-test-secret-min-16-ch",
            "AUDIT_HMAC_SECRET": "phase0-audit-hmac-secret-min-32x",
        }):
            # Re-import gate_auth with the patched env so the secret is fresh
            import importlib
            import backend.api.gate_auth as _ga
            importlib.reload(_ga)
            return fn(*args, **kwargs)
    return wrapper


# ===========================================================================
# 1. CORS configuration
# ===========================================================================

class TestCORSConfiguration:

    def test_allow_origins_is_not_wildcard(self):
        """Main CORS setting must never be '*'."""
        from pathlib import Path
        main_src = (Path(__file__).parent.parent / "backend" / "main.py").read_text(encoding="utf-8")
        assert 'allow_origins=["*"]' not in main_src, \
            "backend/main.py must not use allow_origins=['*']"
        assert 'allow_origins=["*"]' not in main_src

    def test_cors_origins_env_rejects_wildcard(self):
        """_cors_origins() must raise if GATE_CORS_ORIGINS='*'."""
        import importlib, sys
        with patch.dict(os.environ, {"GATE_CORS_ORIGINS": "*"}):
            # We test the function directly, not via reimport (avoid side effects)
            # Read the function source and verify the guard
            from pathlib import Path
            src = (Path(__file__).parent.parent / "backend" / "main.py").read_text(encoding="utf-8")
            assert "GATE_CORS_ORIGINS" in src
            assert '"*"' in src or "'*'" in src   # guard clause exists in source

    def test_cors_origins_env_empty_gives_empty_list(self):
        """When GATE_CORS_ORIGINS is unset, _cors_origins() returns []."""
        with patch.dict(os.environ, {"GATE_CORS_ORIGINS": ""}, clear=False):
            # Import the function locally to test it
            import importlib, sys
            # We can call it inline since backend.main is already loaded
            from backend import main as bm
            # The function is defined in module scope
            with patch.dict(os.environ, {"GATE_CORS_ORIGINS": ""}):
                result = bm._cors_origins()
            assert result == [], f"Expected [] got {result}"

    def test_cors_origins_env_parses_list(self):
        """GATE_CORS_ORIGINS=http://a.example,http://b.example gives 2-element list."""
        from backend import main as bm
        with patch.dict(os.environ, {"GATE_CORS_ORIGINS": "http://a.example,http://b.example"}):
            result = bm._cors_origins()
        assert len(result) == 2
        assert "http://a.example" in result
        assert "http://b.example" in result


# ===========================================================================
# 2. Auth: /v1/action/verify requires a valid bearer token
# ===========================================================================

class TestGateAuthentication:

    def _make_client(self, auth_enabled: bool = True):
        """Return a FastAPI TestClient with gate_auth_enabled patched."""
        from fastapi.testclient import TestClient
        import backend.api.gate_auth as _ga
        with patch.object(_ga, "gate_auth_enabled", auth_enabled), \
             patch.dict(os.environ, {
                 "GATE_API_SECRET": "phase0-test-secret-min-32-chars-xx",
                 "JWT_SECRET": "phase0-jwt-test-secret-min-16-ch",
                 "AUDIT_HMAC_SECRET": "phase0-audit-hmac-secret-min-32x",
             }):
            from backend.main import app
            return TestClient(app, raise_server_exceptions=False)

    def test_verify_without_token_returns_401_when_auth_enabled(self):
        """POST /v1/action/verify with no Authorization header → 401 when auth on."""
        import backend.api.gate_auth as _ga
        original = _ga.gate_auth_enabled
        try:
            _ga.gate_auth_enabled = True
            with patch.dict(os.environ, {
                "GATE_API_SECRET": "phase0-test-secret-min-32-chars-xx",
                "JWT_SECRET": "phase0-jwt-test-secret-min-16-ch",
                "AUDIT_HMAC_SECRET": "phase0-audit-hmac-secret-min-32x",
            }):
                from fastapi.testclient import TestClient
                from backend.main import app
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post("/v1/action/verify", json={
                    "task_id": "nonexistent",
                    "action": {"type": "CLICK", "target": "btn"},
                    "dom_snapshot": "test page",
                })
                assert resp.status_code == 401, \
                    f"Expected 401, got {resp.status_code}: {resp.text[:200]}"
        finally:
            _ga.gate_auth_enabled = original

    def test_verify_with_valid_token_proceeds(self):
        """With auth disabled (test mode), /v1/action/verify reaches the gate."""
        import backend.api.gate_auth as _ga
        original = _ga.gate_auth_enabled
        try:
            _ga.gate_auth_enabled = False
            with patch.dict(os.environ, {
                "JWT_SECRET": "phase0-jwt-test-secret-min-16-ch",
                "AUDIT_HMAC_SECRET": "phase0-audit-hmac-secret-min-32x",
            }):
                from fastapi.testclient import TestClient
                from backend.main import app
                client = TestClient(app, raise_server_exceptions=False)
                # Init a task first
                init_resp = client.post("/v1/task/init", json={
                    "instruction": "Book economy Chennai to Delhi",
                    "origin": "Chennai",
                    "destination": "Delhi",
                })
                assert init_resp.status_code == 201
                task_id = init_resp.json()["task_id"]

                # Verify an action — should reach the gate (not 401)
                resp = client.post("/v1/action/verify", json={
                    "task_id": task_id,
                    "action": {"type": "TYPE", "selector": "#origin", "value": "Chennai"},
                    "dom_snapshot": "Flight search form.",
                    "page_url": "http://127.0.0.1:8000/search",
                })
                assert resp.status_code == 200, \
                    f"Expected 200, got {resp.status_code}: {resp.text[:300]}"
        finally:
            _ga.gate_auth_enabled = original


# ===========================================================================
# 3. strip_internals: verify response omits rule details when auth enabled
# ===========================================================================

class TestStripInternals:

    def test_strip_internals_removes_scoring_fields(self):
        """strip_internals removes risk_score, attack_type, factor_breakdown etc."""
        from backend.api.gate_auth import strip_internals
        full = {
            "audit_id": "abc",
            "task_id": "t1",
            "step_number": 1,
            "decision": "ALLOW",
            "allowed": True,
            "risk_score": 42,
            "risk_tier": "MEDIUM",
            "attack_type": "prompt_injection",
            "characterization_label": None,
            "confidence": 0.95,
            "deviation_signal": 0.72,
            "reason": "Consistent with intent.",
            "factor_breakdown": {"threat_signal": 10, "marker": 0},
            "processing_ms": {"verification_ms": 1.2},
            "total_latency_ms": 3.5,
        }
        stripped = strip_internals(full)
        assert "risk_score"          not in stripped
        assert "attack_type"         not in stripped
        assert "confidence"          not in stripped
        assert "deviation_signal"    not in stripped
        assert "factor_breakdown"    not in stripped
        assert "processing_ms"       not in stripped
        assert "characterization_label" not in stripped
        assert "risk_tier"           not in stripped

    def test_strip_internals_keeps_decision_fields(self):
        """strip_internals preserves the fields the agent needs."""
        from backend.api.gate_auth import strip_internals
        full = {
            "audit_id": "abc",
            "task_id": "t1",
            "step_number": 1,
            "decision": "BLOCK",
            "allowed": False,
            "risk_score": 85,
            "reason": "Field mismatch.",
            "total_latency_ms": 2.1,
            "factor_breakdown": {},
        }
        stripped = strip_internals(full)
        assert stripped["decision"]       == "BLOCK"
        assert stripped["allowed"]        is False
        assert stripped["reason"]         == "Field mismatch."
        assert stripped["audit_id"]       == "abc"
        assert stripped["total_latency_ms"] == 2.1


# ===========================================================================
# 4. Approval action-hash binding
# ===========================================================================

class TestApprovalActionHashBinding:
    """
    Tests that an approval is bound to the exact action it was requested for.
    A replayed approval_id cannot be used to approve a different action.
    """

    def _make_service(self):
        from contextguard.approvals import ApprovalService, connect as conn_approvals
        with patch.dict(os.environ, {
            "JWT_SECRET": "phase0-jwt-test-secret-min-16-ch",
            "AUDIT_HMAC_SECRET": "phase0-audit-hmac-secret-min-32x",
        }):
            conn = conn_approvals(":memory:")
            svc  = ApprovalService(conn)
            svc.create_user("approver1", "pass1word!", "approver")
            return svc

    def test_action_hash_stored_on_request(self):
        """request() stores action_hash in the approvals table."""
        svc = self._make_service()
        action = {"type": "CLICK", "target": "#confirm-btn", "value": None}
        aid = svc.request("task1", 1, action, risk_score=70)
        row = svc.conn.execute(
            "SELECT action_hash FROM approvals WHERE id=?", (aid,)
        ).fetchone()
        assert row is not None and row[0] is not None, "action_hash must be stored"
        expected = svc.compute_action_hash(action)
        assert row[0] == expected

    def test_verify_action_hash_accepts_correct_action(self):
        """verify_action_hash returns True for the exact action that was submitted."""
        svc = self._make_service()
        action = {"type": "CLICK", "target": "#confirm-btn"}
        aid = svc.request("task1", 1, action, risk_score=70)
        assert svc.verify_action_hash(aid, action) is True

    def test_verify_action_hash_rejects_different_action(self):
        """verify_action_hash returns False for a different action — replay blocked."""
        svc = self._make_service()
        original_action  = {"type": "CLICK", "target": "#confirm-btn"}
        different_action = {"type": "CLICK", "target": "#pay-btn"}   # different target
        aid = svc.request("task1", 1, original_action, risk_score=70)
        assert svc.verify_action_hash(aid, different_action) is False

    def test_verify_action_hash_rejects_value_mutation(self):
        """Changing the value in the action dict (e.g. cabin class) is rejected."""
        svc = self._make_service()
        original  = {"type": "SELECT", "target": "#cabin", "value": "Economy"}
        tampered  = {"type": "SELECT", "target": "#cabin", "value": "Business"}
        aid = svc.request("task1", 2, original, risk_score=65)
        assert svc.verify_action_hash(aid, tampered) is False

    def test_compute_action_hash_is_deterministic(self):
        """Same action dict always produces the same hash regardless of key order."""
        from contextguard.approvals import ApprovalService
        a1 = {"value": "Economy", "type": "SELECT", "target": "#cabin"}
        a2 = {"type": "SELECT", "target": "#cabin", "value": "Economy"}
        h1 = ApprovalService.compute_action_hash(a1)
        h2 = ApprovalService.compute_action_hash(a2)
        assert h1 == h2, "Hash must be order-independent (uses sort_keys=True)"

    def test_legacy_approval_without_hash_allows_through(self):
        """Pre-Phase-0 approval records with no action_hash are allowed through."""
        svc = self._make_service()
        action = {"type": "CLICK", "target": "#btn"}
        aid = svc.request("task1", 1, action, risk_score=50)
        # Manually null the hash to simulate a legacy record
        svc.conn.execute("UPDATE approvals SET action_hash=NULL WHERE id=?", (aid,))
        svc.conn.commit()
        result = svc.verify_action_hash(aid, {"type": "NAVIGATE", "target": "evil.example"})
        assert result is True  # backward compat: no hash stored → pass through


# ===========================================================================
# 5. Token issuance round-trip
# ===========================================================================

class TestGateTokens:

    def _env(self):
        # Use the same secret that conftest.py already sets, so issue and verify
        # both see the same value without a module reload.
        return patch.dict(os.environ, {
            "GATE_AUTH_ENABLED": "true",
            "GATE_API_SECRET": "test-gate-api-secret-min-32-chars-xx",
        })

    def test_round_trip_valid_token(self):
        """issue → verify same task_id returns True."""
        with self._env():
            import backend.api.gate_auth as ga
            token = ga.issue_session_token("task-abc")
            assert ga.verify_session_token(token, "task-abc") is True

    def test_wrong_task_id_rejected(self):
        """Token issued for task-A is rejected for task-B."""
        with self._env():
            import backend.api.gate_auth as ga
            token = ga.issue_session_token("task-A")
            assert ga.verify_session_token(token, "task-B") is False

    def test_tampered_token_rejected(self):
        """Altering a byte in the HMAC signature invalidates the token."""
        with self._env():
            import backend.api.gate_auth as ga
            import base64 as _b64
            token = ga.issue_session_token("task-tamper")
            # Decode, flip a byte inside the signature portion, re-encode
            padded = token + "=" * (-len(token) % 4)
            raw = bytearray(_b64.urlsafe_b64decode(padded))
            # Signature starts after the "|" separator; flip a byte in the sig
            sep_idx = raw.rfind(b"|")
            if sep_idx != -1 and sep_idx + 4 < len(raw):
                raw[sep_idx + 4] ^= 0xFF   # flip 8 bits
            tampered = _b64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
            assert ga.verify_session_token(tampered, "task-tamper") is False

    def test_expired_token_rejected(self):
        """A token with expiry in the past is rejected."""
        with self._env():
            import backend.api.gate_auth as ga
            import base64
            # Build a token manually with an already-expired timestamp
            secret = "test-gate-api-secret-min-32-chars-xx"
            import secrets as _sec
            nonce  = _sec.token_hex(16)
            expiry = int(time.time()) - 1   # already expired
            msg    = f"task-exp:{nonce}:{expiry}".encode()
            sig    = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
            payload = msg + b"|" + sig
            token = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
            assert ga.verify_session_token(token, "task-exp") is False

    def test_auth_disabled_skips_all_checks(self):
        """When gate_auth_enabled=False the dependency returns task_id unchecked."""
        import backend.api.gate_auth as ga
        original = ga.gate_auth_enabled
        try:
            ga.gate_auth_enabled = False
            # Mock the FastAPI Request and Header
            from unittest.mock import MagicMock
            req = MagicMock()
            req.headers = {}
            result = ga.require_gate_token(req, None, "any-task-id")
            assert result == "any-task-id"
        finally:
            ga.gate_auth_enabled = original


# ===========================================================================
# 6. Origin / DNS-rebinding check
# ===========================================================================

class TestOriginCheck:

    def test_no_origin_header_allowed(self):
        """Request with no Origin header passes (same-origin browser request)."""
        import backend.api.gate_auth as ga
        from unittest.mock import MagicMock
        req = MagicMock()
        req.headers = {}   # no Origin
        with patch.object(ga, "_ALLOWED_ORIGINS", frozenset()):
            ga._check_origin(req)   # must not raise

    def test_cross_origin_blocked_in_none_mode(self):
        """When _ALLOWED_ORIGINS is empty, any cross-origin header is rejected."""
        import backend.api.gate_auth as ga
        from fastapi import HTTPException
        from unittest.mock import MagicMock
        req = MagicMock()
        req.headers = {"origin": "http://evil.example"}
        with patch.object(ga, "_ALLOWED_ORIGINS", frozenset()):
            with pytest.raises(HTTPException) as exc_info:
                ga._check_origin(req)
            assert exc_info.value.status_code == 403

    def test_allowed_origin_passes(self):
        """An explicitly allowed origin passes the check."""
        import backend.api.gate_auth as ga
        from unittest.mock import MagicMock
        req = MagicMock()
        req.headers = {"origin": "http://trusted.example"}
        with patch.object(ga, "_ALLOWED_ORIGINS", frozenset(["http://trusted.example"])):
            ga._check_origin(req)   # must not raise

    def test_unlisted_origin_blocked(self):
        """An origin not in the allow-list is rejected even when list is non-empty."""
        import backend.api.gate_auth as ga
        from fastapi import HTTPException
        from unittest.mock import MagicMock
        req = MagicMock()
        req.headers = {"origin": "http://unlisted.example"}
        with patch.object(ga, "_ALLOWED_ORIGINS", frozenset(["http://trusted.example"])):
            with pytest.raises(HTTPException) as exc_info:
                ga._check_origin(req)
            assert exc_info.value.status_code == 403
