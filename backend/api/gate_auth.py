"""
backend/api/gate_auth.py  –  Phase 0: Gate API authentication

Provides:
  - Per-session bearer token issuance (issued by /v1/task/init, held only by the
    browser wrapper process, never returned to the agent itself).
  - FastAPI Depends() guard for every /v1/* endpoint.
  - Allowed-origin check (DNS-rebinding mitigation).
  - decision-only response enforcement (strip internals at the boundary).

Design
------
Tokens are HMAC-SHA256(key=GATE_API_SECRET, msg=task_id+":"+nonce+":"+expiry_epoch),
base64url-encoded, with a configurable TTL (default 1 hour).  The secret comes from
the environment variable GATE_API_SECRET (minimum 32 characters).  If the variable is
absent, the module raises at import time so the application refuses to start insecurely.

Allowed origins are set via GATE_ALLOWED_ORIGINS (comma-separated, default "none").
"none" means no cross-origin requests are accepted at all — the gate only talks to the
browser wrapper on the same host.  "*" is explicitly forbidden.

Flag gate_auth_enabled (default True).  Setting it to False restores the old open
behaviour for local development without touching frozen configurations.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Optional

from fastapi import Header, HTTPException, Request, status

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Auth is mandatory on every route (GATE_AUTH_ENABLED bypass removed).
gate_auth_enabled: bool = True

_SECRET_MIN_LEN = 32
_TOKEN_TTL_SEC  = int(os.getenv("GATE_TOKEN_TTL", "3600"))

# Allowed origins — "none" blocks all cross-origin; "*" is refused.
_raw_origins = os.getenv("GATE_ALLOWED_ORIGINS", "none").strip()
if _raw_origins == "*":
    raise RuntimeError(
        "GATE_ALLOWED_ORIGINS='*' is not permitted. "
        "Set it to 'none' (same-origin only) or a comma-separated list of trusted origins."
    )
_ALLOWED_ORIGINS: frozenset[str] = (
    frozenset()
    if _raw_origins.lower() == "none"
    else frozenset(o.strip() for o in _raw_origins.split(",") if o.strip())
)


def _get_secret() -> str:
    """Return GATE_API_SECRET from the environment. Raises if absent or too short."""
    secret = os.getenv("GATE_API_SECRET", "")
    if len(secret) < _SECRET_MIN_LEN:
        raise RuntimeError(
            f"GATE_API_SECRET must be at least {_SECRET_MIN_LEN} characters. "
            "Set it in the environment before starting the server."
        )
    return secret


# ---------------------------------------------------------------------------
# Token issuance
# ---------------------------------------------------------------------------

def issue_session_token(task_id: str) -> str:
    """
    Issue a per-session bearer token for the given task_id.
    Returns a compact base64url string.  The token is held only by the
    browser-wrapper process; it is never forwarded to the agent.
    """
    secret  = _get_secret()
    nonce   = secrets.token_hex(16)
    expiry  = int(time.time()) + _TOKEN_TTL_SEC
    msg     = f"{task_id}:{nonce}:{expiry}"
    sig_hex = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
    payload = f"{msg}|{sig_hex}".encode()
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def verify_session_token(token: str, task_id: str) -> bool:
    """
    Verify that `token` was issued for `task_id` and has not expired.
    Returns True on success, False on any failure (constant-time comparison).
    """
    secret = _get_secret()
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded)
        msg_part, sig_hex = raw.decode("utf-8").rsplit("|", 1)
        parts = msg_part.rsplit(":", 2)
        if len(parts) != 3:
            return False
        tid, _nonce, expiry_str = parts
        if tid != task_id:
            return False
        if int(expiry_str) < int(time.time()):
            return False
        expected_hex = hmac.new(secret.encode(), msg_part.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig_hex, expected_hex)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Origin check (DNS-rebinding mitigation)
# ---------------------------------------------------------------------------

def _check_origin(request: Request) -> None:
    """
    Block requests whose Origin or Referer header points outside the allowed set.
    Same-origin requests (no Origin header) are always permitted.
    """
    origin = request.headers.get("origin") or request.headers.get("referer", "")
    if not origin:
        return   # Same-origin or non-browser — allow.

    # Normalise: strip path from referer
    from urllib.parse import urlparse
    parsed = urlparse(origin)
    request_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else origin

    if _ALLOWED_ORIGINS and request_origin in _ALLOWED_ORIGINS:
        return
    if not _ALLOWED_ORIGINS:
        # "none" mode: any cross-origin header is rejected
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-origin requests are not permitted.",
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Origin '{request_origin}' is not in the allowed origins list.",
    )


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

def require_gate_token(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_task_id: Optional[str] = Header(None, alias="X-Task-Id"),
) -> str:
    """
    FastAPI Depends() guard for /v1/* endpoints. Mandatory on all protected routes.

    Validates:
      1. Origin/Referer header (DNS-rebinding check).
      2. Authorization: Bearer <token> header present and non-empty (401 on failure).
      3. Token is valid, unexpired, and matches task_id (403 on failure).

    Returns the validated task_id on success.
    Raises HTTP 401 on missing/empty bearer token, HTTP 403 on invalid/expired/mismatched token.
    """
    _check_origin(request)

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization: Bearer <token> header is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token cannot be empty.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    path_task_id = None
    if hasattr(request, "path_params") and request.path_params:
        path_task_id = request.path_params.get("task_id")

    if x_task_id and path_task_id and x_task_id != path_task_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="X-Task-Id header does not match path parameter task_id.",
        )

    task_id = x_task_id or path_task_id or ""
    if not task_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Task ID is required (via X-Task-Id header or URL path).",
        )

    if not verify_session_token(token, task_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid, expired, or task-mismatched session token.",
        )

    return task_id


# ---------------------------------------------------------------------------
# Decision-only response filter
# ---------------------------------------------------------------------------

def strip_internals(response_dict: dict) -> dict:
    """
    Remove internal scoring details from the verify response before returning
    it to the caller.  The agent only needs the decision and allowed flag;
    exposing rule IDs and scores lets an adversary tune evasion.

    Returns a copy with these keys removed:
      risk_score, risk_tier, attack_type, characterization_label,
      confidence, deviation_signal, factor_breakdown, processing_ms
    """
    _internal_keys = {
        "risk_score", "risk_tier", "attack_type", "characterization_label",
        "confidence", "deviation_signal", "factor_breakdown", "processing_ms",
    }
    return {k: v for k, v in response_dict.items() if k not in _internal_keys}
