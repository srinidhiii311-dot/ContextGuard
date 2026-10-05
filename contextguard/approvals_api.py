"""FastAPI router for auth, approvals and audit verification.

Mount in backend/main.py:
    from contextguard.approvals import connect, ApprovalService, secret_from_env
    from contextguard.approvals_api import create_router
    svc = ApprovalService(connect(os.getenv("DB_PATH", "contextguard.db")))
    app.include_router(create_router(svc, secret_from_env()))

Roles: viewer (read approvals) < analyst (+audit verify) < approver (+decide) < admin.
NOTE: written against FastAPI's public API but not executed in the authoring sandbox
(FastAPI was unavailable there); run tests/kit/test_api.py in your venv.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from .approvals import (ApprovalService, StateError, has_role, issue_token, verify_token)


class LoginBody(BaseModel):
    username: str
    password: str


class DecisionBody(BaseModel):
    decision: str
    reason: str


def create_router(svc: ApprovalService, secret: str, token_ttl: int = 3600,
                  max_failures: int = 5, window_s: int = 300) -> APIRouter:
    router = APIRouter()
    bearer = HTTPBearer(auto_error=False)
    fails: Dict[str, Deque[float]] = defaultdict(deque)

    def current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> dict:
        claims = verify_token(creds.credentials, secret) if creds else None
        user = svc.get_user(claims["sub"]) if claims else None
        if not user:
            raise HTTPException(401, "invalid or missing token")
        return user                      # role is re-read from the DB, not trusted from the token

    def require_role(minimum: str):
        def dep(user: dict = Depends(current_user)) -> dict:
            if not has_role(user["role"], minimum):
                raise HTTPException(403, f"{minimum} role required")
            return user
        return dep

    @router.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "database": "ok"}

    @router.post("/api/auth/login")
    def login(body: LoginBody) -> dict:
        q, now = fails[body.username], time.time()
        while q and now - q[0] > window_s:
            q.popleft()
        if len(q) >= max_failures:
            raise HTTPException(429, "too many failed attempts")
        user = svc.authenticate(body.username, body.password)
        if not user:
            q.append(now)
            raise HTTPException(401, "invalid credentials")
        return {"access_token": issue_token(user["username"], user["role"], secret, token_ttl),
                "token_type": "bearer", "role": user["role"]}

    @router.get("/api/approvals")
    def list_approvals(status: Optional[str] = None, _: dict = Depends(require_role("viewer"))) -> list:
        return svc.list(status)

    @router.post("/api/approvals/{approval_id}/decision")
    def decide(approval_id: int, body: DecisionBody, user: dict = Depends(require_role("approver"))) -> dict:
        try:
            return svc.decide(approval_id, user["username"], body.decision, body.reason)
        except KeyError:
            raise HTTPException(404, "approval not found")
        except StateError as e:
            raise HTTPException(409, str(e))
        except ValueError as e:
            raise HTTPException(400, str(e))
        except PermissionError as e:
            raise HTTPException(403, str(e))

    @router.get("/api/audit/verify")
    def audit_verify(_: dict = Depends(require_role("analyst"))) -> dict:
        r = svc.audit.verify()
        return {"ok": r.ok, "checked": r.checked, "first_bad_id": r.first_bad_id, "reason": r.reason}

    return router
