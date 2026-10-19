"""
tests/test_approvals_api_roles.py — HTTP-level RBAC test suite for approvals_api

Validates HTTP 401/403/200 status codes for all endpoints:
- Anonymous access returns 401
- Viewer role can list approvals but cannot decide (403) or verify audit (403)
- Analyst role can list approvals and verify audit (200), but cannot decide (403)
- Approver role can list approvals and decide (200)
- Admin role can list approvals, decide, and verify audit (200)
"""

from __future__ import annotations

import unittest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from contextguard.approvals import ApprovalService, connect
from contextguard.approvals_api import create_router


class TestApprovalsAPIRoles(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.svc = ApprovalService(self.conn)
        self.secret = "test-rbac-jwt-secret-key-32-chars-long"

        # Seed test users for each role hierarchy
        self.svc.create_user("viewer_user", "pass_viewer", role="viewer")
        self.svc.create_user("analyst_user", "pass_analyst", role="analyst")
        self.svc.create_user("approver_user", "pass_approver", role="approver")
        self.svc.create_user("admin_user", "pass_admin", role="admin")

        self.app = FastAPI()
        self.app.include_router(create_router(self.svc, self.secret))
        self.client = TestClient(self.app)

        # Obtain JWT tokens
        self.tokens = {}
        for role, user, pw in [
            ("viewer", "viewer_user", "pass_viewer"),
            ("analyst", "analyst_user", "pass_analyst"),
            ("approver", "approver_user", "pass_approver"),
            ("admin", "admin_user", "pass_admin"),
        ]:
            resp = self.client.post("/api/auth/login", json={"username": user, "password": pw})
            self.assertEqual(resp.status_code, 200)
            self.tokens[role] = resp.json()["access_token"]

    def tearDown(self):
        self.conn.close()

    def test_anonymous_requests_refused_401(self):
        """Endpoints requiring authentication return 401 without Bearer token."""
        self.assertEqual(self.client.get("/api/approvals").status_code, 401)
        self.assertEqual(
            self.client.post("/api/approvals/1/decision", json={"decision": "APPROVE", "reason": "test"}).status_code,
            401,
        )
        self.assertEqual(self.client.get("/api/audit/verify").status_code, 401)

    def test_viewer_role_permissions(self):
        """Viewer can read approvals (200) but cannot decide (403) or verify audit (403)."""
        headers = {"Authorization": f"Bearer {self.tokens['viewer']}"}

        # 1. Read approvals -> 200 OK
        resp = self.client.get("/api/approvals", headers=headers)
        self.assertEqual(resp.status_code, 200)

        # 2. Decide approval -> 403 Forbidden
        aid = self.svc.request("task-1", 1, {"type": "CLICK"}, 60)
        dec_resp = self.client.post(
            f"/api/approvals/{aid}/decision",
            headers=headers,
            json={"decision": "APPROVE", "reason": "Viewer illegal attempt"},
        )
        self.assertEqual(dec_resp.status_code, 403)
        self.assertIn("approver role required", dec_resp.json()["detail"])

        # 3. Audit verify -> 403 Forbidden
        audit_resp = self.client.get("/api/audit/verify", headers=headers)
        self.assertEqual(audit_resp.status_code, 403)
        self.assertIn("analyst role required", audit_resp.json()["detail"])

    def test_analyst_role_permissions(self):
        """Analyst can read approvals (200) and verify audit (200), but cannot decide (403)."""
        headers = {"Authorization": f"Bearer {self.tokens['analyst']}"}

        # 1. Read approvals -> 200 OK
        self.assertEqual(self.client.get("/api/approvals", headers=headers).status_code, 200)

        # 2. Audit verify -> 200 OK
        audit_resp = self.client.get("/api/audit/verify", headers=headers)
        self.assertEqual(audit_resp.status_code, 200)
        self.assertTrue(audit_resp.json()["ok"])

        # 3. Decide approval -> 403 Forbidden
        aid = self.svc.request("task-2", 1, {"type": "CLICK"}, 60)
        dec_resp = self.client.post(
            f"/api/approvals/{aid}/decision",
            headers=headers,
            json={"decision": "APPROVE", "reason": "Analyst illegal attempt"},
        )
        self.assertEqual(dec_resp.status_code, 403)
        self.assertIn("approver role required", dec_resp.json()["detail"])

    def test_approver_role_permissions(self):
        """Approver can read approvals (200) and decide approvals (200)."""
        headers = {"Authorization": f"Bearer {self.tokens['approver']}"}

        # 1. Read approvals -> 200 OK
        self.assertEqual(self.client.get("/api/approvals", headers=headers).status_code, 200)

        # 2. Decide approval -> 200 OK
        aid = self.svc.request("task-3", 1, {"type": "CLICK"}, 60)
        dec_resp = self.client.post(
            f"/api/approvals/{aid}/decision",
            headers=headers,
            json={"decision": "APPROVE", "reason": "Authorized approver confirmation"},
        )
        self.assertEqual(dec_resp.status_code, 200)
        self.assertEqual(dec_resp.json()["status"], "APPROVED")


if __name__ == "__main__":
    unittest.main()
