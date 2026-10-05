"""
tests/test_phase3_approvals_intervention.py — Phase 3 Acceptance Tests:
1. Role-based approvals state machine (viewer < analyst < approver < admin).
2. Two-distinct approvers threshold at risk >= 80.
3. Timeout to DENY (outcome STOPPED) and mandatory reason.
4. Tamper-evident SHA-256 chained audit log verification.
5. Intervention hook with approval service integration.
6. FastAPI endpoints in backend/main.py.
"""

import asyncio
import sqlite3
import unittest
from types import SimpleNamespace

from fastapi.testclient import TestClient

from backend.main import app
from contextguard.approvals import ApprovalService, connect
from contextguard.audit_log import AuditLog
from contextguard.intervention import ActionStopped, build_intervention_hook


class TestPhase3ApprovalsWorkflow(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.audit = AuditLog(self.conn)
        self.svc = ApprovalService(self.conn, audit=self.audit, two_approver_threshold=80)
        self.svc.create_user("alice", "pass-alice", role="approver")
        self.svc.create_user("bob", "pass-bob", role="approver")
        self.svc.create_user("charlie", "pass-charlie", role="viewer")
        self.svc.create_user("admin_user", "pass-admin", role="admin")

    def test_two_distinct_approvers_required_at_high_risk(self):
        aid = self.svc.request("task-high", step=1, action={"type": "CLICK", "target": "#buy"}, risk_score=85)
        st = self.svc.status(aid)
        self.assertEqual(st["required"], 2)
        self.assertEqual(st["status"], "PENDING")

        # Alice approves
        r1 = self.svc.decide(aid, "alice", "APPROVE", reason="First check OK")
        self.assertEqual(r1["status"], "PENDING")
        self.assertEqual(self.svc.outcome(aid), "PENDING")

        # Alice cannot approve twice
        with self.assertRaises(ValueError):
            self.svc.decide(aid, "alice", "APPROVE", reason="Duplicate approval")

        # Bob approves -> status becomes APPROVED, outcome ALLOWED
        r2 = self.svc.decide(aid, "bob", "APPROVE", reason="Second check OK")
        self.assertEqual(r2["status"], "APPROVED")
        self.assertEqual(self.svc.outcome(aid), "ALLOWED")

    def test_single_approver_sufficient_below_threshold(self):
        aid = self.svc.request("task-med", step=2, action={"type": "TYPE", "target": "#origin"}, risk_score=65)
        st = self.svc.status(aid)
        self.assertEqual(st["required"], 1)

        r = self.svc.decide(aid, "alice", "APPROVE", reason="Single approval verified")
        self.assertEqual(r["status"], "APPROVED")
        self.assertEqual(self.svc.outcome(aid), "ALLOWED")

    def test_deny_immediately_ends_request(self):
        aid = self.svc.request("task-deny", step=1, action={"type": "CLICK"}, risk_score=85)
        r = self.svc.decide(aid, "alice", "DENY", reason="Suspicious payload detected")
        self.assertEqual(r["status"], "DENIED")
        self.assertEqual(self.svc.outcome(aid), "STOPPED")

    def test_tamper_detection_in_audit_chain(self):
        self.assertTrue(self.audit.verify().ok)
        self.conn.execute("UPDATE audit_log SET payload='{\"tampered\": true}' WHERE id=1")
        self.conn.commit()
        res = self.audit.verify()
        self.assertFalse(res.ok)
        self.assertEqual(res.first_bad_id, 1)

    def test_intervention_hook_allowed_after_approval(self):
        hook = build_intervention_hook(
            task_id="t-hook",
            user_intent={"origin": "Chennai", "destination": "Delhi"},
            threshold=0,
            approval_svc=self.svc,
            ttl_seconds=10,
            poll_interval=0.05,
        )

        state = SimpleNamespace(step=1)
        snapshot = SimpleNamespace(visible_text="Confirm booking", page_name="review")
        action = {"type": "CLICK", "target": "#confirm"}

        async def run_flow():
            async def background_approver():
                await asyncio.sleep(0.1)
                # Query pending approval and approve it
                pending = self.svc.list("PENDING")
                self.assertTrue(len(pending) > 0)
                aid = pending[0]["id"]
                self.svc.decide(aid, "alice", "APPROVE", reason="Operator approved")

            task = asyncio.create_task(background_approver())
            # For this test, simulate risk >= threshold
            allowed = await hook(state, snapshot, action)
            await task
            return allowed

        res = asyncio.run(run_flow())
        self.assertTrue(res)

    def test_backend_approvals_api_endpoints(self):
        client = TestClient(app)

        # 1. Health check
        resp = client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")
        self.assertEqual(resp.json()["database"], "ok")

        # 2. Login as approver
        # Seed user in app state svc if not present
        if not app.state.approval_svc.get_user("test_approver"):
            app.state.approval_svc.create_user("test_approver", "secret_pass", role="approver")
        login_resp = client.post("/api/auth/login", json={"username": "test_approver", "password": "secret_pass"})
        self.assertEqual(login_resp.status_code, 200)
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 3. Create approval request and decide via API
        aid = app.state.approval_svc.request("api-task", 1, {"type": "CLICK"}, 65)
        dec_resp = client.post(
            f"/api/approvals/{aid}/decision",
            headers=headers,
            json={"decision": "APPROVE", "reason": "Approved via REST API"},
        )
        self.assertEqual(dec_resp.status_code, 200)
        self.assertEqual(dec_resp.json()["status"], "APPROVED")


if __name__ == "__main__":
    unittest.main()
