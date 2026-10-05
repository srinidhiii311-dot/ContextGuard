import sqlite3, unittest
from contextguard.audit_log import AuditLog
from contextguard.approvals import (ApprovalService, StateError, connect, issue_token, verify_token,
                                    hash_password, verify_password, has_role)


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


def make():
    clk = Clock(); conn = connect(":memory:"); svc = ApprovalService(conn, clock=clk)
    for u, r in [("vera", "viewer"), ("ann", "analyst"), ("alice", "approver"), ("bob", "approver"), ("root", "admin")]:
        svc.create_user(u, "pw-" + u, r)
    return svc, clk, conn


class T(unittest.TestCase):
    def test_audit_chain_detects_tampering(self):
        conn = sqlite3.connect(":memory:"); a = AuditLog(conn)
        for i in range(5): a.append("e", "u", {"i": i})
        self.assertTrue(a.verify().ok)
        conn.execute("UPDATE audit_log SET payload='{\"i\": 99}' WHERE id=3"); conn.commit()
        r = a.verify(); self.assertFalse(r.ok); self.assertEqual(r.first_bad_id, 3)
        conn.execute("UPDATE audit_log SET payload='{\"i\": 2}' WHERE id=3"); conn.commit()
        self.assertTrue(a.verify().ok)
        conn.execute("DELETE FROM audit_log WHERE id=2"); conn.commit()
        self.assertFalse(a.verify().ok)

    def test_viewer_and_analyst_cannot_decide(self):
        svc, _, _ = make(); aid = svc.request("t1", 3, {"type": "NAVIGATE"}, 65)
        for u in ("vera", "ann", "ghost"):
            with self.assertRaises(PermissionError):
                svc.decide(aid, u, "APPROVE", "ok")
        self.assertEqual(svc.status(aid)["status"], "PENDING")

    def test_reason_mandatory_and_single_decision_per_user(self):
        svc, _, _ = make(); aid = svc.request("t1", 3, {}, 65)
        with self.assertRaises(ValueError): svc.decide(aid, "alice", "APPROVE", "   ")
        self.assertEqual(svc.decide(aid, "alice", "APPROVE", "checked")["status"], "APPROVED")
        with self.assertRaises(StateError): svc.decide(aid, "bob", "APPROVE", "late")

    def test_timeout_defaults_to_deny(self):
        svc, clk, _ = make(); aid = svc.request("t1", 3, {}, 65, ttl_seconds=60)
        clk.t += 61
        self.assertEqual(svc.status(aid)["status"], "EXPIRED"); self.assertEqual(svc.outcome(aid), "STOPPED")
        with self.assertRaises(StateError): svc.decide(aid, "alice", "APPROVE", "too late")

    def test_two_distinct_approvers_at_high_risk(self):
        svc, _, _ = make(); aid = svc.request("t1", 3, {}, 85)
        self.assertEqual(svc.status(aid)["required"], 2)
        self.assertEqual(svc.decide(aid, "alice", "APPROVE", "r1")["status"], "PENDING")
        with self.assertRaises(ValueError): svc.decide(aid, "alice", "APPROVE", "again")   # same user twice
        self.assertEqual(svc.decide(aid, "bob", "APPROVE", "r2")["status"], "APPROVED")
        self.assertEqual(svc.outcome(aid), "ALLOWED")

    def test_deny_ends_request_and_audit_intact(self):
        svc, _, _ = make(); aid = svc.request("t1", 3, {}, 85)
        self.assertEqual(svc.decide(aid, "bob", "DENY", "suspicious")["status"], "DENIED")
        self.assertEqual(svc.outcome(aid), "STOPPED")
        v = svc.audit.verify(); self.assertTrue(v.ok); self.assertGreater(v.checked, 5)

    def test_tokens_and_passwords(self):
        tok = issue_token("alice", "approver", "s" * 20, ttl=10, now=1000)
        self.assertEqual(verify_token(tok, "s" * 20, now=1005)["sub"], "alice")
        self.assertIsNone(verify_token(tok, "s" * 20, now=1011))          # expired
        self.assertIsNone(verify_token(tok, "x" * 20, now=1005))          # wrong secret
        h, b, s = tok.split("."); self.assertIsNone(verify_token(f"{h}.{b}x.{s}", "s" * 20, now=1005))
        stored = hash_password("pw"); self.assertTrue(verify_password("pw", stored)); self.assertFalse(verify_password("no", stored))
        self.assertNotIn("pw", stored)
        self.assertTrue(has_role("admin", "approver")); self.assertFalse(has_role("analyst", "approver"))

    def test_authenticate(self):
        svc, _, _ = make()
        self.assertEqual(svc.authenticate("alice", "pw-alice")["role"], "approver")
        self.assertIsNone(svc.authenticate("alice", "wrong")); self.assertIsNone(svc.authenticate("nobody", "x"))


if __name__ == "__main__":
    unittest.main()
