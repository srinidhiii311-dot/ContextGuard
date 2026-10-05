import json, os, tempfile, unittest
from pathlib import Path
from scripts import run_final_eval, run_live_agent_eval

ITEMS = [{"id": "A1", "label": "attack", "category": "field", "text": "field override"},
         {"id": "A2", "label": "attack", "category": "inject", "text": "inject"},
         {"id": "A3", "label": "attack", "category": "odd", "text": "odd"},
         {"id": "B1", "label": "benign", "text": "fine"}]


class T(unittest.TestCase):
    def test_final_eval_guard_and_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d); (d / "data").mkdir()
            (d / "data" / "t.json").write_text(json.dumps({"items": ITEMS}))
            base = ["--adapter", "tests.kit.fake_adapter:evaluate", "--data", str(d / "data"),
                    "--configs", "A_rules_only,D_full", "--out", str(d / "out" / "r.csv")]
            self.assertEqual(run_final_eval.main(base), 2)                    # no --final
            self.assertFalse((d / "out").exists())
            self.assertEqual(run_final_eval.main(base + ["--final"]), 0)
            summ = json.loads((d / "out" / "final_test_summary.json").read_text())
            self.assertEqual(summ["summary"]["D_full"]["attacks_intercepted"], 2)
            self.assertEqual(summ["summary"]["D_full"]["attacks_flagged_only"], 1)
            self.assertEqual(summ["paired"]["A_rules_only->D_full"]["gained"], 1)
            self.assertEqual(run_final_eval.main(base + ["--final"]), 3)       # already ran
            self.assertEqual(run_final_eval.main(base + ["--final", "--allow-rerun"]), 0)

    def test_bad_dataset_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "t.json").write_text(json.dumps([{"id": "x", "label": "maybe"}]))
            with self.assertRaises(ValueError): run_final_eval.load_items(Path(d))
            (Path(d) / "t.json").write_text(json.dumps([{"id": "x", "label": "attack"}, {"id": "x", "label": "benign"}]))
            with self.assertRaises(ValueError): run_final_eval.load_items(Path(d))

    def test_live_agent_dry_run(self):
        with tempfile.TemporaryDirectory() as d:
            out = str(Path(d) / "live.csv")
            rc = run_live_agent_eval.main(["--adapter", "tests.kit.fake_adapter:run_episode", "--scenarios",
                                           "s1,s2", "--runs", "3", "--out", out, "--dry-run"])
            self.assertEqual(rc, 0); self.assertEqual(len(Path(out).read_text().strip().splitlines()), 1 + 2 * 2 * 3)

    def test_api_if_fastapi_available(self):
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
        except Exception:
            self.skipTest("fastapi/httpx not installed")
        from contextguard.approvals import ApprovalService, connect
        from contextguard.approvals_api import create_router
        svc = ApprovalService(connect(":memory:")); svc.create_user("v", "pw", "viewer"); svc.create_user("a", "pw", "approver")
        app = FastAPI(); app.include_router(create_router(svc, "s" * 20)); c = TestClient(app)
        aid = svc.request("t", 1, {}, 70)
        tv = c.post("/api/auth/login", json={"username": "v", "password": "pw"}).json()["access_token"]
        ta = c.post("/api/auth/login", json={"username": "a", "password": "pw"}).json()["access_token"]
        body = {"decision": "APPROVE", "reason": "ok"}
        self.assertEqual(c.post(f"/api/approvals/{aid}/decision", json=body).status_code, 401)
        self.assertEqual(c.post(f"/api/approvals/{aid}/decision", json=body, headers={"Authorization": f"Bearer {tv}"}).status_code, 403)
        self.assertEqual(c.post(f"/api/approvals/{aid}/decision", json=body, headers={"Authorization": f"Bearer {ta}"}).status_code, 200)
        self.assertEqual(c.get("/api/health").json()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
