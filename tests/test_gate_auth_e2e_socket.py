"""
tests/test_gate_auth_e2e_socket.py — End-to-end TestClient tests for Gate API auth.

NOTE: Marked @pytest.mark.e2e_socket because TestClient / AnyIO socketpair hangs
inside the AppContainer sandbox on Windows. Run this file in your host terminal.
"""
import os
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.api.v1_pipeline import clear_gates


pytestmark = pytest.mark.e2e_socket


@pytest.fixture(autouse=True)
def setup_teardown():
    clear_gates()
    yield
    clear_gates()


def test_e2e_unauthorized_endpoints_return_401():
    client = TestClient(app, raise_server_exceptions=False)

    # 1. /action/verify without token -> 401
    resp = client.post("/v1/action/verify", json={
        "task_id": "test-task",
        "action": {"type": "CLICK", "target": "#btn"},
        "dom_snapshot": "<html></html>",
    })
    assert resp.status_code == 401

    # 2. /task/{id}/status without token -> 401
    resp = client.get("/v1/task/test-task/status")
    assert resp.status_code == 401

    # 3. /task/{id}/audit without token -> 401
    resp = client.get("/v1/task/test-task/audit")
    assert resp.status_code == 401


def test_e2e_invalid_token_returns_403():
    client = TestClient(app, raise_server_exceptions=False)
    headers = {"Authorization": "Bearer invalid-token", "X-Task-Id": "test-task"}

    # 1. /action/verify with invalid token -> 403
    resp = client.post("/v1/action/verify", json={
        "task_id": "test-task",
        "action": {"type": "CLICK", "target": "#btn"},
        "dom_snapshot": "<html></html>",
    }, headers=headers)
    assert resp.status_code == 403

    # 2. /task/{id}/status with invalid token -> 403
    resp = client.get("/v1/task/test-task/status", headers=headers)
    assert resp.status_code == 403

    # 3. /task/{id}/audit with invalid token -> 403
    resp = client.get("/v1/task/test-task/audit", headers=headers)
    assert resp.status_code == 403


def test_e2e_authorized_flow_proceeds():
    client = TestClient(app, raise_server_exceptions=False)

    # 1. Init task and get real session token
    init_res = client.post("/v1/task/init", json={
        "instruction": "Book an economy flight from Chennai to Delhi for 1 passenger",
        "origin": "Chennai",
        "destination": "Delhi",
    })
    assert init_res.status_code == 201
    init_data = init_res.json()
    task_id = init_data["task_id"]
    token = init_data["session_token"]
    assert token is not None

    headers = {"Authorization": f"Bearer {token}", "X-Task-Id": task_id}

    # 2. Verify clean action -> 200
    verify_res = client.post("/v1/action/verify", json={
        "task_id": task_id,
        "action": {"type": "TYPE", "selector": "#from", "value": "Chennai"},
        "dom_snapshot": "Flight search form. Origin: Chennai, Destination: Delhi.",
        "page_url": "http://127.0.0.1:8000/",
    }, headers=headers)
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["decision"] == "ALLOW"
    assert v_data["allowed"] is True

    # 3. Status endpoint with token -> 200
    status_res = client.get(f"/v1/task/{task_id}/status", headers=headers)
    assert status_res.status_code == 200
    s_data = status_res.json()
    assert s_data["task_id"] == task_id
    assert s_data["total_checks"] == 1

    # 4. Audit endpoint with token -> 200
    audit_res = client.get(f"/v1/task/{task_id}/audit", headers=headers)
    assert audit_res.status_code == 200
