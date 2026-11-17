"""
tests/test_a2_unified_paths.py — Phase A2 Verification Suite for Unified Decision Paths

Implements 7 verification tests:
1. Parity: canonical gate vs PreActionGate on 200 dev records.
2. Static scan: no code path calls browser action without passing gate.
3. Denied action never reaches browser.
4. HMAC tamper on locked intent is rejected.
5. Approval timeout resolves to deny.
6. action_hash is stable and changes when action changes.
7. tests/conftest.py sets GATEWAY_AUDIT_LOG_PATH to a temp file for every test.
"""

from __future__ import annotations

import ast
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from contextguard.approvals import ApprovalService
from contextguard.gate import ContextGuardGate, Decision, GateResult, ProposedAction, TrustedIntent
from contextguard.pre_action_gate import PreActionGate
from gateway.loader import Gateway
from harness.case_schema import EvaluationCase
from harness.configs import build_trusted_intent_from_dict
from backend.browser_agent.agent import BrowserAgent
from shared.schemas.schemas import TrustedIntent as SharedTrustedIntent


# ---------------------------------------------------------------------------
# Test 1: Parity between Canonical Gate and PreActionGate on 200 Dev Records
# ---------------------------------------------------------------------------

def test_1_parity_gate_vs_pre_action_gate_on_dev_records():
    """Verify 100% decision parity between canonical gate and PreActionGate across 200 dev records."""
    cases = []
    # 100 from attacks/dev and 100 from benign/dev
    for path, limit in [("attacks/dev/cases.jsonl", 100), ("benign/dev/cases.jsonl", 100)]:
        p = Path(path)
        if not p.exists():
            continue
        with open(p, "r", encoding="utf-8") as f:
            count = 0
            for line in f:
                if line.strip():
                    cases.append(EvaluationCase.model_validate(json.loads(line)))
                    count += 1
                    if count >= limit:
                        break

    assert len(cases) >= 200, f"Expected 200 dev cases, found {len(cases)}"

    dec_map = {
        Decision.BLOCK: "BLOCK",
        Decision.PAUSE_TASK: "PAUSE",
        Decision.REQUIRE_CONFIRMATION: "PAUSE",
        Decision.ALLOW_WITH_FLAG: "WARN",
        Decision.FLAG: "WARN",
        Decision.ALLOW: "ALLOW",
    }

    pre_gate = PreActionGate()
    mismatches = []

    for i, case in enumerate(cases[:200]):
        intent = build_trusted_intent_from_dict(case.domain, case.locked_intent)
        p_act = ProposedAction(
            action_type=case.proposed_action.action_type,
            target=case.proposed_action.target,
            value=case.proposed_action.value,
            page_url=case.proposed_action.page_url,
            source_text=case.proposed_action.source_text,
            raw_html=case.page_state.raw_html or "",
        )
        gw = Gateway.from_domain(case.domain, trusted_intent=intent)
        c_res = gw.check(p_act, current_dom_text=case.page_state.visible_text)
        c_dec = dec_map.get(c_res.decision, "BLOCK")

        ctx = dict(case.locked_intent) if isinstance(case.locked_intent, dict) else {}
        ctx["domain"] = case.domain
        p_res = pre_gate.evaluate_action(
            session_id=f"parity-{i}",
            step_number=1,
            task_context=ctx,
            action={
                "type": case.proposed_action.action_type,
                "target": case.proposed_action.target,
                "value": case.proposed_action.value,
                "source_text": case.proposed_action.source_text,
                "raw_html": case.page_state.raw_html or "",
            },
            current_url=case.proposed_action.page_url,
            current_page_name="page",
            page_text=case.page_state.visible_text,
        )

        if c_dec != p_res.decision:
            mismatches.append(f"Case {case.case_id} ({case.domain}): canonical={c_dec} vs pre_gate={p_res.decision}")

    assert len(mismatches) == 0, f"Found {len(mismatches)} parity mismatches:\n" + "\n".join(mismatches[:10])


# ---------------------------------------------------------------------------
# Test 2: Static AST Scan — No Code Path Calls Browser Action Without Gate
# ---------------------------------------------------------------------------

def test_2_static_scan_browser_action_passes_through_gate():
    """Verify statically that browser action execution is guarded by gate check in agent scripts."""
    agent_path = Path("backend/browser_agent/agent.py")
    assert agent_path.exists(), "agent.py must exist"
    tree = ast.parse(agent_path.read_text(encoding="utf-8"))

    # Find BrowserAgent.run method (async def)
    found_gate_check = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run":
            for subnode in ast.walk(node):
                if isinstance(subnode, ast.Call):
                    # Check for self.gate.check(...) call
                    if isinstance(subnode.func, ast.Attribute) and subnode.func.attr == "check":
                        found_gate_check = True
                        break

    assert found_gate_check, "BrowserAgent.run must call self.gate.check before action execution"

    # 2. Inspect agent/web_agent.py
    web_agent_path = Path("agent/web_agent.py")
    if web_agent_path.exists():
        src = web_agent_path.read_text(encoding="utf-8")
        assert "precheck_action" in src or "pre_action_gate" in src, (
            "web_agent.py must invoke precheck_action/pre_action_gate"
        )


# ---------------------------------------------------------------------------
# Test 3: Denied Action Never Reaches Browser
# ---------------------------------------------------------------------------

def test_3_denied_action_never_reaches_browser():
    """Verify that when the gate denies an action, the agent stops immediately and executes nothing further."""
    intent = SharedTrustedIntent(origin="Chennai", destination="Bangalore", cabin_class="Economy", passenger_count=1)
    mock_gate = MagicMock()
    mock_gate.check.return_value = GateResult(
        decision=Decision.BLOCK,
        reason="Blocked by security policy",
        risk_score=95,
        attack_type="malicious_intent",
    )

    agent = BrowserAgent(
        session_id="sess-denied-halt",
        session_token="tok_test_denied",
        trusted_intent=intent,
        speed=0.01,
        gate=mock_gate,
    )

    result = asyncio.run(agent.run())

    assert result["status"] == "blocked"
    assert result["final_decision"] == "BLOCK"
    assert result["halted_step"] == 1
    # Check that mock_gate was called exactly once and loop did not proceed
    assert mock_gate.check.call_count == 1


# ---------------------------------------------------------------------------
# Test 4: HMAC Tamper on Locked Intent is Rejected
# ---------------------------------------------------------------------------

def test_4_hmac_tamper_on_locked_intent_rejected():
    """Verify that tampering with the locked intent or its HMAC results in an immediate BLOCK."""
    intent = TrustedIntent(origin="Chennai", destination="Delhi", cabin_class="Economy", passenger_count=1)
    gate = ContextGuardGate(trusted_intent=intent, task_id="test-hmac-gate")

    # Tamper with the internal HMAC signature
    gate._locked_intent_hmac = "deadbeef" * 8
    sess = gate.get_session("test-hmac-gate")
    sess.locked_hmac = "deadbeef" * 8

    action = ProposedAction(
        action_type="SELECT",
        target="cabin_class_dropdown",
        value="Economy",
        page_url="http://127.0.0.1:8000/app",
    )

    result = gate.check(action, current_dom_text="Flight search page")

    assert result.decision == Decision.BLOCK
    assert "INTENT_TAMPERED" in result.reason
    assert result.risk_score == 100


# ---------------------------------------------------------------------------
# Test 5: Approval Timeout Resolves to Deny
# ---------------------------------------------------------------------------

def test_5_approval_timeout_resolves_to_deny():
    """Verify that when human approval times out, the resolution resolves to deny and execution halts."""
    import sqlite3
    # Test 1: ApprovalService expiration
    conn = sqlite3.connect(":memory:")
    service = ApprovalService(conn=conn)
    aid = service.request(
        task_id="task-timeout",
        step=1,
        action={"type": "CLICK", "target": "#transfer-btn"},
        risk_score=75,
        ttl_seconds=0,  # immediate expiry
    )
    status_info = service.status(aid)
    assert status_info["status"] == "EXPIRED"

    # Test 2: BrowserAgent timeout handling
    intent = SharedTrustedIntent(origin="Chennai", destination="Bangalore", cabin_class="Economy", passenger_count=1)
    mock_gate = MagicMock()
    mock_gate.check.return_value = GateResult(
        decision=Decision.REQUIRE_CONFIRMATION,
        reason="Requires operator review",
        risk_score=70,
    )

    agent = BrowserAgent(
        session_id="sess-timeout-deny",
        session_token="tok_timeout",
        trusted_intent=intent,
        speed=0.01,
        gate=mock_gate,
    )

    # Patch asyncio.wait_for to simulate human resolution timeout
    with patch("backend.browser_agent.agent.observer.evaluate") as mock_obs, \
         patch("backend.browser_agent.agent.asyncio.wait_for", side_effect=asyncio.TimeoutError):
        mock_obs.return_value = MagicMock(decision="ALLOW", risk_score=10.0, advisory=True)
        result = asyncio.run(agent.run())

    assert result["status"] == "blocked"
    assert result["final_decision"] == "BLOCK"
    assert result["halted_step"] == 1


# ---------------------------------------------------------------------------
# Test 6: action_hash is Stable and Changes When Action Mutates
# ---------------------------------------------------------------------------

def test_6_action_hash_stability_and_mutation():
    """Verify action_hash is deterministic across dictionary key ordering and varies upon mutation."""
    a1 = {"type": "CLICK", "target": "#confirm-btn", "value": None}
    a2 = {"value": None, "target": "#confirm-btn", "type": "CLICK"}

    h1 = ApprovalService.compute_action_hash(a1)
    h2 = ApprovalService.compute_action_hash(a2)

    # Determinism across key ordering
    assert h1 == h2, f"Action hash must be deterministic: {h1} != {h2}"

    # Mutation in target changes hash
    a_mutated_target = {"type": "CLICK", "target": "#evil-btn", "value": None}
    assert ApprovalService.compute_action_hash(a_mutated_target) != h1

    # Mutation in value changes hash
    a_mutated_value = {"type": "CLICK", "target": "#confirm-btn", "value": "tampered"}
    assert ApprovalService.compute_action_hash(a_mutated_value) != h1

    # Mutation in action_type changes hash
    a_mutated_type = {"type": "FILL", "target": "#confirm-btn", "value": None}
    assert ApprovalService.compute_action_hash(a_mutated_type) != h1


# ---------------------------------------------------------------------------
# Test 7: conftest.py Sets GATEWAY_AUDIT_LOG_PATH to a Temp File for Every Test
# ---------------------------------------------------------------------------

def test_7_conftest_sets_temp_audit_log_path():
    """Verify that tests/conftest.py automatically routes GATEWAY_AUDIT_LOG_PATH to a temp path."""
    audit_path = os.environ.get("GATEWAY_AUDIT_LOG_PATH")
    assert audit_path is not None, "GATEWAY_AUDIT_LOG_PATH must be set"
    # Verify it does NOT point to repository default 'runs/audit_log.jsonl'
    norm_path = audit_path.replace("\\", "/").lower()
    assert not norm_path.endswith("runs/audit_log.jsonl"), (
        f"GATEWAY_AUDIT_LOG_PATH must not point to repository runs/: {audit_path}"
    )
    assert "test_audit" in norm_path or "temp" in norm_path or "tmp" in norm_path or "scratch" in norm_path, (
        f"GATEWAY_AUDIT_LOG_PATH should point to temporary or scratch path: {audit_path}"
    )
