"""
tests/test_confirmation_handshake.py — Verification of Asynchronous Human Confirmation (FR20) & Pause (FR19)

Tests:
1. Agent loop suspends on REQUIRE_CONFIRMATION and executes when operator approves.
2. Agent loop suspends on REQUIRE_CONFIRMATION and aborts/pauses when operator rejects.
3. Agent loop times out safely if operator fails to respond within confirmation_timeout.
4. Agent loop immediately halts when PAUSE_TASK is enforced.
5. Pluggable decision_engine callable drives the agent loop cleanly.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agent.agent_controller import (
    AgentController,
    AgentState,
    resolve_confirmation,
    get_pending_confirmation,
)
from agent.browser_controller import DOMSnapshot
from contextguard.gate import ContextGuardGate, Decision, GateResult, ProposedAction, TrustedIntent
from contextguard.models import PolicyDecision, RiskTier


@pytest.fixture
def intent():
    return TrustedIntent(
        origin="Chennai",
        destination="Delhi",
        cabin_class="Economy",
        passenger_count=1,
    )


def test_require_confirmation_approved(intent):
    """Test that REQUIRE_CONFIRMATION suspends the loop and resumes upon operator approval."""
    async def _run():
        task_id = "test-confirm-approve"

        mock_browser = MagicMock()
        mock_browser.start = AsyncMock()
        mock_browser.stop = AsyncMock()
        mock_browser.navigate_to_base = AsyncMock()
        mock_browser.observe = AsyncMock(return_value=DOMSnapshot(
            url="http://127.0.0.1:8000/review",
            title="Review",
            page_name="review",
            visible_text="Review booking: Chennai to Delhi.",
        ))
        mock_browser.act = AsyncMock(return_value={"success": True, "new_url": "/confirmed"})

        proposed_action = {"type": "CLICK", "selector": "#confirm-booking"}

        mock_gate = MagicMock()
        mock_gate.check = MagicMock(return_value=GateResult(
            decision=Decision.REQUIRE_CONFIRMATION,
            reason="Requires human confirmation on booking_critical action.",
            risk_score=45,
        ))

        ctrl = AgentController(
            headless=True,
            gate=mock_gate,
            with_contextguard=True,
            decision_engine=lambda state, snap: proposed_action if state.step == 0 else None,
            confirmation_timeout=2.0,
        )
        ctrl.browser = mock_browser

        async def _simulate_operator():
            await asyncio.sleep(0.1)
            assert get_pending_confirmation(task_id) is True
            success = resolve_confirmation(task_id, approved=True)
            assert success is True

        op_task = asyncio.create_task(_simulate_operator())
        state = await ctrl.run(task_id, "Book Chennai to Delhi", attack_mode="off")
        await op_task

        assert state.status == "DONE"
        assert mock_browser.act.called is True
        assert state.step == 1

    asyncio.run(_run())


def test_require_confirmation_rejected(intent):
    """Test that REQUIRE_CONFIRMATION halts and marks PAUSED when operator rejects."""
    async def _run():
        task_id = "test-confirm-reject"

        mock_browser = MagicMock()
        mock_browser.start = AsyncMock()
        mock_browser.stop = AsyncMock()
        mock_browser.navigate_to_base = AsyncMock()
        mock_browser.observe = AsyncMock(return_value=DOMSnapshot(
            url="http://127.0.0.1:8000/review",
            title="Review",
            page_name="review",
            visible_text="Review booking.",
        ))
        mock_browser.act = AsyncMock()

        mock_gate = MagicMock()
        mock_gate.check = MagicMock(return_value=GateResult(
            decision=Decision.REQUIRE_CONFIRMATION,
            reason="Requires human confirmation.",
            risk_score=50,
        ))

        ctrl = AgentController(
            headless=True,
            gate=mock_gate,
            with_contextguard=True,
            decision_engine=lambda state, snap: {"type": "CLICK", "selector": "#confirm-booking"},
            confirmation_timeout=2.0,
        )
        ctrl.browser = mock_browser

        async def _simulate_reject():
            await asyncio.sleep(0.1)
            resolve_confirmation(task_id, approved=False)

        op_task = asyncio.create_task(_simulate_reject())
        state = await ctrl.run(task_id, "Book Chennai to Delhi", attack_mode="off")
        await op_task

        assert state.status == "PAUSED"
        assert mock_browser.act.called is False

    asyncio.run(_run())


def test_require_confirmation_timeout(intent):
    """Test that REQUIRE_CONFIRMATION times out safely if operator is unresponsive."""
    async def _run():
        task_id = "test-confirm-timeout"

        mock_browser = MagicMock()
        mock_browser.start = AsyncMock()
        mock_browser.stop = AsyncMock()
        mock_browser.navigate_to_base = AsyncMock()
        mock_browser.observe = AsyncMock(return_value=DOMSnapshot(
            url="http://127.0.0.1:8000/review",
            title="Review",
            page_name="review",
            visible_text="Review booking.",
        ))
        mock_browser.act = AsyncMock()

        mock_gate = MagicMock()
        mock_gate.check = MagicMock(return_value=GateResult(
            decision=Decision.REQUIRE_CONFIRMATION,
            reason="Requires human confirmation.",
            risk_score=50,
        ))

        ctrl = AgentController(
            headless=True,
            gate=mock_gate,
            with_contextguard=True,
            decision_engine=lambda state, snap: {"type": "CLICK", "selector": "#confirm-booking"},
            confirmation_timeout=0.1,
        )
        ctrl.browser = mock_browser

        state = await ctrl.run(task_id, "Book Chennai to Delhi", attack_mode="off")

        assert state.status == "PAUSED"
        assert mock_browser.act.called is False

    asyncio.run(_run())


def test_pause_task_enforcement(intent):
    """Test that PAUSE_TASK immediately halts the agent loop."""
    async def _run():
        task_id = "test-pause-task"

        mock_browser = MagicMock()
        mock_browser.start = AsyncMock()
        mock_browser.stop = AsyncMock()
        mock_browser.navigate_to_base = AsyncMock()
        mock_browser.observe = AsyncMock(return_value=DOMSnapshot(
            url="http://127.0.0.1:8000/review",
            title="Review",
            page_name="review",
            visible_text="Hostile environment.",
        ))
        mock_browser.act = AsyncMock()

        mock_gate = MagicMock()
        mock_gate.check = MagicMock(return_value=GateResult(
            decision=Decision.PAUSE_TASK,
            reason="Multiple critical anomalies detected — task suspended.",
            risk_score=95,
        ))

        ctrl = AgentController(
            headless=True,
            gate=mock_gate,
            with_contextguard=True,
            decision_engine=lambda state, snap: {"type": "CLICK", "selector": "#confirm-booking"},
        )
        ctrl.browser = mock_browser

        state = await ctrl.run(task_id, "Book Chennai to Delhi", attack_mode="off")

        assert state.status == "PAUSED"
        assert mock_browser.act.called is False

    asyncio.run(_run())


def test_require_confirmation_with_llm_decision(intent, monkeypatch):
    """Test REQUIRE_CONFIRMATION when the agent decision is generated via the LLM decision path."""
    import agent.agent_controller as ac
    from unittest.mock import patch, MagicMock

    async def _run():
        task_id = "test-confirm-llm"

        mock_browser = MagicMock()
        mock_browser.start = AsyncMock()
        mock_browser.stop = AsyncMock()
        mock_browser.navigate_to_base = AsyncMock()
        mock_browser.observe = AsyncMock(return_value=DOMSnapshot(
            url="http://127.0.0.1:8000/review",
            title="Review Booking",
            page_name="review",
            visible_text="Review your flight: Chennai to Delhi, Economy. Total: INR 4500.",
        ))
        mock_browser.act = AsyncMock(return_value={"success": True, "new_url": "/confirmed"})

        # Gate requires confirmation on booking-critical action
        mock_gate = MagicMock()
        mock_gate.check = MagicMock(return_value=GateResult(
            decision=Decision.REQUIRE_CONFIRMATION,
            reason="LLM proposed irreversible booking submission — requires human confirmation.",
            risk_score=50,
        ))

        # Enable LLM decisions on the controller
        monkeypatch.setattr(ac, "USE_LLM_DECISIONS", True)

        # Mock the LLM HTTP response to return a valid JSON action
        llm_json_response = json.dumps({"response": '```json\n{"type": "CLICK", "selector": "#confirm-booking"}\n```'}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = llm_json_response
        mock_resp.__enter__.return_value = mock_resp

        ctrl = AgentController(
            headless=True,
            gate=mock_gate,
            with_contextguard=True,
            confirmation_timeout=2.0,
        )
        ctrl.browser = mock_browser

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            # Schedule approval after 50ms
            async def _approve_after_delay():
                await asyncio.sleep(0.05)
                resolved = resolve_confirmation(task_id, approved=True)
                assert resolved is True

            asyncio.create_task(_approve_after_delay())
            state = await ctrl.run(task_id, "Book Chennai to Delhi", attack_mode="off")

            # Verify LLM was actually consulted
            assert mock_urlopen.called is True
            # Verify gate checked the LLM-derived action
            assert mock_gate.check.called is True
            call_proposed = mock_gate.check.call_args[0][0]
            assert call_proposed.action_type == "CLICK"
            assert call_proposed.target == "#confirm-booking"

            # Verify browser acted after confirmation
            assert mock_browser.act.called is True
            assert state.status == "DONE"

    asyncio.run(_run())


def test_abort_confirmation_and_stop_agent():
    """
    Demo-Safety Regression Test: Ensures abort_confirmation() and /api/agent/stop
    cleanly unblock suspended agent loops with rejection, and clear_all_confirmations()
    resets state completely, leaving zero dangling zombie events.
    """
    from agent.agent_controller import (
        _active_confirmations,
        _confirmation_results,
        abort_confirmation,
        clear_all_confirmations,
        get_pending_confirmation,
    )
    from backend.main import app, AgentControlRequest, stop_agent
    from backend.database.db import init_db, insert_task, get_conn

    init_db()
    task_id = insert_task("Book Chennai to Delhi")

    # 1. Simulate an active confirmation event waiting for user input
    ev = asyncio.Event()
    _active_confirmations[task_id] = ev
    assert get_pending_confirmation(task_id) is True

    # 2. Call abort_confirmation()
    aborted = abort_confirmation(task_id)
    assert aborted is True
    assert ev.is_set() is True
    assert _confirmation_results.get(task_id) is False

    # 3. Clean up and test stop_agent endpoint integration
    clear_all_confirmations()
    assert len(_active_confirmations) == 0

    ev2 = asyncio.Event()
    _active_confirmations[task_id] = ev2
    res = stop_agent(AgentControlRequest(task_id=task_id))
    assert res["status"] == "stopped"
    assert ev2.is_set() is True
    assert _confirmation_results.get(task_id) is False

    # Verify task status in database is STOPPED
    conn = get_conn()
    row = conn.execute("SELECT status FROM tasks WHERE task_id=?", (task_id,)).fetchone()
    conn.close()
    assert row["status"] == "STOPPED"


