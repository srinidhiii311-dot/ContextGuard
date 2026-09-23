"""
backend/session_controller/controller.py — Execution Session Controller

Coordinates session lifecycle:
1. Parses natural language instruction into locked TrustedIntent
2. Creates session in DB with session_token for server-side mock_site gating
3. Arms testbed attack injector with test_case_id (strictly isolated from ContextGuard)
4. Launches autonomous BrowserAgent in background asyncio task
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Dict, Optional

from backend.attack_injector.injector import attack_injector
from backend.browser_agent.agent import BrowserAgent
from backend.db.models import SessionControllerDAO
from backend.session_controller.intent_parser import parse_natural_language_intent
from shared.schemas.schemas import SessionCreateRequest, SessionCreateResponse, TrustedIntent

_ACTIVE_TASKS: Dict[str, asyncio.Task] = {}


class SessionController:
    """Controls session launch and agent lifecycle."""

    @staticmethod
    def launch_session(payload: SessionCreateRequest) -> SessionCreateResponse:
        """
        Creates session, arms testbed injector, and starts agent loop in background.
        ContextGuard never receives payload.test_case_id.
        """
        # 1. Parse & lock trusted intent
        defaults = {
            "origin": payload.origin,
            "destination": payload.destination,
            "cabin_class": payload.cabin_class,
            "passenger_count": payload.passenger_count,
            "date": payload.date,
        }
        intent = parse_natural_language_intent(payload.instruction, defaults=defaults)

        # 2. Create session record in DB (ground truth test_case_id stored for offline reporting only)
        test_case_id = payload.test_case_id or "TC-01"
        session_id, session_token, viewer_token = SessionControllerDAO.create_session(
            raw_instruction=payload.instruction,
            trusted_intent=intent.to_dict(),
            test_case_id=test_case_id,
        )

        # 2b. Initialize server-side session state for mock booking site
        from backend.mock_site.session_state import session_state_store
        session_state_store.init_session(
            session_id=session_id,
            origin=intent.origin,
            destination=intent.destination,
            cabin_class=intent.cabin_class,
            passenger_count=intent.passenger_count,
        )

        # 3. Arm testbed injector independently
        attack_injector.arm_scenario(session_id=session_id, test_case_id=test_case_id)

        # 4. Spawn autonomous BrowserAgent in background
        agent = BrowserAgent(
            session_id=session_id,
            session_token=session_token,
            trusted_intent=intent,
            speed=payload.speed or 1.2,
            headless=payload.headless or False,
        )

        def _run_agent_in_thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(agent.run())
            finally:
                loop.close()

        t = threading.Thread(target=_run_agent_in_thread, daemon=True)
        t.start()

        return SessionCreateResponse(
            session_id=session_id,
            status="running",
            live_url=f"/live/{session_id}",
            session_token=session_token,
            viewer_token=viewer_token,
            trusted_intent=intent.to_dict(),
        )


session_controller = SessionController()
