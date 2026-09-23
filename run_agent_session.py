"""
run_agent_session.py — Independent Session Runner for Pop-Up Browser & Agent Loop

Launches the headful Chromium browser window, executes the autonomous agent loop
with synchronous Pre-Action Gate and Post-Action State Difference Engine monitoring.

ISOLATION ENFORCEMENT:
- The selected --scenario argument is passed ONLY to testbed_injector!
- ContextGuardSession is initialized with TrustedTaskContext only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Dict

from backend.database.db import ContextGuardRuntimeDAO, init_db
from contextguard.orchestrator import ContextGuardSession, register_session
from contextguard.task_context import TrustedTaskContext
from testbed.injector import testbed_injector
from agent.web_agent import AutonomousWebAgent


if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


async def main_async():
    parser = argparse.ArgumentParser(description="Run ContextGuard Agent Session")
    parser.add_argument("--session-id", type=str, default="")
    parser.add_argument("--task-id", type=str, default="")
    parser.add_argument("--instruction", type=str, default="Book an economy flight from Chennai to Bangalore for 2 passengers")
    parser.add_argument("--origin", type=str, default="Chennai")
    parser.add_argument("--destination", type=str, default="Bangalore")
    parser.add_argument("--passengers", type=int, default=2)
    parser.add_argument("--cabin-class", type=str, default="Economy")
    parser.add_argument("--date", type=str, default="2026-09-25")
    parser.add_argument("--scenario", type=str, default="baseline")
    parser.add_argument("--speed", type=float, default=1.8)
    parser.add_argument("--slowmo", type=int, default=250)
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()

    init_db()

    # 1. Task Context & Session Creation
    task_id = args.task_id or ContextGuardRuntimeDAO.create_task(
        instruction=args.instruction,
        parsed_intent={
            "origin": args.origin,
            "destination": args.destination,
            "passengers": args.passengers,
            "cabin_class": args.cabin_class,
            "date": args.date,
        },
    )

    session_id = args.session_id or ContextGuardRuntimeDAO.create_session(task_id)

    print("=" * 75)
    print(f"  CONTEXTGUARD MISSION CONTROL -- SESSION INITIALIZED")
    print(f"  Session ID : {session_id}")
    print(f"  Task ID    : {task_id}")
    print(f"  Intent     : {args.origin} -> {args.destination} | {args.passengers} pax | {args.cabin_class}")
    print("=" * 75)

    # 2. ISOLATION: Arm Testbed (Ground truth only!)
    # ContextGuard does NOT know this scenario!
    print(f"[Testbed] Arming experimental environment scenario: '{args.scenario}'...")
    testbed_info = testbed_injector.arm_scenario(session_id=session_id, scenario_id=args.scenario)
    print(f"[Testbed] Ground truth logged to isolated table: {testbed_info}")

    # 3. ContextGuard Initialization (Clean, isolated context)
    task_context = TrustedTaskContext(
        task_id=task_id,
        raw_instruction=args.instruction,
        origin=args.origin,
        destination=args.destination,
        date=args.date,
        passengers=args.passengers,
        cabin_class=args.cabin_class,
    )

    cg_session = ContextGuardSession(
        session_id=session_id,
        task_context=task_context,
        base_domain="127.0.0.1:8000",
        stabilization_delay_sec=0.3,
    )
    register_session(cg_session)

    # 4. Launch Autonomous Web Agent
    print(f"[Agent] Launching browser agent (Headless={args.headless}, Speed={args.speed}s)...")
    agent = AutonomousWebAgent(
        session_id=session_id,
        task_context=task_context,
        base_url="http://127.0.0.1:8000/app",
        speed=args.speed,
        slow_mo=args.slowmo,
        headless=args.headless,
    )

    results = await agent.run(max_steps=15)

    print("\n" + "=" * 75)
    print(f"  SESSION RUN COMPLETED — OUTCOME: {results['outcome']}")
    print(f"  Total Steps: {results['total_steps']}")
    print("=" * 75)


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(main_async())
