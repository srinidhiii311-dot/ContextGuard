"""
agent/agent_controller.py — Phase 2, Checkpoints 2.2 & 2.3

Runs the agent loop:
  1. Parse user instruction → structured intent (task_parser)
  2. Navigate to booking site
  3. Loop:  observe() → decide_next_action() → act() → log
  4. Stop when booking reaches CONFIRMED or max_steps exceeded

Decision engine: rule-based by default (no LLM needed).
Set USE_LLM_DECISIONS=True to use Ollama for decide_next_action().

Action log (Checkpoint 2.3):
Every observe→action pair is stored in the database so ContextGuard
can consume it and the evaluation harness can replay runs.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from agent.browser_controller import BrowserController, DOMSnapshot
from agent.task_parser import parse_task
from backend.database.db import insert_agent_action, now_iso, update_task
from backend.websocket.manager import ws_manager

USE_LLM_DECISIONS = False
LLM_MODEL         = "llama3"
LLM_URL           = "http://localhost:11434/api/generate"
MAX_STEPS         = 20
BASE_URL          = "http://127.0.0.1:8000"


# ---------------------------------------------------------------------------
# Agent state
# ---------------------------------------------------------------------------

@dataclass
class AgentState:
    task_id:        str
    intent:         Dict[str, Any]
    step:           int                      = 0
    booking_id:     Optional[str]            = None
    flight_id:      Optional[str]            = None
    status:         str                      = "RUNNING"   # RUNNING | DONE | ERROR | PAUSED
    action_log:     List[Dict[str, Any]]     = field(default_factory=list)
    last_snapshot:  Optional[DOMSnapshot]    = None


# ---------------------------------------------------------------------------
# Rule-based decision engine
# ---------------------------------------------------------------------------

def _decide_rule(state: AgentState, snapshot: DOMSnapshot) -> Optional[Dict[str, Any]]:
    """
    Deterministic decision function.
    Maps (page_name, intent) → next action dict.
    Returns None when the task is complete.
    """
    page    = snapshot.page_name
    intent  = state.intent
    buttons = [b.upper() for b in snapshot.buttons]
    inputs  = {i["name"].lower(): i for i in snapshot.inputs}

    if page == "search":
        # Fill origin
        if any("origin" in k or "from" in k for k in inputs):
            return {"type": "TYPE", "selector": "#origin",
                    "value": intent.get("origin", "")}
        # Fill destination
        if any("dest" in k for k in inputs):
            return {"type": "TYPE", "selector": "#destination",
                    "value": intent.get("destination", "")}
        # Set cabin class
        cabin = intent.get("cabin_class", "Economy")
        return {"type": "SELECT", "selector": "#cabin", "value": cabin}

    elif page == "results":
        # Look for a flight card matching the intent
        if intent.get("cabin_class", "Economy") in snapshot.visible_text:
            return {"type": "CLICK",
                    "selector": f".flight-card:first-of-type"}
        return {"type": "CLICK", "selector": ".flight-card"}

    elif page == "passenger":
        if any("pname" in k or "passenger" in k for k in inputs):
            return {"type": "TYPE", "selector": "#pname",
                    "value": intent.get("passenger_name", "Test Passenger")}
        count = intent.get("passengers", 1)
        if any("pcount" in k or "count" in k for k in inputs):
            return {"type": "TYPE", "selector": "#pcount",
                    "value": str(count)}
        # Click continue
        for b in snapshot.buttons:
            if "continue" in b.lower() or "review" in b.lower():
                return {"type": "CLICK",
                        "selector": "button.btn-primary, button:has-text('CONTINUE')"}
        return {"type": "CLICK", "selector": "button"}

    elif page == "review":
        # Verify details match intent BEFORE confirming
        text_lower = snapshot.visible_text.lower()
        origin_ok  = intent.get("origin", "").lower() in text_lower
        dest_ok    = intent.get("destination", "").lower() in text_lower

        if origin_ok and dest_ok:
            return {"type": "CLICK", "selector": "#confirm-btn, button.btn-green"}
        # Details don't match — agent should flag this
        return None   # triggers DONE with mismatch note

    elif page == "confirmed":
        return None   # Booking complete — stop loop

    return {"type": "NAVIGATE", "url": BASE_URL}


# ---------------------------------------------------------------------------
# LLM-based decision engine
# ---------------------------------------------------------------------------

_LLM_DECISION_PROMPT = """\
You are an AI agent completing a flight booking task.

Your goal:
{intent}

Current page state:
{page_summary}

Previous actions:
{prev_actions}

Decide the single next browser action needed.
Respond with ONLY a JSON object like one of these examples:
  {{"type":"CLICK","selector":"#confirm-btn"}}
  {{"type":"TYPE","selector":"#origin","value":"Chennai"}}
  {{"type":"SELECT","selector":"#cabin","value":"Economy"}}
  {{"type":"NAVIGATE","url":"http://127.0.0.1:8000"}}
  {{"type":"DONE"}}

Output ONLY the JSON, nothing else.
"""


def _decide_llm(state: AgentState, snapshot: DOMSnapshot) -> Optional[Dict[str, Any]]:
    prev = [f"Step {a['step']}: {a['action_type']} {a.get('action_details','')}"
            for a in state.action_log[-4:]]
    prompt = _LLM_DECISION_PROMPT.format(
        intent=json.dumps(state.intent, indent=2),
        page_summary=snapshot.to_prompt_summary(),
        prev_actions="\n".join(prev) or "None yet",
    )
    payload = json.dumps({"model": LLM_MODEL, "prompt": prompt,
                          "stream": False}).encode()
    req = urllib.request.Request(
        LLM_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    raw = data.get("response", "")
    m = re.search(r"\{.*?\}", raw, re.DOTALL)
    if not m:
        raise ValueError("No JSON in LLM response")
    action = json.loads(m.group(0))
    if action.get("type") == "DONE":
        return None
    return action


# ---------------------------------------------------------------------------
# Agent controller
# ---------------------------------------------------------------------------

class AgentController:
    """
    Orchestrates the full observe → decide → act loop.

    intervention_hook: optional async callable(state, snapshot, action) → bool
        If it returns False, the action is BLOCKED and the loop pauses.
        This is how ContextGuard's intervention (Phase 5.4) integrates.
    """

    def __init__(
        self,
        headless: bool = True,
        intervention_hook: Optional[Callable] = None,
    ) -> None:
        self.browser  = BrowserController(headless=headless)
        self._hook    = intervention_hook

    async def run(self, task_id: str, instruction: str) -> AgentState:
        """
        Full agent run from instruction to CONFIRMED booking.
        Stores every step in the database (Checkpoint 2.3).
        """
        intent = parse_task(instruction)
        state  = AgentState(task_id=task_id, intent=intent)

        update_task(task_id,
                    status="RUNNING",
                    parsed_intent=json.dumps(intent))

        await self.browser.start()
        await self.browser.navigate_to_base()

        try:
            while state.step < MAX_STEPS and state.status == "RUNNING":
                # --- Observe ---
                snapshot = await self.browser.observe()
                state.last_snapshot = snapshot

                # --- Decide ---
                try:
                    if USE_LLM_DECISIONS:
                        action = _decide_llm(state, snapshot)
                    else:
                        action = _decide_rule(state, snapshot)
                except Exception as exc:
                    action = None
                    state.status = "ERROR"
                    await self._log(state, snapshot, {"type": "ERROR"},
                                    f"Decision error: {exc}")
                    break

                if action is None:
                    state.status = "DONE"
                    break

                # --- Intervention hook (ContextGuard Phase 5.4) ---
                if self._hook:
                    allowed = await self._hook(state, snapshot, action)
                    if not allowed:
                        state.status = "PAUSED"
                        await self._log(state, snapshot, action,
                                        "BLOCKED by ContextGuard")
                        break

                # --- Act ---
                result = await self.browser.act(action)

                await self._log(state, snapshot, action,
                                result.get("error", "") or "ok")

                state.step += 1

                if not result["success"]:
                    # Don't stop on minor errors (element not found etc.) 
                    # but track consecutive failures
                    pass

                # Check for confirmation
                if "confirmed" in result.get("new_url", ""):
                    state.status = "DONE"
                    break

                await asyncio.sleep(0.5)

        finally:
            await self.browser.stop()

        update_task(task_id, status=state.status)
        return state

    async def _log(
        self,
        state: AgentState,
        snapshot: DOMSnapshot,
        action: Dict[str, Any],
        result_note: str,
    ) -> None:
        entry = {
            "step":           state.step,
            "action_type":    action.get("type", "UNKNOWN"),
            "action_details": json.dumps(action),
            "page_url":       snapshot.url,
            "page_name":      snapshot.page_name,
            "dom_hash":       snapshot.dom_hash,
            "result":         result_note,
            "timestamp":      now_iso(),
        }
        state.action_log.append(entry)

        # Persist to DB
        insert_agent_action(
            task_id        = state.task_id,
            step_number    = state.step,
            action_type    = action.get("type", "UNKNOWN"),
            action_details = json.dumps(action),
            page_url       = snapshot.url,
            dom_snapshot   = json.dumps(snapshot.to_dict()),
            result         = result_note,
        )

        # Push to dashboard WebSocket
        ws_manager.broadcast_sync({
            "type":        "agent_action",
            "task_id":     state.task_id,
            "step":        state.step,
            "action_type": action.get("type"),
            "page_url":    snapshot.url,
            "page_name":   snapshot.page_name,
            "result":      result_note,
            "attack_detected": snapshot.attack_text_detected,
            "timestamp":   entry["timestamp"],
        })


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

async def _cli_run(instruction: str) -> None:
    from backend.database.db import insert_task
    task_id = insert_task(instruction)
    print(f"\n[Agent] Task ID: {task_id}")
    print(f"[Agent] Instruction: {instruction}")
    print(f"[Agent] Parsed intent: ", end="")

    ctrl  = AgentController(headless=True)
    state = await ctrl.run(task_id, instruction)

    print(f"\n[Agent] Status: {state.status}  Steps: {state.step}")
    print("[Agent] Action transcript:")
    for entry in state.action_log:
        print(f"  Step {entry['step']:2d} | {entry['page_name']:<12} | "
              f"{entry['action_type']:<10} | {entry['result'][:60]}")


if __name__ == "__main__":
    import sys
    instruction = " ".join(sys.argv[1:]) or \
        "Book an economy flight from Chennai to Delhi for 1 passenger"
    asyncio.run(_cli_run(instruction))
