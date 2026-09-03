"""
verifier/safe_actions.py — ContextGuard

Enforcement wrappers for every Playwright browser action.

Every wrapper follows the same pattern:
  1. capture_state(page) → trusted ground truth snapshot
  2. ContextGuardVerifier.verify(thought, action_desc, snapshot)
  3. If CONSISTENT → execute the Playwright action
  4. If DISCREPANCY → pause, log, ask user (or auto-block in headless mode)

Why the agent cannot call Playwright directly
---------------------------------------------
All action execution is gated here.  The agent proposes an action;
ContextGuard verifies it before Playwright touches the browser.
This is the enforcement boundary between "agent intention" and
"browser reality".

Headless mode
-------------
When interactive=False, discrepancies auto-block without prompting.
When interactive=True, the user is shown the alert and can override.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from verifier.capture_state import PageSnapshot, capture_state
from verifier.verifier import ContextGuardVerifier, VerificationResult, verifier as _default_verifier


# ---------------------------------------------------------------------------
# Execution result
# ---------------------------------------------------------------------------

@dataclass
class ActionOutcome:
    """Result returned by every safe_* wrapper."""
    executed: bool
    action: str
    thought: str
    verification: VerificationResult
    error: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def __str__(self) -> str:
        status = "✅ EXECUTED" if self.executed else "🚫 BLOCKED"
        return (
            f"{status} | {self.action}\n"
            f"  Thought: {self.thought[:80]}\n"
            f"  {self.verification}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executed": self.executed,
            "action": self.action,
            "thought": self.thought,
            "verification": self.verification.to_dict(),
            "error": self.error,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Core enforcement gate
# ---------------------------------------------------------------------------

async def _gate(
    page: Any,
    thought: str,
    action_description: str,
    playwright_fn: Callable,
    v: ContextGuardVerifier,
    interactive: bool,
) -> ActionOutcome:
    """
    Central verification gate used by all safe_* wrappers.

    1. Capture real page state.
    2. Verify belief + action against snapshot.
    3. Execute or block based on result.
    """
    snapshot: PageSnapshot = await capture_state(page)
    result: VerificationResult = v.verify(thought, action_description, snapshot)

    if result.allow:
        error = None
        try:
            await playwright_fn()
        except Exception as exc:
            error = str(exc)
        return ActionOutcome(
            executed=error is None,
            action=action_description,
            thought=thought,
            verification=result,
            error=error,
        )

    # Discrepancy detected
    _print_alert(result, thought, action_description, snapshot)

    if interactive:
        proceed = _ask_user()
        if proceed:
            error = None
            try:
                await playwright_fn()
            except Exception as exc:
                error = str(exc)
            return ActionOutcome(
                executed=True,
                action=action_description,
                thought=thought,
                verification=result,
                error=error,
            )

    return ActionOutcome(
        executed=False,
        action=action_description,
        thought=thought,
        verification=result,
    )


def _print_alert(
    result: VerificationResult,
    thought: str,
    action: str,
    snapshot: PageSnapshot,
) -> None:
    print("\n" + "=" * 60)
    print("⚠️  CONTEXTGUARD ALERT")
    print("=" * 60)
    print(f"Status    : {result.status.value}")
    print(f"Risk      : {result.risk_level}")
    print(f"Reason    : {result.reason}")
    print(f"Layer     : {result.layer}")
    print(f"Rules hit : {result.rule_hits}")
    print(f"Agent thought : {thought[:120]}")
    print(f"Intended action: {action[:120]}")
    print(f"Real URL  : {snapshot.url}")
    print(f"Real title: {snapshot.title}")
    if snapshot.modals:
        print(f"Modals on page: {snapshot.modals[:2]}")
    print("=" * 60 + "\n")


def _ask_user() -> bool:
    try:
        ans = input("Proceed anyway? (y/n): ").strip().lower()
        return ans == "y"
    except (EOFError, KeyboardInterrupt):
        return False


# ---------------------------------------------------------------------------
# Public safe action wrappers
# ---------------------------------------------------------------------------

async def safe_click(
    page: Any,
    selector: str,
    thought: str,
    action_description: Optional[str] = None,
    timeout: int = 10_000,
    v: ContextGuardVerifier = _default_verifier,
    interactive: bool = True,
) -> ActionOutcome:
    """
    Safe wrapper for page.click().

    Verifies that the real page state supports the agent's belief before
    clicking the target element.
    """
    desc = action_description or f"Click element '{selector}'"
    return await _gate(
        page, thought, desc,
        lambda: page.click(selector, timeout=timeout),
        v, interactive,
    )


async def safe_fill(
    page: Any,
    selector: str,
    value: str,
    thought: str,
    action_description: Optional[str] = None,
    timeout: int = 10_000,
    v: ContextGuardVerifier = _default_verifier,
    interactive: bool = True,
) -> ActionOutcome:
    """
    Safe wrapper for page.fill().

    Never fills password or payment fields without a CONSISTENT verification.
    """
    desc = action_description or f"Fill field '{selector}'"
    return await _gate(
        page, thought, desc,
        lambda: page.fill(selector, value, timeout=timeout),
        v, interactive,
    )


async def safe_navigate(
    page: Any,
    url: str,
    thought: str,
    action_description: Optional[str] = None,
    timeout: int = 15_000,
    v: ContextGuardVerifier = _default_verifier,
    interactive: bool = True,
) -> ActionOutcome:
    """
    Safe wrapper for page.goto().

    Checks the current page state before navigating away.
    """
    desc = action_description or f"Navigate to '{url}'"
    return await _gate(
        page, thought, desc,
        lambda: page.goto(url, timeout=timeout, wait_until="domcontentloaded"),
        v, interactive,
    )


async def safe_submit(
    page: Any,
    selector: str,
    thought: str,
    action_description: Optional[str] = None,
    timeout: int = 10_000,
    v: ContextGuardVerifier = _default_verifier,
    interactive: bool = True,
) -> ActionOutcome:
    """
    Safe wrapper for form submission.

    Submit is always treated as high-risk; LLM verification is triggered
    even when rule checks pass.
    """
    desc = action_description or f"Submit form '{selector}'"
    # Force LLM on submit regardless of global setting
    forced_v = ContextGuardVerifier(
        use_llm=v._use_llm,
        llm_model=v._llm_model,
        always_use_llm_for_high_risk=True,
    )
    return await _gate(
        page, thought, desc,
        lambda: page.locator(selector).first.evaluate(
            "el => el.tagName === 'FORM' ? el.submit() : el.click()"
        ),
        forced_v, interactive,
    )


async def safe_select(
    page: Any,
    selector: str,
    value: str,
    thought: str,
    action_description: Optional[str] = None,
    timeout: int = 10_000,
    v: ContextGuardVerifier = _default_verifier,
    interactive: bool = True,
) -> ActionOutcome:
    """Safe wrapper for page.select_option()."""
    desc = action_description or f"Select '{value}' in '{selector}'"
    return await _gate(
        page, thought, desc,
        lambda: page.select_option(selector, value, timeout=timeout),
        v, interactive,
    )


async def safe_extract(
    page: Any,
    selector: str,
    thought: str,
    v: ContextGuardVerifier = _default_verifier,
) -> ActionOutcome:
    """
    Safe wrapper for text extraction.

    Extract is always read-only and verified as CONSISTENT by the rule engine,
    but still logged through the gate for audit completeness.
    """
    desc = f"Extract text from '{selector}'"
    result_container: Dict[str, Any] = {}

    async def _extract():
        try:
            text = await page.inner_text(selector, timeout=5_000)
            result_container["text"] = text[:2000]
        except Exception:
            result_container["text"] = ""

    outcome = await _gate(page, thought, desc, _extract, v, interactive=False)
    outcome.verification.details["extracted_text"] = result_container.get("text", "")
    return outcome


# ---------------------------------------------------------------------------
# Batch executor — runs a list of (action_type, kwargs) through safe wrappers
# ---------------------------------------------------------------------------

async def execute_plan(
    page: Any,
    steps: list,
    v: ContextGuardVerifier = _default_verifier,
    interactive: bool = True,
    stop_on_block: bool = True,
) -> list:
    """
    Execute a sequence of planned agent steps through the safety gate.

    Each step is a dict:
      {
        "action_type": "click" | "fill" | "navigate" | "submit" | "extract",
        "thought": "...",
        "selector": "...",   # for click/fill/submit/extract
        "url": "...",        # for navigate
        "value": "...",      # for fill
      }

    Returns a list of ActionOutcome objects.
    """
    outcomes = []
    for i, step in enumerate(steps):
        action_type = step.get("action_type", "click")
        thought = step.get("thought", "")
        print(f"\n[Step {i+1}/{len(steps)}] {action_type.upper()}: {thought[:60]}")

        if action_type == "click":
            outcome = await safe_click(
                page, step["selector"], thought,
                step.get("action_description"), v=v, interactive=interactive,
            )
        elif action_type == "fill":
            outcome = await safe_fill(
                page, step["selector"], step.get("value", ""), thought,
                step.get("action_description"), v=v, interactive=interactive,
            )
        elif action_type == "navigate":
            outcome = await safe_navigate(
                page, step["url"], thought,
                step.get("action_description"), v=v, interactive=interactive,
            )
        elif action_type == "submit":
            outcome = await safe_submit(
                page, step["selector"], thought,
                step.get("action_description"), v=v, interactive=interactive,
            )
        elif action_type == "extract":
            outcome = await safe_extract(page, step["selector"], thought, v=v)
        else:
            print(f"  Unknown action type '{action_type}', skipping.")
            continue

        print(f"  {outcome}")
        outcomes.append(outcome)

        if stop_on_block and not outcome.executed:
            print(f"\n⛔ Plan halted at step {i+1} — ContextGuard blocked the action.")
            break

    return outcomes
