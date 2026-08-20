"""
Browser Service — ContextGuard Services

Executes approved browser actions using Playwright with Chromium.

Why the agent cannot access Playwright directly
------------------------------------------------
All browser automation is gated behind this service. The service checks the
DecisionResult's 'executable' flag and the approval record before taking any
action. An agent calling Playwright directly would bypass ContextGuard
entirely; the required execution path is:

    Agent → ContextGuard API → Decision Engine → BrowserService

The agent has no import path to Playwright and no API endpoint that exposes
raw browser primitives. Every action must be expressed as a BrowserAction
and evaluated by the decision engine first.

Security properties
--------------------
- BLOCK decisions are rejected unconditionally.
- REQUIRE_APPROVAL decisions are rejected unless an approval record exists.
- No arbitrary JavaScript supplied by the agent is executed.
- Each session uses an isolated browser context.
- File access is restricted to approved paths.
- Navigation and action timeouts prevent infinite hangs.
- Cookies and credentials are never written to audit logs.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, Optional

from app.models.action import ActionType, BrowserAction
from app.models.decision import DecisionResult, DecisionType

# Playwright is imported lazily so the application can start without
# a Chromium binary installed (e.g., in CI or testing environments).
_playwright_available = False
try:
    from playwright.async_api import (
        Browser,
        BrowserContext,
        Page,
        Playwright,
        async_playwright,
    )
    _playwright_available = True
except ImportError:
    pass

_APPROVED_DOWNLOAD_DIR = Path(__file__).parent.parent.parent / "downloads"
_NAV_TIMEOUT_MS = 15_000
_ACTION_TIMEOUT_MS = 10_000


class BrowserExecutionError(Exception):
    """Raised when the browser service cannot execute an action."""


class BrowserService:
    """
    Manages Playwright browser contexts and executes approved actions.

    One BrowserContext is maintained per session_id to isolate state.
    The service is stateful but thread-safe at the session level.
    """

    def __init__(self) -> None:
        self._playwright: Optional[Any] = None
        self._browser: Optional[Any] = None
        self._contexts: Dict[str, Any] = {}  # session_id -> BrowserContext
        self._pages: Dict[str, Any] = {}     # session_id -> Page
        self._started = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start_browser(self) -> None:
        """Launch the Chromium browser. Called once at application startup."""
        if not _playwright_available:
            return  # Graceful degradation in environments without Playwright
        if self._started:
            return
        pw = await async_playwright().start()
        self._playwright = pw
        self._browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-plugins",
                "--disable-background-networking",
            ],
        )
        self._started = True
        _APPROVED_DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

    async def create_context(self, session_id: str) -> None:
        """Create an isolated browser context for a session."""
        if not self._started or not self._browser:
            return
        if session_id in self._contexts:
            return
        context = await self._browser.new_context(
            accept_downloads=True,
            java_script_enabled=True,
            bypass_csp=False,
            # Do not store cookies between sessions
            storage_state=None,
        )
        page = await context.new_page()
        self._contexts[session_id] = context
        self._pages[session_id] = page

    async def close_context(self, session_id: str) -> None:
        """Close and clean up the browser context for a session."""
        if session_id in self._contexts:
            try:
                await self._contexts[session_id].close()
            except Exception:
                pass
            del self._contexts[session_id]
        if session_id in self._pages:
            del self._pages[session_id]

    async def stop_browser(self) -> None:
        """Shut down all contexts and the browser."""
        for sid in list(self._contexts.keys()):
            await self.close_context(sid)
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
        self._started = False

    # ------------------------------------------------------------------
    # Gate: only ALLOW and WARN are executable
    # ------------------------------------------------------------------

    def _assert_executable(
        self,
        action: BrowserAction,
        decision: DecisionResult,
        approved: bool = False,
    ) -> None:
        """
        Raise BrowserExecutionError for non-executable decisions.

        BLOCK: always rejected.
        REQUIRE_APPROVAL: rejected unless an approval record exists.
        """
        if decision.decision == DecisionType.BLOCK:
            raise BrowserExecutionError(
                f"Action '{action.action_id}' was BLOCKED by ContextGuard. "
                f"Reasons: {decision.reasons}"
            )

        if decision.decision == DecisionType.REQUIRE_APPROVAL:
            if not approved:
                raise BrowserExecutionError(
                    f"Action '{action.action_id}' requires human approval. "
                    "Submit a POST to /api/approvals/{approval_id}/approve first."
                )

        if not decision.executable and not approved:
            raise BrowserExecutionError(
                f"Action '{action.action_id}' is not executable "
                f"(decision={decision.decision})."
            )

    # ------------------------------------------------------------------
    # Public execution entry points
    # ------------------------------------------------------------------

    async def execute_action(
        self,
        action: BrowserAction,
        decision: DecisionResult,
        approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute a browser action after verifying it is permitted.

        This is the only public execution method. Routing all execution
        through a single gate prevents direct calls to individual execute_*
        methods from bypassing the safety check.
        """
        self._assert_executable(action, decision, approved)

        if not self._started or not _playwright_available:
            # Return a simulated result when Playwright is unavailable
            return self._simulate_execution(action)

        session_id = action.session_id
        if session_id not in self._contexts:
            await self.create_context(session_id)

        action_type = action.action_type
        dispatch = {
            ActionType.navigate: self.execute_navigate,
            ActionType.click: self.execute_click,
            ActionType.fill: self.execute_fill,
            ActionType.submit: self.execute_submit,
            ActionType.upload: self.execute_upload,
            ActionType.download: self.execute_download,
            ActionType.extract: self.execute_extract,
        }

        handler = dispatch.get(action_type)
        if not handler:
            raise BrowserExecutionError(f"Unsupported action type: {action_type}")

        return await handler(action)

    # ------------------------------------------------------------------
    # Individual action executors
    # ------------------------------------------------------------------

    async def execute_navigate(self, action: BrowserAction) -> Dict[str, Any]:
        """Navigate to the target URL."""
        page = self._get_page(action.session_id)
        url = action.target.url
        if not url:
            raise BrowserExecutionError("navigate requires a URL")

        response = await page.goto(url, timeout=_NAV_TIMEOUT_MS, wait_until="domcontentloaded")
        return {
            "action": "navigate",
            "url": url,
            "status_code": response.status if response else None,
            "title": await page.title(),
        }

    async def execute_click(self, action: BrowserAction) -> Dict[str, Any]:
        """Click a page element by CSS selector."""
        page = self._get_page(action.session_id)
        selector = action.target.selector
        if not selector:
            raise BrowserExecutionError("click requires a selector")
        await page.click(selector, timeout=_ACTION_TIMEOUT_MS)
        return {"action": "click", "selector": selector, "success": True}

    async def execute_fill(self, action: BrowserAction) -> Dict[str, Any]:
        """Fill a form field. Payload values are used directly (not from page content)."""
        page = self._get_page(action.session_id)
        selector = action.target.selector
        if not selector:
            raise BrowserExecutionError("fill requires a selector")
        # Only fill with payload values; never execute content from the page
        value = str(action.payload.get("value", ""))
        await page.fill(selector, value, timeout=_ACTION_TIMEOUT_MS)
        return {"action": "fill", "selector": selector, "success": True}

    async def execute_submit(self, action: BrowserAction) -> Dict[str, Any]:
        """Submit a form by clicking its submit element."""
        page = self._get_page(action.session_id)
        selector = action.target.selector or "form"
        await page.locator(selector).first.evaluate(
            "el => el.tagName === 'FORM' ? el.submit() : el.click()"
        )
        return {"action": "submit", "selector": selector, "success": True}

    async def execute_upload(self, action: BrowserAction) -> Dict[str, Any]:
        """Upload a file from an approved path only."""
        page = self._get_page(action.session_id)
        selector = action.target.selector
        file_path = action.payload.get("file_path", "")

        # Restrict uploads to files inside the workspace download dir
        resolved = Path(file_path).resolve()
        approved_root = _APPROVED_DOWNLOAD_DIR.resolve()
        if not str(resolved).startswith(str(approved_root)):
            raise BrowserExecutionError(
                f"Upload path '{file_path}' is outside the approved directory"
            )

        if not selector:
            raise BrowserExecutionError("upload requires a selector")

        await page.set_input_files(selector, str(resolved), timeout=_ACTION_TIMEOUT_MS)
        return {"action": "upload", "file": str(resolved), "success": True}

    async def execute_download(self, action: BrowserAction) -> Dict[str, Any]:
        """Download a file to the approved downloads directory."""
        page = self._get_page(action.session_id)
        url = action.target.url
        if not url:
            raise BrowserExecutionError("download requires a URL")

        async with page.expect_download(timeout=_NAV_TIMEOUT_MS) as dl_info:
            await page.goto(url, timeout=_NAV_TIMEOUT_MS)
        download = await dl_info.value
        dest = _APPROVED_DOWNLOAD_DIR / download.suggested_filename
        await download.save_as(str(dest))
        return {
            "action": "download",
            "filename": download.suggested_filename,
            "saved_to": str(dest),
            "success": True,
        }

    async def execute_extract(self, action: BrowserAction) -> Dict[str, Any]:
        """Extract text content from a page element."""
        page = self._get_page(action.session_id)
        selector = action.target.selector or "body"
        content = await page.inner_text(selector, timeout=_ACTION_TIMEOUT_MS)
        # Truncate extracted content to prevent large data exfiltration
        truncated = content[:2048] if content else ""
        return {
            "action": "extract",
            "selector": selector,
            "content": truncated,
            "truncated": len(content or "") > 2048,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_page(self, session_id: str) -> Any:
        page = self._pages.get(session_id)
        if not page:
            raise BrowserExecutionError(
                f"No browser page for session '{session_id}'. "
                "Call create_context() first."
            )
        return page

    @staticmethod
    def _simulate_execution(action: BrowserAction) -> Dict[str, Any]:
        """
        Return a simulated result when Playwright is not available.
        Used during testing and in environments without a Chromium binary.
        """
        return {
            "action": str(action.action_type),
            "simulated": True,
            "session_id": action.session_id,
            "target_url": action.target.url,
            "target_selector": action.target.selector,
            "success": True,
            "note": "Playwright not available; execution simulated by ContextGuard",
        }


# Module-level singleton
browser_service = BrowserService()
