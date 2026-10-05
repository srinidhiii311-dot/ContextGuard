"""
agent/browser_controller.py — Phase 2, Checkpoint 2.2

Wraps Playwright to give the agent a clean observe/act interface.

observe() → returns a simplified DOM snapshot (text, buttons, inputs,
            current URL, page title) — NOT the raw HTML.
            This is what the agent sees; ContextGuard also compares
            this against the expected context.

act(action) → executes one structured action:
    {"type": "CLICK",    "selector": "css_selector"}
    {"type": "TYPE",     "selector": "css_selector", "value": "text"}
    {"type": "SELECT",   "selector": "css_selector", "value": "option_value"}
    {"type": "SUBMIT",   "selector": "css_selector"}
    {"type": "NAVIGATE", "url": "https://..."}
    {"type": "WAIT",     "ms": 500}

Why we wrap Playwright here
---------------------------
The agent never calls Playwright directly. Every action goes through
act() which can be intercepted by ContextGuard's intervention hook
before execution. This is the enforcement boundary.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Playwright import — graceful degradation if not installed
try:
    from playwright.async_api import Browser, BrowserContext, Page, async_playwright
    _PW_AVAILABLE = True
except ImportError:
    _PW_AVAILABLE = False

BASE_URL     = "http://127.0.0.1:8000"
NAV_TIMEOUT  = 15_000   # ms
ACT_TIMEOUT  = 8_000    # ms


# ---------------------------------------------------------------------------
# DOM snapshot
# ---------------------------------------------------------------------------

@dataclass
class DOMSnapshot:
    """Simplified, structured, objective representation of what the agent and browser see."""
    url:          str
    title:        str
    page_name:    str                   # search | results | passenger | review | confirmed
    headings:     List[str]             = field(default_factory=list)
    buttons:      List[str]             = field(default_factory=list)
    inputs:       List[Dict[str, str]]  = field(default_factory=list)   # {name, type, value}
    forms:        List[Dict[str, str]]  = field(default_factory=list)
    links:        List[str]             = field(default_factory=list)
    visible_text: str                   = ""
    dom_hash:     str                   = ""
    screenshot_path: str                = ""
    attack_text_detected: bool          = False
    attack_indicators:   List[str]      = field(default_factory=list)
    raw_html:            str            = ""
    hidden_findings:     List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url":             self.url,
            "title":           self.title,
            "page_name":       self.page_name,
            "headings":        self.headings,
            "buttons":         self.buttons,
            "inputs":          self.inputs,
            "forms":           self.forms,
            "links":           self.links,
            "visible_text":    self.visible_text[:1200],
            "dom_hash":        self.dom_hash,
            "screenshot_path": self.screenshot_path,
            "attack_text_detected": self.attack_text_detected,
            "attack_indicators":    self.attack_indicators,
            "raw_html":        self.raw_html,
            "hidden_findings": self.hidden_findings,
        }

    def to_prompt_summary(self) -> str:
        """Compact text representation sent to agent decision step."""
        return (
            f"URL: {self.url}\n"
            f"Page: {self.page_name}\n"
            f"Title: {self.title}\n"
            f"Buttons: {', '.join(self.buttons[:8])}\n"
            f"Inputs: {[i.get('name', '') for i in self.inputs[:6]]}\n"
            f"Text snippet: {self.visible_text[:300]}\n"
        )


# JS run inside the page — objective DOM extraction
_JS_OBSERVE = """
() => {
    const headings = Array.from(document.querySelectorAll('h1,h2,h3'))
        .filter(e=>e.offsetParent!==null)
        .map(e=>e.innerText.trim().slice(0,80));

    const buttons = Array.from(document.querySelectorAll('button,[role=button],input[type=submit],input[type=button]'))
        .filter(e=>e.offsetParent!==null)
        .map(e=>(e.innerText||e.value||e.getAttribute('aria-label')||'').trim().slice(0,60));

    const inputs = Array.from(document.querySelectorAll('input:not([type=hidden]),select,textarea'))
        .filter(e=>e.offsetParent!==null)
        .map(e=>({
            name:  (e.name||e.id||e.placeholder||'').slice(0,30),
            type:  e.type||e.tagName.toLowerCase(),
            value: (e.type==='password'?'[hidden]':(e.value||'').slice(0,40))
        }));

    const forms = Array.from(document.querySelectorAll('form'))
        .map(f=>({
            action: f.getAttribute('action') || '',
            id: f.id || '',
            inputs_count: f.querySelectorAll('input,select').length
        }));

    const links = Array.from(document.querySelectorAll('a[href]'))
        .map(a => a.getAttribute('href') || '')
        .filter(h => h && !h.startsWith('#') && !h.startsWith('javascript:'))
        .slice(0, 20);

    const text = document.body
        ? document.body.innerText.replace(/\\s+/g,' ').trim().slice(0,4000)
        : '';

    return { headings, buttons, inputs, forms, links, text };
}
"""


def _page_name_from_url(url: str) -> str:
    if "confirmed" in url:  return "confirmed"
    if "review"    in url:  return "review"
    if "passenger" in url:  return "passenger"
    if "results"   in url:  return "results"
    return "search"


# ---------------------------------------------------------------------------
# Browser controller
# ---------------------------------------------------------------------------

class BrowserController:
    """
    Manages one Playwright browser session for the agent.
    Never used directly by the agent — always through AgentController.
    """

    def __init__(self, headless: bool = True) -> None:
        self.headless  = headless
        self._pw:      Optional[Any] = None
        self._browser: Optional[Any] = None
        self._context: Optional[Any] = None
        self._page:    Optional[Any] = None
        self._started  = False

    async def start(self) -> None:
        if not _PW_AVAILABLE:
            return
        if self._started:
            return
        self._pw      = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=self.headless)
        self._context = await self._browser.new_context()
        self._page    = await self._context.new_page()
        self._started = True

    async def stop(self) -> None:
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
        if self._pw:
            try:
                await self._pw.stop()
            except Exception:
                pass
        self._started = False

    async def navigate_to_base(self) -> None:
        if self._page:
            await self._page.goto(BASE_URL, timeout=NAV_TIMEOUT,
                                  wait_until="domcontentloaded")

    # ------------------------------------------------------------------
    # observe() — Checkpoint 2.2
    # ------------------------------------------------------------------

    async def observe(self) -> DOMSnapshot:
        """
        Capture a structured DOM snapshot.
        This is what the agent uses to decide its next action.
        ContextGuard also hashes this to detect unexpected DOM changes.
        """
        if not self._page:
            return DOMSnapshot(url="", title="", page_name="search")

        url   = self._page.url
        title = await self._page.title()

        try:
            data = await self._page.evaluate(_JS_OBSERVE)
        except Exception:
            data = {"headings": [], "buttons": [], "inputs": [], "text": ""}

        text      = data.get("text", "")
        dom_hash  = hashlib.md5(text.encode()).hexdigest()

        raw_html = ""
        hidden_findings = []
        try:
            raw_html = await self._page.content()
        except Exception:
            pass

        try:
            from contextguard.hidden_content import scan_page_async
            hidden_findings = await scan_page_async(self._page)
        except Exception:
            pass

        return DOMSnapshot(
            url=url,
            title=title,
            page_name=_page_name_from_url(url),
            headings=data.get("headings", []),
            buttons=data.get("buttons", []),
            inputs=data.get("inputs", []),
            forms=data.get("forms", []),
            links=data.get("links", []),
            visible_text=text,
            dom_hash=dom_hash,
            raw_html=raw_html,
            hidden_findings=hidden_findings,
        )

    # ------------------------------------------------------------------
    # act() — Checkpoint 2.2
    # ------------------------------------------------------------------

    async def act(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute one structured browser action.
        Returns {"success": bool, "error": str, "new_url": str}.
        """
        if not self._page:
            return {"success": False, "error": "Browser not started", "new_url": ""}

        atype = action.get("type", "").upper()
        result = {"success": False, "error": "", "new_url": self._page.url}

        try:
            if atype == "NAVIGATE":
                await self._page.goto(
                    action["url"], timeout=NAV_TIMEOUT,
                    wait_until="domcontentloaded"
                )
            elif atype == "CLICK":
                await self._page.click(
                    action["selector"], timeout=ACT_TIMEOUT
                )
                await self._page.wait_for_load_state(
                    "domcontentloaded", timeout=ACT_TIMEOUT
                )
            elif atype == "TYPE":
                await self._page.fill(
                    action["selector"], action.get("value", ""),
                    timeout=ACT_TIMEOUT
                )
            elif atype == "SELECT":
                await self._page.select_option(
                    action["selector"], action.get("value", ""),
                    timeout=ACT_TIMEOUT
                )
            elif atype == "SUBMIT":
                sel = action.get("selector", "form")
                await self._page.locator(sel).first.evaluate(
                    "el => el.tagName==='FORM' ? el.submit() : el.click()"
                )
                await self._page.wait_for_load_state(
                    "domcontentloaded", timeout=ACT_TIMEOUT
                )
            elif atype == "WAIT":
                await asyncio.sleep(action.get("ms", 500) / 1000)
            else:
                result["error"] = f"Unknown action type: {atype}"
                return result

            result["success"] = True
            result["new_url"] = self._page.url

        except Exception as exc:
            result["error"] = str(exc)

        return result

    @property
    def current_url(self) -> str:
        if self._page:
            return self._page.url
        return ""
