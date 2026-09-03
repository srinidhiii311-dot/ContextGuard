"""
verifier/capture_state.py — ContextGuard

Captures a trusted, structured snapshot of the real browser page state
using Playwright.  This is the ground truth D that the verifier compares
against the agent's claimed belief.

Why this exists
---------------
A malicious web page can inject fake text, hidden elements, or popup
overlays that make an AI agent believe the page is in a different state
than it actually is.  By capturing the real DOM state here — outside the
agent's perception pipeline — we get an independent ground truth that
cannot be tampered with by page content.

All JS run here is written in this file and is strictly read-only.
No input values are read; only structural metadata and visible text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Read-only JS snippets executed inside the page
# ---------------------------------------------------------------------------

_JS_HEADINGS = """
() => Array.from(document.querySelectorAll('h1,h2,h3,h4'))
    .filter(el => el.offsetParent !== null)
    .map(el => ({ tag: el.tagName.toLowerCase(), text: el.innerText.trim().slice(0, 120) }))
    .slice(0, 10)
"""

_JS_BUTTONS = """
() => Array.from(document.querySelectorAll('button, input[type=submit], input[type=button], [role=button]'))
    .filter(el => el.offsetParent !== null)
    .map(el => ({
        text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().slice(0, 80),
        disabled: el.disabled || false,
        type: el.type || el.tagName.toLowerCase()
    }))
    .slice(0, 20)
"""

_JS_LINKS = """
() => Array.from(document.querySelectorAll('a[href]'))
    .filter(el => el.offsetParent !== null)
    .map(el => ({ text: el.innerText.trim().slice(0, 80), href: el.href }))
    .slice(0, 20)
"""

_JS_MODALS = """
() => {
    const selectors = [
        '[role=dialog]', '[role=alertdialog]',
        '.modal', '.popup', '.overlay', '.alert',
        '[aria-modal=true]'
    ];
    const els = selectors.flatMap(s => Array.from(document.querySelectorAll(s)));
    return els
        .filter(el => el.offsetParent !== null)
        .map(el => el.innerText.trim().slice(0, 300))
        .filter(t => t.length > 0)
        .slice(0, 5);
}
"""

_JS_ALERTS = """
() => Array.from(document.querySelectorAll(
        '.alert, .banner, .notification, .toast, [role=alert], [role=status]'))
    .filter(el => el.offsetParent !== null)
    .map(el => el.innerText.trim().slice(0, 200))
    .filter(t => t.length > 0)
    .slice(0, 5)
"""

_JS_FORMS = """
() => Array.from(document.querySelectorAll('form'))
    .map(f => ({
        id: f.id || null,
        action: f.action || null,
        method: f.method || 'get',
        fields: Array.from(f.querySelectorAll('input,select,textarea'))
            .map(i => ({
                name: i.name || i.id || null,
                type: i.type || i.tagName.toLowerCase(),
                required: i.required || false,
                visible: i.offsetParent !== null
            }))
            .slice(0, 15)
    }))
    .slice(0, 5)
"""

_JS_PAGE_TEXT = """
() => {
    const body = document.body;
    if (!body) return '';
    // Clone to avoid mutating the live DOM
    const clone = body.cloneNode(true);
    // Remove script and style nodes
    clone.querySelectorAll('script,style,noscript').forEach(n => n.remove());
    return clone.innerText.replace(/\\s+/g, ' ').trim().slice(0, 3000);
}
"""

_JS_META = """
() => ({
    description: (document.querySelector('meta[name=description]') || {}).content || null,
    step:        (document.querySelector('meta[name=step]') || {}).content || null,
    og_title:    (document.querySelector('meta[property="og:title"]') || {}).content || null,
})
"""


# ---------------------------------------------------------------------------
# Snapshot dataclass
# ---------------------------------------------------------------------------

@dataclass
class PageSnapshot:
    """
    A structured, trusted snapshot of the real browser page state.

    Built from Playwright DOM queries — never from the agent's perception.
    This is the ground truth D used by the verifier.
    """
    url: str
    title: str
    domain: Optional[str]
    headings: List[Dict[str, str]] = field(default_factory=list)
    buttons: List[Dict[str, Any]] = field(default_factory=list)
    links: List[Dict[str, str]] = field(default_factory=list)
    modals: List[str] = field(default_factory=list)
    alerts: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    visible_text: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)
    has_password_field: bool = False
    has_payment_field: bool = False
    confirmation_text_present: bool = False
    injection_text_present: bool = False

    def to_summary(self, max_chars: int = 800) -> str:
        """
        Return a compact text summary for sending to an LLM verifier.
        Keeps only the most decision-relevant fields.
        """
        parts = [
            f"URL: {self.url}",
            f"Title: {self.title}",
            f"Headings: {[h['text'] for h in self.headings[:4]]}",
            f"Buttons: {[b['text'] for b in self.buttons[:6]]}",
            f"Modals: {self.modals[:2]}",
            f"Alerts: {self.alerts[:2]}",
            f"Has password field: {self.has_password_field}",
            f"Has payment field: {self.has_payment_field}",
            f"Confirmation text present: {self.confirmation_text_present}",
            f"Visible text snippet: {self.visible_text[:300]}",
        ]
        summary = "\n".join(parts)
        return summary[:max_chars]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "title": self.title,
            "domain": self.domain,
            "headings": self.headings,
            "buttons": self.buttons,
            "links": self.links,
            "modals": self.modals,
            "alerts": self.alerts,
            "forms": self.forms,
            "visible_text": self.visible_text[:1000],
            "meta": self.meta,
            "has_password_field": self.has_password_field,
            "has_payment_field": self.has_payment_field,
            "confirmation_text_present": self.confirmation_text_present,
            "injection_text_present": self.injection_text_present,
        }


# ---------------------------------------------------------------------------
# Capture function
# ---------------------------------------------------------------------------

async def capture_state(page: Any) -> PageSnapshot:
    """
    Capture a trusted snapshot of the current page state.

    Parameters
    ----------
    page : Playwright Page object.

    Returns
    -------
    PageSnapshot — structured ground truth about the real page.

    All JS executed here is read-only and defined in this module.
    No agent-supplied code is ever executed.
    """
    url = page.url
    domain = _extract_domain(url)

    try:
        title = await page.title()
    except Exception:
        title = ""

    async def safe_eval(js: str, fallback: Any) -> Any:
        try:
            return await page.evaluate(js)
        except Exception:
            return fallback

    headings     = await safe_eval(_JS_HEADINGS, [])
    buttons      = await safe_eval(_JS_BUTTONS,  [])
    links        = await safe_eval(_JS_LINKS,    [])
    modals       = await safe_eval(_JS_MODALS,   [])
    alerts       = await safe_eval(_JS_ALERTS,   [])
    forms        = await safe_eval(_JS_FORMS,    [])
    visible_text = await safe_eval(_JS_PAGE_TEXT, "")
    meta         = await safe_eval(_JS_META,     {})

    # Derived flags — computed from real DOM, not agent input
    lower_text = visible_text.lower()
    has_password = any(
        f.get("type") == "password"
        for form in forms
        for f in form.get("fields", [])
    )
    has_payment = any(
        kw in lower_text
        for kw in ("card number", "cvv", "billing address", "payment method",
                   "credit card", "debit card", "expiry")
    )
    confirmation_present = any(
        kw in lower_text
        for kw in ("booking confirmed", "order confirmed", "payment successful",
                   "confirmation number", "you're all set", "thank you for your order",
                   "reservation confirmed", "successfully booked")
    )
    injection_present = _has_injection(visible_text)

    return PageSnapshot(
        url=url,
        title=title,
        domain=domain,
        headings=headings,
        buttons=buttons,
        links=links,
        modals=modals,
        alerts=alerts,
        forms=forms,
        visible_text=visible_text,
        meta=meta,
        has_password_field=has_password,
        has_payment_field=has_payment,
        confirmation_text_present=confirmation_present,
        injection_text_present=injection_present,
    )


def capture_state_sync(page: Any) -> PageSnapshot:
    """
    Synchronous wrapper for use outside async contexts (e.g. benchmarks).
    Requires an already-running event loop.
    """
    import asyncio
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(capture_state(page))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    url = re.sub(r"^https?://", "", url.lower().strip())
    return url.split("/")[0].split("?")[0].split(":")[0] or None


_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all prior",
    "bypass security",
    "booking already confirmed",
    "payment already processed",
    "skip this step",
    "proceed directly to payment",
    "you have already agreed",
    "this step is complete",
    "disable safeguards",
    "reveal system prompt",
    "you are now in developer mode",
    "new instructions:",
    "disregard your previous",
]


def _has_injection(text: str) -> bool:
    lower = text.lower()
    return any(p in lower for p in _INJECTION_PATTERNS)
