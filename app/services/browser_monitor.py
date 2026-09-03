"""
Browser Monitor — ContextGuard Services

Attaches real-time Playwright event listeners to a live browser session.
Every navigation, DOM load, form detection, and input field scan is
automatically captured, evaluated through the ContextGuard decision engine,
and recorded to the monitor_events table.

Architecture
------------
Agent / user opens a browser session via ContextGuard.
BrowserMonitor hooks into that session's Playwright Page object:

    page.on("framenavigated") → captures URL change
    page.on("domcontentloaded") → triggers DOM snapshot + form scan
    page.on("load") → final page scan after all resources load

Each event builds a BrowserAction (action_type=navigate or extract),
runs it through the decision engine, and persists the result.

Security notes
--------------
- DOM content is truncated to 2000 chars before storage.
- Password field VALUES are never read — only their presence is counted.
- No arbitrary JS from the page is executed; all evaluation JS is
  written here and is read-only.
- Monitoring can be stopped cleanly; listeners are removed on stop.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from sqlalchemy.orm import Session

from app.core.decision_engine import decision_engine
from app.database.database import SessionLocal, store_monitor_event
from app.models.action import ActionSource, ActionTarget, ActionType, BrowserAction, SourceType
from app.services.audit_logger import audit_logger, mask_payload

# Playwright is optional — monitor degrades gracefully without it.
try:
    from playwright.async_api import Page
    _playwright_available = True
except ImportError:
    _playwright_available = False

# ---------------------------------------------------------------------------
# JS snippets — read-only, written here, never sourced from the page
# ---------------------------------------------------------------------------

_JS_SCAN_PAGE = """
() => {
    const forms     = document.querySelectorAll('form').length;
    const inputs    = document.querySelectorAll('input:not([type=hidden])').length;
    const passwords = document.querySelectorAll('input[type=password]').length;
    const extLinks  = Array.from(document.querySelectorAll('a[href]'))
                        .filter(a => {
                            try {
                                return new URL(a.href).hostname !== window.location.hostname;
                            } catch { return false; }
                        }).length;
    const metaDesc  = document.querySelector('meta[name=description]');
    const canonical = document.querySelector('link[rel=canonical]');
    return {
        forms,
        inputs,
        passwords,
        ext_links: extLinks,
        meta_description: metaDesc ? metaDesc.content : null,
        canonical_url: canonical ? canonical.href : null,
        has_payment_form: document.querySelectorAll(
            'input[name*=card], input[name*=cvv], input[name*=billing]'
        ).length > 0
    };
}
"""

_JS_DOM_SNIPPET = """
() => {
    // Return only the visible text content and key structural elements.
    // Never returns input values — only presence/structure.
    const body = document.body;
    if (!body) return '';
    return body.innerText.slice(0, 2000);
}
"""


# ---------------------------------------------------------------------------
# Active monitor state per session
# ---------------------------------------------------------------------------

class _MonitorState:
    def __init__(self, session_id: str, agent_id: str):
        self.session_id = session_id
        self.agent_id = agent_id
        self.active = True
        self.event_count = 0
        self.last_url: Optional[str] = None
        self.blocked_count = 0


# ---------------------------------------------------------------------------
# BrowserMonitor
# ---------------------------------------------------------------------------

class BrowserMonitor:
    """
    Attaches to a Playwright Page and records all browsing activity
    through ContextGuard's evaluation pipeline in real time.
    """

    def __init__(self) -> None:
        # session_id -> _MonitorState
        self._monitors: Dict[str, _MonitorState] = {}
        # session_id -> Playwright Page object
        self._pages: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start_monitoring(
        self,
        session_id: str,
        agent_id: str,
        page: Any,
        start_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Attach event listeners to a Playwright page and begin recording.

        Parameters
        ----------
        session_id : Existing ContextGuard session ID.
        agent_id   : Agent identifier for audit records.
        page       : Playwright Page object from browser_service.
        start_url  : Optional URL to navigate to immediately.
        """
        if not _playwright_available:
            return {"status": "error", "message": "Playwright not available"}

        if session_id in self._monitors and self._monitors[session_id].active:
            return {"status": "already_active", "session_id": session_id}

        state = _MonitorState(session_id=session_id, agent_id=agent_id)
        self._monitors[session_id] = state
        self._pages[session_id] = page

        # Attach Playwright event listeners
        page.on("framenavigated",   lambda frame: asyncio.create_task(
            self._on_navigation(session_id, frame)
        ))
        page.on("load",             lambda: asyncio.create_task(
            self._on_page_load(session_id)
        ))
        page.on("dialog",           lambda dialog: asyncio.create_task(
            self._on_dialog(session_id, dialog)
        ))
        page.on("download",         lambda download: asyncio.create_task(
            self._on_download(session_id, download)
        ))
        page.on("filechooser",      lambda fc: asyncio.create_task(
            self._on_file_chooser(session_id, fc)
        ))

        if start_url:
            try:
                await page.goto(start_url, timeout=15_000, wait_until="domcontentloaded")
            except Exception as exc:
                pass  # navigation error logged by on_navigation

        return {
            "status": "monitoring",
            "session_id": session_id,
            "agent_id": agent_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

    async def stop_monitoring(self, session_id: str) -> Dict[str, Any]:
        """Stop monitoring a session and remove event listeners."""
        state = self._monitors.get(session_id)
        if not state:
            return {"status": "not_found", "session_id": session_id}

        state.active = False
        events_recorded = state.event_count

        page = self._pages.pop(session_id, None)
        if page:
            try:
                page.remove_all_listeners()
            except Exception:
                pass

        self._monitors.pop(session_id, None)

        return {
            "status": "stopped",
            "session_id": session_id,
            "events_recorded": events_recorded,
        }

    def is_monitoring(self, session_id: str) -> bool:
        """Return True if a monitor is active for this session."""
        return (
            session_id in self._monitors
            and self._monitors[session_id].active
        )

    def list_active_sessions(self) -> List[str]:
        """Return session IDs currently being monitored."""
        return [
            sid for sid, state in self._monitors.items()
            if state.active
        ]

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def _on_navigation(self, session_id: str, frame: Any) -> None:
        """Called on every frame navigation. Only processes main frame."""
        state = self._monitors.get(session_id)
        if not state or not state.active:
            return
        try:
            if not frame.is_detached() and frame.parent_frame is None:
                url = frame.url
                if url and url != state.last_url and url != "about:blank":
                    state.last_url = url
                    await self._record_navigation(session_id, url)
        except Exception:
            pass

    async def _on_page_load(self, session_id: str) -> None:
        """Called after full page load. Scans DOM for forms and inputs."""
        state = self._monitors.get(session_id)
        if not state or not state.active:
            return
        try:
            await self._record_dom_snapshot(session_id)
        except Exception:
            pass

    async def _on_dialog(self, session_id: str, dialog: Any) -> None:
        """Capture and auto-dismiss dialogs; log them as monitor events."""
        state = self._monitors.get(session_id)
        if not state or not state.active:
            return
        try:
            page = self._pages.get(session_id)
            url = page.url if page else None
            await self._persist_event(session_id, {
                "event_type": "dialog_detected",
                "url": url,
                "domain": _extract_domain(url),
                "raw_metadata": {
                    "dialog_type": dialog.type,
                    "dialog_message": dialog.message[:200],
                },
            })
            await dialog.dismiss()
        except Exception:
            pass

    async def _on_download(self, session_id: str, download: Any) -> None:
        """Capture download events and evaluate them as BrowserActions."""
        state = self._monitors.get(session_id)
        if not state or not state.active:
            return
        try:
            page = self._pages.get(session_id)
            url = download.url
            suggested_name = download.suggested_filename
            action = self._build_action(
                session_id=session_id,
                agent_id=state.agent_id,
                action_type=ActionType.download,
                url=url,
                current_domain=_extract_domain(page.url if page else url),
                payload={"filename": suggested_name},
                source_type=SourceType.page_content,
                content=f"Automatic download detected: {suggested_name}",
            )
            await self._evaluate_and_persist(session_id, action, "download_detected")
        except Exception:
            pass

    async def _on_file_chooser(self, session_id: str, fc: Any) -> None:
        """Capture file chooser (upload) dialogs."""
        state = self._monitors.get(session_id)
        if not state or not state.active:
            return
        try:
            page = self._pages.get(session_id)
            url = page.url if page else None
            await self._persist_event(session_id, {
                "event_type": "file_upload_dialog",
                "url": url,
                "domain": _extract_domain(url),
                "raw_metadata": {"multiple": fc.is_multiple()},
            })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Core capture methods
    # ------------------------------------------------------------------

    async def _record_navigation(self, session_id: str, url: str) -> None:
        """Record a URL navigation and evaluate it as a BrowserAction."""
        state = self._monitors.get(session_id)
        if not state:
            return

        domain = _extract_domain(url)
        action = self._build_action(
            session_id=session_id,
            agent_id=state.agent_id,
            action_type=ActionType.navigate,
            url=url,
            current_domain=domain,
            source_type=SourceType.user,
        )
        await self._evaluate_and_persist(session_id, action, "navigation")

    async def _record_dom_snapshot(self, session_id: str) -> None:
        """Scan the loaded page DOM and record structural metadata."""
        state = self._monitors.get(session_id)
        if not state:
            return

        page = self._pages.get(session_id)
        if not page:
            return

        url = page.url
        if not url or url == "about:blank":
            return

        domain = _extract_domain(url)

        try:
            title = await page.title()
        except Exception:
            title = None

        # Run read-only JS scans
        try:
            scan = await page.evaluate(_JS_SCAN_PAGE)
        except Exception:
            scan = {}

        try:
            dom_text = await page.evaluate(_JS_DOM_SNIPPET)
        except Exception:
            dom_text = None

        # Detect prompt injection in visible page text
        injection_detected = _has_injection(dom_text or "")

        event: Dict[str, Any] = {
            "event_type": "dom_snapshot",
            "url": url,
            "domain": domain,
            "page_title": title,
            "dom_snippet": (dom_text or "")[:2000],
            "forms_found": scan.get("forms", 0),
            "inputs_found": scan.get("inputs", 0),
            "password_fields": scan.get("passwords", 0),
            "external_links": scan.get("ext_links", 0),
            "raw_metadata": {
                "has_payment_form": scan.get("has_payment_form", False),
                "meta_description": scan.get("meta_description"),
                "canonical_url": scan.get("canonical_url"),
                "injection_detected": injection_detected,
            },
        }

        # If password or payment fields found, also run a risk evaluation
        if scan.get("passwords", 0) > 0 or scan.get("has_payment_form", False):
            field = "password" if scan.get("passwords", 0) > 0 else "payment"
            action = self._build_action(
                session_id=session_id,
                agent_id=state.agent_id,
                action_type=ActionType.fill,
                url=url,
                current_domain=domain,
                element_type=field,
                field_name=field,
                source_type=SourceType.page_content,
                content=dom_text[:500] if dom_text else None,
            )
            dec = decision_engine.evaluate(action, state.blocked_count)
            if dec.decision == "BLOCK":
                state.blocked_count += 1
            event["risk_score"] = dec.risk_score
            event["decision"] = str(dec.decision)
            event["risk_factors"] = dec.risk_factors
            event["action_id"] = action.action_id
            event["event_type"] = "risk_evaluation"

        if injection_detected:
            event["event_type"] = "injection_detected"

        await self._persist_event(session_id, event)

        # Separate event for password field warning
        if scan.get("passwords", 0) > 0:
            await self._persist_event(session_id, {
                "event_type": "password_field_detected",
                "url": url,
                "domain": domain,
                "page_title": title,
                "password_fields": scan.get("passwords", 0),
                "raw_metadata": {"source": "dom_scan"},
            })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_action(
        self,
        session_id: str,
        agent_id: str,
        action_type: ActionType,
        url: Optional[str] = None,
        current_domain: Optional[str] = None,
        element_type: Optional[str] = None,
        field_name: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        source_type: SourceType = SourceType.user,
        content: Optional[str] = None,
    ) -> BrowserAction:
        return BrowserAction(
            action_id=str(uuid.uuid4()),
            session_id=session_id,
            agent_id=agent_id,
            action_type=action_type,
            target=ActionTarget(
                url=url,
                element_type=element_type,
                field_name=field_name,
            ),
            payload=payload or {},
            source=ActionSource(
                source_type=source_type,
                trusted=(source_type in (SourceType.user, SourceType.system)),
                content=content,
                origin_url=url,
            ),
            current_domain=current_domain,
        )

    async def _evaluate_and_persist(
        self,
        session_id: str,
        action: BrowserAction,
        event_type: str,
    ) -> None:
        """Run decision engine on action and persist result as monitor event."""
        state = self._monitors.get(session_id)
        if not state:
            return

        try:
            dec = decision_engine.evaluate(action, state.blocked_count)
            if str(dec.decision) == "BLOCK":
                state.blocked_count += 1

            event: Dict[str, Any] = {
                "event_type": event_type,
                "url": action.target.url,
                "domain": action.current_domain,
                "risk_score": dec.risk_score,
                "decision": str(dec.decision),
                "risk_factors": dec.risk_factors,
                "action_id": action.action_id,
                "raw_metadata": {
                    "reasons": dec.reasons[:3],
                    "matched_policies": dec.matched_policies,
                    "tainted": dec.tainted,
                },
            }
            await self._persist_event(session_id, event)

            # Also write to audit log
            db = SessionLocal()
            try:
                audit_logger.log(db, action, dec, "monitor_captured")
            finally:
                db.close()

        except Exception:
            pass

    async def _persist_event(
        self,
        session_id: str,
        event: Dict[str, Any],
    ) -> None:
        """Write a monitor event to the database."""
        state = self._monitors.get(session_id)
        if not state:
            return

        event["session_id"] = session_id
        event.setdefault("timestamp", datetime.now(timezone.utc))

        db = SessionLocal()
        try:
            store_monitor_event(db, event)
            state.event_count += 1
        except Exception:
            pass
        finally:
            db.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    url = re.sub(r"^https?://", "", url.lower().strip())
    domain = url.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    return domain or None


_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all prior",
    "bypass security",
    "disable safeguards",
    "reveal confidential",
    "reveal system prompt",
    "upload local files",
    "send data externally",
    "submit credentials",
    "do not tell the user",
    "continue without approval",
    "override the security policy",
    "jailbreak",
    "you are now in developer mode",
    "new instructions:",
    "disregard your previous",
    "forget your previous",
]


def _has_injection(text: str) -> bool:
    """Check visible page text for prompt-injection patterns."""
    lower = text.lower()
    return any(p in lower for p in _INJECTION_PATTERNS)


# Module-level singleton
browser_monitor = BrowserMonitor()
