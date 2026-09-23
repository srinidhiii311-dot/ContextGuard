"""
contextguard/state_collector.py — Objective Browser State Collector

Observes the live browser page state after action execution and page stabilization.
Extracts objective signals: URL, domain, page title, DOM text, forms, inputs, buttons,
links, and screenshot.
NO attack keywords, NO test case awareness.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from backend.database.db import ContextGuardRuntimeDAO


@dataclass
class BrowserState:
    """Standardized representation of an observed browser state."""
    state_id:        str
    session_id:      str
    step_number:     int
    timestamp:       float
    url:             str
    domain:          str
    page_title:      str
    dom_hash:        str
    text_length:     int
    visible_text:    str
    forms:           List[Dict[str, Any]] = field(default_factory=list)
    inputs:          List[Dict[str, Any]] = field(default_factory=list)
    buttons:         List[str]            = field(default_factory=list)
    links:           List[str]            = field(default_factory=list)
    screenshot_path: str                  = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_id":        self.state_id,
            "session_id":      self.session_id,
            "step_number":     self.step_number,
            "timestamp":       self.timestamp,
            "url":             self.url,
            "domain":          self.domain,
            "page_title":      self.page_title,
            "dom_hash":        self.dom_hash,
            "text_length":     self.text_length,
            "visible_text":    self.visible_text[:1200],
            "forms":           self.forms,
            "inputs":          self.inputs,
            "buttons":         self.buttons,
            "links":           self.links,
            "screenshot_path": self.screenshot_path,
        }


class StateCollector:
    """Collects and persists objective browser states for ContextGuard analysis."""

    def __init__(self, stabilization_delay_sec: float = 0.3) -> None:
        self.stabilization_delay_sec = stabilization_delay_sec

    async def capture_from_page(
        self,
        page: Any,
        session_id: str,
        step_number: int,
        screenshot_dir: Optional[Path] = None,
    ) -> BrowserState:
        """
        Waits for page stabilization and extracts complete observable state from Playwright Page.
        """
        # Configurable stabilization delay
        if self.stabilization_delay_sec > 0:
            time.sleep(self.stabilization_delay_sec)

        url = page.url or ""
        domain = urlparse(url).netloc or "localhost"
        title = await page.title() if hasattr(page, "title") else ""

        # Run extraction JS
        js_extract = """
        () => {
            const headings = Array.from(document.querySelectorAll('h1,h2,h3'))
                .filter(e => e.offsetParent !== null)
                .map(e => e.innerText.trim().slice(0, 80));

            const buttons = Array.from(document.querySelectorAll('button,[role=button],input[type=submit],input[type=button]'))
                .filter(e => e.offsetParent !== null)
                .map(e => (e.innerText || e.value || e.getAttribute('aria-label') || '').trim().slice(0, 60))
                .filter(Boolean);

            const inputs = Array.from(document.querySelectorAll('input,select,textarea'))
                .map(e => ({
                    id: (e.id || '').slice(0, 30),
                    name: (e.name || '').slice(0, 30),
                    type: (e.type || e.tagName.toLowerCase()).slice(0, 20),
                    placeholder: (e.placeholder || '').slice(0, 40),
                    value: (e.type === 'password' ? '[hidden]' : (e.value || '')).slice(0, 40),
                    visible: e.offsetParent !== null
                }));

            const forms = Array.from(document.querySelectorAll('form')).map(f => ({
                id: f.id || '',
                action: f.getAttribute('action') || '',
                method: f.getAttribute('method') || 'GET',
                inputs_count: f.querySelectorAll('input,select').length
            }));

            const links = Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.getAttribute('href') || '')
                .filter(h => h && !h.startsWith('#') && !h.startsWith('javascript:'))
                .slice(0, 25);

            const text = document.body ? document.body.innerText.replace(/\\s+/g, ' ').trim() : '';

            return { headings, buttons, inputs, forms, links, text };
        }
        """
        try:
            dom_data = await page.evaluate(js_extract)
        except Exception:
            dom_data = {"headings": [], "buttons": [], "inputs": [], "forms": [], "links": [], "text": ""}

        visible_text = dom_data.get("text", "")
        text_length = len(visible_text)
        dom_hash = hashlib.md5(visible_text.encode("utf-8", errors="replace")).hexdigest()

        # Capture screenshot if screenshot directory provided
        screenshot_path = ""
        if screenshot_dir:
            os.makedirs(screenshot_dir, exist_ok=True)
            shot_file = screenshot_dir / f"step_{step_number}_{int(time.time()*1000)}.png"
            try:
                await page.screenshot(path=str(shot_file), full_page=False)
                screenshot_path = str(shot_file)
            except Exception:
                pass

        # Persist to database via ContextGuardRuntimeDAO
        state_id = ContextGuardRuntimeDAO.record_browser_state(
            session_id=session_id,
            step_number=step_number,
            url=url,
            domain=domain,
            page_title=title,
            dom_hash=dom_hash,
            text_length=text_length,
            forms=dom_data.get("forms", []),
            inputs=dom_data.get("inputs", []),
            buttons=dom_data.get("buttons", []),
            links=dom_data.get("links", []),
            screenshot_path=screenshot_path,
        )

        return BrowserState(
            state_id=state_id,
            session_id=session_id,
            step_number=step_number,
            timestamp=time.time(),
            url=url,
            domain=domain,
            page_title=title,
            dom_hash=dom_hash,
            text_length=text_length,
            visible_text=visible_text,
            forms=dom_data.get("forms", []),
            inputs=dom_data.get("inputs", []),
            buttons=dom_data.get("buttons", []),
            links=dom_data.get("links", []),
            screenshot_path=screenshot_path,
        )
