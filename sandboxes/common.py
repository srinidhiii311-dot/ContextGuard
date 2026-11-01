"""
sandboxes/common.py — Shared Mock Site Engine & Injection Slot Renderer (Block 2)

Provides:
- Reusable HTML layout with standard CSS and the 7 fixed injection slots
- State reset mechanism (/reset)
- Injection slot state management (/inject)
- Deterministic mock seed data
"""

from __future__ import annotations

import html
import json
from typing import Any, Dict, Optional
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse

SLOT_MARKERS = [
    "hidden_css",
    "off_screen",
    "html_comment",
    "system_banner",
    "user_content",
    "form_action_override",
    "overlay",
]


class BaseSandboxState:
    """Manages injection slots and mutable runtime state for a sandbox."""
    def __init__(self, site_id: str, port: int):
        self.site_id = site_id
        self.port = port
        self.slots: Dict[str, str] = {marker: "" for marker in SLOT_MARKERS}
        self.data: Dict[str, Any] = {}
        self.initial_seed: Dict[str, Any] = {}

    def set_seed(self, seed: Dict[str, Any]) -> None:
        self.initial_seed = json.loads(json.dumps(seed))
        self.reset()

    def reset(self) -> None:
        self.slots = {marker: "" for marker in SLOT_MARKERS}
        self.data = json.loads(json.dumps(self.initial_seed))

    def set_slot(self, slot_id: str, content: str) -> None:
        if slot_id in self.slots:
            self.slots[slot_id] = content


def render_injection_slots(slots: Dict[str, str]) -> Dict[str, str]:
    """Renders HTML for each injection slot with its fixed marker."""
    hidden_css_content = html.escape(slots.get("hidden_css", ""))
    hidden_css_html = (
        f'<span id="slot-hidden-css" class="injection-slot injection-hidden-css" '
        f'style="display:none;" data-slot="hidden_css">{hidden_css_content}</span>'
    )

    off_screen_content = html.escape(slots.get("off_screen", ""))
    off_screen_html = (
        f'<div id="slot-off-screen" class="injection-slot injection-off-screen" '
        f'style="position:absolute;left:-9999px;top:-9999px;" data-slot="off_screen">{off_screen_content}</div>'
    )

    comment_content = slots.get("html_comment", "").replace("--", "__")
    comment_html = f"<!-- [INJECTION_SLOT:html_comment] {comment_content} -->"

    banner_content = slots.get("system_banner", "")
    if banner_content:
        banner_html = (
            f'<div id="slot-system-banner" class="injection-slot injection-system-banner" data-slot="system_banner">'
            f'<div class="system-alert-box" style="background:#fee2e2;border:1px solid #ef4444;color:#991b1b;padding:12px;margin-bottom:16px;border-radius:6px;font-weight:500;">'
            f'{html.escape(banner_content)}</div></div>'
        )
    else:
        banner_html = '<div id="slot-system-banner" class="injection-slot injection-system-banner" data-slot="system_banner"></div>'

    user_content_str = html.escape(slots.get("user_content", ""))
    user_content_html = (
        f'<div id="slot-user-content" class="injection-slot injection-user-content" data-slot="user_content">{user_content_str}</div>'
    )

    override_content = html.escape(slots.get("form_action_override", ""))
    override_html = (
        f'<input type="hidden" id="slot-form-action-override" class="injection-slot injection-form-action-override" '
        f'data-slot="form_action_override" data-override-action="{override_content}" />'
    )

    overlay_content = slots.get("overlay", "")
    if overlay_content:
        overlay_html = (
            f'<div id="slot-overlay" class="injection-slot injection-overlay" data-slot="overlay" '
            f'style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);color:white;display:flex;align-items:center;justify-content:center;z-index:99999;">'
            f'<div style="background:#1e293b;padding:24px;border-radius:8px;max-width:500px;">{html.escape(overlay_content)}</div></div>'
        )
    else:
        overlay_html = '<div id="slot-overlay" class="injection-slot injection-overlay" data-slot="overlay" style="display:none;"></div>'

    return {
        "hidden_css": hidden_css_html,
        "off_screen": off_screen_html,
        "html_comment": comment_html,
        "system_banner": banner_html,
        "user_content": user_content_html,
        "form_action_override": override_html,
        "overlay": overlay_html,
    }


def render_page_html(
    title: str,
    site_name: str,
    nav_links: list[tuple[str, str]],
    content_html: str,
    slots: Dict[str, str],
    action_url: Optional[str] = None,
) -> str:
    """Wraps body content in a complete HTML document with fixed injection slots."""
    rendered_slots = render_injection_slots(slots)
    nav_items_html = "".join(
        f'<a href="{path}" style="color:#2563eb;text-decoration:none;font-weight:600;margin-right:16px;">{label}</a>'
        for path, label in nav_links
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{html.escape(title)} - {html.escape(site_name)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; background: #f8fafc; color: #1e293b; }}
    header {{ background: #ffffff; border-bottom: 1px solid #e2e8f0; padding: 16px 32px; display: flex; justify-content: space-between; align-items: center; }}
    main {{ max-width: 900px; margin: 32px auto; padding: 24px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
    h1 {{ margin-top: 0; color: #0f172a; font-size: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
    th {{ background: #f1f5f9; font-weight: 600; }}
    .form-group {{ margin-bottom: 16px; }}
    label {{ display: block; font-weight: 600; margin-bottom: 6px; font-size: 14px; }}
    input[type="text"], input[type="password"], input[type="number"], select, textarea {{ width: 100%; box-sizing: border-box; padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; }}
    button, input[type="submit"] {{ background: #2563eb; color: #ffffff; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px; }}
    button:hover, input[type="submit"]:hover {{ background: #1d4ed8; }}
    .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
    .badge-success {{ background: #dcfce7; color: #166534; }}
    .badge-warn {{ background: #fef9c3; color: #854d0e; }}
  </style>
</head>
<body>
  {rendered_slots["overlay"]}
  {rendered_slots["html_comment"]}
  <header>
    <div style="font-size: 20px; font-weight: bold; color: #0f172a;">{html.escape(site_name)}</div>
    <nav>{nav_items_html}</nav>
  </header>
  <main>
    {rendered_slots["system_banner"]}
    {content_html}
    {rendered_slots["user_content"]}
    {rendered_slots["hidden_css"]}
    {rendered_slots["off_screen"]}
    {rendered_slots["form_action_override"]}
  </main>
</body>
</html>"""

