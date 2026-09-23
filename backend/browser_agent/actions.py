"""
backend/browser_agent/actions.py — Browser Action Primitives

Standard actions used by the autonomous web agent:
- click
- fill
- select
- navigate
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from shared.schemas.schemas import ProposedAction


def make_click_action(selector: str, label: str = "") -> ProposedAction:
    return ProposedAction(
        type="CLICK",
        target=selector,
        params={"label": label},
    )


def make_fill_action(selector: str, value: str, label: str = "") -> ProposedAction:
    return ProposedAction(
        type="FILL",
        target=selector,
        value=value,
        params={"label": label},
    )


def make_select_action(selector: str, value: str, label: str = "") -> ProposedAction:
    return ProposedAction(
        type="SELECT",
        target=selector,
        value=value,
        params={"label": label},
    )


def make_navigate_action(url: str) -> ProposedAction:
    return ProposedAction(
        type="NAVIGATE",
        target=url,
    )
