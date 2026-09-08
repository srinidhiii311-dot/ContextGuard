"""
attacks/payloads.py — Phase 4

Central dispatcher: given (attack_type, target_page) returns the HTML
injection payload.  This is the only import backend/main.py needs.

Attack types
------------
prompt_injection     Visible "AI agent instruction" text block
context_manipulation Fake "updated user preference" block
hidden_content       display:none instruction text
dom_manipulation     Inline JS that silently mutates form values
navigation_attack    Injected link / JS that rewrites navigation targets
"""

from __future__ import annotations

from attacks import (
    context_manipulation,
    dom_manipulation,
    hidden_content,
    navigation_attack,
    prompt_injection,
)

_DISPATCH = {
    "prompt_injection":     prompt_injection.get_payload,
    "context_manipulation": context_manipulation.get_payload,
    "hidden_content":       hidden_content.get_payload,
    "dom_manipulation":     dom_manipulation.get_payload,
    "navigation_attack":    navigation_attack.get_payload,
}

VALID_ATTACK_TYPES = list(_DISPATCH.keys())
VALID_TARGET_PAGES = ["search", "results", "passenger", "review", "confirmed"]


def get_attack_payload(attack_type: str, target_page: str) -> str:
    """
    Return the HTML injection payload for the given attack type and page.
    Raises ValueError for unknown attack types.
    """
    fn = _DISPATCH.get(attack_type)
    if fn is None:
        raise ValueError(
            f"Unknown attack type '{attack_type}'. "
            f"Valid types: {VALID_ATTACK_TYPES}"
        )
    return fn(target_page)


def get_all_payloads_for_page(target_page: str) -> dict:
    """Return all attack payloads for a given page (used in tests)."""
    return {
        attack_type: fn(target_page)
        for attack_type, fn in _DISPATCH.items()
    }
