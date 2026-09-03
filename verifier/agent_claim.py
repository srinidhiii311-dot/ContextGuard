"""
verifier/agent_claim.py — ContextGuard

Parses and normalises the AI agent's output into a structured AgentClaim.

Why this exists
---------------
An AI agent emits free-form text or JSON describing what it believes
about the current page and what it intends to do next.  Before the
verifier can check consistency, that output must be reduced to two
clean fields:
  - belief  : what the agent thinks is true about the page right now
  - action  : what the agent wants Playwright to do next

This module handles all parsing, cleaning, and keyword extraction so
the rest of the pipeline works with typed data, not raw strings.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AgentClaim:
    """
    Structured representation of an agent's current belief and intended action.

    Fields
    ------
    belief           : What the agent believes is true about the page state.
    intended_action  : The specific browser action the agent wants to take.
    action_type      : Normalised action category (click/fill/submit/navigate/etc.).
    target_selector  : CSS selector or element description if present.
    target_text      : Button/link text the agent wants to interact with.
    raw              : Original unmodified agent output, for audit logs.
    confidence       : 0.0–1.0, set by caller if available.
    keywords         : Key terms extracted from belief for rule-based matching.
    """
    belief: str
    intended_action: str
    action_type: str = "unknown"
    target_selector: Optional[str] = None
    target_text: Optional[str] = None
    raw: str = ""
    confidence: float = 1.0
    keywords: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "belief": self.belief,
            "intended_action": self.intended_action,
            "action_type": self.action_type,
            "target_selector": self.target_selector,
            "target_text": self.target_text,
            "confidence": self.confidence,
            "keywords": self.keywords,
        }


# ---------------------------------------------------------------------------
# Action type normalisation
# ---------------------------------------------------------------------------

_ACTION_TYPE_PATTERNS: List[tuple[str, re.Pattern]] = [
    ("click",    re.compile(r"\b(click|press|tap|select|choose|activate)\b", re.I)),
    ("fill",     re.compile(r"\b(fill|type|enter|input|write|set)\b", re.I)),
    ("submit",   re.compile(r"\b(submit|send|confirm|finalise|finalize)\b", re.I)),
    ("navigate", re.compile(r"\b(navigate|go to|open|visit|load|redirect)\b", re.I)),
    ("scroll",   re.compile(r"\b(scroll|swipe|drag)\b", re.I)),
    ("extract",  re.compile(r"\b(read|extract|scrape|capture|get text)\b", re.I)),
    ("download", re.compile(r"\b(download|save file|export)\b", re.I)),
    ("upload",   re.compile(r"\b(upload|attach|file chooser)\b", re.I)),
]

# Keywords in the belief that signal dangerous state claims
_DANGEROUS_BELIEF_KEYWORDS = [
    "confirmed", "completed", "already done", "already processed",
    "payment successful", "booking confirmed", "order placed",
    "step complete", "already agreed", "already accepted",
    "no need to review", "skip", "proceed directly",
    "already verified", "automatically approved",
]

# Keywords that suggest the action is high-risk
_HIGH_RISK_ACTION_KEYWORDS = [
    "pay", "payment", "purchase", "buy", "checkout",
    "submit", "confirm", "finalize", "finalise",
    "transfer", "send money", "wire", "book",
    "sign", "agree", "accept terms",
]


def _normalise_action_type(action_text: str) -> str:
    for action_type, pattern in _ACTION_TYPE_PATTERNS:
        if pattern.search(action_text):
            return action_type
    return "unknown"


def _extract_keywords(text: str) -> List[str]:
    """Extract meaningful keywords from belief/action text."""
    # Remove common stop words and punctuation
    stop = {
        "the", "a", "an", "is", "are", "was", "were", "be", "been",
        "to", "of", "and", "or", "in", "on", "at", "for", "with",
        "this", "that", "it", "i", "my", "we", "our", "has", "have",
        "will", "would", "should", "can", "could", "already", "now",
    }
    words = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
    return [w for w in words if w not in stop][:20]


def _extract_selector(text: str) -> Optional[str]:
    """Pull out any CSS selector or #id/.class from the action text."""
    m = re.search(r'["\']([#.][^\'"]+)["\']', text)
    if m:
        return m.group(1)
    m = re.search(r'\b(#[\w-]+|\.[\w-]+)\b', text)
    if m:
        return m.group(1)
    return None


def _extract_target_text(text: str) -> Optional[str]:
    """Extract quoted button/link text from the action description."""
    m = re.search(r'"([^"]{2,60})"', text)
    if m:
        return m.group(1)
    m = re.search(r"'([^']{2,60})'", text)
    if m:
        return m.group(1)
    # Look for "click X button" / "press X"
    m = re.search(
        r'\b(?:click|press|tap|select)\s+(?:the\s+)?["\']?([A-Za-z0-9 ]{2,40}?)["\']?\s*(?:button|link|tab|option|$)',
        text, re.I
    )
    if m:
        return m.group(1).strip()
    return None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def extract_agent_claim(agent_output: Any) -> AgentClaim:
    """
    Parse agent output into a structured AgentClaim.

    Accepts:
      - dict  with keys: thought/belief, action/intended_action
      - str   JSON with those keys
      - str   free-form text (heuristic extraction)
      - tuple (belief_str, action_str)

    Returns an AgentClaim with all fields populated.
    """
    raw = str(agent_output)

    # --- Case 1: already a dict ---
    if isinstance(agent_output, dict):
        belief = (
            agent_output.get("belief")
            or agent_output.get("thought")
            or agent_output.get("reasoning")
            or agent_output.get("observation")
            or ""
        )
        action = (
            agent_output.get("intended_action")
            or agent_output.get("action")
            or agent_output.get("next_action")
            or agent_output.get("command")
            or ""
        )
        confidence = float(agent_output.get("confidence", 1.0))
        return _build_claim(str(belief), str(action), raw, confidence)

    # --- Case 2: tuple (belief, action) ---
    if isinstance(agent_output, tuple) and len(agent_output) == 2:
        return _build_claim(str(agent_output[0]), str(agent_output[1]), raw)

    # --- Case 3: JSON string ---
    if isinstance(agent_output, str):
        stripped = agent_output.strip()
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
                return extract_agent_claim(data)  # recurse with dict
            except json.JSONDecodeError:
                pass

        # --- Case 4: Free-form text with labelled fields ---
        belief = _extract_labelled_field(
            stripped,
            labels=["Thought:", "Belief:", "I think", "I believe",
                    "Observation:", "Context:"],
        )
        action = _extract_labelled_field(
            stripped,
            labels=["Action:", "Intended action:", "Next action:",
                    "I will", "I want to", "Step:"],
        )

        if belief or action:
            return _build_claim(belief or stripped[:200], action or stripped[:200], raw)

        # --- Case 5: Treat entire string as both belief and action ---
        return _build_claim(stripped[:300], stripped[:300], raw)

    # Fallback
    return _build_claim("Unknown", "Unknown", raw)


def _extract_labelled_field(text: str, labels: List[str]) -> str:
    """Find the first labelled section in text and return its content."""
    for label in labels:
        pattern = re.compile(
            re.escape(label) + r"\s*(.+?)(?=\n[A-Z][a-z]+:|\Z)",
            re.IGNORECASE | re.DOTALL,
        )
        m = pattern.search(text)
        if m:
            return m.group(1).strip()[:400]
    return ""


def _build_claim(
    belief: str,
    action: str,
    raw: str,
    confidence: float = 1.0,
) -> AgentClaim:
    """Construct an AgentClaim from normalised belief and action strings."""
    action_type   = _normalise_action_type(action)
    selector      = _extract_selector(action)
    target_text   = _extract_target_text(action)
    keywords      = _extract_keywords(belief + " " + action)

    return AgentClaim(
        belief=belief.strip(),
        intended_action=action.strip(),
        action_type=action_type,
        target_selector=selector,
        target_text=target_text,
        raw=raw,
        confidence=confidence,
        keywords=keywords,
    )


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def claim_contains_dangerous_belief(claim: AgentClaim) -> bool:
    """Return True if the agent's belief asserts a dangerous state."""
    lower = claim.belief.lower()
    return any(kw in lower for kw in _DANGEROUS_BELIEF_KEYWORDS)


def claim_is_high_risk_action(claim: AgentClaim) -> bool:
    """Return True if the intended action is financially or irreversibly risky."""
    lower = claim.intended_action.lower()
    return any(kw in lower for kw in _HIGH_RISK_ACTION_KEYWORDS)
