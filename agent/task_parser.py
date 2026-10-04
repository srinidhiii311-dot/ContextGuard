"""
agent/task_parser.py — Phase 2, Checkpoint 2.1

Turns a plain-English booking instruction into a structured intent dict.

Two modes:
  1. Rule-based (default, no LLM required) — regex + keyword extraction.
     Works offline, deterministic, good for testing.
  2. LLM-based (optional) — sends a prompt to Ollama (llama3 or similar).
     Set USE_LLM=True and have Ollama running locally.

Structured intent produced:
  {
    "origin":       str,    e.g. "Chennai"
    "destination":  str,    e.g. "Delhi"
    "date":         str,    ISO date or "" if not specified
    "passengers":   int,    default 1
    "cabin_class":  str,    "Economy" | "Business"
    "passenger_name": str,  default "Passenger"
    "raw":          str,    original instruction
  }

Done when: 10 varied phrasings of the same task all parse to the same
structured intent (Checkpoint 2.1 test).
"""

from __future__ import annotations

import json
import re
import urllib.request
from datetime import date, timedelta
from typing import Any, Dict, Optional

USE_LLM    = False          # Set True to use Ollama
LLM_MODEL  = "llama3"
LLM_URL    = "http://localhost:11434/api/generate"

# Known city names for extraction
CITIES = [
    "chennai", "delhi", "mumbai", "bangalore", "bengaluru", "kolkata",
    "hyderabad", "pune", "ahmedabad", "jaipur", "surat", "lucknow",
    "kanpur", "nagpur", "indore", "bhopal", "patna", "vadodara",
]

_CABIN_PATTERNS = [
    (re.compile(r"\b(business|biz|first\s*class)\b", re.I), "Business"),
    (re.compile(r"\b(economy|eco|coach)\b", re.I),          "Economy"),
]

_DATE_TODAY    = re.compile(r"\btoday\b", re.I)
_DATE_TOMORROW = re.compile(r"\btomorrow\b", re.I)
_DATE_IN_DAYS  = re.compile(r"\bin\s+(\d+)\s+days?\b", re.I)
_DATE_ISO      = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
_DATE_NEXT_WK  = re.compile(r"\bnext\s+week\b", re.I)

_PASSENGER_COUNT = re.compile(
    r"\b(\d+|one|two|three|four|five|six|seven|eight|nine)\s+"
    r"(passenger|person|people|adult|seat|ticket|traveller|traveler)s?\b", re.I
)
_NUM_WORDS = {
    "one":1,"two":2,"three":3,"four":4,"five":5,
    "six":6,"seven":7,"eight":8,"nine":9,
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse_task(instruction: str) -> Dict[str, Any]:
    """
    Parse a plain-English booking instruction into structured intent.

    Returns the structured dict regardless of whether rule-based or LLM mode
    is used.  Falls back to rule-based if the LLM call fails.
    """
    if USE_LLM:
        try:
            return _llm_parse(instruction)
        except Exception:
            pass  # Fall through to rule-based

    return _rule_parse(instruction)


# ---------------------------------------------------------------------------
# Rule-based parser
# ---------------------------------------------------------------------------

def _rule_parse(instruction: str) -> Dict[str, Any]:
    text_lower = instruction.lower()
    words      = text_lower.split()

    # --- Origin / destination ---
    found_cities = [c.title() for c in CITIES if c in text_lower]

    origin      = ""
    destination = ""

    # Detect "from X to Y" pattern — extract both cities from one match
    m_from_to = re.search(
        r"\bfrom\s+([a-z]+(?:\s+[a-z]+)?)\s+to\s+([a-z]+(?:\s+[a-z]+)?)\b",
        text_lower
    )
    m_to_only = re.search(r"\bto\s+([a-z]+(?:\s+[a-z]+)?)\b", text_lower)

    if m_from_to:
        # Both origin and destination in one pattern
        for c in CITIES:
            if c in m_from_to.group(1) and not origin:
                origin = c.title()
            if c in m_from_to.group(2) and not destination:
                destination = c.title()
        if not origin:
            origin = m_from_to.group(1).strip().title()
        if not destination:
            destination = m_from_to.group(2).strip().title()
    else:
        # Separate "from X" and "to Y" patterns
        m_from = re.search(r"\bfrom\s+([a-z]+(?:\s+[a-z]+)?)\b", text_lower)
        if m_from:
            for c in CITIES:
                if c in m_from.group(1):
                    origin = c.title(); break
            if not origin:
                origin = m_from.group(1).strip().title()

        if m_to_only:
            # Skip "to fly/travel/go" patterns — only use if a city follows
            for c in CITIES:
                if c in m_to_only.group(1):
                    destination = c.title(); break

    # Fallback: first two found cities
    if not origin and len(found_cities) >= 1:
        origin = found_cities[0]
    if not destination and len(found_cities) >= 2:
        destination = found_cities[1]

    # --- Cabin class ---
    cabin_class = "Economy"
    for pattern, cabin in _CABIN_PATTERNS:
        if pattern.search(instruction):
            cabin_class = cabin
            break

    # --- Date ---
    travel_date = ""
    today = date.today()

    if _DATE_TODAY.search(instruction):
        travel_date = today.isoformat()
    elif _DATE_TOMORROW.search(instruction):
        travel_date = (today + timedelta(days=1)).isoformat()
    elif _DATE_NEXT_WK.search(instruction):
        travel_date = (today + timedelta(weeks=1)).isoformat()
    else:
        m = _DATE_IN_DAYS.search(instruction)
        if m:
            travel_date = (today + timedelta(days=int(m.group(1)))).isoformat()
        else:
            m = _DATE_ISO.search(instruction)
            if m:
                travel_date = m.group(1)

    # --- Passenger count ---
    passengers = 1
    # Try "2 passengers", "two people" etc.
    m = _PASSENGER_COUNT.search(instruction)
    if m:
        raw_num = m.group(1).lower()
        passengers = _NUM_WORDS.get(raw_num, None) or int(raw_num)
    else:
        # Also catch "N economy/business tickets/seats" pattern
        m2 = re.search(
            r"\b(\d+|one|two|three|four|five|six|seven|eight|nine)\s+"
            r"(?:economy|business|eco|biz)?\s*"
            r"(?:ticket|seat|pass|adult)s?\b",
            instruction, re.I
        )
        if m2:
            raw = m2.group(1).lower()
            passengers = _NUM_WORDS.get(raw, None) or int(raw)

    # --- Passenger name (look for "for <Name>" pattern) ---
    passenger_name = "Passenger"
    m_name = re.search(r"\bfor\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b", instruction)
    if m_name:
        passenger_name = m_name.group(1)

    # --- Contact email (if specified in instruction) ---
    m_email = re.search(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", instruction)
    contact_email = m_email.group(1) if m_email else None

    # --- Add-ons policy constraint: "none" for standard booking tasks ---
    addons_allowed = "none"

    return {
        "origin":         origin,
        "destination":    destination,
        "date":           travel_date or None,
        "travel_date":    travel_date or None,
        "passengers":     passengers,
        "passenger_count": passengers,
        "cabin_class":    cabin_class,
        "passenger_name": passenger_name,
        "addons_allowed": addons_allowed,
        "contact_email":  contact_email,
        "raw":            instruction,
    }


# ---------------------------------------------------------------------------
# LLM-based parser (Ollama)
# ---------------------------------------------------------------------------

_LLM_PROMPT = """\
You are a flight booking assistant. Parse the following booking instruction
into a JSON object with exactly these keys:
  origin, destination, date (YYYY-MM-DD or empty string), passengers (integer),
  cabin_class ("Economy" or "Business"), passenger_name (string or "Passenger")

Instruction: {instruction}

Respond with ONLY valid JSON, no other text.
"""


def _llm_parse(instruction: str) -> Dict[str, Any]:
    prompt  = _LLM_PROMPT.format(instruction=instruction)
    payload = json.dumps({
        "model": LLM_MODEL, "prompt": prompt, "stream": False
    }).encode()

    req = urllib.request.Request(
        LLM_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())

    raw_response = data.get("response", "")
    # Extract JSON from response
    m = re.search(r"\{.*\}", raw_response, re.DOTALL)
    if not m:
        raise ValueError("LLM returned no JSON")

    parsed = json.loads(m.group(0))
    parsed.setdefault("raw", instruction)
    parsed.setdefault("cabin_class",    "Economy")
    parsed.setdefault("passengers",     1)
    parsed.setdefault("passenger_name", "Passenger")
    parsed.setdefault("date",           "")
    parsed.setdefault("travel_date",    parsed.get("date") or None)
    parsed.setdefault("addons_allowed", "none")
    parsed.setdefault("contact_email",  None)
    return parsed
