"""
backend/session_controller/intent_parser.py — Natural Language Intent Parser

Extracts structured immutable intent from user instructions:
- origin
- destination
- cabin_class
- passenger_count
- date
"""

from __future__ import annotations

import datetime
import re
from typing import Any, Dict

from shared.schemas.schemas import TrustedIntent

AIRPORT_CITIES = [
    "Chennai", "Bangalore", "Delhi", "Mumbai", "Kolkata", "Hyderabad", "Goa", "Pune", "Ahmedabad"
]


def parse_natural_language_intent(instruction: str, defaults: Dict[str, Any] = None) -> TrustedIntent:
    defaults = defaults or {}
    text = instruction.strip()
    lower = text.lower()

    # 1. Cabin Class
    cabin_class = defaults.get("cabin_class")
    if not cabin_class:
        if "business" in lower:
            cabin_class = "Business"
        elif "first" in lower:
            cabin_class = "First"
        else:
            cabin_class = "Economy"

    # 2. Passenger count
    passenger_count = defaults.get("passenger_count")
    if not passenger_count:
        pax_match = re.search(r"(\d+)\s*(?:business|economy)?\s*(?:ticket|tickets|passenger|passengers|pax|seat|seats)", lower)
        if pax_match:
            passenger_count = int(pax_match.group(1))
        elif "two" in lower:
            passenger_count = 2
        elif "three" in lower:
            passenger_count = 3
        elif "four" in lower:
            passenger_count = 4
        else:
            passenger_count = 1

    # 3. Origin and Destination
    origin = defaults.get("origin")
    destination = defaults.get("destination")

    # Match "from X to Y"
    from_to = re.search(r"from\s+([A-Za-z\s]+?)\s+to\s+([A-Za-z\s]+?)(?:\s+for|\s+on|\s*$)", text, re.IGNORECASE)
    if from_to:
        cand_orig = from_to.group(1).strip()
        cand_dest = from_to.group(2).strip()
        for city in AIRPORT_CITIES:
            if city.lower() in cand_orig.lower():
                origin = city
            if city.lower() in cand_dest.lower():
                destination = city

    if not origin or not destination:
        # Match cities found in order
        found_cities = []
        for city in AIRPORT_CITIES:
            idx = text.lower().find(city.lower())
            if idx != -1:
                found_cities.append((idx, city))
        found_cities.sort(key=lambda x: x[0])
        if len(found_cities) >= 2:
            if not origin:
                origin = found_cities[0][1]
            if not destination:
                destination = found_cities[1][1]

    origin = origin or "Chennai"
    destination = destination or "Bangalore"

    # 4. Date
    date = defaults.get("date") or defaults.get("travel_date")
    if not date:
        date_match = re.search(r"(\d{4}-\d{2}-\d{2})", text)
        if date_match:
            date = date_match.group(1)
        else:
            date = (datetime.date.today() + datetime.timedelta(days=7)).isoformat()

    # 5. Add-ons policy (default "none" for booking tasks unless user explicitly requested)
    addons_allowed = defaults.get("addons_allowed", "none")

    # 6. Contact email (if user specifies an email address)
    email_match = re.search(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", text)
    contact_email = defaults.get("contact_email") or (email_match.group(1) if email_match else None)

    return TrustedIntent(
        origin=origin,
        destination=destination,
        cabin_class=cabin_class,
        passenger_count=passenger_count,
        date=date,
        travel_date=date,
        addons_allowed=addons_allowed,
        contact_email=contact_email,
    )
