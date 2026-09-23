"""
contextguard/task_context.py — Immutable Trusted Task Context

Locks user intent from Page 1 (both natural-language instruction and structured parameters).
ContextGuard continuously compares observed browser actions and state against this context.
NEVER modified during runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class TrustedTaskContext:
    """
    Immutable representation of user goal and constraints locked at task start.
    Contains both structured parameters and raw natural language.
    """
    task_id:         str
    raw_instruction: str
    origin:          str
    destination:     str
    date:            str
    passengers:      int
    cabin_class:     str                   # "Economy" | "Business"
    constraints:     str                   = ""
    created_at:      str                   = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrustedTaskContext":
        return cls(
            task_id         = str(data.get("task_id", "")).strip(),
            raw_instruction = str(data.get("raw_instruction", data.get("instruction", ""))).strip(),
            origin          = str(data.get("origin", "")).strip(),
            destination     = str(data.get("destination", "")).strip(),
            date            = str(data.get("date", "")).strip(),
            passengers      = int(data.get("passengers", data.get("passenger_count", 1))),
            cabin_class     = str(data.get("cabin_class", "Economy")).strip().capitalize(),
            constraints     = str(data.get("constraints", "")).strip(),
            created_at      = str(data.get("created_at", "")).strip(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id":         self.task_id,
            "raw_instruction": self.raw_instruction,
            "origin":          self.origin,
            "destination":     self.destination,
            "date":            self.date,
            "passengers":      self.passengers,
            "cabin_class":     self.cabin_class,
            "constraints":     self.constraints,
            "created_at":      self.created_at,
        }

    def check_entity_mismatch(self, field_name: str, proposed_val: Any) -> Optional[str]:
        """
        Validates a specific action value against locked context.
        Returns mismatch explanation if inconsistent, None if consistent.
        """
        fname = field_name.lower().strip()
        val_str = str(proposed_val).strip() if proposed_val is not None else ""

        if not val_str:
            return None

        if "cabin" in fname or "class" in fname:
            if self.cabin_class.lower() not in val_str.lower() and val_str.lower() not in self.cabin_class.lower():
                return f"Cabin class mismatch: Expected '{self.cabin_class}', observed '{val_str}'"

        elif "origin" in fname or "from" in fname:
            if self.origin and self.origin.lower() not in val_str.lower():
                return f"Origin mismatch: Expected '{self.origin}', observed '{val_str}'"

        elif "dest" in fname or "to" in fname:
            if self.destination and self.destination.lower() not in val_str.lower():
                return f"Destination mismatch: Expected '{self.destination}', observed '{val_str}'"

        elif "passenger" in fname or "count" in fname or "pcount" in fname:
            try:
                p_num = int("".join(c for c in val_str if c.isdigit()))
                if p_num != self.passengers:
                    return f"Passenger count mismatch: Expected {self.passengers}, observed {p_num}"
            except Exception:
                pass

        return None
