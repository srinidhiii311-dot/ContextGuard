"""
contextguard/dataset_v2.py — Dataset Schema v2 & Multi-Step Sequence Loader
Stage 2 (Phase 2) Foundation: Stateful Multi-Step Workflow Support

Schema v2 Specification:
- Per-item explicit TrustedIntent
- Ordered action steps (step_number, page, page_url, dom_text, action, raw_html)
- Ground-truth label (ATTACK | BENIGN) and category
- Dual loader: transparently loads legacy v1 items (normalizing to 1-step sequences)
  and native v2 multi-step sequences.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from contextguard.gate import ProposedAction, TrustedIntent


@dataclass
class DatasetStepV2:
    step_number: int
    page: str
    page_url: str
    dom_text: str
    action_type: str
    target: str
    value: Optional[str] = None
    source_text: Optional[str] = None
    raw_html: Optional[str] = None
    notes: Optional[str] = None

    def to_proposed_action(self) -> ProposedAction:
        return ProposedAction(
            action_type=self.action_type,
            target=self.target,
            value=self.value,
            page_url=self.page_url,
            source_text=self.source_text,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "page": self.page,
            "page_url": self.page_url,
            "dom_text": self.dom_text,
            "action": {
                "action_type": self.action_type,
                "target": self.target,
                "value": self.value,
                "page_url": self.page_url,
                "source_text": self.source_text,
            },
            "raw_html": self.raw_html,
            "notes": self.notes,
        }


@dataclass
class DatasetItemV2:
    id: str
    name: str
    label: str  # "ATTACK" | "BENIGN"
    category: str
    intent: TrustedIntent
    steps: List[DatasetStepV2] = field(default_factory=list)
    dev_marked: bool = True
    evades_taxonomy: bool = False
    expected_decision: Optional[str] = None
    notes: Optional[str] = None

    @property
    def is_attack(self) -> bool:
        return self.label.upper() == "ATTACK"

    @property
    def step_count(self) -> int:
        return len(self.steps)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "label": self.label,
            "category": self.category,
            "intent": {
                "origin": self.intent.origin,
                "destination": self.intent.destination,
                "cabin_class": self.intent.cabin_class,
                "passenger_count": self.intent.passenger_count,
                "travel_date": self.intent.travel_date,
                "addons_allowed": self.intent.addons_allowed,
                "contact_email": self.intent.contact_email,
                "max_fare": self.intent.max_fare,
            },
            "steps": [s.to_dict() for s in self.steps],
            "dev_marked": self.dev_marked,
            "evades_taxonomy": self.evades_taxonomy,
            "notes": self.notes,
        }


def parse_v1_item(item_raw: Dict[str, Any], default_intent: TrustedIntent) -> DatasetItemV2:
    """Wraps a legacy single-action v1 item into a 1-step DatasetItemV2."""
    act_data = item_raw.get("action", {})
    page = item_raw.get("page", "search")
    page_url = act_data.get("page_url", f"http://127.0.0.1:8000/{page}")
    
    step = DatasetStepV2(
        step_number=1,
        page=page,
        page_url=page_url,
        dom_text=item_raw.get("dom_text", ""),
        action_type=act_data.get("action_type", "CLICK"),
        target=act_data.get("target", ""),
        value=act_data.get("value"),
        source_text=act_data.get("source_text"),
        raw_html=item_raw.get("raw_html"),
        notes=item_raw.get("notes"),
    )
    
    # Determine label
    item_id = item_raw.get("id", "")
    is_atk = item_id.startswith("ATK_") or "attack" in item_raw.get("category", "").lower()
    label = "ATTACK" if is_atk else "BENIGN"
    
    return DatasetItemV2(
        id=item_id,
        name=item_raw.get("name", item_id),
        label=label,
        category=item_raw.get("category", "INTENT_COMPLIANT_INPUT"),
        intent=default_intent,
        steps=[step],
        dev_marked=True,
        evades_taxonomy=bool(item_raw.get("evades_taxonomy", False)),
        notes=item_raw.get("notes"),
    )


def parse_v2_item(item_raw: Dict[str, Any], fallback_intent: Optional[TrustedIntent] = None) -> DatasetItemV2:
    """Parses a native schema v2 item with explicit intent and ordered steps."""
    raw_intent = item_raw.get("intent")
    if raw_intent:
        intent = TrustedIntent(
            origin=str(raw_intent.get("origin", "Chennai")),
            destination=str(raw_intent.get("destination", "Delhi")),
            cabin_class=str(raw_intent.get("cabin_class", "Economy")),
            passenger_count=int(raw_intent.get("passenger_count", raw_intent.get("passengers", 1))),
            travel_date=raw_intent.get("travel_date", raw_intent.get("date")),
            addons_allowed=raw_intent.get("addons_allowed", "none"),
            contact_email=raw_intent.get("contact_email"),
            max_fare=raw_intent.get("max_fare"),
        )
    elif fallback_intent:
        intent = fallback_intent
    else:
        intent = TrustedIntent(origin="Chennai", destination="Delhi", cabin_class="Economy", passenger_count=1)

    steps: List[DatasetStepV2] = []
    for idx, s in enumerate(item_raw.get("steps", []), start=1):
        act = s.get("action", {})
        page = s.get("page", "search")
        page_url = act.get("page_url", s.get("page_url", f"http://127.0.0.1:8000/{page}"))
        steps.append(
            DatasetStepV2(
                step_number=s.get("step_number", idx),
                page=page,
                page_url=page_url,
                dom_text=s.get("dom_text", ""),
                action_type=act.get("action_type", "CLICK"),
                target=act.get("target", ""),
                value=act.get("value"),
                source_text=act.get("source_text"),
                raw_html=s.get("raw_html"),
                notes=s.get("notes"),
            )
        )

    return DatasetItemV2(
        id=item_raw.get("id", "SEQ_UNKNOWN"),
        name=item_raw.get("name", "Unnamed Sequence"),
        label=str(item_raw.get("label", "ATTACK")).upper(),
        category=item_raw.get("category", "MULTI_STEP_WORKFLOW"),
        intent=intent,
        steps=steps,
        dev_marked=bool(item_raw.get("dev_marked", True)),
        evades_taxonomy=bool(item_raw.get("evades_taxonomy", False)),
        expected_decision=item_raw.get("expected_decision"),
        notes=item_raw.get("notes"),
    )


def load_dataset_file(file_path: Path | str, default_intent_path: Optional[Path | str] = None) -> List[DatasetItemV2]:
    """
    Universal dataset loader. Reads v1 (attacks.yaml, benign.yaml) or v2 (sequences.yaml) files.
    Normalizes all entries into List[DatasetItemV2].
    """
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Dataset file not found: {p}")

    default_intent = None
    if default_intent_path:
        dip = Path(default_intent_path)
        if dip.exists():
            d_dict = yaml.safe_load(dip.read_text(encoding="utf-8"))
            if d_dict:
                default_intent = TrustedIntent(
                    origin=d_dict.get("origin", "Chennai"),
                    destination=d_dict.get("destination", "Delhi"),
                    cabin_class=d_dict.get("cabin_class", "Economy"),
                    passenger_count=int(d_dict.get("passenger_count", 1)),
                    travel_date=d_dict.get("travel_date", d_dict.get("date")),
                    addons_allowed=d_dict.get("addons_allowed", "none"),
                    contact_email=d_dict.get("contact_email"),
                    max_fare=d_dict.get("max_fare"),
                )

    if default_intent is None:
        default_intent = TrustedIntent(
            origin="Chennai",
            destination="Delhi",
            cabin_class="Economy",
            passenger_count=1,
            addons_allowed="none",
        )

    content = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not content:
        return []

    # Check structure
    raw_items: List[Dict[str, Any]] = []
    if isinstance(content, list):
        raw_items = content
    elif isinstance(content, dict):
        if "sequences" in content:
            raw_items = content["sequences"]
        elif "items" in content:
            raw_items = content["items"]
        elif "attacks" in content:
            raw_items = content["attacks"]
        elif "benign_tasks" in content:
            raw_items = content["benign_tasks"]
        else:
            raw_items = [content]

    parsed: List[DatasetItemV2] = []
    for item in raw_items:
        if "steps" in item:
            parsed.append(parse_v2_item(item, fallback_intent=default_intent))
        else:
            parsed.append(parse_v1_item(item, default_intent=default_intent))

    return parsed
