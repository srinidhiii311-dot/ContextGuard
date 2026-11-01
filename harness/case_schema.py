"""
harness/case_schema.py — Canonical Evaluation Case Schema for ContextGuard (Block 3)

Defines the Pydantic schema for all evaluation cases (attacks and benign),
ensuring compatibility with the real ContextGuardGate execution pipeline.
"""

from __future__ import annotations

from typing import Any, Dict, Literal, Optional, Union
from pydantic import BaseModel, Field, field_validator


class ProposedActionSchema(BaseModel):
    """The action proposed by an agent (compromised or normal)."""
    action_type: str = Field(description="Action type, e.g. CLICK, TYPE, SELECT, NAVIGATE, SUBMIT")
    target: str = Field(description="Target CSS selector, element ID, or URL")
    value: Optional[str] = Field(default=None, description="Input string value, selection value, or URL target")
    page_url: str = Field(default="", description="The URL of the page where the action occurs")
    source_text: Optional[str] = Field(default=None, description="Optional text content associated with action")

    @field_validator("action_type")
    @classmethod
    def normalize_action_type(cls, v: str) -> str:
        return v.upper().strip()


class PageStateSchema(BaseModel):
    """The DOM state of the web page during evaluation."""
    visible_text: str = Field(default="", description="Browser-rendered visible text seen by the gate (current_dom_text)")
    raw_html: str = Field(default="", description="Raw HTML snapshot including tags, hidden elements, and comments")


class EvaluationCase(BaseModel):
    """
    Standard ContextGuard evaluation case representing an action evaluation trial.
    Saved to JSONL in attacks/<split>/cases.jsonl or benign/<split>/cases.jsonl.
    """
    case_id: str = Field(description="Unique deterministic case identifier")
    domain: Literal["flight", "banking", "ecommerce", "healthcare", "email"] = Field(
        description="Target mock domain"
    )
    split: Literal["dev", "test"] = Field(
        description="Deterministic evaluation split: 'dev' for tuning, 'test' held-out"
    )
    case_type: Literal["attack", "benign"] = Field(
        description="High-level case category"
    )
    family: str = Field(
        description="Attack family name or benign category (e.g. hidden_css_text, benign_standard)"
    )
    variant_id: str = Field(
        description="Variant identifier (e.g. v1, v2, ...)"
    )
    user_task: str = Field(
        description="Original user instruction provided to the web agent"
    )
    locked_intent: Dict[str, Any] = Field(
        description="Structured dict of user constraints verified by the gate"
    )
    page_snapshot_ref: str = Field(
        default="none",
        description="Sandbox page route and injected slot reference (e.g. /transfer#slot-hidden-css)"
    )
    page_state: PageStateSchema = Field(
        description="DOM text and HTML representations"
    )
    proposed_action: ProposedActionSchema = Field(
        description="Action proposed by the agent"
    )
    expected_decision: Literal["allow", "block_or_ask"] = Field(
        description="Ground truth expectation: allow or block_or_ask"
    )
    ground_truth_label: Literal["attack_divergent", "attack_uncompromised", "benign"] = Field(
        description="Granular ground truth label distinguishing uncompromised agents from hijacked agents"
    )
    attack_mechanism: str = Field(
        default="none",
        description="Attack delivery mechanism or 'none' for benign"
    )
    rationale: str = Field(
        description="Detailed justification for the ground truth label and expected decision"
    )

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("case_id cannot be empty")
        return v.strip()

