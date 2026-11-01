"""
gateway/schema.py — Pydantic Schemas for Site Manifests & Domain Policy Packs (Block 2)

Enforces strict structural validation for:
- sandboxes/<site>/manifest.json
- policies/<domain>.yaml
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


class PolicyMode(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    ASK_HUMAN = "ask_human"
    LOG_ONLY = "log_only"


class PageEntry(BaseModel):
    path: str
    name: str
    description: str
    method: str = "GET"


class AllowedAction(BaseModel):
    action_type: str
    target: str
    page: str
    sensitive: bool = False
    irreversible: bool = False
    description: str


class SensitiveActionItem(BaseModel):
    action_type: str
    target: str
    page: Optional[str] = "*"
    mode: Optional[PolicyMode] = PolicyMode.ASK_HUMAN
    irreversible: bool = True
    description: str


class InjectionSlot(BaseModel):
    slot_id: str
    marker_type: str
    element_id: str
    description: str


class SiteManifest(BaseModel):
    """Schema for sandboxes/<site>/manifest.json."""
    site_id: str
    domain: str
    port: int
    base_url: str
    description: str
    pages: List[PageEntry]
    allowed_actions: List[AllowedAction]
    sensitive_actions: List[SensitiveActionItem]
    injection_slots: List[InjectionSlot]

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if v < 1 or v > 65535:
            raise ValueError(f"Port must be between 1 and 65535, got {v}")
        return v


class SensitiveActionRule(BaseModel):
    action_type: str
    target: str
    irreversible: bool = False
    description: str = ""


class PolicyPack(BaseModel):
    """Schema for policies/<domain>.yaml."""
    domain: str
    domain_allowlist: List[str]
    allowed_action_types: List[str]
    sensitive_actions: List[SensitiveActionRule]

    @field_validator("domain_allowlist")
    @classmethod
    def validate_allowlist(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("domain_allowlist must not be empty.")
        return v

    def is_host_allowed(self, host: str) -> bool:
        """Checks if a given host or origin is permitted under domain_allowlist."""
        clean_host = host.split("//")[-1].split("/")[0].lower()
        for allowed in self.domain_allowlist:
            clean_allowed = allowed.split("//")[-1].split("/")[0].lower()
            if clean_host == clean_allowed or clean_host.endswith("." + clean_allowed):
                return True
        return False

