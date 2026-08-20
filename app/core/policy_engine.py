"""
Policy Engine — ContextGuard Core

Loads policies from data/policies.json and evaluates them against a
BrowserAction. Each policy has a condition function that inspects the action
and returns True when the policy fires.

Why critical policies override the risk score
---------------------------------------------
A numeric risk score can be fooled by a carefully crafted action that scores
just below a threshold. Critical policies are absolute rules: if a policy
says BLOCK, the action is blocked regardless of its score. This provides a
deterministic, auditable safety layer on top of the probabilistic scorer.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from app.models.action import ActionType, BrowserAction, SourceType
from app.models.decision import DecisionType

# ---------------------------------------------------------------------------
# Approved / blocked domain lists (configurable via policies.json)
# ---------------------------------------------------------------------------

_APPROVED_DOMAINS = {
    "docs.python.org",
    "developer.mozilla.org",
    "fastapi.tiangolo.com",
    "github.com",
    "wikipedia.org",
    "stackoverflow.com",
    "pypi.org",
    "example-trusted.com",
}

_BLOCKED_DOMAINS = {
    "malware.example",
    "phishing.example",
    "exfil.example",
    "evil.example",
    "badactor.example",
    "untrusted.example",
    "exploit.example",
}

_EXECUTABLE_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".msi", ".ps1", ".sh",
    ".vbs", ".js", ".jar", ".dmg", ".pkg", ".deb", ".rpm",
}

_SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "pass", "pin", "secret",
    "card_number", "credit_card", "cvv", "cvc", "expiry",
    "ssn", "social_security", "bank_account", "routing_number",
    "api_key", "access_token", "token", "private_key",
}

_PERSONAL_INFO_FIELDS = {
    "email", "phone", "address", "dob", "date_of_birth",
    "full_name", "national_id", "passport", "driving_license",
}


# ---------------------------------------------------------------------------
# Policy result dataclass
# ---------------------------------------------------------------------------

@dataclass
class PolicyMatchResult:
    """The result of evaluating all policies against one action."""
    matched_policy_ids: List[str] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)
    recommended_decision: Optional[DecisionType] = None
    explanations: List[str] = field(default_factory=list)
    risk_contribution: int = 0
    critical_override: bool = False  # True when a BLOCK-severity policy fires


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Evaluates structured policies against a BrowserAction.

    Policies are loaded from data/policies.json. Each policy's 'condition'
    field maps to a Python callable defined in this module.
    """

    def __init__(self, policies_path: Optional[Path] = None) -> None:
        if policies_path is None:
            policies_path = Path(__file__).parent.parent.parent / "data" / "policies.json"
        self._policies_path = policies_path
        self._policies: List[Dict[str, Any]] = []
        self._condition_map: Dict[str, Callable[[BrowserAction], bool]] = (
            self._build_condition_map()
        )
        self._load_policies()

    def _load_policies(self) -> None:
        """Load and parse policies.json. Silently skips disabled policies."""
        try:
            with open(self._policies_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._policies = [p for p in data.get("policies", []) if p.get("enabled", True)]
        except FileNotFoundError:
            self._policies = []
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"policies.json is malformed: {exc}") from exc

    def reload_policies(self) -> None:
        """Reload policies from disk (useful after hot-reload)."""
        self._load_policies()

    # ------------------------------------------------------------------
    # Main evaluation entry point
    # ------------------------------------------------------------------

    def evaluate(self, action: BrowserAction) -> PolicyMatchResult:
        """
        Evaluate all enabled policies against the action.

        Returns a PolicyMatchResult summarising every matched policy,
        the highest-priority recommended decision, and total risk contribution.
        Critical policies (severity=critical) set critical_override=True.
        """
        result = PolicyMatchResult()
        decision_priority = {
            DecisionType.ALLOW: 0,
            DecisionType.WARN: 1,
            DecisionType.REQUIRE_APPROVAL: 2,
            DecisionType.BLOCK: 3,
        }
        current_priority = -1

        for policy in self._policies:
            pid = policy["id"]
            condition_key = policy.get("condition", "")
            condition_fn = self._condition_map.get(condition_key)

            if condition_fn is None:
                continue

            try:
                fired = condition_fn(action)
            except Exception:
                # Fail closed: treat evaluation errors as the policy firing
                fired = True

            if not fired:
                continue

            # Policy matched
            result.matched_policy_ids.append(pid)
            severity = policy.get("severity", "medium")
            result.severities.append(severity)
            result.explanations.append(
                f"[{pid}] {policy.get('name', pid)}: {policy.get('description', '')}"
            )
            result.risk_contribution += policy.get("risk_contribution", 10)

            policy_decision_str = policy.get("decision", "WARN")
            try:
                policy_decision = DecisionType(policy_decision_str)
            except ValueError:
                policy_decision = DecisionType.WARN

            p = decision_priority.get(policy_decision, 1)
            if p > current_priority:
                current_priority = p
                result.recommended_decision = policy_decision

            if severity.lower() == "critical":
                result.critical_override = True

        if result.recommended_decision is None and not result.matched_policy_ids:
            result.recommended_decision = None  # No policy matched

        return result

    # ------------------------------------------------------------------
    # Condition functions
    # Each function receives a BrowserAction and returns bool.
    # ------------------------------------------------------------------

    def _build_condition_map(self) -> Dict[str, Callable[[BrowserAction], bool]]:
        return {
            "is_approved_domain": self._cond_approved_domain,
            "is_blocked_domain": self._cond_blocked_domain,
            "is_unknown_domain": self._cond_unknown_domain,
            "is_sensitive_form_submit": self._cond_sensitive_form_submit,
            "is_password_field": self._cond_password_field,
            "is_payment_field": self._cond_payment_field,
            "is_file_upload": self._cond_file_upload,
            "is_upload_to_external": self._cond_upload_to_external,
            "is_executable_download": self._cond_executable_download,
            "is_download_unknown_domain": self._cond_download_unknown_domain,
            "is_cross_site_sensitive": self._cond_cross_site_sensitive,
            "is_prompt_injection": self._cond_prompt_injection,
            "is_data_exfiltration": self._cond_data_exfiltration,
            "is_irreversible_action": self._cond_irreversible_action,
        }

    @staticmethod
    def _extract_domain(url: Optional[str]) -> Optional[str]:
        if not url:
            return None
        url = url.lower().strip()
        url = re.sub(r"^https?://", "", url)
        domain = url.split("/")[0].split("?")[0].split("#")[0]
        # Strip port
        domain = domain.split(":")[0]
        return domain or None

    def _cond_approved_domain(self, action: BrowserAction) -> bool:
        if action.action_type != ActionType.navigate:
            return False
        domain = self._extract_domain(action.target.url)
        return domain in _APPROVED_DOMAINS if domain else False

    def _cond_blocked_domain(self, action: BrowserAction) -> bool:
        domain = self._extract_domain(action.target.url)
        if domain and domain in _BLOCKED_DOMAINS:
            return True
        # Also check current domain
        if action.current_domain and action.current_domain.lower() in _BLOCKED_DOMAINS:
            return True
        return False

    def _cond_unknown_domain(self, action: BrowserAction) -> bool:
        if action.action_type != ActionType.navigate:
            return False
        domain = self._extract_domain(action.target.url)
        if not domain:
            return False
        return domain not in _APPROVED_DOMAINS and domain not in _BLOCKED_DOMAINS

    def _cond_sensitive_form_submit(self, action: BrowserAction) -> bool:
        if action.action_type != ActionType.submit:
            return False
        field_name = (action.target.field_name or "").lower()
        return (
            field_name in _SENSITIVE_FIELD_NAMES
            or field_name in _PERSONAL_INFO_FIELDS
            or any(k.lower() in _SENSITIVE_FIELD_NAMES for k in action.payload)
        )

    def _cond_password_field(self, action: BrowserAction) -> bool:
        if action.action_type not in (ActionType.fill, ActionType.submit):
            return False
        field_name = (action.target.field_name or "").lower()
        element_type = (action.target.element_type or "").lower()
        return (
            field_name in {"password", "passwd", "pass", "pin"}
            or element_type == "password"
            or any(k.lower() in {"password", "passwd", "pass", "pin"}
                   for k in action.payload)
        )

    def _cond_payment_field(self, action: BrowserAction) -> bool:
        if action.action_type not in (ActionType.fill, ActionType.submit):
            return False
        field_name = (action.target.field_name or "").lower()
        payment_fields = {"card_number", "credit_card", "cvv", "cvc", "expiry",
                          "payment", "billing", "bank_account", "routing_number"}
        return (
            field_name in payment_fields
            or any(k.lower() in payment_fields for k in action.payload)
        )

    def _cond_file_upload(self, action: BrowserAction) -> bool:
        return action.action_type == ActionType.upload

    def _cond_upload_to_external(self, action: BrowserAction) -> bool:
        if action.action_type != ActionType.upload:
            return False
        target_domain = self._extract_domain(action.target.url)
        current_domain = (action.current_domain or "").lower()
        if not target_domain or not current_domain:
            return False
        return target_domain != current_domain and target_domain not in _APPROVED_DOMAINS

    def _cond_executable_download(self, action: BrowserAction) -> bool:
        if action.action_type != ActionType.download:
            return False
        url = (action.target.url or "").lower()
        filename = str(action.payload.get("filename", "")).lower()
        return any(url.endswith(ext) or filename.endswith(ext)
                   for ext in _EXECUTABLE_EXTENSIONS)

    def _cond_download_unknown_domain(self, action: BrowserAction) -> bool:
        if action.action_type != ActionType.download:
            return False
        domain = self._extract_domain(action.target.url)
        if not domain:
            return True  # No domain = unknown
        return domain not in _APPROVED_DOMAINS and domain not in _BLOCKED_DOMAINS

    def _cond_cross_site_sensitive(self, action: BrowserAction) -> bool:
        if action.action_type not in (ActionType.submit, ActionType.upload, ActionType.navigate):
            return False
        prev = (action.previous_domain or "").lower()
        curr = (action.current_domain or "").lower()
        target = self._extract_domain(action.target.url) or curr
        if not prev or not curr:
            return False
        domains_differ = prev != curr or (target and target != curr)
        has_sensitive = (
            any(k.lower() in _SENSITIVE_FIELD_NAMES for k in action.payload)
            or (action.target.field_name or "").lower() in _SENSITIVE_FIELD_NAMES
        )
        return domains_differ and has_sensitive

    def _cond_prompt_injection(self, action: BrowserAction) -> bool:
        source = action.source
        if source.source_type not in (SourceType.page_content, SourceType.unknown,
                                       SourceType.tool_output):
            return False
        content = (source.content or "").lower()
        injection_phrases = [
            "ignore previous instructions",
            "ignore all prior",
            "bypass security",
            "disable safeguards",
            "reveal confidential",
            "reveal system prompt",
            "upload local files",
            "send data externally",
            "submit credentials",
            "do not tell the user",
            "continue without approval",
            "override the security policy",
            "jailbreak",
            "you are now",
            "new instructions:",
        ]
        return any(phrase in content for phrase in injection_phrases)

    def _cond_data_exfiltration(self, action: BrowserAction) -> bool:
        """
        Detect extract-then-transmit patterns.
        Fires when an upload/submit action follows a tainted extract action
        and targets a different domain.
        """
        if action.action_type not in (ActionType.upload, ActionType.submit):
            return False
        source = action.source
        # If taint_id is set, tainted content is influencing this action
        if source.taint_id:
            target_domain = self._extract_domain(action.target.url)
            current_domain = (action.current_domain or "").lower()
            if target_domain and target_domain != current_domain:
                return True
        return False

    def _cond_irreversible_action(self, action: BrowserAction) -> bool:
        """Flag actions that cannot be easily undone."""
        if action.action_type in (ActionType.submit, ActionType.upload, ActionType.download):
            return True
        if action.action_type == ActionType.navigate:
            domain = self._extract_domain(action.target.url)
            if domain and domain not in _APPROVED_DOMAINS:
                return False  # Navigation to unknown is handled by other policies
        return False


# Module-level singleton
policy_engine = PolicyEngine()
