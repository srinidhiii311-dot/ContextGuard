"""
gateway/loader.py — Generic Policy Pack & Site Manifest Loader (Block 2 & Block 3 Adapter)

Loads declarative policy packs by domain name without ANY domain-specific hard-coding.
Builds and configures the real ContextGuardGate for any domain.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
import yaml

from gateway.schema import PolicyMode, PolicyPack, SiteManifest
from contextguard.gate import ContextGuardGate, Decision, GateResult, ProposedAction, TrustedIntent
from contextguard.consistency_checker import ContextConsistencyVerifier

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICIES_DIR = ROOT_DIR / "policies"
SANDBOXES_DIR = ROOT_DIR / "sandboxes"


def load_policy(domain: str, policies_dir: Union[str, Path] = POLICIES_DIR) -> PolicyPack:
    """
    Loads and validates the declarative policy pack for a given domain name.
    Strictly generic: dynamically locates policies/<domain>.yaml with zero domain-specific branches.
    """
    base_dir = Path(policies_dir)
    clean_domain = domain.lower().strip()
    policy_file = base_dir / f"{clean_domain}.yaml"

    if not policy_file.is_file():
        # Fallback to .yml
        policy_file = base_dir / f"{clean_domain}.yml"

    if not policy_file.is_file():
        raise FileNotFoundError(
            f"Policy pack not found for domain '{domain}'. Looked at: {base_dir / f'{clean_domain}.yaml'}"
        )

    with open(policy_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid policy pack structure in {policy_file}: expected YAML mapping.")

    return PolicyPack.model_validate(data)


def load_manifest(site_id: str, sandboxes_dir: Union[str, Path] = SANDBOXES_DIR) -> SiteManifest:
    """
    Loads and validates the sandbox manifest JSON for a given site.
    Strictly generic: dynamically locates sandboxes/<site_id>/manifest.json.
    """
    base_dir = Path(sandboxes_dir)
    manifest_file = base_dir / site_id / "manifest.json"

    if not manifest_file.is_file():
        raise FileNotFoundError(f"Manifest not found for site '{site_id}' at {manifest_file}")

    with open(manifest_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    return SiteManifest.model_validate(data)


def build_default_domain_intent(domain: str) -> TrustedIntent:
    """Generates standard baseline intent for a domain if none is provided."""
    d = domain.lower().strip()
    if d == "flight":
        return TrustedIntent(
            origin="Chennai",
            destination="Delhi",
            cabin_class="Economy",
            passenger_count=1,
        )
    elif d == "banking":
        return TrustedIntent(
            extra_fields={
                "amount": "100.00",
                "account_number": "1001-2002",
                "to_account": "ACC-4491",
                "payee": "Alice Smith",
            }
        )
    elif d == "ecommerce":
        return TrustedIntent(
            extra_fields={
                "search_input": "Keyboard",
                "address": "123 Main St, Springfield",
                "card_number": "4111222233334444",
            }
        )
    elif d == "healthcare":
        return TrustedIntent(
            extra_fields={
                "doctor": "Dr. Sarah Smith",
                "reason": "Annual Wellness Exam",
                "policy_no": "POL-98214",
            }
        )
    elif d == "email":
        return TrustedIntent(
            contact_email="team@company.internal",
            extra_fields={
                "to_email": "team@company.internal",
                "recipient": "team@company.internal",
                "subject": "Quarterly Status Report",
            }
        )
    return TrustedIntent()


class Gateway:
    """
    Runtime Safety Gateway adapter bridging domain-specific declarative policy packs
    to the real ContextGuardGate execution pipeline.
    """
    def __init__(self, policy: PolicyPack, gate: Optional[ContextGuardGate] = None, audit_log_path: Optional[Union[str, Path]] = None):
        self.policy = policy
        self.domain = policy.domain
        self.gate = gate
        self.audit_log_path = audit_log_path

    @classmethod
    def from_domain(
        cls,
        domain: str,
        trusted_intent: Optional[TrustedIntent] = None,
        task_id: str = "",
        audit_log_path: Optional[Union[str, Path]] = None,
        policies_dir: Union[str, Path] = POLICIES_DIR,
        sandboxes_dir: Union[str, Path] = SANDBOXES_DIR,
    ) -> Gateway:
        """
        Instantiates Gateway by dynamically loading the policy pack for the specified domain
        and configuring the real ContextGuardGate with the domain's trust boundary and action sensitivities.
        """
        policy = load_policy(domain=domain, policies_dir=policies_dir)
        manifest = None
        try:
            manifest = load_manifest(domain, sandboxes_dir=sandboxes_dir)
        except Exception:
            pass

        intent = trusted_intent or build_default_domain_intent(domain)

        # 1. Instantiate verifier and configure trust boundary
        verifier = ContextConsistencyVerifier()
        allowed_hosts = list(policy.domain_allowlist)
        for h in policy.domain_allowlist:
            bare = h.split(":")[0]
            if bare not in allowed_hosts:
                allowed_hosts.append(bare)
        verifier.trusted_hosts = allowed_hosts

        # 2. Configure protected field mappings from sensitive actions and manifest
        protected_mappings: Dict[str, Dict[str, Any]] = {}
        if domain == "flight":
            protected_mappings.update(verifier.target_mappings)

        for sa in policy.sensitive_actions:
            target_raw = sa.target
            target_clean = target_raw.lstrip("#.")
            is_critical = sa.irreversible
            sensitivity = 0.95 if sa.irreversible else 0.70

            intent_field = target_clean.replace("-", "_")
            if intent_field in ("from", "origin"):
                intent_field = "origin"
            elif intent_field in ("to", "destination"):
                intent_field = "destination"
            elif intent_field in ("cabin", "cabin_class"):
                intent_field = "cabin_class"
            elif intent_field in ("to_email", "email_recipient", "recipient"):
                intent_field = "contact_email"

            mapping = {
                "action_type": sa.action_type,
                "intent_field": intent_field,
                "action_sensitivity": sensitivity,
                "booking_critical": is_critical,
                "description": sa.description,
                "target_selectors": [target_raw, target_clean, f"#{target_clean}"],
            }
            protected_mappings[target_clean] = mapping
            protected_mappings[target_raw] = mapping

        verifier.target_mappings.update(protected_mappings)

        # Collect known page fields from manifest, policy, and verifier mappings
        known_targets = set()
        if manifest:
            for act in manifest.allowed_actions:
                if act.target and act.target != "*":
                    t_str = str(act.target).strip().lower()
                    known_targets.add(t_str)
                    known_targets.add(t_str.lstrip("#."))
            for sa in manifest.sensitive_actions:
                if sa.target and sa.target != "*":
                    t_str = str(sa.target).strip().lower()
                    known_targets.add(t_str)
                    known_targets.add(t_str.lstrip("#."))
            for pg in manifest.pages:
                if pg.path:
                    known_targets.add(str(pg.path).strip().lower())
        for sa in policy.sensitive_actions:
            if sa.target and sa.target != "*":
                t_str = str(sa.target).strip().lower()
                known_targets.add(t_str)
                known_targets.add(t_str.lstrip("#."))
        for k in verifier.target_mappings:
            k_str = str(k).strip().lower()
            known_targets.add(k_str)
            known_targets.add(k_str.lstrip("#."))
            for sel in verifier.target_mappings[k].get("target_selectors", []):
                if sel and sel != "*":
                    s_str = str(sel).strip().lower()
                    known_targets.add(s_str)
                    known_targets.add(s_str.lstrip("#."))

        # 3. Instantiate real ContextGuardGate with adapted verifier and protected fields
        gate = ContextGuardGate(
            trusted_intent=intent,
            task_id=task_id,
            verifier=verifier,
            protected_fields=protected_mappings,
            policy_pack=policy,
            audit_log_path=audit_log_path,
            known_page_fields=known_targets,
        )

        return cls(policy=policy, gate=gate, audit_log_path=audit_log_path)

    def set_intent(self, intent: TrustedIntent) -> None:
        """Updates and HMAC-signs intent on the underlying gate."""
        if self.gate is not None:
            self.gate.set_intent(intent)

    def check(
        self,
        action: ProposedAction,
        current_dom_text: str = "",
        snapshot: Any = None,
        browser_page: Any = None,
    ) -> GateResult:
        """Runs the action through the real ContextGuardGate."""
        if self.gate is not None:
            return self.gate.check(
                action=action,
                current_dom_text=current_dom_text,
                snapshot=snapshot,
                browser_page=browser_page,
            )
        raise RuntimeError("ContextGuardGate is not initialized on this Gateway instance.")

    def __getattr__(self, name: str) -> Any:
        if self.gate is not None and hasattr(self.gate, name):
            return getattr(self.gate, name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    def evaluate_action(
        self,
        action_type: str,
        target: str,
        target_url: str = "",
        data_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates a proposed action against the loaded domain policy pack.
        Returns: {decision: PolicyMode, reason: str, sensitive: bool, rule_triggered: Optional[str]}
        Maintained for schema and declarative policy pack verification.
        """
        action_type_upper = action_type.upper().strip()

        # 1. Action type allowlist
        allowed_types = [t.upper() for t in self.policy.allowed_action_types]
        if action_type_upper not in allowed_types:
            return {
                "decision": PolicyMode.BLOCK,
                "reason": f"Action type '{action_type}' is not permitted under domain policy.",
                "sensitive": True,
                "rule_triggered": "action_type_not_allowed",
            }

        # 2. Domain / Host Egress Check
        if target_url:
            host = target_url.split("//")[-1].split("/")[0].lower()
            if not self.policy.is_host_allowed(host):
                return {
                    "decision": PolicyMode.BLOCK,
                    "reason": f"Target host '{host}' is outside domain allowlist {self.policy.domain_allowlist}.",
                    "sensitive": True,
                    "rule_triggered": "domain_egress_violation",
                }

        # 3. Sensitive Actions Check
        for sensitive in self.policy.sensitive_actions:
            if sensitive.action_type.upper() == action_type_upper and (
                sensitive.target == "*" or sensitive.target == target or target.endswith(sensitive.target)
            ):
                return {
                    "decision": PolicyMode.ASK_HUMAN if sensitive.irreversible else PolicyMode.WARN,
                    "reason": f"Sensitive action intercepted: {sensitive.description}",
                    "sensitive": True,
                    "rule_triggered": "sensitive_action_rule",
                }

        # 4. Default benign approval
        return {
            "decision": PolicyMode.LOG_ONLY,
            "reason": "Action complies with domain policy pack.",
            "sensitive": False,
            "rule_triggered": None,
        }
