"""
Risk Analyzer — ContextGuard Core

Calculates a deterministic risk score (0–100) by summing weighted risk
contributions from action properties, source trust, domain reputation,
field sensitivity, and taint state.

Determinism is important: the same action always produces the same score,
making the system auditable and predictable. Scores are capped at 100.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from app.core.source_classifier import ClassificationResult
from app.core.taint_tracker import TaintTracker
from app.models.action import ActionType, BrowserAction, SourceType
from app.models.decision import RiskLevel

# ---------------------------------------------------------------------------
# Risk contribution weights
# ---------------------------------------------------------------------------

_WEIGHTS = {
    "unknown_domain": 20,
    "blocked_domain": 70,
    "cross_site_navigation": 15,
    "page_derived_source": 25,
    "untrusted_tool_output": 20,
    "password_field": 30,
    "payment_field": 35,
    "personal_info_field": 25,
    "file_upload": 30,
    "upload_unknown_domain": 40,
    "file_download": 20,
    "executable_download": 40,
    "external_data_transfer": 35,
    "prompt_injection_indicator": 30,
    "tainted_session": 20,
    "previous_blocked_action": 15,
    "irreversible_action": 20,
    "sensitive_form_submission": 30,
}

_APPROVED_DOMAINS = {
    "docs.python.org", "developer.mozilla.org", "fastapi.tiangolo.com",
    "github.com", "wikipedia.org", "stackoverflow.com", "pypi.org",
    "example-trusted.com",
}

_BLOCKED_DOMAINS = {
    "malware.example", "phishing.example", "exfil.example",
    "evil.example", "badactor.example", "untrusted.example", "exploit.example",
}

_EXECUTABLE_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".msi", ".ps1", ".sh",
    ".vbs", ".js", ".jar", ".dmg", ".pkg", ".deb", ".rpm",
}

_SENSITIVE_FIELDS = {
    "password", "passwd", "pass", "pin", "secret",
    "card_number", "credit_card", "cvv", "cvc", "expiry",
    "ssn", "api_key", "access_token", "token", "private_key",
    "bank_account", "routing_number",
}

_PAYMENT_FIELDS = {
    "card_number", "credit_card", "cvv", "cvc", "expiry",
    "payment", "billing", "bank_account", "routing_number",
}

_PERSONAL_FIELDS = {
    "email", "phone", "address", "dob", "date_of_birth",
    "full_name", "national_id", "passport", "driving_license", "ssn",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class RiskAnalysisResult:
    """Full output of the risk analyser."""
    score: int                               # 0–100
    risk_level: RiskLevel
    factors: List[str] = field(default_factory=list)
    explanations: List[str] = field(default_factory=list)
    sensitive_data_indicators: List[str] = field(default_factory=list)
    injection_indicators: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Risk analyser
# ---------------------------------------------------------------------------

class RiskAnalyzer:
    """
    Deterministic risk scorer.

    Combines domain reputation, source trust, field sensitivity, taint state,
    and session history into a single integer score. The score feeds the
    decision engine but can be overridden by critical policy violations.
    """

    def analyze(
        self,
        action: BrowserAction,
        classification: ClassificationResult,
        taint_tracker: TaintTracker,
        blocked_count: int = 0,
    ) -> RiskAnalysisResult:
        """
        Calculate the risk score for an action.

        Parameters
        ----------
        action:         The proposed browser action.
        classification: Output of the source classifier.
        taint_tracker:  The session taint tracker instance.
        blocked_count:  Number of previously blocked actions in this session.
        """
        score = 0
        factors: List[str] = []
        explanations: List[str] = []
        sensitive_indicators: List[str] = []
        injection_indicators: List[str] = list(classification.injection_indicators)

        target_url = (action.target.url or "").lower()
        current_domain = (action.current_domain or "").lower()
        previous_domain = (action.previous_domain or "").lower()
        field_name = (action.target.field_name or "").lower()
        element_type = (action.target.element_type or "").lower()
        action_type = action.action_type

        # --- Domain checks ---
        target_domain = self._extract_domain(target_url) or current_domain

        if target_domain in _BLOCKED_DOMAINS or current_domain in _BLOCKED_DOMAINS:
            score += _WEIGHTS["blocked_domain"]
            factors.append("blocked_domain")
            explanations.append(f"Domain '{target_domain or current_domain}' is on the blocked list")

        elif target_domain and target_domain not in _APPROVED_DOMAINS:
            score += _WEIGHTS["unknown_domain"]
            factors.append("unknown_domain")
            explanations.append(f"Domain '{target_domain}' is not on the approved list")

        # Cross-site navigation penalty
        if previous_domain and current_domain and previous_domain != current_domain:
            score += _WEIGHTS["cross_site_navigation"]
            factors.append("cross_site_navigation")
            explanations.append(
                f"Cross-site context change: {previous_domain} → {current_domain}"
            )

        # --- Source trust ---
        if action.source.source_type == SourceType.page_content:
            score += _WEIGHTS["page_derived_source"]
            factors.append("page_derived_source")
            explanations.append("Action instruction derived from untrusted page content")

        elif action.source.source_type == SourceType.tool_output:
            score += _WEIGHTS["untrusted_tool_output"]
            factors.append("untrusted_tool_output")
            explanations.append("Action instruction derived from tool output (partially trusted)")

        elif action.source.source_type == SourceType.unknown:
            score += _WEIGHTS["untrusted_tool_output"]
            factors.append("unknown_source")
            explanations.append("Action instruction source is unknown")

        # --- Field sensitivity ---
        payload_keys = {k.lower() for k in action.payload}

        if (field_name in {"password", "passwd", "pass", "pin"}
                or element_type == "password"
                or payload_keys & {"password", "passwd", "pass", "pin"}):
            score += _WEIGHTS["password_field"]
            factors.append("password_field")
            explanations.append("Action interacts with a password or PIN field")
            sensitive_indicators.append("password_field")

        if (field_name in _PAYMENT_FIELDS
                or payload_keys & _PAYMENT_FIELDS):
            score += _WEIGHTS["payment_field"]
            factors.append("payment_field")
            explanations.append("Action interacts with a payment or billing field")
            sensitive_indicators.append("payment_field")

        if (field_name in _PERSONAL_FIELDS
                or payload_keys & _PERSONAL_FIELDS):
            score += _WEIGHTS["personal_info_field"]
            factors.append("personal_info_field")
            explanations.append("Action involves personal identification information")
            sensitive_indicators.append("personal_info_field")

        # --- Upload checks ---
        if action_type == ActionType.upload:
            score += _WEIGHTS["file_upload"]
            factors.append("file_upload")
            explanations.append("Action performs a file upload")

            upload_domain = self._extract_domain(target_url) or current_domain
            if upload_domain and upload_domain not in _APPROVED_DOMAINS:
                score += _WEIGHTS["upload_unknown_domain"]
                factors.append("upload_unknown_domain")
                explanations.append(
                    f"File upload targets unknown domain '{upload_domain}'"
                )

        # --- Download checks ---
        if action_type == ActionType.download:
            score += _WEIGHTS["file_download"]
            factors.append("file_download")
            explanations.append("Action performs a file download")

            filename = str(action.payload.get("filename", "")).lower()
            if (any(target_url.endswith(ext) for ext in _EXECUTABLE_EXTENSIONS)
                    or any(filename.endswith(ext) for ext in _EXECUTABLE_EXTENSIONS)):
                score += _WEIGHTS["executable_download"]
                factors.append("executable_download")
                explanations.append("Download target appears to be an executable file")

        # --- External data transfer ---
        if action_type in (ActionType.submit, ActionType.upload):
            submit_domain = self._extract_domain(target_url) or current_domain
            if submit_domain and current_domain and submit_domain != current_domain:
                if submit_domain not in _APPROVED_DOMAINS:
                    score += _WEIGHTS["external_data_transfer"]
                    factors.append("external_data_transfer")
                    explanations.append(
                        f"Data submitted to external domain '{submit_domain}'"
                    )

        # --- Prompt injection ---
        if classification.injection_detected:
            score += _WEIGHTS["prompt_injection_indicator"]
            factors.append("prompt_injection_indicator")
            explanations.append(
                f"Prompt-injection patterns detected in source content: "
                f"{classification.injection_indicators}"
            )

        # --- Sensitive form submission ---
        if action_type == ActionType.submit:
            has_sensitive = bool(payload_keys & _SENSITIVE_FIELDS)
            field_sensitive = field_name in _SENSITIVE_FIELDS
            if has_sensitive or field_sensitive:
                score += _WEIGHTS["sensitive_form_submission"]
                factors.append("sensitive_form_submission")
                explanations.append("Form submission contains sensitive field data")

        # --- Taint ---
        taint_bonus = taint_tracker.get_taint_risk_bonus(
            action.session_id, str(action_type), field_name or None
        )
        if taint_bonus > 0:
            score += taint_bonus
            factors.append("tainted_session")
            explanations.append(
                f"Session contains tainted content (bonus +{taint_bonus})"
            )

        # --- Session history ---
        if blocked_count > 0:
            bonus = min(blocked_count * _WEIGHTS["previous_blocked_action"], 30)
            score += bonus
            factors.append("previous_blocked_action")
            explanations.append(
                f"{blocked_count} previously blocked action(s) in this session"
            )

        # --- Irreversible actions ---
        if action_type in (ActionType.submit, ActionType.upload, ActionType.download):
            score += _WEIGHTS["irreversible_action"]
            factors.append("irreversible_action")
            explanations.append("Action is potentially irreversible")

        # Cap at 100
        score = min(score, 100)

        return RiskAnalysisResult(
            score=score,
            risk_level=_score_to_level(score),
            factors=factors,
            explanations=explanations,
            sensitive_data_indicators=sensitive_indicators,
            injection_indicators=injection_indicators,
        )

    @staticmethod
    def _extract_domain(url: str) -> Optional[str]:
        if not url:
            return None
        url = re.sub(r"^https?://", "", url.lower().strip())
        domain = url.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
        return domain or None


import re


def _score_to_level(score: int) -> RiskLevel:
    if score >= 70:
        return RiskLevel.CRITICAL
    elif score >= 50:
        return RiskLevel.HIGH
    elif score >= 25:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW


# Module-level singleton
risk_analyzer = RiskAnalyzer()
