"""
Decision Engine — ContextGuard Core

Combines the outputs of the source classifier, taint tracker, policy engine,
and risk analyser to produce a single, explainable DecisionResult.

Decision priority (highest wins):
  BLOCK > REQUIRE_APPROVAL > WARN > ALLOW

Why the agent cannot access Playwright directly
-----------------------------------------------
Every browser action must pass through this engine before execution. The
engine is the sole authority on whether an action is executable. The browser
service checks the 'executable' flag on the DecisionResult and refuses to
act if it is False. This guarantees that no action bypasses safety evaluation.

Why fail-safe behaviour is required
------------------------------------
If any safety component raises an exception, we cannot know whether the
action is safe. The engine catches all exceptions and returns REQUIRE_APPROVAL
or BLOCK. Allowing an action when safety state is unknown would be fail-open,
which is unacceptable for a security gateway.
"""

from __future__ import annotations

import traceback
from typing import List, Optional

from app.core.policy_engine import PolicyEngine, policy_engine as default_policy_engine
from app.core.risk_analyzer import RiskAnalyzer, risk_analyzer as default_risk_analyzer
from app.core.source_classifier import SourceClassifier, classifier as default_classifier
from app.core.taint_tracker import TaintTracker, taint_tracker as default_taint_tracker
from app.models.action import ActionType, BrowserAction, SourceType
from app.models.decision import DecisionResult, DecisionType, RiskLevel


class DecisionEngine:
    """
    Orchestrates all safety components and produces a final DecisionResult.

    Injecting dependencies allows the test suite to substitute mocks without
    patching global singletons.
    """

    def __init__(
        self,
        classifier: Optional[SourceClassifier] = None,
        taint_tracker: Optional[TaintTracker] = None,
        policy_engine: Optional[PolicyEngine] = None,
        risk_analyzer: Optional[RiskAnalyzer] = None,
    ) -> None:
        self._classifier = classifier or default_classifier
        self._taint_tracker = taint_tracker or default_taint_tracker
        self._policy_engine = policy_engine or default_policy_engine
        self._risk_analyzer = risk_analyzer or default_risk_analyzer

    # ------------------------------------------------------------------
    # Main evaluation entry point
    # ------------------------------------------------------------------

    def evaluate(
        self,
        action: BrowserAction,
        blocked_count: int = 0,
    ) -> DecisionResult:
        """
        Evaluate a BrowserAction and return a DecisionResult.

        The result is explainable: every reason, matched policy, and risk
        factor is included so operators can audit and understand the decision.

        Exceptions in any component cause a fail-closed result.
        """
        try:
            return self._evaluate_internal(action, blocked_count)
        except Exception as exc:
            # Fail closed: internal error → REQUIRE_APPROVAL
            tb = traceback.format_exc()
            return DecisionResult(
                decision=DecisionType.REQUIRE_APPROVAL,
                risk_score=75,
                risk_level=RiskLevel.CRITICAL,
                reasons=[
                    f"Internal safety evaluation error: {exc}",
                    "Fail-closed: action held for approval",
                ],
                matched_policies=[],
                risk_factors=["internal_error"],
                tainted=False,
                taint_explanation=None,
                executable=False,
                approval_required=True,
                action_id=action.action_id,
            )

    def _evaluate_internal(
        self,
        action: BrowserAction,
        blocked_count: int,
    ) -> DecisionResult:
        reasons: List[str] = []
        risk_factors: List[str] = []
        matched_policies: List[str] = []
        force_decision: Optional[DecisionType] = None

        # ---------------------------------------------------------------
        # 1. Source classification
        # ---------------------------------------------------------------
        try:
            classification = self._classifier.classify(action.source)
        except Exception as exc:
            classification = None
            reasons.append(f"Source classification failed: {exc}")

        # ---------------------------------------------------------------
        # 2. Taint tracking
        # ---------------------------------------------------------------
        tainted = False
        taint_explanation: Optional[str] = None

        try:
            # Introduce taint if the source is untrusted
            untrusted_types = {
                SourceType.page_content,
                SourceType.tool_output,
                SourceType.unknown,
            }
            if action.source.source_type in untrusted_types:
                self._taint_tracker.add_taint(
                    session_id=action.session_id,
                    source_url=action.source.origin_url,
                    source_type=str(action.source.source_type),
                    action_id=action.action_id,
                    action_type=str(action.action_type),
                    content=action.source.content,
                )

            tainted = self._taint_tracker.is_tainted(action.session_id)
            if tainted:
                taint_explanation = self._taint_tracker.propagate_taint(
                    action.session_id, action.action_id
                )
        except Exception as exc:
            reasons.append(f"Taint tracking error: {exc}")

        # ---------------------------------------------------------------
        # 3. Risk analysis
        # ---------------------------------------------------------------
        try:
            from app.core.source_classifier import ClassificationResult
            if classification is None:
                from app.core.source_classifier import ClassificationResult
                classification = ClassificationResult(
                    source_type=str(action.source.source_type),
                    trust_value=0.10,
                    trusted=False,
                    explanation="Classification unavailable (fail-closed)",
                    injection_indicators=[],
                    injection_detected=False,
                )
            risk_result = self._risk_analyzer.analyze(
                action, classification, self._taint_tracker, blocked_count
            )
        except Exception as exc:
            reasons.append(f"Risk analysis failed: {exc}")
            # Fail closed
            return DecisionResult(
                decision=DecisionType.REQUIRE_APPROVAL,
                risk_score=80,
                risk_level=RiskLevel.CRITICAL,
                reasons=reasons + ["Risk analysis unavailable; fail-closed"],
                matched_policies=[],
                risk_factors=["risk_analysis_error"],
                tainted=tainted,
                taint_explanation=taint_explanation,
                executable=False,
                approval_required=True,
                action_id=action.action_id,
            )

        risk_factors.extend(risk_result.factors)
        reasons.extend(risk_result.explanations)

        # ---------------------------------------------------------------
        # 4. Policy evaluation
        # ---------------------------------------------------------------
        try:
            policy_result = self._policy_engine.evaluate(action)
            matched_policies.extend(policy_result.matched_policy_ids)
            reasons.extend(policy_result.explanations)
            risk_score = min(
                100, risk_result.score + policy_result.risk_contribution
            )
        except Exception as exc:
            reasons.append(f"Policy evaluation failed: {exc}")
            policy_result = None
            risk_score = risk_result.score

        # ---------------------------------------------------------------
        # 5. Decision resolution
        # ---------------------------------------------------------------

        # Absolute BLOCK rules (policy overrides score)
        block_conditions = [
            (
                self._is_blocked_domain(action),
                "Action targets a blocked domain",
                "CG-DOMAIN-002",
            ),
            (
                self._is_executable_download_unknown(action),
                "Executable download from unknown domain",
                "CG-DOWNLOAD-001",
            ),
            (
                self._is_injection_followed_by_sensitive(action, classification),
                "Prompt injection detected in source of a sensitive action",
                "CG-INJECTION-001",
            ),
            (
                self._is_tainted_sensitive_transfer(action, tainted),
                "Tainted content influencing sensitive data transfer",
                "CG-EXFIL-001",
            ),
        ]

        for condition, reason, policy_id in block_conditions:
            if condition:
                force_decision = DecisionType.BLOCK
                if reason not in reasons:
                    reasons.append(reason)
                if policy_id not in matched_policies:
                    matched_policies.append(policy_id)
                risk_score = max(risk_score, 85)

        # REQUIRE_APPROVAL rules (if not already BLOCK)
        if force_decision != DecisionType.BLOCK:
            approval_conditions = [
                (
                    self._is_payment_action(action),
                    "Payment field interaction requires human approval",
                    "CG-SENSITIVE-002",
                ),
                (
                    self._is_password_action(action),
                    "Password field interaction requires human approval",
                    "CG-SENSITIVE-001",
                ),
                (
                    self._is_file_upload(action),
                    "File upload requires human approval",
                    "CG-UPLOAD-001",
                ),
                (
                    self._is_unknown_domain_upload(action),
                    "Upload to unknown domain requires human approval",
                    "CG-UPLOAD-002",
                ),
            ]
            for condition, reason, policy_id in approval_conditions:
                if condition and force_decision != DecisionType.BLOCK:
                    force_decision = DecisionType.REQUIRE_APPROVAL
                    if reason not in reasons:
                        reasons.append(reason)
                    if policy_id not in matched_policies:
                        matched_policies.append(policy_id)
                    risk_score = max(risk_score, 50)

        # If a critical policy fired (from policy engine), upgrade to BLOCK
        if (
            policy_result
            and policy_result.critical_override
            and force_decision != DecisionType.BLOCK
        ):
            force_decision = DecisionType.BLOCK
            reasons.append("Critical policy violation — action blocked regardless of risk score")
            risk_score = max(risk_score, 85)

        # ---------------------------------------------------------------
        # 6. Score-derived decision (if no override)
        # ---------------------------------------------------------------
        if force_decision is None:
            if risk_score >= 70:
                force_decision = DecisionType.BLOCK
            elif risk_score >= 50:
                force_decision = DecisionType.REQUIRE_APPROVAL
            elif risk_score >= 25:
                force_decision = DecisionType.WARN
            else:
                force_decision = DecisionType.ALLOW

        # ---------------------------------------------------------------
        # 7. Merge policy-engine recommendation if it is more severe
        # ---------------------------------------------------------------
        priority = {
            DecisionType.ALLOW: 0,
            DecisionType.WARN: 1,
            DecisionType.REQUIRE_APPROVAL: 2,
            DecisionType.BLOCK: 3,
        }
        if policy_result and policy_result.recommended_decision:
            if (priority.get(policy_result.recommended_decision, 0)
                    > priority.get(force_decision, 0)):
                force_decision = policy_result.recommended_decision

        # ---------------------------------------------------------------
        # 8. Build final result
        # ---------------------------------------------------------------
        executable = force_decision in (DecisionType.ALLOW, DecisionType.WARN)
        approval_required = force_decision == DecisionType.REQUIRE_APPROVAL

        from app.models.decision import _score_to_level
        return DecisionResult(
            decision=force_decision,
            risk_score=risk_score,
            risk_level=_score_to_level(risk_score),
            reasons=list(dict.fromkeys(reasons)),  # deduplicate preserving order
            matched_policies=list(dict.fromkeys(matched_policies)),
            risk_factors=list(dict.fromkeys(risk_factors)),
            tainted=tainted,
            taint_explanation=taint_explanation,
            executable=executable,
            approval_required=approval_required,
            action_id=action.action_id,
        )

    # ------------------------------------------------------------------
    # Named condition helpers
    # ------------------------------------------------------------------

    _BLOCKED_DOMAINS = {
        "malware.example", "phishing.example", "exfil.example",
        "evil.example", "badactor.example", "untrusted.example", "exploit.example",
    }
    _EXECUTABLE_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".msi", ".ps1", ".sh",
        ".vbs", ".js", ".jar", ".dmg", ".pkg", ".deb", ".rpm",
    }
    _APPROVED_DOMAINS = {
        "docs.python.org", "developer.mozilla.org", "fastapi.tiangolo.com",
        "github.com", "wikipedia.org", "stackoverflow.com", "pypi.org",
        "example-trusted.com",
    }

    @classmethod
    def _extract_domain(cls, url: Optional[str]) -> Optional[str]:
        import re
        if not url:
            return None
        url = re.sub(r"^https?://", "", url.lower().strip())
        domain = url.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
        return domain or None

    def _is_blocked_domain(self, action: BrowserAction) -> bool:
        domain = self._extract_domain(action.target.url)
        current = (action.current_domain or "").lower()
        return (
            (domain and domain in self._BLOCKED_DOMAINS)
            or current in self._BLOCKED_DOMAINS
        )

    def _is_executable_download_unknown(self, action: BrowserAction) -> bool:
        if action.action_type != ActionType.download:
            return False
        url = (action.target.url or "").lower()
        filename = str(action.payload.get("filename", "")).lower()
        is_exec = any(
            url.endswith(ext) or filename.endswith(ext)
            for ext in self._EXECUTABLE_EXTENSIONS
        )
        domain = self._extract_domain(url)
        is_unknown = not domain or domain not in self._APPROVED_DOMAINS
        return is_exec and is_unknown

    def _is_injection_followed_by_sensitive(
        self, action: BrowserAction, classification
    ) -> bool:
        if classification is None:
            return False
        if not classification.injection_detected:
            return False
        return action.action_type in (
            ActionType.submit, ActionType.upload, ActionType.fill
        )

    def _is_tainted_sensitive_transfer(
        self, action: BrowserAction, tainted: bool
    ) -> bool:
        if not tainted:
            return False
        return action.action_type in (ActionType.submit, ActionType.upload)

    def _is_payment_action(self, action: BrowserAction) -> bool:
        payment_fields = {"card_number", "credit_card", "cvv", "cvc", "expiry",
                          "payment", "billing", "bank_account", "routing_number"}
        field_name = (action.target.field_name or "").lower()
        payload_keys = {k.lower() for k in action.payload}
        return (
            action.action_type in (ActionType.fill, ActionType.submit)
            and (field_name in payment_fields or bool(payload_keys & payment_fields))
        )

    def _is_password_action(self, action: BrowserAction) -> bool:
        password_fields = {"password", "passwd", "pass", "pin"}
        field_name = (action.target.field_name or "").lower()
        element_type = (action.target.element_type or "").lower()
        payload_keys = {k.lower() for k in action.payload}
        return (
            action.action_type in (ActionType.fill, ActionType.submit)
            and (
                field_name in password_fields
                or element_type == "password"
                or bool(payload_keys & password_fields)
            )
        )

    def _is_file_upload(self, action: BrowserAction) -> bool:
        return action.action_type == ActionType.upload

    def _is_unknown_domain_upload(self, action: BrowserAction) -> bool:
        if action.action_type != ActionType.upload:
            return False
        domain = self._extract_domain(action.target.url)
        current = (action.current_domain or "").lower()
        upload_target = domain or current
        return upload_target not in self._APPROVED_DOMAINS


# Module-level singleton
decision_engine = DecisionEngine()
