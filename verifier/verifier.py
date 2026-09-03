"""
verifier/verifier.py — ContextGuard

ContextGuardVerifier: checks whether the agent's claimed belief and
intended action are consistent with the real page state captured by
capture_state().

Two-layer architecture
----------------------
Layer 1 — Rule-based (always runs, zero latency):
  Fast deterministic checks covering the most common attack patterns.
  A rule match immediately returns DISCREPANCY without calling the LLM.
  A confirmed-safe rule match immediately returns CONSISTENT.

Layer 2 — LLM (optional, runs when rules are inconclusive):
  Sends a compact prompt to a local Ollama model (default: llama3).
  Falls back gracefully when Ollama is unavailable — the rule layer
  result is used instead.

Decision priority:  DISCREPANCY > CONSISTENT > INCONCLUSIVE

Why fail-closed
---------------
If both layers fail or return conflicting results for a high-risk action,
we return DISCREPANCY.  Allowing an unverified high-risk action is worse
than blocking a legitimate one.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from verifier.agent_claim import (
    AgentClaim,
    claim_contains_dangerous_belief,
    claim_is_high_risk_action,
)
from verifier.capture_state import PageSnapshot


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class VerificationStatus(str, Enum):
    CONSISTENT          = "CONSISTENT"
    DISCREPANCY         = "DISCREPANCY DETECTED"
    INCONCLUSIVE        = "INCONCLUSIVE"


@dataclass
class VerificationResult:
    """
    The complete output of a ContextGuard verification pass.

    Fields
    ------
    status        : CONSISTENT | DISCREPANCY DETECTED | INCONCLUSIVE
    reason        : One-sentence human-readable explanation.
    layer         : "rule" | "llm" | "both" — which layer produced the result.
    rule_hits     : Names of rules that fired.
    risk_level    : "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    allow         : True only when status is CONSISTENT.
    latency_ms    : Total wall-clock time in milliseconds.
    llm_raw       : Raw LLM response (for audit), empty when LLM not used.
    details       : Additional structured detail dict.
    """
    status: VerificationStatus
    reason: str
    layer: str = "rule"
    rule_hits: List[str] = field(default_factory=list)
    risk_level: str = "MEDIUM"
    allow: bool = False
    latency_ms: float = 0.0
    llm_raw: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "layer": self.layer,
            "rule_hits": self.rule_hits,
            "risk_level": self.risk_level,
            "allow": self.allow,
            "latency_ms": round(self.latency_ms, 2),
            "llm_raw": self.llm_raw,
            "details": self.details,
        }

    def __str__(self) -> str:
        icon = "✅" if self.allow else "🚫"
        return (
            f"{icon} STATUS: {self.status.value}\n"
            f"   REASON: {self.reason}\n"
            f"   LAYER:  {self.layer}  |  RISK: {self.risk_level}  |  "
            f"LATENCY: {self.latency_ms:.1f}ms"
        )


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

class _RuleEngine:
    """
    Deterministic rule-based consistency checker.

    Each rule returns (VerificationStatus, reason_str, rule_name) or None
    if the rule does not apply.  Rules are evaluated in order; the first
    conclusive result wins.
    """

    def evaluate(
        self,
        claim: AgentClaim,
        snapshot: PageSnapshot,
    ) -> Tuple[Optional[VerificationStatus], str, List[str]]:
        """
        Run all rules.  Returns (status, reason, rule_hits).
        status is None when no rule fires conclusively.
        """
        hits: List[str] = []
        reasons: List[str] = []

        for rule_fn in self._rules:
            result = rule_fn(self, claim, snapshot)
            if result is None:
                continue
            status, reason, rule_name = result
            hits.append(rule_name)
            reasons.append(reason)
            if status == VerificationStatus.DISCREPANCY:
                return status, reason, hits

        # If any CONSISTENT rule fired and no DISCREPANCY, return CONSISTENT
        if hits:
            return VerificationStatus.CONSISTENT, reasons[0], hits

        return None, "", []

    # ------------------------------------------------------------------
    # Individual rules
    # Each method signature: (self, claim, snapshot) -> Optional[tuple]
    # ------------------------------------------------------------------

    def _rule_confirmation_not_on_page(
        self, claim: AgentClaim, snapshot: PageSnapshot
    ) -> Optional[tuple]:
        """
        Agent claims booking/payment is confirmed but page has no
        confirmation text and is not on a thank-you/success URL.
        """
        belief_lower = claim.belief.lower()
        confirmation_words = [
            "confirmed", "confirmation", "success", "completed",
            "order placed", "booked", "payment processed",
        ]
        belief_claims_confirmed = any(w in belief_lower for w in confirmation_words)

        if not belief_claims_confirmed:
            return None

        url_lower = snapshot.url.lower()
        url_looks_confirmed = any(
            kw in url_lower
            for kw in ("confirm", "success", "thank", "receipt", "complete")
        )

        if belief_claims_confirmed and not snapshot.confirmation_text_present and not url_looks_confirmed:
            return (
                VerificationStatus.DISCREPANCY,
                "Agent believes action is confirmed but page shows no confirmation text "
                f"and URL ({snapshot.url}) does not indicate a success page.",
                "confirmation_not_on_page",
            )
        return None

    def _rule_payment_action_on_review_page(
        self, claim: AgentClaim, snapshot: PageSnapshot
    ) -> Optional[tuple]:
        """
        Agent wants to pay/submit payment but page is still on a
        review, cart, or form-filling step.
        """
        action_lower = claim.intended_action.lower()
        is_pay_action = any(
            kw in action_lower
            for kw in ("pay", "payment", "checkout", "purchase", "buy now",
                       "proceed to payment", "confirm payment")
        )
        if not is_pay_action:
            return None

        url_lower = snapshot.url.lower()
        text_lower = snapshot.visible_text.lower()
        on_review = any(
            kw in url_lower or kw in text_lower
            for kw in ("review", "cart", "basket", "summary", "details",
                       "check your", "verify your")
        )
        if on_review and not snapshot.confirmation_text_present:
            return (
                VerificationStatus.DISCREPANCY,
                "Agent wants to proceed to payment but page appears to be on a "
                "review/cart step, not a payment confirmation page.",
                "payment_action_on_review_page",
            )
        return None

    def _rule_injection_text_detected(
        self, claim: AgentClaim, snapshot: PageSnapshot
    ) -> Optional[tuple]:
        """
        Page contains prompt-injection patterns in visible text.
        Any action following an injected page is suspect.
        """
        if not snapshot.injection_text_present:
            return None
        return (
            VerificationStatus.DISCREPANCY,
            "Prompt-injection patterns detected in page visible text. "
            "The page may be attempting to manipulate the agent's behaviour.",
            "injection_text_detected",
        )

    def _rule_modal_contradicts_belief(
        self, claim: AgentClaim, snapshot: PageSnapshot
    ) -> Optional[tuple]:
        """
        A modal/popup on the page contains text that contradicts
        the agent's belief (e.g. an error modal while agent says success).
        """
        if not snapshot.modals:
            return None

        modal_text = " ".join(snapshot.modals).lower()
        belief_lower = claim.belief.lower()

        # Modal says error but agent believes success
        modal_has_error = any(
            kw in modal_text for kw in ("error", "failed", "invalid", "declined",
                                         "not found", "unavailable", "try again")
        )
        belief_says_success = any(
            kw in belief_lower for kw in ("confirmed", "success", "completed", "done")
        )
        if modal_has_error and belief_says_success:
            return (
                VerificationStatus.DISCREPANCY,
                f"Page shows an error modal ({snapshot.modals[0][:80]}) but agent "
                "believes the action succeeded.",
                "modal_contradicts_belief",
            )

        # Modal contains injection text
        if any(
            kw in modal_text
            for kw in ("ignore previous", "skip this step", "already confirmed",
                       "proceed directly", "bypass")
        ):
            return (
                VerificationStatus.DISCREPANCY,
                f"Modal/popup contains suspicious override text: "
                f"'{snapshot.modals[0][:100]}'",
                "modal_injection_detected",
            )
        return None

    def _rule_button_not_present(
        self, claim: AgentClaim, snapshot: PageSnapshot
    ) -> Optional[tuple]:
        """
        Agent wants to click a button whose text does not appear on page.
        """
        target = claim.target_text
        if not target:
            return None

        button_texts = [b["text"].lower() for b in snapshot.buttons]
        all_text = snapshot.visible_text.lower()
        target_lower = target.lower()

        if target_lower not in all_text and not any(
            target_lower in bt for bt in button_texts
        ):
            return (
                VerificationStatus.DISCREPANCY,
                f"Agent wants to click '{target}' but that text is not present "
                "on the current page.",
                "button_not_present",
            )
        return None

    def _rule_url_mismatch(
        self, claim: AgentClaim, snapshot: PageSnapshot
    ) -> Optional[tuple]:
        """
        Agent action implies a specific URL context that does not match
        the current page URL.
        """
        action_lower = claim.intended_action.lower()
        url_lower = snapshot.url.lower()

        pairs = [
            ("log in", ("login", "signin", "auth")),
            ("sign in", ("login", "signin", "auth")),
            ("checkout", ("checkout", "cart", "payment")),
            ("register", ("register", "signup", "create-account")),
        ]
        for action_kw, url_kws in pairs:
            if action_kw in action_lower:
                if not any(uk in url_lower for uk in url_kws):
                    return (
                        VerificationStatus.DISCREPANCY,
                        f"Agent wants to '{action_kw}' but current URL "
                        f"({snapshot.url}) does not appear to be that page.",
                        "url_mismatch",
                    )
        return None

    def _rule_safe_read_action(
        self, claim: AgentClaim, snapshot: PageSnapshot
    ) -> Optional[tuple]:
        """
        Read-only extract/scroll actions are always safe to allow.
        Produces a CONSISTENT result to short-circuit further checks.
        """
        action_type = claim.action_type
        if action_type in ("extract", "scroll"):
            return (
                VerificationStatus.CONSISTENT,
                f"Action type '{action_type}' is read-only and safe to allow.",
                "safe_read_action",
            )
        return None

    # Registry — order matters: discrepancy rules before safe rules
    _rules = [
        _rule_injection_text_detected,
        _rule_modal_injection_detected := _rule_modal_contradicts_belief,
        _rule_confirmation_not_on_page,
        _rule_payment_action_on_review_page,
        _rule_button_not_present,
        _rule_url_mismatch,
        _rule_safe_read_action,
    ]


# Fix: rebuild the list with bound method references
_RuleEngine._rules = [
    _RuleEngine._rule_injection_text_detected,
    _RuleEngine._rule_modal_contradicts_belief,
    _RuleEngine._rule_confirmation_not_on_page,
    _RuleEngine._rule_payment_action_on_review_page,
    _RuleEngine._rule_button_not_present,
    _RuleEngine._rule_url_mismatch,
    _RuleEngine._rule_safe_read_action,
]


# ---------------------------------------------------------------------------
# LLM layer (Ollama)
# ---------------------------------------------------------------------------

_OLLAMA_PROMPT_TEMPLATE = """\
You are a security verifier for an AI web agent named ContextGuard.
Your job is to check whether the agent's belief and intended action
are consistent with the real browser page state.

Agent belief:
{belief}

Intended action:
{action}

Real page state summary:
{snapshot_summary}

Instructions:
- Compare the agent's belief with the real page state.
- If they are consistent, respond with exactly:
  STATUS: CONSISTENT
- If there is a discrepancy (the page does not support the belief or action), respond with exactly:
  STATUS: DISCREPANCY DETECTED
  REASON: <one concise sentence explaining the discrepancy>
- Do not add any other text.
"""


def _call_ollama(
    belief: str,
    action: str,
    snapshot_summary: str,
    model: str = "llama3",
    timeout: int = 10,
) -> Tuple[Optional[VerificationStatus], str, str]:
    """
    Call local Ollama API.  Returns (status, reason, raw_response).
    Returns (None, "", "") on any error so the rule layer result is used.
    """
    try:
        import urllib.request
        import urllib.error

        prompt = _OLLAMA_PROMPT_TEMPLATE.format(
            belief=belief[:400],
            action=action[:200],
            snapshot_summary=snapshot_summary[:600],
        )
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        raw = data.get("response", "").strip()
        return _parse_llm_response(raw), _extract_llm_reason(raw), raw

    except Exception:
        return None, "", ""


def _parse_llm_response(text: str) -> Optional[VerificationStatus]:
    upper = text.upper()
    if "STATUS: CONSISTENT" in upper:
        return VerificationStatus.CONSISTENT
    if "DISCREPANCY" in upper:
        return VerificationStatus.DISCREPANCY
    return None


def _extract_llm_reason(text: str) -> str:
    m = re.search(r"REASON:\s*(.+)", text, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return text[:120] if text else "LLM returned no reason."


# ---------------------------------------------------------------------------
# Main verifier
# ---------------------------------------------------------------------------

class ContextGuardVerifier:
    """
    The core ContextGuard verification engine.

    Usage
    -----
    verifier = ContextGuardVerifier(use_llm=True, llm_model="llama3")
    result = verifier.verify(thought, action, snapshot)

    if result.allow:
        await page.click(selector)
    else:
        print("ContextGuard Alert:", result.reason)
    """

    def __init__(
        self,
        use_llm: bool = True,
        llm_model: str = "llama3",
        llm_timeout: int = 10,
        always_use_llm_for_high_risk: bool = True,
    ) -> None:
        self._use_llm = use_llm
        self._llm_model = llm_model
        self._llm_timeout = llm_timeout
        self._always_llm_high_risk = always_use_llm_for_high_risk
        self._rule_engine = _RuleEngine()

    # ------------------------------------------------------------------

    def verify(
        self,
        thought: str,
        action: str,
        snapshot: PageSnapshot,
        claim: Optional[AgentClaim] = None,
    ) -> VerificationResult:
        """
        Verify consistency between agent belief/action and real page state.

        Parameters
        ----------
        thought  : Agent's belief about the current page state.
        action   : Agent's intended browser action.
        snapshot : Trusted PageSnapshot from capture_state().
        claim    : Pre-parsed AgentClaim (optional; built from thought/action if None).

        Returns
        -------
        VerificationResult with .allow indicating whether execution is safe.
        """
        from verifier.agent_claim import extract_agent_claim as _parse
        t0 = time.monotonic()

        if claim is None:
            claim = _parse({"belief": thought, "intended_action": action})

        is_high_risk = claim_is_high_risk_action(claim)
        has_dangerous_belief = claim_contains_dangerous_belief(claim)
        risk_level = _compute_risk_level(claim, snapshot, is_high_risk)

        # --- Layer 1: Rule engine ---
        rule_status, rule_reason, rule_hits = self._rule_engine.evaluate(claim, snapshot)

        # Fast path: rules found a DISCREPANCY
        if rule_status == VerificationStatus.DISCREPANCY:
            return VerificationResult(
                status=rule_status,
                reason=rule_reason,
                layer="rule",
                rule_hits=rule_hits,
                risk_level=risk_level,
                allow=False,
                latency_ms=(time.monotonic() - t0) * 1000,
                details={"claim": claim.to_dict()},
            )

        # Decide whether to call LLM
        call_llm = (
            self._use_llm
            and (
                rule_status is None            # rules inconclusive
                or (self._always_llm_high_risk and is_high_risk)
                or has_dangerous_belief
            )
        )

        llm_status: Optional[VerificationStatus] = None
        llm_reason = ""
        llm_raw = ""

        if call_llm:
            llm_status, llm_reason, llm_raw = _call_ollama(
                belief=claim.belief,
                action=claim.intended_action,
                snapshot_summary=snapshot.to_summary(),
                model=self._llm_model,
                timeout=self._llm_timeout,
            )

        # --- Combine results ---
        # DISCREPANCY from either layer wins
        if llm_status == VerificationStatus.DISCREPANCY:
            final_status = VerificationStatus.DISCREPANCY
            final_reason = llm_reason or "LLM detected discrepancy."
            final_layer = "llm" if not rule_hits else "both"

        elif rule_status == VerificationStatus.CONSISTENT:
            final_status = VerificationStatus.CONSISTENT
            final_reason = rule_reason
            final_layer = "rule" if not llm_status else "both"

        elif llm_status == VerificationStatus.CONSISTENT:
            final_status = VerificationStatus.CONSISTENT
            final_reason = llm_reason or "LLM verified consistency."
            final_layer = "llm"

        else:
            # Both layers inconclusive — fail closed for high-risk actions
            if is_high_risk or has_dangerous_belief:
                final_status = VerificationStatus.DISCREPANCY
                final_reason = (
                    "Verification inconclusive for a high-risk action. "
                    "Blocking as a precaution (fail-closed)."
                )
                final_layer = "fail_closed"
            else:
                final_status = VerificationStatus.CONSISTENT
                final_reason = "No inconsistency detected by rule engine."
                final_layer = "rule"

        allow = final_status == VerificationStatus.CONSISTENT

        return VerificationResult(
            status=final_status,
            reason=final_reason,
            layer=final_layer,
            rule_hits=rule_hits,
            risk_level=risk_level,
            allow=allow,
            latency_ms=(time.monotonic() - t0) * 1000,
            llm_raw=llm_raw,
            details={"claim": claim.to_dict()},
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_risk_level(
    claim: AgentClaim,
    snapshot: PageSnapshot,
    is_high_risk: bool,
) -> str:
    score = 0
    if is_high_risk:
        score += 2
    if claim_contains_dangerous_belief(claim):
        score += 2
    if snapshot.injection_text_present:
        score += 3
    if snapshot.has_payment_field:
        score += 2
    if snapshot.has_password_field:
        score += 1
    if snapshot.modals:
        score += 1

    if score >= 5:
        return "CRITICAL"
    if score >= 3:
        return "HIGH"
    if score >= 1:
        return "MEDIUM"
    return "LOW"


# Module-level singleton with LLM enabled by default.
# Set use_llm=False for offline / test environments.
verifier = ContextGuardVerifier(use_llm=True)
