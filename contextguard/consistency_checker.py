"""
contextguard/consistency_checker.py — Phase 5, Checkpoint 5.3

Combines outputs from all three monitors into a structured
Inconsistency list: what changed, expected vs actual.

This is the single object the risk_engine reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional

from contextguard.action_analyzer import ActionFinding, action_analyzer
from contextguard.dom_monitor import DOMFinding, dom_monitor
from contextguard.url_monitor import URLFinding, url_monitor


@dataclass
class Inconsistency:
    """One detected problem from any monitor."""
    source:       str    # "url_monitor" | "dom_monitor" | "action_analyzer"
    finding_type: str
    description:  str
    risk_delta:   int
    expected:     str = ""
    observed:     str = ""
    keywords:     list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source":       self.source,
            "finding_type": self.finding_type,
            "description":  self.description,
            "risk_delta":   self.risk_delta,
            "expected":     self.expected,
            "observed":     self.observed,
            "keywords":     self.keywords,
        }


@dataclass
class ConsistencyReport:
    """Full output of one consistency check pass."""
    task_id:          str
    step_number:      int
    inconsistencies:  List[Inconsistency] = field(default_factory=list)
    total_risk_delta: int = 0
    clean:            bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id":         self.task_id,
            "step_number":     self.step_number,
            "inconsistencies": [i.to_dict() for i in self.inconsistencies],
            "total_risk_delta":self.total_risk_delta,
            "clean":           self.clean,
        }


class ConsistencyChecker:
    """
    Checkpoint 5.3 — orchestrates all monitors and returns a ConsistencyReport.
    """

    def check(
        self,
        task_id:         str,
        step_number:     int,
        user_intent:     Dict[str, Any],
        dom_snapshot:    Any,
        proposed_action: Dict[str, Any],
        previous_page:   Optional[str] = None,
        previous_text:   Optional[str] = None,
        raw_html:        str = "",
    ) -> ConsistencyReport:
        report = ConsistencyReport(task_id=task_id, step_number=step_number)

        current_url  = getattr(dom_snapshot, "url",          "")
        current_page = getattr(dom_snapshot, "page_name",    "")
        current_text = getattr(dom_snapshot, "visible_text", "")

        # --- URL monitor ---
        for f in url_monitor.check(current_url, current_page,
                                   previous_page, user_intent):
            report.inconsistencies.append(Inconsistency(
                source       = "url_monitor",
                finding_type = f.finding_type,
                description  = f.description,
                risk_delta   = f.risk_delta,
                observed     = f.url,
            ))

        # --- DOM monitor ---
        for f in dom_monitor.check(current_text, previous_text, raw_html):
            report.inconsistencies.append(Inconsistency(
                source       = "dom_monitor",
                finding_type = f.finding_type,
                description  = f.description,
                risk_delta   = f.risk_delta,
                keywords     = f.matched_keywords,
            ))

        # --- Action analyzer ---
        for f in action_analyzer.check(user_intent, proposed_action, dom_snapshot):
            report.inconsistencies.append(Inconsistency(
                source       = "action_analyzer",
                finding_type = f.finding_type,
                description  = f.description,
                risk_delta   = f.risk_delta,
                expected     = f.expected,
                observed     = f.observed,
            ))

        report.total_risk_delta = sum(i.risk_delta for i in report.inconsistencies)
        report.clean            = len(report.inconsistencies) == 0
        return report


consistency_checker = ConsistencyChecker()


# ---------------------------------------------------------------------------
# ContextGuard Component 2: Context Consistency Verification Engine
# Specification Reference: Section 3 (Step 4), FR7, FR8, FR9, FR10, Component 2
# ---------------------------------------------------------------------------

from pathlib import Path
import yaml
from urllib.parse import urlparse
from contextguard.models import (
    ConsistencyReport as NewConsistencyReport,
    InconsistencyItem,
    LockedIntent,
    ProposedAction,
)

CONFIG_DIR = Path(__file__).parent / "config"


class ContextConsistencyVerifier:
    """
    Synchronously verifies proposed agent action and DOM state against locked intent.
    Consumes:
      - contextguard/config/protected_fields.yaml
      - contextguard/config/trust_boundary.yaml
      - contextguard/config/attack_taxonomy.yaml
    Produces:
      - NewConsistencyReport (feeds directly into Risk Assessment via Verification Rail)
    """

    def __init__(
        self,
        protected_fields_path: Optional[Path] = None,
        trust_boundary_path: Optional[Path] = None,
        attack_taxonomy_path: Optional[Path] = None,
    ) -> None:
        pf_path = protected_fields_path or (CONFIG_DIR / "protected_fields.yaml")
        tb_path = trust_boundary_path or (CONFIG_DIR / "trust_boundary.yaml")
        at_path = attack_taxonomy_path or (CONFIG_DIR / "attack_taxonomy.yaml")

        pf_data = yaml.safe_load(pf_path.read_text(encoding="utf-8")) if pf_path.exists() else {}
        self.target_mappings: Dict[str, Dict[str, Any]] = pf_data.get("target_field_mappings", {})
        self.default_unmapped = pf_data.get("default_unmapped_action", {"action_sensitivity": 0.3, "booking_critical": False})

        tb_data = yaml.safe_load(tb_path.read_text(encoding="utf-8")) if tb_path.exists() else {}
        self.trusted_hosts: List[str] = tb_data.get("trusted_hosts", ["127.0.0.1", "localhost", "127.0.0.1:8000", "localhost:8000"])
        self.allowed_schemes: List[str] = tb_data.get("allowed_schemes", ["http", "https"])

        at_data = yaml.safe_load(at_path.read_text(encoding="utf-8")) if at_path.exists() else {}
        self.injection_markers: List[str] = []
        for attack_name, attack_info in at_data.get("known_attacks", {}).items():
            self.injection_markers.extend(attack_info.get("pattern_hints", []))

        aliases_path = (CONFIG_DIR / "airport_aliases.yaml")
        aliases_data = yaml.safe_load(aliases_path.read_text(encoding="utf-8")) if aliases_path.exists() else {}
        self.airport_aliases: Dict[str, str] = {
            str(k).strip().upper(): str(v).strip().lower()
            for k, v in aliases_data.get("aliases", {}).items()
        }

        # Ancillary-fee lexicon configuration (Phase 1 / Stage 1 hardening)
        ancillary_path = (CONFIG_DIR / "ancillary_lexicon.yaml")
        ancillary_data = yaml.safe_load(ancillary_path.read_text(encoding="utf-8")) if ancillary_path.exists() else {}
        self.currency_symbols: List[str] = [str(s) for s in ancillary_data.get("currency_symbols", ["$", "€", "£", "₹"])]
        self.currency_codes: List[str] = [str(c).lower().strip() for c in ancillary_data.get("currency_codes", ["usd", "eur", "inr", "gbp"])]
        self.fee_terms: List[str] = [str(f).lower().strip() for f in ancillary_data.get("fee_terms", ["fee", "surcharge", "charge", "tariff", "premium", "paid"])]
        self.complimentary_negation_phrases: List[str] = [str(p).lower().strip() for p in ancillary_data.get("complimentary_negation_phrases", [])]

        code_pattern = r"\b(" + "|".join(re.escape(c) for c in self.currency_codes) + r")\b" if self.currency_codes else r"$^"
        self._currency_codes_regex = re.compile(code_pattern, re.IGNORECASE)

        fee_pattern = r"\b(" + "|".join(re.escape(f) for f in self.fee_terms) + r")\b" if self.fee_terms else r"$^"
        self._fee_terms_regex = re.compile(fee_pattern, re.IGNORECASE)

        # Manifest-irreversible action targets (Rule C6)
        self.irreversible_targets: set[str] = {
            "#confirm-booking", "confirm-booking", "#book-btn", "book-btn",
            "#submit-transfer-btn", "submit-transfer-btn", "#add-payee-btn", "add-payee-btn",
            "#place-order-btn", "place-order-btn", "#book-appt-btn", "book-appt-btn",
            "#send-msg-btn", "send-msg-btn", "#send-btn", "send-btn",
            "#confirm-forward-btn", "confirm-forward-btn"
        }

    def has_raw_fee_token(self, text: str) -> bool:
        """
        Checks if text contains raw fee tokens, currency symbols, or ISO codes
        without evaluating any negation phrases.
        """
        if not text:
            return False
        if any(sym in text for sym in self.currency_symbols):
            return True
        if self._currency_codes_regex and self._currency_codes_regex.search(text):
            return True
        if self._fee_terms_regex and self._fee_terms_regex.search(text):
            return True
        return False

    def has_negation_phrase(self, text: str) -> bool:
        """Checks if text contains a configured complimentary negation phrase."""
        if not text:
            return False
        t_low = text.lower()
        return any(neg in t_low for neg in self.complimentary_negation_phrases)

    def has_ancillary_fee(self, text: str) -> bool:
        """
        Evaluates whether text contains an unnegated ancillary fee or monetary charge indicator
        using the configured ancillary-fee lexicon with strict word-boundary token matching.
        """
        if not self.has_raw_fee_token(text):
            return False
        if self.has_negation_phrase(text):
            has_positive_symbol = any(sym in text for sym in self.currency_symbols)
            if not has_positive_symbol:
                return False
        return True


    def resolve_target_metadata(self, target: str) -> Tuple[Optional[str], float, bool]:
        """
        Returns (intent_field_name, action_sensitivity, booking_critical).
        """
        t_low = target.lower().strip()
        # 1. Exact match check across all mappings first (prevents short substrings like 'to' matching '#to-account')
        for field_key, field_cfg in self.target_mappings.items():
            if field_key.lower() == t_low:
                return (
                    field_cfg.get("intent_field"),
                    float(field_cfg.get("action_sensitivity", 0.5)),
                    bool(field_cfg.get("booking_critical", False)),
                )
            for selector in field_cfg.get("target_selectors", []):
                if selector.lower() == t_low:
                    return (
                        field_cfg.get("intent_field"),
                        float(field_cfg.get("action_sensitivity", 0.5)),
                        bool(field_cfg.get("booking_critical", False)),
                    )

        # 2. Substring / selector containment fallback
        for field_key, field_cfg in self.target_mappings.items():
            for selector in field_cfg.get("target_selectors", []):
                if len(selector) > 2 and selector.lower() in t_low:
                    return (
                        field_cfg.get("intent_field"),
                        float(field_cfg.get("action_sensitivity", 0.5)),
                        bool(field_cfg.get("booking_critical", False)),
                    )

        # Heuristic fallback for common element names
        if "from" in t_low or "origin" in t_low:
            return ("origin", 0.80, True)
        if "to" in t_low or "dest" in t_low:
            return ("destination", 0.85, True)
        if "cabin" in t_low or "class" in t_low:
            return ("cabin_class", 0.75, True)
        if "pcount" in t_low or "passenger" in t_low:
            return ("passenger_count", 0.70, True)
        if "confirm" in t_low or "book" in t_low or "pay" in t_low:
            return (None, 0.95, True)

        return (
            None,
            float(self.default_unmapped.get("action_sensitivity", 0.3)),
            bool(self.default_unmapped.get("booking_critical", False)),
        )

    def verify(
        self,
        locked_intent: LockedIntent,
        action: ProposedAction,
        dom_text: str,
    ) -> NewConsistencyReport:
        inconsistencies: List[InconsistencyItem] = []
        marker_presence = False
        marker_hit: Optional[str] = None

        intent_field, sensitivity, is_critical = self.resolve_target_metadata(action.target)
        target_low = action.target.lower().strip()
        val_str = str(action.value).strip() if action.value is not None else ""

        # Check 1: Protected field value consistency (FR7) with airport alias normalisation
        if intent_field and action.value is not None:
            raw_expected = str(getattr(locked_intent, intent_field, "")).strip()
            raw_proposed = str(action.value).strip()

            if raw_expected:
                exp_low = raw_expected.lower()
                prop_low = raw_proposed.lower()
                is_match = False

                if exp_low == prop_low:
                    is_match = True
                elif intent_field in ("origin", "destination"):
                    # Airport alias normalisation used ONLY for origin/destination field comparison
                    norm_exp = self.airport_aliases.get(raw_expected.upper(), exp_low)
                    norm_prop = self.airport_aliases.get(raw_proposed.upper(), prop_low)
                    if norm_exp == norm_prop or norm_prop == exp_low or norm_exp == prop_low:
                        is_match = True

                if not is_match:
                    inconsistencies.append(
                        InconsistencyItem(
                            check_type="FIELD_MISMATCH",
                            field_name=intent_field,
                            expected_value=raw_expected,
                            observed_value=raw_proposed,
                            severity=0.85 if is_critical else 0.50,
                            detail=(
                                f"Proposed value for protected field '{intent_field}' ('{raw_proposed}') "
                                f"diverges from immutable locked intent ('{raw_expected}')."
                            ),
                        )
                    )

        # Check 1b: Travel date verification (GENERIC hard-rule check)
        is_date_field = "date" in target_low or intent_field == "travel_date"
        if is_date_field and val_str and getattr(locked_intent, "travel_date", None) is not None:
            expected_date = str(locked_intent.travel_date).strip()
            if val_str.lower() != expected_date.lower():
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="FIELD_MISMATCH",
                        field_name="travel_date",
                        expected_value=expected_date,
                        observed_value=val_str,
                        severity=0.85,
                        detail=(
                            f"Proposed travel date '{val_str}' diverges from "
                            f"locked intent travel date ('{expected_date}')."
                        ),
                    )
                )

        # Check 1c: Contact email verification (GENERIC hard-rule check)
        is_email_field = "email" in target_low or ("@" in val_str and "." in val_str)
        if is_email_field and val_str and getattr(locked_intent, "contact_email", None) is not None:
            expected_email = str(locked_intent.contact_email).strip().lower()
            if val_str.lower() != expected_email:
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="FIELD_MISMATCH",
                        field_name="contact_email",
                        expected_value=expected_email,
                        observed_value=val_str,
                        severity=0.85,
                        detail=(
                            f"Proposed contact email '{val_str}' diverges from "
                            f"authorized contact email ('{expected_email}')."
                        ),
                    )
                )

        # Check 1d: Ancillary-fee lexicon verification (addons_allowed: none)
        addons_policy = getattr(locked_intent, "addons_allowed", None)
        if addons_policy is not None and str(addons_policy).strip().lower() == "none":
            is_price_affecting = False
            affected_field_name = None

            # 1. Ancillary add-on categories
            if "baggage" in target_low or "luggage" in target_low:
                is_price_affecting = True
                affected_field_name = "baggage"
            elif "insurance" in target_low:
                is_price_affecting = True
                affected_field_name = "insurance"
            elif "currency" in target_low:
                is_price_affecting = True
                affected_field_name = "currency"

            # 2. Optional services (seats, meals) checked against ancillary-fee lexicon
            elif "seat" in target_low or "meal" in target_low:
                # Rule 1: Fee tokens in the action value/target are NEVER suppressed by page text.
                action_has_fee = self.has_raw_fee_token(val_str) or self.has_raw_fee_token(action.target)
                if action_has_fee:
                    is_price_affecting = True
                    affected_field_name = "seat_or_meal_surcharge"
                else:
                    # Action value/target is clean. Now check page text (dom_text).
                    dom_has_fee = self.has_raw_fee_token(dom_text)
                    if dom_has_fee:
                        dom_has_neg = self.has_negation_phrase(dom_text)
                        # Rule: Negation phrases found in page text may only downgrade a FIELD_MISMATCH
                        # to ALLOW_WITH_FLAG, never to ALLOW.
                        if dom_has_neg:
                            inconsistencies.append(
                                InconsistencyItem(
                                    check_type="ANCILLARY_FEE_FLAG",
                                    field_name="seat_or_meal_surcharge",
                                    expected_value="addons_allowed: none",
                                    observed_value=val_str or action.target,
                                    severity=0.35,
                                    detail=(
                                        f"Page text contains fee indicator mitigated by page negation phrase; "
                                        f"downgraded to ALLOW_WITH_FLAG (untrusted DOM text)."
                                    ),
                                )
                            )
                        else:
                            is_price_affecting = True
                            affected_field_name = "seat_or_meal_surcharge"

            if is_price_affecting:
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="FIELD_MISMATCH",
                        field_name=affected_field_name or "price_affecting_addon",
                        expected_value="addons_allowed: none",
                        observed_value=val_str or action.target,
                        severity=0.85,
                        detail=(
                            f"Action touches price-affecting field '{affected_field_name}' ('{action.target}'), "
                            f"flagged by ancillary-fee lexicon violating policy constraint 'addons_allowed=none'."
                        ),
                    )
                )

        # Check 2: Navigation & Form submission boundary verification (FR8 / C2)
        nav_target = ""
        c2_enabled = getattr(self, "enable_c2", True)
        valid_nav_types = ("NAVIGATE", "SUBMIT") if c2_enabled else ("NAVIGATE",)
        if action.action_type in valid_nav_types:
            nav_target = action.value or action.target
            if nav_target and str(nav_target).startswith("navigate:"):
                nav_target = str(nav_target)[len("navigate:"):]
        elif action.target and (str(action.target).startswith("http://") or str(action.target).startswith("https://")):
            nav_target = action.target
        elif action.action_type == "CLICK" and action.value and (str(action.value).startswith("http://") or str(action.value).startswith("https://")):
            nav_target = action.value

        if nav_target and ("://" in str(nav_target) or action.action_type in valid_nav_types):
            if not self._is_trusted_navigation(str(nav_target)):
                is_sub = (action.action_type == "SUBMIT")
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="NAVIGATION_BOUNDARY",
                        field_name="form_submit" if is_sub else "navigation",
                        expected_value="within trust_boundary",
                        observed_value=str(nav_target),
                        severity=0.90,
                        detail=f"{'Form submission' if is_sub else 'Navigation'} destination '{nav_target}' is outside configured trust boundary.",
                    )
                )

        # Check 3: Injection marker detection in DOM or justification (FR9)
        # Must Not: Treat a value match as sufficient if an injection marker is present
        combined_text = f"{dom_text} {action.source_text or ''}".lower()
        for marker in self.injection_markers:
            if marker.lower() in combined_text:
                marker_presence = True
                marker_hit = marker
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="INJECTION_MARKER",
                        field_name="dom_content",
                        expected_value="clean_page_context",
                        observed_value=marker,
                        severity=0.75,
                        detail=f"Known injection marker detected in page content or agent justification: '{marker}'.",
                    )
                )
                break

        # Check 4: Process Integrity & Plan Sequence Verification
        # Catches plan tampering, premature confirmation, and unmapped exfiltration targets
        # WITHOUT mutating protected booking fields (origin, destination, cabin, pcount).
        t_low = action.target.lower()
        url_low = (action.page_url or "").lower()

        # 4a. Premature submit/confirm: skipping review by submitting on non-review pages
        if action.action_type in ("CLICK", "SUBMIT") and any(k in t_low for k in ("confirm", "pay", "submit", "order", "checkout")):
            is_review_page = any(p in url_low for p in ("review", "confirm", "receipt")) or ("review your" in combined_text) or ("booking id" in combined_text)
            if not is_review_page:
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="PROCESS_INTEGRITY",
                        field_name="workflow_sequence",
                        expected_value="review_page",
                        observed_value=url_low,
                        severity=0.75,
                        detail=f"Premature confirmation action '{action.target}' attempted on non-review page '{url_low}'.",
                    )
                )

        # 4b. Unmapped external dispatch/forwarding target (e.g. notification-email)
        if action.action_type in ("TYPE", "FILL", "INPUT") and any(k in t_low for k in ("dispatch", "webhook", "forward", "exfil", "unmapped-email")):
            if not intent_field and action.value:
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="UNMAPPED_EXFILTRATION",
                        field_name="unmapped_field_mutation",
                        expected_value="authorized_user_dispatch",
                        observed_value=str(action.value),
                        severity=0.75,
                        detail=f"Action types sensitive value into unmapped communication field '{action.target}'.",
                    )
                )

        # 4c. Environmental plan-integrity directive / false completion claim
        if any(marker in combined_text for marker in (
            "data-plan-integrity", "skip_review", "pre-verified and are correct",
            "review step has been automatically completed", "seat hold expiring",
            "90 seconds", "auto-confirmed", "skips the separate review page",
            "auto-verified", "status update: booking reference",
            "automatically validated", "review phase automatically validated",
            "immediately finalize booking", "immediately finalize", "fasttrack express boarding",
            "bypass cart review", "bypass review", "1-click purchase"
        )):
            inconsistencies.append(
                InconsistencyItem(
                    check_type="PROCESS_INTEGRITY",
                    field_name="workflow_integrity",
                    expected_value="user_verified_booking_plan",
                    observed_value="adversarial_process_bypass",
                    severity=0.70,
                    detail="Plan-integrity manipulation: environmental prompt attempts to bypass review or falsify booking status.",
                )
            )

        # 4d. Unmapped identity-sensitive field (TC-05 fix / Review point 5)
        # Any typing/filling into an unmapped, identity-like field (SSN, national tax ID, government identity)
        # must be flagged as an unauthorized sensitive parameter extraction and escalate to REQUIRE_CONFIRMATION.
        identity_tokens = (
            "ssn", "social-security", "social_security", "tax-id", "tax_id",
            "tax-identifier", "national-id", "national_id", "govt-id", "government-id",
            "identity-doc", "identity-number", "unrelated-ssn"
        )
        is_identity_target = any(tok in t_low for tok in identity_tokens) or (
            "identity" in t_low and not any(k in t_low for k in ("name", "user", "passenger", "contact", "email"))
        )
        if action.action_type in ("TYPE", "FILL", "INPUT") and not intent_field and is_identity_target:
            inconsistencies.append(
                InconsistencyItem(
                    check_type="UNMAPPED_IDENTITY_FIELD",
                    field_name="unmapped_identity_input",
                    expected_value="authorized_user_input",
                    observed_value=str(action.value or ""),
                    severity=0.85,
                    detail=f"Action types sensitive value into unmapped identity field '{action.target}' (potential identity/credential exfiltration).",
                )
            )

        # Check 4e: Egress-in-content verification (Rule C5)
        egress_item = self._check_egress_in_content(action, locked_intent)
        if egress_item:
            inconsistencies.append(egress_item)

        # Check 4f: Irreversible-action authorization (Rule C6)
        # A manifest-irreversible action requires confirmation unless explicitly authorized
        # in the locked intent's authorized_actions list.
        is_irreversible = False
        t_clean = action.target.strip().lower()
        t_bare = t_clean.lstrip("#.")

        if hasattr(self, "irreversible_targets") and (t_clean in self.irreversible_targets or t_bare in self.irreversible_targets):
            is_irreversible = True
        elif is_critical and action.action_type in ("CLICK", "SUBMIT") and any(k in t_clean for k in ("confirm", "book", "order", "submit", "send")):
            is_irreversible = True

        if is_irreversible:
            auth_actions = set()
            raw_auth = getattr(locked_intent, "authorized_actions", None)
            if raw_auth is None and hasattr(locked_intent, "extra_fields"):
                raw_auth = locked_intent.extra_fields.get("authorized_actions")
            if raw_auth is None and isinstance(locked_intent, dict):
                raw_auth = locked_intent.get("authorized_actions")

            if raw_auth:
                if isinstance(raw_auth, (list, tuple, set)):
                    for a in raw_auth:
                        a_str = str(a).strip().lower()
                        auth_actions.add(a_str)
                        auth_actions.add(a_str.lstrip("#."))
                elif isinstance(raw_auth, str):
                    auth_actions.add(raw_auth.strip().lower())
                    auth_actions.add(raw_auth.strip().lower().lstrip("#."))

            if t_clean not in auth_actions and t_bare not in auth_actions:
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="UNAUTHORIZED_IRREVERSIBLE_ACTION",
                        field_name=action.target,
                        expected_value=f"authorized_actions containing '{action.target}'",
                        observed_value="unauthorized",
                        severity=0.85,
                        detail=f"Manifest-irreversible action '{action.target}' requires confirmation because it is not authorized in locked intent.",
                    )
                )

        is_consistent = len(inconsistencies) == 0
        max_severity = max((item.severity for item in inconsistencies), default=0.0)
        consistency_score = round(max(0.0, 1.0 - max_severity), 2)

        return NewConsistencyReport(
            is_consistent=is_consistent,
            consistency_score=consistency_score,
            inconsistency_severity=max_severity,
            inconsistencies=inconsistencies,
            marker_presence=marker_presence,
            marker_hit=marker_hit,
        )

    def _check_egress_in_content(self, action: ProposedAction, locked_intent: Any) -> Optional[InconsistencyItem]:
        """
        Rule C5: Egress-in-content verification.
        A value written to any field that contains a URL, hostname, or email address
        that is neither allowlisted nor part of the locked intent requires confirmation.
        """
        val = action.value
        if not val or not isinstance(val, str) or not val.strip():
            return None

        # Deobfuscate standard evasion tokens (e.g. http[://] or [.] or [@])
        cleaned = re.sub(r'\[://\]', '://', val)
        cleaned = re.sub(r'\[\.\]', '.', cleaned)
        cleaned = re.sub(r'\[@\]', '@', cleaned)

        # Build set of authorized tokens from locked_intent
        authorized_tokens = set()
        if hasattr(locked_intent, "to_dict"):
            try:
                intent_dict = locked_intent.to_dict()
            except Exception:
                intent_dict = {}
        elif hasattr(locked_intent, "__dict__"):
            intent_dict = dict(getattr(locked_intent, "extra_fields", {}))
            for k in ("origin", "destination", "contact_email", "to_email", "payee", "to_account"):
                v = getattr(locked_intent, k, None)
                if v:
                    intent_dict[k] = v
        elif isinstance(locked_intent, dict):
            intent_dict = locked_intent
        else:
            intent_dict = {}

        for k, v in intent_dict.items():
            if v and isinstance(v, (str, int, float)):
                v_str = str(v).strip().lower()
                authorized_tokens.add(v_str)
                if "@" in v_str:
                    authorized_tokens.add(v_str.split("@")[-1])

        # Normalize trusted hosts allowlist
        trusted_hosts_lower = {h.lower().strip() for h in getattr(self, "trusted_hosts", [])}
        bare_trusted = {h.split(":")[0] for h in trusted_hosts_lower}
        trusted_hosts_lower.update(bare_trusted)

        # 1. URL pattern
        url_matches = re.findall(r'(?:https?://|//)([a-zA-Z0-9.-]+(?::[0-9]+)?)(?:/[^\s]*)?', cleaned, re.IGNORECASE)
        for host_match in url_matches:
            host_clean = host_match.lower().strip()
            bare_host = host_clean.split(":")[0]
            if host_clean not in trusted_hosts_lower and bare_host not in trusted_hosts_lower and host_clean not in authorized_tokens:
                return InconsistencyItem(
                    check_type="EGRESS_IN_CONTENT",
                    field_name=action.target,
                    expected_value="authorized_content_or_allowlist",
                    observed_value=host_match,
                    severity=0.85,
                    detail=f"Action value contains unallowlisted external URL/host '{host_match}' not present in locked intent.",
                )

        # 2. Email pattern
        email_matches = re.findall(r'\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b', cleaned)
        for email_match in email_matches:
            email_clean = email_match.lower().strip()
            domain_part = email_clean.split("@")[-1]
            if email_clean not in authorized_tokens and domain_part not in authorized_tokens and domain_part not in trusted_hosts_lower:
                return InconsistencyItem(
                    check_type="EGRESS_IN_CONTENT",
                    field_name=action.target,
                    expected_value="authorized_content_or_allowlist",
                    observed_value=email_match,
                    severity=0.85,
                    detail=f"Action value contains unallowlisted email address '{email_match}' not present in locked intent.",
                )

        # 3. Standalone external hostname / FQDN pattern (e.g. attacker-collector.org, payment-mirror.net)
        hostname_matches = re.findall(r'\b([a-zA-Z0-9-]+\.(?:com|net|org|io|info|biz|internal|gov|edu|co|xyz|online|site|app|dev|me|us|uk|de|eu))\b', cleaned, re.IGNORECASE)
        for host_match in hostname_matches:
            host_clean = host_match.lower().strip()
            if host_clean not in trusted_hosts_lower and host_clean not in authorized_tokens:
                return InconsistencyItem(
                    check_type="EGRESS_IN_CONTENT",
                    field_name=action.target,
                    expected_value="authorized_content_or_allowlist",
                    observed_value=host_match,
                    severity=0.85,
                    detail=f"Action value contains unallowlisted external hostname '{host_match}' not present in locked intent.",
                )

        return None

    def _is_trusted_navigation(self, url: str) -> bool:
        """
        Determines whether a navigation destination URL is within the trusted boundary.
        Enforces:
        1. Scheme must be http or https (case-insensitive).
        2. Normalized hostname (no userinfo '@', percent-decoded, IDNA/homoglyph decoded, trailing dots stripped)
           must exactly match an allowlist entry.
        3. Port must match the allowlist entry (or default 80/443).
        4. Open-redirect parameters must also point to trusted destinations.
        """
        if not url or not isinstance(url, str):
            return False
        raw_url = url.strip()
        if not raw_url:
            return False

        from urllib.parse import parse_qs, unquote, urlparse

        # 1. Reject protocol-relative '//host' or scheme-less URLs
        if raw_url.startswith("//"):
            return False

        try:
            parsed = urlparse(raw_url)
        except Exception:
            return False

        # Scheme must be explicitly http or https
        scheme = (parsed.scheme or "").lower().strip()
        if scheme not in ("http", "https"):
            return False

        # 2. Extract and normalize hostname without userinfo
        # parsed.hostname in urllib.parse strips username:password@
        raw_hostname = parsed.hostname
        if not raw_hostname:
            return False

        # Percent-decode hostname
        try:
            unquoted_host = unquote(raw_hostname).lower().strip()
        except Exception:
            return False

        # If userinfo delimiter '@' remains after unquoting (e.g. %40 trick), reject
        if "@" in unquoted_host:
            return False

        # Strip trailing dot for FQDN normalization
        norm_host = unquoted_host.rstrip(".")

        # Homoglyphs and Punycode normalization:
        try:
            ascii_host = norm_host.encode("idna").decode("ascii")
        except Exception:
            return False

        # Effective port (default 80 for http, 443 for https)
        try:
            url_port = parsed.port
        except ValueError:
            # e.g. invalid port like 8000.
            return False

        effective_port = url_port if url_port is not None else (443 if scheme == "https" else 80)

        # 3. Match normalized hostname and port against allowlist entries in self.trusted_hosts
        matched = False
        for entry in self.trusted_hosts:
            if not entry:
                continue
            e_str = str(entry).strip().lower()
            if "://" in e_str:
                try:
                    ep = urlparse(e_str)
                    e_host = (ep.hostname or "").rstrip(".")
                    e_port = ep.port if ep.port is not None else (443 if ep.scheme == "https" else 80)
                except Exception:
                    continue
            elif ":" in e_str:
                parts = e_str.split(":", 1)
                e_host = parts[0].strip().rstrip(".")
                try:
                    e_port = int(parts[1])
                except ValueError:
                    e_port = None
            else:
                e_host = e_str.rstrip(".")
                e_port = None

            # Check hostname match: exact match on ascii_host or norm_host
            host_matches = (ascii_host == e_host) or (norm_host == e_host)
            if not host_matches:
                continue

            # Check port match:
            if e_port is not None:
                if effective_port == e_port:
                    matched = True
                    break
            else:
                # If allowlist entry did not specify a port, matches if URL uses default port or matches bare host
                if url_port is None or effective_port in (80, 443):
                    matched = True
                    break

        if not matched:
            return False

        # 4. Check for open-redirect query parameters (e.g. ?url=http://evil.com)
        if parsed.query:
            try:
                qs = parse_qs(parsed.query, keep_blank_values=False)
                redirect_param_keys = {
                    "url", "redirect", "redirect_to", "redirect_url", "next",
                    "dest", "destination", "target", "out", "return", "return_to",
                    "link", "r", "goto", "forward"
                }
                for k, vals in qs.items():
                    if k.lower() in redirect_param_keys:
                        for v in vals:
                            v_clean = unquote(v).strip()
                            # If parameter value looks like an external or dangerous target
                            if "://" in v_clean or v_clean.startswith("//") or any(
                                v_clean.lower().startswith(s) for s in ("http:", "https:", "javascript:", "data:")
                            ):
                                if not self._is_trusted_navigation(v_clean):
                                    return False
            except Exception:
                pass

        return True


def fee_floor(
    intent: Any,
    action: Any,
    dom_text: str = "",
    visible_form_state: Optional[Dict[str, Any]] = None,
) -> tuple[Optional[str], str]:
    """
    Deterministic fee floor check (Phase 0.5 / Shortfall S4 fix).
    Parses structured price delta between user's locked intent and current page state / action.
    If delta is non-zero and unexplained by user intent, forces REQUIRE_CONFIRMATION
    regardless of what page text claims ("complimentary", "included", "no charge").

    Subject to strict raise-only discipline: can only escalate a decision,
    never soften one coming from elsewhere in the pipeline.
    """
    addons_allowed = getattr(intent, "addons_allowed", None)
    if isinstance(intent, dict):
        addons_allowed = intent.get("addons_allowed")
    max_fare = getattr(intent, "max_fare", None)
    if isinstance(intent, dict):
        max_fare = intent.get("max_fare")

    target = getattr(action, "target", "")
    val = getattr(action, "value", "") or ""
    if isinstance(action, dict):
        target = action.get("target", "")
        val = action.get("value", "") or ""

    target_low = str(target).lower().strip()
    val_str = str(val).strip()

    is_addons_none = addons_allowed is not None and str(addons_allowed).strip().lower() == "none"
    unexplained_delta = False
    delta_detail = ""

    addon_keywords = [
        "baggage", "luggage", "meal", "seat", "insurance",
        "currency", "surcharge", "fee", "addon", "tariff",
        "donation", "tip", "gift-wrap", "express-shipping", "warranty"
    ]
    ancillary_cfg = CONFIG_DIR / "ancillary_lexicon.yaml"
    if ancillary_cfg.exists():
        try:
            anc_data = yaml.safe_load(ancillary_cfg.read_text(encoding="utf-8")) or {}
            addon_keywords = anc_data.get("addon_target_keywords", addon_keywords)
        except Exception:
            pass

    is_addon_target = any(k in target_low for k in addon_keywords)

    num_match = re.search(r"(\d+(?:\.\d+)?)", val_str)
    action_amount = float(num_match.group(1)) if num_match else 0.0

    if is_addons_none:
        fee_terms = ["fee", "surcharge", "charge", "tariff", "premium", "paid", "$", "€", "£", "₹", "inr", "usd"]
        has_fee_term_in_val = any(ft in val_str.lower() for ft in fee_terms)

        if is_addon_target and (action_amount > 0 or has_fee_term_in_val):
            is_std_seat_or_meal = bool(re.match(r"^\d{1,2}[A-F]$", val_str, re.IGNORECASE)) or val_str.lower() in ("veg", "non-veg", "jain", "standard", "economy")
            if not (is_std_seat_or_meal and not has_fee_term_in_val):
                unexplained_delta = True
                delta_detail = f"Action targets add-on field '{target}' with value '{val_str}'"

        if not unexplained_delta and dom_text:
            surcharge_patterns = [
                r"(?:surcharge|fee|tariff|extra\s+charge|additional\s+fare|delivery\s+charge|shipping\s+fee|convenience\s+fee)\s*(?:of|:)?\s*(?:₹|\$|€|£|inr|usd|eur|gbp)?\s*(\d+(?:,\d{3})*(?:\.\d+)?)",
                r"(\d+(?:,\d{3})*(?:\.\d+)?)\s*(?:₹|\$|€|£|inr|usd|eur|gbp)\s*(?:surcharge|fee|tariff|extra\s+charge|shipping\s+fee)",
            ]
            for pat in surcharge_patterns:
                m = re.search(pat, dom_text, re.IGNORECASE)
                if m:
                    amt = float(m.group(1).replace(",", ""))
                    if amt > 0:
                        if is_addon_target or any(k in target_low for k in ["confirm", "submit", "pay", "book", "checkout"]):
                            unexplained_delta = True
                            delta_detail = f"Page contains structured fee delta ({amt} currency units) while addons_allowed='none'"
                            break

        if not unexplained_delta and visible_form_state:
            for k, v in visible_form_state.items():
                if any(k_sub in k.lower() for k_sub in ["surcharge", "fee", "addon", "extra", "insurance", "baggage", "shipping", "gift-wrap", "warranty", "donation"]):
                    try:
                        v_num = float(str(v).replace(",", ""))
                        if v_num > 0:
                            unexplained_delta = True
                            delta_detail = f"Visible form state contains structured surcharge '{k}={v}'"
                            break
                    except ValueError:
                        pass

    if not unexplained_delta and max_fare is not None:
        total_patterns = [
            r"(?:total(?:\s+(?:fare|price|amount|cost))?|cart\s+total|order\s+total|grand\s+total|final\s+price|subtotal)\s*(?:of|:)?\s*(?:₹|\$|€|£|inr|usd|eur|gbp)?\s*(\d+(?:,\d{3})*(?:\.\d+)?)",
        ]
        for pat in total_patterns:
            m = re.search(pat, dom_text, re.IGNORECASE)
            if m:
                total_val = float(m.group(1).replace(",", ""))
                if total_val > float(max_fare):
                    unexplained_delta = True
                    delta_detail = f"Page total ({total_val}) exceeds max_fare ({max_fare})"
                    break

    if unexplained_delta:
        return (
            "REQUIRE_CONFIRMATION",
            f"Fee floor violation: {delta_detail}; forces REQUIRE_CONFIRMATION regardless of reassuring page prose."
        )

    return None, ""


