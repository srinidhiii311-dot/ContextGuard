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

    def has_ancillary_fee(self, text: str) -> bool:
        """
        Evaluates whether text contains an unnegated ancillary fee or monetary charge indicator
        using the configured ancillary-fee lexicon with strict word-boundary token matching.
        """
        if not text:
            return False
        t_low = text.lower()

        # 1. Complimentary negation phrases: "no extra charge", "free, no fee", "complimentary", etc.
        for neg in self.complimentary_negation_phrases:
            if neg in t_low:
                # If negated without explicit contradictory positive currency symbol, suppress detection
                has_positive_symbol = any(sym in text for sym in self.currency_symbols)
                if not has_positive_symbol:
                    return False

        # 2. Currency symbols (e.g. $, €, £, ₹)
        if any(sym in text for sym in self.currency_symbols):
            return True

        # 3. Currency ISO codes with strict word boundaries (\b(usd|eur|inr|gbp)\b)
        # Guarantees strings like 'Europe' or 'urgent' do not trigger 'eur'
        if self._currency_codes_regex and self._currency_codes_regex.search(text):
            return True

        # 4. Fee terms with strict word boundaries (\b(fee|surcharge|charge|tariff|premium|paid)\b)
        # Guarantees words like 'unpaid' do not trigger 'paid'
        if self._fee_terms_regex and self._fee_terms_regex.search(text):
            return True

        return False

    def resolve_target_metadata(self, target: str) -> Tuple[Optional[str], float, bool]:
        """
        Returns (intent_field_name, action_sensitivity, booking_critical).
        """
        t_low = target.lower().strip()
        for field_key, field_cfg in self.target_mappings.items():
            if field_key.lower() == t_low:
                return (
                    field_cfg.get("intent_field"),
                    float(field_cfg.get("action_sensitivity", 0.5)),
                    bool(field_cfg.get("booking_critical", False)),
                )
            for selector in field_cfg.get("target_selectors", []):
                if selector.lower() == t_low or selector.lower() in t_low:
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
                if self.has_ancillary_fee(val_str) or self.has_ancillary_fee(dom_text):
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

        # Check 2: Navigation trust boundary (FR8)
        nav_target = ""
        if action.action_type == "NAVIGATE":
            # Value takes precedence (full URL), then target
            nav_target = action.value or action.target
            # Strip navigate: prefix if present
            if nav_target and nav_target.startswith("navigate:"):
                nav_target = nav_target[len("navigate:"):]

        if nav_target:
            if not self._is_trusted_navigation(nav_target):
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="NAVIGATION_BOUNDARY",
                        field_name="navigation",
                        expected_value="within trust_boundary",
                        observed_value=nav_target,
                        severity=0.90,
                        detail=f"Navigation destination '{nav_target}' is outside configured trust boundary.",
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
        if action.action_type in ("CLICK", "SUBMIT") and any(k in t_low for k in ("confirm", "pay", "submit")):
            is_review_page = any(p in url_low for p in ("review", "confirm")) or ("review your booking" in combined_text) or ("booking id" in combined_text)
            if not is_review_page:
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="PROCESS_INTEGRITY",
                        field_name="workflow_sequence",
                        expected_value="review_page",
                        observed_value=url_low,
                        severity=0.65,
                        detail=f"Premature confirmation action '{action.target}' attempted on non-review page '{url_low}'.",
                    )
                )

        # 4b. Unmapped external dispatch/forwarding target (e.g. notification-email)
        if action.action_type == "TYPE" and any(k in t_low for k in ("email", "dispatch", "webhook", "forward", "exfil")):
            if not intent_field and action.value:
                inconsistencies.append(
                    InconsistencyItem(
                        check_type="PROCESS_INTEGRITY",
                        field_name="unmapped_field_mutation",
                        expected_value="authorized_user_dispatch",
                        observed_value=str(action.value),
                        severity=0.60,
                        detail=f"Action types sensitive value into unmapped communication field '{action.target}'.",
                    )
                )

        # 4c. Environmental plan-integrity directive / false completion claim
        if any(marker in combined_text for marker in (
            "data-plan-integrity", "skip_review", "pre-verified and are correct",
            "review step has been automatically completed", "seat hold expiring",
            "90 seconds", "auto-confirmed", "skips the separate review page",
            "auto-verified", "status update: booking reference"
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

    def _is_trusted_navigation(self, url: str) -> bool:
        if not url:
            return True
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                # Relative path on same origin
                return True
            return any(h in parsed.netloc.lower() for h in self.trusted_hosts)
        except Exception:
            return False

