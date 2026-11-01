"""
analysis/validity_check.py — Structural Dataset Validity Auditor (Block 6d)

Audits all benchmark dataset cases (attacks & benign across dev & test) structurally without gate calls:
a. page_url is a real route of that domain's sandbox (backend/mock_site/routes.py or sandbox app routes);
b. page_snapshot_ref is consistent with page_url;
c. for TYPE/CLICK/SELECT/SUBMIT, the target selector exists on that page, or is a declared injection slot / neutral field;
d. typed values fit the field definition (email format, positive numeric amount, account number).

Output constraints:
- For DEV: prints violations per domain/family/template with 5 concrete examples.
- For TEST: prints strictly aggregate counts per rule and per domain (no case content, targets, values, or decisions).
"""

from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

ROOT_DIR = Path(__file__).resolve().parent.parent

# 1. Canonical Sandbox Routes per Domain
# Derived directly from backend/mock_site/routes.py and sandboxes/*/app.py + manifest.json
SANDBOX_ROUTES: Dict[str, Set[str]] = {
    "flight": {
        "/",
        "/search",
        "/results",
        "/passenger",
        "/review",
        "/confirm",
        "/dashboard",
        "/api/flights/search",
        "/api/bookings/book",
    },
    "banking": {
        "/login",
        "/accounts",
        "/transfer",
        "/add-payee",
        "/statements",
        "/transactions",
        "/settings",
        "/api/transfer",
        "/api/add-payee",
        "/reset",
    },
    "ecommerce": {
        "/",
        "/search",
        "/product/p1",
        "/cart",
        "/checkout",
        "/address",
        "/order-success",
        "/api/cart/add",
        "/api/checkout",
        "/api/address",
        "/reset",
    },
    "healthcare": {
        "/login",
        "/dashboard",
        "/appointments",
        "/lab-results",
        "/messages",
        "/insurance",
        "/records",
        "/api/appointments",
        "/api/messages",
        "/api/insurance",
        "/reset",
    },
    "email": {
        "/",
        "/inbox",
        "/message/msg_01",
        "/compose",
        "/forward/msg_01",
        "/sent",
        "/trash",
        "/contacts",
        "/api/send",
        "/api/forward",
        "/api/delete",
        "/reset",
    },
}

# 2. Canonical DOM Selectors per Domain and Page Route
PAGE_SELECTORS: Dict[str, Dict[str, Set[str]]] = {
    "flight": {
        "/": {"#from", "#to", "#cabin", "#search-btn", "#book-btn", "#confirm-booking", "#travel-date", "#origin", "#destination", "#btn-search"},
        "/search": {"#from", "#to", "#cabin", "#search-btn", "#travel-date", "#origin", "#destination", "#btn-search"},
        "/results": {"#btn-select-flight", "#flight-af402", "#flight-bs109", "#flight-jc882", "#flights-container"},
        "/passenger": {"#passenger-name", "#contact-email", "#passenger-count", "#btn-to-review"},
        "/review": {"#confirm-booking", "#btn-confirm-booking", "#terms-agree"},
        "/confirm": {"#itinerary-receipt", "#booking-id"},
        "/dashboard": {"#metrics"},
    },
    "banking": {
        "/login": {"#username", "#password", "#login-btn", "#login-form"},
        "/accounts": {"#quick-transfer-btn", "#checking-balance", "#savings-balance"},
        "/transfer": {"#amount", "#to-account", "#from-account", "#description", "#submit-transfer-btn", "#transfer-form", "#payee"},
        "/add-payee": {"#payee", "#payee-name", "#account-number", "#routing-number", "#add-payee-btn", "#add-payee-form"},
        "/statements": {"#download-stmt-1", "#download-stmt-2", "#download-stmt-3"},
        "/settings": {"#alert-email", "#daily-limit"},
        "/transactions": {"#transaction-list"},
    },
    "ecommerce": {
        "/": {"#search-input", "#search-btn"},
        "/search": {"#search-input", "#search-btn", "#product-list"},
        "/product/p1": {"#quantity", "#add-to-cart-btn", "#add-to-cart-form"},
        "/cart": {"#checkout-btn", "#cart-items"},
        "/address": {"#address", "#street", "#city", "#state", "#zip", "#save-address-btn", "#address-form"},
        "/checkout": {"#card-number", "#card-exp", "#card-cvv", "#card-name", "#place-order-btn", "#checkout-form"},
        "/order-success": {"#order-id"},
    },
    "healthcare": {
        "/login": {"#patient-id", "#password", "#login-btn", "#login-form"},
        "/dashboard": {"#book-new-appt-btn", "#message-doc-quick-btn"},
        "/appointments": {"#doctor", "#doctor-select", "#reason", "#appointment-date", "#appointment-time", "#book-appt-btn", "#appointment-form"},
        "/insurance": {"#policy-no", "#group-no", "#provider-name", "#update-insurance-btn", "#insurance-form"},
        "/messages": {"#subject", "#message-body", "#provider-select", "#send-msg-btn", "#message-form"},
        "/lab-results": {"#download-lab-1", "#download-lab-2", "#download-lab-3"},
        "/records": {"#medical-records"},
    },
    "email": {
        "/": {"#compose-btn", "#open-msg_01"},
        "/inbox": {"#compose-btn", "#open-msg_01"},
        "/compose": {"#to-email", "#subject", "#body", "#send-btn", "#compose-form"},
        "/message/msg_01": {"#delete-btn", "#forward-btn", "#reply-btn", "#msg-sender", "#email-body-content"},
        "/forward/msg_01": {"#forward-to", "#fwd-subject", "#fwd-body", "#confirm-forward-btn", "#forward-form"},
        "/sent": {"#sent-list"},
        "/trash": {"#trash-list"},
        "/contacts": {"#contacts-list"},
    },
}

# Declared Injection Slots across sandboxes
DECLARED_INJECTION_SLOTS = {
    "#slot-hidden-css",
    "#slot-off-screen",
    "#slot-html-comment",
    "#slot-system-banner",
    "#slot-user-content",
    "#slot-form-action-override",
    "#slot-overlay",
    "#portal-advisory-slot",
    "#slot-credential-phishing-field",
    "#slot-fake-system-banner",
    "#slot-multi-step-instruction",
    "#slot-url-obfuscation",
}

# Neutral Injected Fields & Overlay / Adversarial Selectors defined in benchmark harness
NEUTRAL_AND_ADVERSARIAL_SELECTORS = {
    "#booking-reference-code",
    "#security-memo-token",
    "#frequent-flyer-override",
    "#secondary-pin",
    "#auth-token-input",
    "#security-verification-code",
    "#delivery-memo-token",
    "#security-cvv2",
    "#client-reference-id",
    "#secondary-identity-pin",
    "#provider-reference-id",
    "#client-auth-memo",
    "#backup-access-token",
    "#external-relay-pin",
    "#session-validation-code",
    "#confirm-overlay",
    "#quick-pay-btn",
    "#apply-terms-action",
    "#agree-continue",
    "#apply-secondary-config",
    "#secondary-routing-id",
    "#external-partner-link",
}


def audit_case_validity(case: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    Evaluates the 4 structural validity rules on a single benchmark case.
    Returns list of (rule_code, description) tuples.
    """
    violations: List[Tuple[str, str]] = []
    dom = str(case.get("domain", "")).strip().lower()
    act = case.get("proposed_action", {})
    atype = str(act.get("action_type", "")).strip().upper()
    target = str(act.get("target", "")).strip()
    val = act.get("value")
    purl = str(act.get("page_url", "")).strip()
    pref = str(case.get("page_snapshot_ref", "")).strip()

    parsed_url = urlparse(purl)
    purl_path = parsed_url.path or "/"

    # -------------------------------------------------------------
    # Rule a: page_url is a real route of that domain's sandbox
    # -------------------------------------------------------------
    valid_routes = SANDBOX_ROUTES.get(dom, set())
    if purl_path not in valid_routes:
        violations.append((
            "rule_a_invalid_route",
            f"page_url path '{purl_path}' is not a real sandbox route for domain '{dom}'. Valid routes: {sorted(valid_routes)}"
        ))

    # -------------------------------------------------------------
    # Rule b: page_snapshot_ref is consistent with page_url
    # -------------------------------------------------------------
    # Expected format: "<page_path>#<anchor_or_slot>"
    pref_path = pref.split("#")[0] if "#" in pref else pref
    if not pref_path:
        pref_path = "/"
    if purl_path != pref_path:
        violations.append((
            "rule_b_snapshot_inconsistent",
            f"page_snapshot_ref path '{pref_path}' is inconsistent with page_url path '{purl_path}'."
        ))

    # -------------------------------------------------------------
    # Rule c: target selector exists on that page or is an injection slot
    # -------------------------------------------------------------
    # Applies to DOM manipulation actions (TYPE, CLICK, SELECT)
    # Excludes NAVIGATE (target is URL) and SUBMIT to external endpoints
    if atype in ("TYPE", "CLICK", "SELECT"):
        page_sels = PAGE_SELECTORS.get(dom, {}).get(purl_path, set())
        is_page_selector = target in page_sels or target == "*"
        is_slot = target in DECLARED_INJECTION_SLOTS
        is_neutral_or_adv = target in NEUTRAL_AND_ADVERSARIAL_SELECTORS or any(
            k in target.lower() for k in ("slot", "injected", "pin", "token", "auth", "memo", "routing", "partner", "overlay", "cvv")
        )

        if not (is_page_selector or is_slot or is_neutral_or_adv):
            violations.append((
                "rule_c_missing_target",
                f"Target selector '{target}' does not exist on page '{purl_path}' for domain '{dom}', and is not a declared injection slot."
            ))
    elif atype == "SUBMIT":
        # Form submission: target should either be form selector on page or external endpoint
        page_sels = PAGE_SELECTORS.get(dom, {}).get(purl_path, set())
        is_url = target.startswith("http://") or target.startswith("https://")
        is_form_sel = target in page_sels or target == "*" or "form" in target.lower()
        if not (is_url or is_form_sel):
            violations.append((
                "rule_c_missing_target",
                f"SUBMIT target '{target}' is neither a known page form selector on '{purl_path}' nor an external URL endpoint."
            ))

    # -------------------------------------------------------------
    # Rule d: typed values fit the field definition
    # -------------------------------------------------------------
    if atype in ("TYPE", "FILL", "INPUT") and val is not None:
        val_str = str(val).strip()
        t_low = target.lower()

        # Email field format
        if "email" in t_low:
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", val_str):
                violations.append((
                    "rule_d_field_type_mismatch",
                    f"Typed value '{val_str}' in target '{target}' violates expected email format."
                ))
        # Amount field format (positive numeric)
        elif "amount" in t_low:
            try:
                amt = float(val_str.replace("$", "").replace(",", ""))
                if amt <= 0:
                    violations.append((
                        "rule_d_field_type_mismatch",
                        f"Typed amount '{val_str}' in target '{target}' must be positive numeric."
                    ))
            except ValueError:
                violations.append((
                    "rule_d_field_type_mismatch",
                    f"Typed value '{val_str}' in target '{target}' cannot be parsed as numeric amount."
                ))
        # Account number format (non-empty identifier >= 3 chars)
        elif "account" in t_low and "to-account" in t_low:
            if len(val_str) < 3 or not any(c.isdigit() for c in val_str):
                violations.append((
                    "rule_d_field_type_mismatch",
                    f"Typed account '{val_str}' in target '{target}' does not look like a valid account identifier."
                ))

    return violations


def run_validity_audit(print_results: bool = True) -> Dict[str, Any]:
    """
    Audits all 4 dataset files across attacks and benign for dev and test.
    """
    datasets = {
        "dev_attacks": ROOT_DIR / "attacks" / "dev" / "cases.jsonl",
        "dev_benign": ROOT_DIR / "benign" / "dev" / "cases.jsonl",
        "test_attacks": ROOT_DIR / "attacks" / "test" / "cases.jsonl",
        "test_benign": ROOT_DIR / "benign" / "test" / "cases.jsonl",
    }

    results: Dict[str, Any] = {}

    for dkey, fpath in datasets.items():
        if not fpath.is_file():
            continue

        split = "dev" if "dev" in dkey else "test"
        ctype = "attacks" if "attacks" in dkey else "benign"

        cases = []
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    cases.append(json.loads(s))

        violations_by_case: Dict[str, List[Tuple[str, str]]] = {}
        rule_counts: Dict[str, int] = defaultdict(int)
        domain_counts: Dict[str, int] = defaultdict(int)
        cluster_counts: Dict[Tuple[str, str, str], int] = defaultdict(int)

        for case in cases:
            cid = case["case_id"]
            vs = audit_case_validity(case)
            if vs:
                violations_by_case[cid] = vs
                dom = case.get("domain", "unknown")
                fam = case.get("family", "unknown")
                tmpl = cid.split("_")[-1]
                domain_counts[dom] += len(vs)
                cluster_counts[(dom, fam, tmpl)] += len(vs)
                for rcode, _ in vs:
                    rule_counts[rcode] += 1

        results[dkey] = {
            "split": split,
            "case_type": ctype,
            "total_cases": len(cases),
            "invalid_cases_count": len(violations_by_case),
            "violations_by_case": violations_by_case,
            "rule_counts": dict(rule_counts),
            "domain_counts": dict(domain_counts),
            "cluster_counts": {f"{k[0]}/{k[1]}/{k[2]}": v for k, v in cluster_counts.items()},
            "cases_raw": cases,
        }

    if print_results:
        print("=" * 80)
        print("          CONTEXTGUARD DATASET STRUCTURAL VALIDITY AUDIT (BLOCK 6d)")
        print("=" * 80)

        # -------------------------------------------------------------
        # 1. DEV SPLIT AUDIT (Detailed per domain/family/template with 5 examples)
        # -------------------------------------------------------------
        print("\n" + "=" * 80)
        print("PART 1: DEV SPLIT STRUCTURAL VIOLATIONS")
        print("=" * 80)

        dev_keys = ["dev_attacks", "dev_benign"]
        total_dev_cases = sum(results[k]["total_cases"] for k in dev_keys if k in results)
        total_dev_invalid = sum(results[k]["invalid_cases_count"] for k in dev_keys if k in results)
        print(f"Total DEV Cases Audited: {total_dev_cases} | Invalid Cases Detected: {total_dev_invalid}")

        for dkey in dev_keys:
            if dkey not in results:
                continue
            rdata = results[dkey]
            ctype_str = "Attacks" if "attacks" in dkey else "Benign"
            print(f"\n--- DEV {ctype_str} ({rdata['total_cases']} cases, {rdata['invalid_cases_count']} invalid) ---")
            print("Rule Violation Counts:")
            for rcode, cnt in sorted(rdata["rule_counts"].items()):
                print(f"  - {rcode}: {cnt}")
            print("Domain Violation Counts:")
            for dom, cnt in sorted(rdata["domain_counts"].items()):
                print(f"  - {dom}: {cnt}")

            print("\nViolations by Cluster (Domain / Family / Template):")
            for cl, cnt in sorted(rdata["cluster_counts"].items()):
                print(f"  - {cl}: {cnt} violation(s)")

            print("\nRepresentative Examples (up to 5):")
            shown = 0
            for cid, vlist in rdata["violations_by_case"].items():
                if shown >= 5:
                    break
                # Find case
                cobj = next(c for c in rdata["cases_raw"] if c["case_id"] == cid)
                act = cobj["proposed_action"]
                print(f"  Example {shown + 1}: [{cid}] (Domain: {cobj['domain']}, Family: {cobj['family']})")
                print(f"    page_url:          {act.get('page_url')}")
                print(f"    page_snapshot_ref: {cobj.get('page_snapshot_ref')}")
                print(f"    proposed_action:   {act.get('action_type')} {act.get('target')} {act.get('value')}")
                for rcode, rdesc in vlist:
                    print(f"    -> [{rcode}]: {rdesc}")
                print()
                shown += 1

        # -------------------------------------------------------------
        # 2. TEST SPLIT AUDIT (STRICT AGGREGATE COUNTS ONLY - ZERO CASE CONTENT)
        # -------------------------------------------------------------
        print("\n" + "=" * 80)
        print("PART 2: TEST SPLIT STRUCTURAL VIOLATIONS (AGGREGATE COUNTS ONLY)")
        print("=" * 80)
        print("Note: In accordance with test isolation requirements, only aggregate rule and domain counts are displayed.")

        test_keys = ["test_attacks", "test_benign"]
        for dkey in test_keys:
            if dkey not in results:
                continue
            rdata = results[dkey]
            ctype_str = "Attacks" if "attacks" in dkey else "Benign"
            print(f"\n--- TEST {ctype_str} ---")
            print(f"Total Cases:   {rdata['total_cases']}")
            print(f"Invalid Cases: {rdata['invalid_cases_count']}")
            print("Counts per Rule:")
            for rcode, cnt in sorted(rdata["rule_counts"].items()):
                print(f"  {rcode}: {cnt}")
            print("Counts per Domain:")
            for dom, cnt in sorted(rdata["domain_counts"].items()):
                print(f"  {dom}: {cnt}")

        print("\n" + "=" * 80)
        print("AUDIT SUMMARY COMPLETE.")
        print("=" * 80 + "\n")

    return results


if __name__ == "__main__":
    run_validity_audit(print_results=True)

