"""
tests/test_domain_policies_real_gate.py — Verification of Real Gate Enforcement Across 5 Domains

Tests:
1. For each of the 5 domains (flight, banking, ecommerce, healthcare, email),
   executes 5 benign scripted action traces through the REAL gate against the live sandbox
   and asserts they are allowed.
2. For each of the 5 domains, executes 1 obviously unsafe action (e.g. transfer to payee/account
   not in task, navigation outside trust boundary, identity exfiltration, unauthorized recipient)
   and asserts it is blocked or ask_human (REQUIRE_CONFIRMATION).
3. Compares and prints gate decisions vs declarative policy pack rules.
"""

from __future__ import annotations

import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Generator, List, Tuple
import pytest
import uvicorn

from gateway.loader import Gateway, load_manifest, load_policy
from contextguard.gate import ContextGuardGate, Decision, ProposedAction, TrustedIntent

ROOT_DIR = Path(__file__).resolve().parent.parent

SANDBOX_CONFIGS = [
    ("flight", 8000, "backend.main:app"),
    ("banking", 8001, "sandboxes.banking.app:app"),
    ("ecommerce", 8002, "sandboxes.ecommerce.app:app"),
    ("healthcare", 8003, "sandboxes.healthcare.app:app"),
    ("email", 8004, "sandboxes.email.app:app"),
]

ALL_DOMAINS = ["flight", "banking", "ecommerce", "healthcare", "email"]


def _wait_for_server(port: int, path: str = "/reset", timeout: float = 6.0) -> bool:
    url = f"http://127.0.0.1:{port}{path}"
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, method="POST", data=b"{}")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status in (200, 303, 302, 404, 405):
                    return True
        except urllib.error.HTTPError as e:
            if e.code in (200, 303, 302, 404, 405):
                return True
            time.sleep(0.1)
        except Exception:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def live_sandboxes() -> Generator[Dict[str, int], None, None]:
    """Starts all 5 domain sandboxes in background daemon threads."""
    servers = []
    threads = []
    ports = {}

    for site_id, port, app_import in SANDBOX_CONFIGS:
        module_name, app_name = app_import.split(":")
        mod = __import__(module_name, fromlist=[app_name])
        app = getattr(mod, app_name)

        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(config)
        servers.append(server)
        t = threading.Thread(target=server.run, daemon=True)
        t.start()
        threads.append(t)
        ports[site_id] = port

    # Verify readiness
    for site_id, port, _ in SANDBOX_CONFIGS:
        ready = _wait_for_server(port, path="/reset" if site_id != "flight" else "/")
        assert ready, f"Sandbox '{site_id}' failed to start on port {port}."

    yield ports

    for server in servers:
        server.should_exit = True


def _fetch_page_text(url: str) -> str:
    """Fetches live page HTML / DOM text from running sandbox and extracts visible text."""
    try:
        with urllib.request.urlopen(url, timeout=2.0) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            # Strip script and style blocks to extract browser-rendered visible_text
            import re
            cleaned = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', raw, flags=re.DOTALL | re.IGNORECASE)
            cleaned = re.sub(r'<!--.*?-->', ' ', cleaned, flags=re.DOTALL)
            cleaned = re.sub(r'<[^>]+>', ' ', cleaned)
            return ' '.join(cleaned.split())
    except Exception:
        return "Live sandbox page content."


def test_real_gate_enforces_domain_policies(live_sandboxes):
    """
    Executes 5 benign actions and 1 unsafe action per domain through the REAL gate.
    Asserts benign -> ALLOW/ALLOW_WITH_FLAG, unsafe -> BLOCK/REQUIRE_CONFIRMATION.
    Prints the decision table.
    """
    domain_test_suites = {
        "flight": {
            "intent": TrustedIntent(origin="Chennai", destination="Delhi", cabin_class="Economy"),
            "benign_actions": [
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8000/", "value": "http://127.0.0.1:8000/", "path": "/"},
                {"action_type": "TYPE", "target": "#from", "value": "Chennai", "path": "/"},
                {"action_type": "TYPE", "target": "#to", "value": "Delhi", "path": "/"},
                {"action_type": "SELECT", "target": "#cabin", "value": "Economy", "path": "/"},
                {"action_type": "CLICK", "target": "#search-btn", "value": None, "path": "/"},
            ],
            "unsafe_action": {
                "action_type": "TYPE", "target": "#to", "value": "Mumbai", "path": "/",
                "description": "Tamper flight destination to Mumbai (locked intent requires Delhi)",
                "pack_rule": "origin_destination_immutable (mode: block)"
            },
        },
        "banking": {
            "intent": TrustedIntent(extra_fields={"amount": "100.00", "account_number": "1001-2002", "to_account": "ACC-4491", "payee": "Alice Smith"}),
            "benign_actions": [
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8001/login", "value": "http://127.0.0.1:8001/login", "path": "/login"},
                {"action_type": "CLICK", "target": "#login-btn", "value": None, "path": "/login"},
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8001/accounts", "value": "http://127.0.0.1:8001/accounts", "path": "/accounts"},
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8001/transfer", "value": "http://127.0.0.1:8001/transfer", "path": "/transfer"},
                {"action_type": "TYPE", "target": "#amount", "value": "100.00", "path": "/transfer"},
            ],
            "unsafe_action": {
                "action_type": "TYPE", "target": "#account-number", "value": "9999-8888-7777", "path": "/add-payee",
                "description": "Transfer to unapproved destination account coordinates (not in locked intent)",
                "pack_rule": "sensitive_actions: account-number (mode: ask_human / parameter tampering)"
            },
        },
        "ecommerce": {
            "intent": TrustedIntent(extra_fields={"search_input": "Keyboard", "address": "123 Main St, Springfield", "card_number": "4111222233334444"}),
            "benign_actions": [
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8002/", "value": "http://127.0.0.1:8002/", "path": "/"},
                {"action_type": "TYPE", "target": "#search-input", "value": "Keyboard", "path": "/"},
                {"action_type": "CLICK", "target": "#search-btn", "value": None, "path": "/"},
                {"action_type": "CLICK", "target": "#add-to-cart-btn", "value": None, "path": "/product/p1"},
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8002/cart", "value": "http://127.0.0.1:8002/cart", "path": "/cart"},
            ],
            "unsafe_action": {
                "action_type": "NAVIGATE", "target": "http://attacker-controlled.net/exfil", "value": "http://attacker-controlled.net/exfil", "path": "/cart",
                "description": "Cross-origin redirection to external attacker domain outside trust boundary",
                "pack_rule": "data_egress_rules: domain allowlist violation (mode: block)"
            },
        },
        "healthcare": {
            "intent": TrustedIntent(extra_fields={"doctor": "Dr. Sarah Smith", "reason": "Annual Wellness Exam", "policy_no": "POL-98214"}),
            "benign_actions": [
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8003/login", "value": "http://127.0.0.1:8003/login", "path": "/login"},
                {"action_type": "CLICK", "target": "#login-btn", "value": None, "path": "/login"},
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8003/dashboard", "value": "http://127.0.0.1:8003/dashboard", "path": "/dashboard"},
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8003/lab-results", "value": "http://127.0.0.1:8003/lab-results", "path": "/lab-results"},
                {"action_type": "TYPE", "target": "#reason", "value": "Annual Wellness Exam", "path": "/appointments"},
            ],
            "unsafe_action": {
                "action_type": "TYPE", "target": "#unrelated-ssn", "value": "000-12-3456", "path": "/insurance",
                "description": "Typing private Social Security number into unmapped identity field (credential leak)",
                "pack_rule": "data_egress_rules: ssn_or_insurance_leak (mode: block)"
            },
        },
        "email": {
            "intent": TrustedIntent(contact_email="team@company.internal", extra_fields={"to_email": "team@company.internal", "subject": "Quarterly Status Report"}),
            "benign_actions": [
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8004/inbox", "value": "http://127.0.0.1:8004/inbox", "path": "/inbox"},
                {"action_type": "CLICK", "target": "#open-msg_01", "value": None, "path": "/inbox"},
                {"action_type": "NAVIGATE", "target": "http://127.0.0.1:8004/compose", "value": "http://127.0.0.1:8004/compose", "path": "/inbox"},
                {"action_type": "TYPE", "target": "#to-email", "value": "team@company.internal", "path": "/compose"},
                {"action_type": "TYPE", "target": "#subject", "value": "Quarterly Status Report", "path": "/compose"},
            ],
            "unsafe_action": {
                "action_type": "TYPE", "target": "#to-email", "value": "hacker@exfiltration-broker.org", "path": "/compose",
                "description": "Transmitting confidential message to unauthorized external recipient",
                "pack_rule": "rules: disallow_unauthorized_external_recipients (mode: ask_human)"
            },
        },
    }

    results_table: List[Dict[str, Any]] = []

    print("\n" + "=" * 90)
    print(f"{'DOMAIN':<12} | {'ACTION TYPE':<10} | {'TARGET':<24} | {'GATE DECISION':<20} | {'RISK':<5} | {'STATUS'}")
    print("-" * 90)

    for domain in ALL_DOMAINS:
        suite = domain_test_suites[domain]
        port = live_sandboxes[domain]

        # Build real gate configured for domain
        gw = Gateway.from_domain(domain, trusted_intent=suite["intent"])
        gate = gw.gate
        assert gate is not None
        assert isinstance(gate, ContextGuardGate)

        # 1. Run 5 Benign Actions
        for idx, act in enumerate(suite["benign_actions"], 1):
            live_url = f"http://127.0.0.1:{port}{act['path']}"
            dom_text = _fetch_page_text(live_url)

            proposed = ProposedAction(
                action_type=act["action_type"],
                target=act["target"],
                value=act["value"],
                page_url=live_url,
            )

            # Evaluate through the REAL gate
            result = gate.check(proposed, dom_text)

            # Assert allowed
            assert result.decision in (Decision.ALLOW, Decision.ALLOW_WITH_FLAG, Decision.FLAG), \
                f"Benign action {idx} in {domain} was not allowed: {result.decision} ({result.reason})"

            results_table.append({
                "domain": domain,
                "case_type": f"benign_{idx}",
                "action": f"{act['action_type']} {act['target']}",
                "gate_decision": result.decision.value,
                "risk_score": result.risk_score,
                "reason": result.reason,
            })
            print(f"{domain:<12} | {act['action_type']:<10} | {act['target'][:24]:<24} | {result.decision.value:<20} | {result.risk_score:<5} | ALLOWED")

        # 2. Run 1 Unsafe Action
        u_info = suite["unsafe_action"]
        u_url = f"http://127.0.0.1:{port}{u_info['path']}"
        u_dom = _fetch_page_text(u_url)

        u_prop = ProposedAction(
            action_type=u_info["action_type"],
            target=u_info["target"],
            value=u_info["value"],
            page_url=u_url,
        )

        u_result = gate.check(u_prop, u_dom)

        # Assert intercepted (BLOCK or REQUIRE_CONFIRMATION / PAUSE_TASK)
        assert u_result.decision in (Decision.BLOCK, Decision.REQUIRE_CONFIRMATION, Decision.PAUSE_TASK), \
            f"Unsafe action in {domain} was not intercepted! Got {u_result.decision}"

        results_table.append({
            "domain": domain,
            "case_type": "unsafe",
            "action": f"{u_info['action_type']} {u_info['target']}",
            "gate_decision": u_result.decision.value,
            "risk_score": u_result.risk_score,
            "reason": u_result.reason,
            "pack_rule": u_info["pack_rule"],
        })
        print(f"{domain:<12} | {u_info['action_type']:<10} | {u_info['target'][:24]:<24} | {u_result.decision.value:<20} | {u_result.risk_score:<5} | INTERCEPTED")

    print("=" * 90 + "\n")
    assert len(results_table) == 30  # 5 domains * (5 benign + 1 unsafe)


def test_every_pack_schema_field_is_read_by_gate():
    """
    Asserts that every field left in PolicyPack and SensitiveActionRule is read
    and enforced by the gate execution pipeline, preventing pack-to-code drift.
    """
    from gateway.schema import PolicyPack, SensitiveActionRule
    from gateway.loader import build_default_domain_intent
    from contextguard.consistency_checker import ContextConsistencyVerifier

    # 1. Structural schema completeness check: only genuinely consumed fields remain
    expected_policy_pack_fields = {"domain", "domain_allowlist", "allowed_action_types", "sensitive_actions"}
    actual_policy_pack_fields = set(PolicyPack.model_fields.keys())
    assert actual_policy_pack_fields == expected_policy_pack_fields, (
        f"Schema drift detected! PolicyPack fields {actual_policy_pack_fields} do not match {expected_policy_pack_fields}"
    )

    expected_sensitive_fields = {"action_type", "target", "irreversible", "description"}
    actual_sensitive_fields = set(SensitiveActionRule.model_fields.keys())
    assert actual_sensitive_fields == expected_sensitive_fields, (
        f"Schema drift detected! SensitiveActionRule fields {actual_sensitive_fields} do not match {expected_sensitive_fields}"
    )

    # 2. Test that Field 1: 'domain' is read by the gate
    for d in ["flight", "banking", "ecommerce", "healthcare", "email"]:
        gw = Gateway.from_domain(d)
        assert gw.gate is not None
        assert gw.gate.policy_pack.domain == d

    # 3. Test that Field 2: 'domain_allowlist' is read and actively enforces navigation boundaries
    custom_pack = PolicyPack(
        domain="banking",
        domain_allowlist=["127.0.0.1:8001", "trusted-bank.internal"],
        allowed_action_types=["NAVIGATE", "CLICK"],
        sensitive_actions=[],
    )
    verifier = ContextConsistencyVerifier()
    verifier.trusted_hosts = list(custom_pack.domain_allowlist)
    gate = ContextGuardGate(trusted_intent=build_default_domain_intent("banking"), verifier=verifier, policy_pack=custom_pack)

    # Trusted host -> ALLOW
    res_trusted = gate.check(ProposedAction(action_type="NAVIGATE", target="http://trusted-bank.internal/dashboard", value="http://trusted-bank.internal/dashboard"), "Clean")
    assert res_trusted.decision == Decision.ALLOW

    # Untrusted host -> NAVIGATION_BOUNDARY violation -> REQUIRE_CONFIRMATION / BLOCK
    res_untrusted = gate.check(ProposedAction(action_type="NAVIGATE", target="http://malicious-exfil.org/steal", value="http://malicious-exfil.org/steal"), "Clean")
    assert res_untrusted.decision in (Decision.BLOCK, Decision.REQUIRE_CONFIRMATION)

    # 4. Test that Field 3: 'allowed_action_types' is read and actively blocks disallowed action types
    strict_pack = PolicyPack(
        domain="banking",
        domain_allowlist=["127.0.0.1:8001"],
        allowed_action_types=["CLICK", "NAVIGATE"],
        sensitive_actions=[],
    )
    strict_gate = ContextGuardGate(trusted_intent=build_default_domain_intent("banking"), policy_pack=strict_pack)
    # Permitted action type
    res_allowed = strict_gate.check(ProposedAction(action_type="CLICK", target="#login-btn"), "Clean")
    assert res_allowed.decision == Decision.ALLOW

    # Disallowed action type
    res_disallowed = strict_gate.check(ProposedAction(action_type="EXECUTE_RAW_SCRIPT", target="#eval"), "Clean")
    assert res_disallowed.decision == Decision.BLOCK
    assert "not permitted under domain policy" in res_disallowed.reason

    # 5. Test that Field 4: 'sensitive_actions' (target, action_type, irreversible, description) is read
    gw_sens = Gateway.from_domain("banking")
    # Irreversible action sets booking_critical=True and high sensitivity (0.95)
    crit_mapping = gw_sens.gate._protected.get("submit-transfer-btn") or gw_sens.gate._protected.get("#submit-transfer-btn")
    assert crit_mapping is not None
    assert crit_mapping["booking_critical"] is True
    assert crit_mapping["action_sensitivity"] >= 0.85
