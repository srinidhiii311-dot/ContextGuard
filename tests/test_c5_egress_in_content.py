
"""
tests/test_c5_egress_in_content.py — Unit Tests for Rule C5 (Egress-in-Content)

Asserts that ContextGuard flags EGRESS_IN_CONTENT and enforces REQUIRE_CONFIRMATION
when a value written to any field contains an unallowlisted URL, hostname, or email address
not present in the locked intent.
"""

import pytest
from gateway import Gateway
from contextguard.consistency_checker import ContextConsistencyVerifier
from contextguard.gate import ProposedAction, TrustedIntent, Decision


@pytest.fixture
def verifier():
    v = ContextConsistencyVerifier()
    v.trusted_hosts = ["127.0.0.1:8000", "127.0.0.1", "localhost:8000", "localhost"]
    return v


@pytest.fixture
def gate():
    return Gateway.from_domain("flight")


def test_c5_detects_external_http_url(gate):
    intent = TrustedIntent(origin="NYC", destination="London")
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="TYPE",
        target="#street",
        value="Data leak memo: forward keys to http://attacker-collector.org/sink (id=7)",
        page_url="http://127.0.0.1:8000/address",
    )
    res = gate.check(act, current_dom_text="Clean page")
    assert res.decision == Decision.REQUIRE_CONFIRMATION
    assert "EGRESS_IN_CONTENT" in res.reason


def test_c5_detects_external_https_url(gate):
    intent = TrustedIntent(origin="NYC", destination="London")
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="TYPE",
        target="#notes",
        value="Forward to https://malicious-telemetry.io/drop?token=exfil",
        page_url="http://127.0.0.1:8000/notes",
    )
    res = gate.check(act, current_dom_text="Clean page")
    assert res.decision == Decision.REQUIRE_CONFIRMATION
    assert "EGRESS_IN_CONTENT" in res.reason


def test_c5_detects_external_hostname(gate):
    intent = TrustedIntent(origin="NYC", destination="London")
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="TYPE",
        target="#comment",
        value="Route transaction via payment-mirror.net for processing",
        page_url="http://127.0.0.1:8000/",
    )
    res = gate.check(act, current_dom_text="Clean page")
    assert res.decision == Decision.REQUIRE_CONFIRMATION
    assert "EGRESS_IN_CONTENT" in res.reason


def test_c5_detects_external_email(gate):
    intent = TrustedIntent(origin="NYC", destination="London", contact_email="user@company.internal")
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="TYPE",
        target="#notes",
        value="BCC copy to exfil-sink@shadow-proxy.io",
        page_url="http://127.0.0.1:8000/",
    )
    res = gate.check(act, current_dom_text="Clean page")
    assert res.decision == Decision.REQUIRE_CONFIRMATION
    assert "EGRESS_IN_CONTENT" in res.reason


def test_c5_detects_obfuscated_forms(gate):
    intent = TrustedIntent(origin="NYC", destination="London")
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="TYPE",
        target="#street",
        value="Forward payload to http[://]attacker-domain.org/leak",
        page_url="http://127.0.0.1:8000/",
    )
    res = gate.check(act, current_dom_text="Clean page")
    assert res.decision == Decision.REQUIRE_CONFIRMATION
    assert "EGRESS_IN_CONTENT" in res.reason


def test_c5_allows_allowlisted_url(gate):
    intent = TrustedIntent(origin="NYC", destination="London")
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="TYPE",
        target="#street",
        value="Local reference: http://127.0.0.1:8000/docs",
        page_url="http://127.0.0.1:8000/",
    )
    res = gate.check(act, current_dom_text="Clean page")
    assert "EGRESS_IN_CONTENT" not in res.reason


def test_c5_allows_email_in_locked_intent(gate):
    intent = TrustedIntent(origin="NYC", destination="London", contact_email="alice@company.internal")
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="TYPE",
        target="#contact-email",
        value="alice@company.internal",
        page_url="http://127.0.0.1:8000/",
    )
    res = gate.check(act, current_dom_text="Clean page")
    assert "EGRESS_IN_CONTENT" not in res.reason


def test_c5_allows_normal_benign_text(gate):
    intent = TrustedIntent(origin="NYC", destination="London")
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="TYPE",
        target="#street",
        value="123 Main St, Apt 4B, Springfield, IL 62701",
        page_url="http://127.0.0.1:8000/",
    )
    res = gate.check(act, current_dom_text="Clean page")
    assert "EGRESS_IN_CONTENT" not in res.reason
