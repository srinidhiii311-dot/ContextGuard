"""
tests/test_c6_irreversible_authorization.py — Unit Tests for Rule C6 (Irreversible-Action Authorization)

Asserts that ContextGuard flags UNAUTHORIZED_IRREVERSIBLE_ACTION and enforces REQUIRE_CONFIRMATION
when a manifest-irreversible action is proposed without explicit authorization in the locked intent's
authorized_actions list.
"""

import pytest
from gateway import Gateway
from contextguard.gate import ProposedAction, TrustedIntent, Decision


def test_c6_requires_confirmation_for_unauthorized_flight_confirm():
    gate = Gateway.from_domain("flight")
    intent = TrustedIntent(origin="Chennai", destination="Delhi", authorized_actions=[])
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="CLICK",
        target="#confirm-booking",
        value=None,
        page_url="http://127.0.0.1:8000/review",
    )
    res = gate.check(act, current_dom_text="Clean review page. Review your flight reservation details below.")
    assert res.decision in (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK)
    assert "Manifest-irreversible action" in res.reason or "UNAUTHORIZED_IRREVERSIBLE_ACTION" in res.reason


def test_c6_requires_confirmation_for_unauthorized_banking_transfer():
    gate = Gateway.from_domain("banking")
    intent = TrustedIntent.from_dict({"payee": "Alice Smith", "to_account": "ACC-4491", "amount": 100.00, "authorized_actions": []})
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="CLICK",
        target="#submit-transfer-btn",
        value=None,
        page_url="http://127.0.0.1:8001/transfer",
    )
    res = gate.check(act, current_dom_text="Transfer form")
    assert res.decision in (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK)
    assert "Manifest-irreversible action" in res.reason or "UNAUTHORIZED_IRREVERSIBLE_ACTION" in res.reason


def test_c6_requires_confirmation_for_unauthorized_ecommerce_order():
    gate = Gateway.from_domain("ecommerce")
    intent = TrustedIntent.from_dict({"address": "123 Main St", "authorized_actions": []})
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="CLICK",
        target="#place-order-btn",
        value=None,
        page_url="http://127.0.0.1:8002/checkout",
    )
    res = gate.check(act, current_dom_text="Checkout page")
    assert res.decision in (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK)
    assert "Manifest-irreversible action" in res.reason or "UNAUTHORIZED_IRREVERSIBLE_ACTION" in res.reason


def test_c6_requires_confirmation_for_unauthorized_email_send():
    gate = Gateway.from_domain("email")
    intent = TrustedIntent.from_dict({"to_email": "team@company.internal", "subject": "Notes", "authorized_actions": []})
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="CLICK",
        target="#send-btn",
        value=None,
        page_url="http://127.0.0.1:8004/compose",
    )
    res = gate.check(act, current_dom_text="Compose page")
    assert res.decision in (Decision.REQUIRE_CONFIRMATION, Decision.BLOCK)
    assert "Manifest-irreversible action" in res.reason or "UNAUTHORIZED_IRREVERSIBLE_ACTION" in res.reason


def test_c6_allows_authorized_flight_confirm():
    gate = Gateway.from_domain("flight")
    intent = TrustedIntent(origin="Chennai", destination="Delhi", authorized_actions=["#confirm-booking"])
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="CLICK",
        target="#confirm-booking",
        value=None,
        page_url="http://127.0.0.1:8000/review",
    )
    res = gate.check(act, current_dom_text="Clean review page. Review your flight reservation details below.")
    assert "UNAUTHORIZED_IRREVERSIBLE_ACTION" not in res.reason
    assert res.decision in (Decision.ALLOW, Decision.ALLOW_WITH_FLAG)


def test_c6_allows_non_irreversible_action():
    gate = Gateway.from_domain("flight")
    intent = TrustedIntent(origin="Chennai", destination="Delhi", authorized_actions=[])
    gate.set_intent(intent)
    act = ProposedAction(
        action_type="CLICK",
        target="#search-btn",
        value=None,
        page_url="http://127.0.0.1:8000/",
    )
    res = gate.check(act, current_dom_text="Clean search page")
    assert "UNAUTHORIZED_IRREVERSIBLE_ACTION" not in res.reason
    assert res.decision in (Decision.ALLOW, Decision.ALLOW_WITH_FLAG)
