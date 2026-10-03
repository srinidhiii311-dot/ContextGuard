"""
tests/test_airport_aliases_and_addons.py — Unit Tests for Stage 1 Requirements

Verifies:
1. Airport alias normalisation:
   - MAA == Chennai passes (no FIELD_MISMATCH)
   - DEL == Delhi passes (no FIELD_MISMATCH)
   - BOM vs Chennai gives FIELD_MISMATCH
   - Unknown code (e.g. XYZ) vs Chennai gives FIELD_MISMATCH
2. Generic hard-rule checks:
   - Touching price-affecting fields when addons_allowed="none" gives FIELD_MISMATCH
     (baggage, meal surcharge, exit-row seat fee, currency, insurance)
   - Complimentary preferences (meal-opt: Vegetarian, seat-opt: 15A) pass cleanly
   - Date different from travel_date gives FIELD_MISMATCH; matching date passes
   - Email different from contact_email gives FIELD_MISMATCH; matching email passes
"""

import pytest
from contextguard.consistency_checker import ContextConsistencyVerifier
from contextguard.models import LockedIntent, ProposedAction


@pytest.fixture
def verifier():
    return ContextConsistencyVerifier()


@pytest.fixture
def base_intent():
    return LockedIntent(
        origin="Chennai",
        destination="Delhi",
        cabin_class="Economy",
        passenger_count=1,
        travel_date="2026-10-25",
        addons_allowed="none",
        contact_email="srinidhi@traveler-corp.com",
    )


def test_airport_alias_maa_equals_chennai(verifier, base_intent):
    """MAA == Chennai passes without FIELD_MISMATCH."""
    action = ProposedAction(
        action_type="TYPE",
        target="#origin",
        value="MAA",
        page_url="http://127.0.0.1:8000/search",
    )
    report = verifier.verify(base_intent, action, "Flight search screen.")
    mismatches = [i for i in report.inconsistencies if i.check_type == "FIELD_MISMATCH"]
    assert len(mismatches) == 0, f"Unexpected mismatch: {mismatches}"


def test_airport_alias_del_equals_delhi(verifier, base_intent):
    """DEL == Delhi passes without FIELD_MISMATCH."""
    action = ProposedAction(
        action_type="TYPE",
        target="#destination",
        value="DEL",
        page_url="http://127.0.0.1:8000/search",
    )
    report = verifier.verify(base_intent, action, "Flight search screen.")
    mismatches = [i for i in report.inconsistencies if i.check_type == "FIELD_MISMATCH"]
    assert len(mismatches) == 0, f"Unexpected mismatch: {mismatches}"


def test_airport_alias_bom_vs_chennai_gives_mismatch(verifier, base_intent):
    """BOM vs Chennai gives FIELD_MISMATCH."""
    action = ProposedAction(
        action_type="TYPE",
        target="#origin",
        value="BOM",
        page_url="http://127.0.0.1:8000/search",
    )
    report = verifier.verify(base_intent, action, "Flight search screen.")
    mismatches = [i for i in report.inconsistencies if i.check_type == "FIELD_MISMATCH"]
    assert len(mismatches) == 1
    assert mismatches[0].field_name == "origin"


def test_unknown_code_vs_chennai_gives_mismatch(verifier, base_intent):
    """Unknown airport code (XYZ) vs Chennai gives FIELD_MISMATCH."""
    action = ProposedAction(
        action_type="TYPE",
        target="#origin",
        value="XYZ",
        page_url="http://127.0.0.1:8000/search",
    )
    report = verifier.verify(base_intent, action, "Flight search screen.")
    mismatches = [i for i in report.inconsistencies if i.check_type == "FIELD_MISMATCH"]
    assert len(mismatches) == 1
    assert mismatches[0].field_name == "origin"


def test_price_affecting_fields_give_mismatch_when_addons_none(verifier, base_intent):
    """Touching baggage, insurance, currency, exit-row, or paid meal when addons_allowed='none' gives FIELD_MISMATCH."""
    cases = [
        ("#baggage", "5000", "SELECT", "Excess baggage policy revision: Oversized baggage fee of 5000 INR."),
        ("#insurance-opt-in", None, "CLICK", "Mandatory adventure travel insurance enrollment at 4500 INR fee."),
        ("#currency", "USD", "SELECT", "Tariff currency adjustment to USD."),
        ("#seat", "12A_ExitRow", "SELECT", "Seat assignment changed to Extra Legroom Exit Row with 2500 INR surcharge."),
        ("#meal", "Caviar_Banquet_9000", "SELECT", "Standard meal service suspended. Premium caviar banquet option selected."),
    ]

    for target, value, action_type, dom in cases:
        action = ProposedAction(
            action_type=action_type,
            target=target,
            value=value,
            page_url="http://127.0.0.1:8000/passenger",
        )
        report = verifier.verify(base_intent, action, dom)
        mismatches = [i for i in report.inconsistencies if i.check_type == "FIELD_MISMATCH"]
        assert len(mismatches) >= 1, f"Expected FIELD_MISMATCH for target={target}"


def test_complimentary_preferences_pass_cleanly(verifier, base_intent):
    """Complimentary dietary preferences and standard seat assignments pass cleanly."""
    complimentary_cases = [
        ("#meal-opt", "Vegetarian", "SELECT"),
        ("#seat-opt", "15A", "SELECT"),
    ]

    for target, value, action_type in complimentary_cases:
        action = ProposedAction(
            action_type=action_type,
            target=target,
            value=value,
            page_url="http://127.0.0.1:8000/passenger",
        )
        report = verifier.verify(base_intent, action, "Form screen.")
        mismatches = [i for i in report.inconsistencies if i.check_type == "FIELD_MISMATCH"]
        assert len(mismatches) == 0, f"Complimentary {target} should not give FIELD_MISMATCH"


def test_travel_date_verification(verifier, base_intent):
    """Date different from travel_date gives FIELD_MISMATCH; matching date passes."""
    # Mismatch
    mismatch_action = ProposedAction(
        action_type="TYPE",
        target="#depart-date",
        value="2026-11-15",
        page_url="http://127.0.0.1:8000/search",
    )
    rep_mismatch = verifier.verify(base_intent, mismatch_action, "Search screen.")
    assert any(i.check_type == "FIELD_MISMATCH" and i.field_name == "travel_date" for i in rep_mismatch.inconsistencies)

    # Match
    match_action = ProposedAction(
        action_type="TYPE",
        target="#depart-date",
        value="2026-10-25",
        page_url="http://127.0.0.1:8000/search",
    )
    rep_match = verifier.verify(base_intent, match_action, "Search screen.")
    assert not any(i.check_type == "FIELD_MISMATCH" and i.field_name == "travel_date" for i in rep_match.inconsistencies)


def test_contact_email_verification(verifier, base_intent):
    """Email different from contact_email gives FIELD_MISMATCH; matching email passes."""
    # Mismatch
    mismatch_action = ProposedAction(
        action_type="TYPE",
        target="#dispatch-email",
        value="adversary-ops@exfil-travel.com",
        page_url="http://127.0.0.1:8000/passenger",
    )
    rep_mismatch = verifier.verify(base_intent, mismatch_action, "Passenger form.")
    assert any(i.check_type == "FIELD_MISMATCH" and i.field_name == "contact_email" for i in rep_mismatch.inconsistencies)

    # Match
    match_action = ProposedAction(
        action_type="TYPE",
        target="#email",
        value="srinidhi@traveler-corp.com",
        page_url="http://127.0.0.1:8000/passenger",
    )
    rep_match = verifier.verify(base_intent, match_action, "Passenger form.")
    assert not any(i.check_type == "FIELD_MISMATCH" and i.field_name == "contact_email" for i in rep_match.inconsistencies)


def test_optional_intent_fields_default_to_none_and_skip_checks(verifier):
    """When optional intent fields are None, their consistency checks are skipped."""
    intent_none = LockedIntent(
        origin="Chennai",
        destination="Delhi",
        cabin_class="Economy",
        passenger_count=1,
    )
    assert intent_none.travel_date is None
    assert intent_none.contact_email is None
    assert intent_none.addons_allowed is None

    # Date action should not mismatch
    date_action = ProposedAction(action_type="TYPE", target="#depart-date", value="2026-11-15", page_url="http://127.0.0.1:8000/search")
    assert not any(i.check_type == "FIELD_MISMATCH" and i.field_name == "travel_date" for i in verifier.verify(intent_none, date_action, "Search").inconsistencies)

    # Email action should not mismatch
    email_action = ProposedAction(action_type="TYPE", target="#dispatch-email", value="exfil@evil.com", page_url="http://127.0.0.1:8000/passenger")
    assert not any(i.check_type == "FIELD_MISMATCH" and i.field_name == "contact_email" for i in verifier.verify(intent_none, email_action, "Passenger").inconsistencies)

    # Add-on action should not mismatch when addons_allowed is None
    addon_action = ProposedAction(action_type="SELECT", target="#baggage", value="5000", page_url="http://127.0.0.1:8000/passenger")
    assert not any(i.check_type == "FIELD_MISMATCH" and i.field_name == "baggage" for i in verifier.verify(intent_none, addon_action, "Passenger").inconsistencies)

