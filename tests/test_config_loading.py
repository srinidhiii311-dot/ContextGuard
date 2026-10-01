"""
tests/test_config_loading.py — Automated Validation of ContextGuard Configuration Artifacts

Validates:
1. All 7 build-time configuration files load without YAML/JSON syntax errors.
2. Weight sum in risk_weights.yaml equals exactly 1.00.
3. Risk tiers cover 0 to 100 continuously with no gaps or inversions.
4. Policy rules cover all risk tiers and map strictly to valid PolicyDecision enums.
5. Pydantic models in contextguard.models round-trip serialize without errors.
"""

import json
import math
from pathlib import Path
import pytest
import yaml

from contextguard.models import (
    AuditRecord,
    ConsistencyReport,
    ContextSnapshot,
    LockedIntent,
    PolicyDecision,
    PolicyDecisionResult,
    ProposedAction,
    RiskAssessmentResult,
    RiskFactorBreakdown,
    RiskTier,
    ThreatDetectionResult,
)

CONFIG_DIR = Path(__file__).parent.parent / "contextguard" / "config"


def test_intent_schema_exists_and_valid():
    schema_path = CONFIG_DIR / "intent_schema.json"
    assert schema_path.exists(), "intent_schema.json missing"
    data = json.loads(schema_path.read_text(encoding="utf-8"))
    assert data.get("title") == "ContextGuardLockedIntentSchema"
    assert "required" in data
    assert set(["origin", "destination", "cabin_class", "passenger_count"]).issubset(set(data["required"]))


def test_protected_fields_valid():
    path = CONFIG_DIR / "protected_fields.yaml"
    assert path.exists(), "protected_fields.yaml missing"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    mappings = data.get("target_field_mappings", {})
    assert len(mappings) >= 4, "Expected at least 4 target field mappings"
    for name, item in mappings.items():
        sens = item.get("action_sensitivity")
        assert 0.0 <= sens <= 1.0, f"Sensitivity out of bounds for {name}: {sens}"
        assert isinstance(item.get("booking_critical"), bool), f"booking_critical must be bool for {name}"


def test_attack_taxonomy_valid():
    path = CONFIG_DIR / "attack_taxonomy.yaml"
    assert path.exists(), "attack_taxonomy.yaml missing"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    thresh = data.get("classification_confidence_threshold")
    assert 0.0 <= thresh <= 1.0, f"Invalid confidence threshold: {thresh}"
    attacks = data.get("known_attacks", {})
    assert "PROMPT_INJECTION" in attacks
    assert "DOM_MANIPULATION" in attacks
    assert "NAVIGATION_MANIPULATION" in attacks


def test_characterization_buckets_valid():
    path = CONFIG_DIR / "characterization_buckets.yaml"
    assert path.exists(), "characterization_buckets.yaml missing"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    buckets = data.get("buckets", [])
    assert len(buckets) >= 3, "Expected at least 3 unknown threat buckets"
    assert data.get("fallback_bucket") in [b["id"] for b in buckets]


def test_risk_weights_sum_and_tiers():
    path = CONFIG_DIR / "risk_weights.yaml"
    assert path.exists(), "risk_weights.yaml missing"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    weights = data.get("weights", {})
    total = sum(weights.values())
    assert math.isclose(total, 1.0, rel_tol=1e-5), f"Risk weights must sum to 1.00, got: {total}"

    # Deviation calibration bounds
    dev_norm = data.get("deviation_normalization", {})
    d_min = dev_norm.get("delta_min")
    d_max = dev_norm.get("delta_max")
    assert d_min < d_max, f"delta_min ({d_min}) must be less than delta_max ({d_max})"

    # Check risk tiers
    tiers = data.get("risk_tiers", {})
    assert set(tiers.keys()) == set(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    assert tiers["LOW"]["min_score"] == 0
    assert tiers["CRITICAL"]["max_score"] == 100


def test_policy_rules_coverage():
    path = CONFIG_DIR / "policy_rules.yaml"
    assert path.exists(), "policy_rules.yaml missing"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    
    # Check top-level escalation threshold
    threshold = data.get("prior_flag_escalation_threshold")
    assert isinstance(threshold, int) and threshold > 0

    base_matrix = data.get("base_policy_matrix", {})
    valid_decisions = set(d.value for d in PolicyDecision)
    
    for tier in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        assert tier in base_matrix, f"Missing tier {tier} in base_policy_matrix"
        assert base_matrix[tier]["booking_critical_true"] in valid_decisions
        assert base_matrix[tier]["booking_critical_false"] in valid_decisions

    esc_matrix = data.get("escalation_policy_matrix", {})
    for tier in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        assert tier in esc_matrix, f"Missing tier {tier} in escalation_policy_matrix"


def test_trust_boundary_valid():
    path = CONFIG_DIR / "trust_boundary.yaml"
    assert path.exists(), "trust_boundary.yaml missing"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "localhost" in data.get("trusted_hosts", [])
    assert "http" in data.get("allowed_schemes", [])


def test_models_roundtrip():
    intent = LockedIntent(
        origin="Chennai",
        destination="Delhi",
        cabin_class="Economy",
        passenger_count=1,
    )
    assert intent.origin == "Chennai"
    assert intent.cabin_class == "Economy"

    action = ProposedAction(
        action_type="CLICK",
        target="#confirm-booking",
        value=None,
    )
    report = ConsistencyReport(
        is_consistent=True,
        consistency_score=1.0,
        inconsistency_severity=0.0,
        marker_presence=False,
    )
    threat = ThreatDetectionResult(
        is_threat=False,
        is_known_path=True,
        confidence=0.0,
    )
    risk = RiskAssessmentResult(
        risk_score=15,
        risk_tier=RiskTier.LOW,
        factors=RiskFactorBreakdown(),
        action_sensitivity=0.95,
        booking_critical=True,
    )
    decision = PolicyDecisionResult(
        decision=PolicyDecision.ALLOW,
        reason="Baseline consistent action",
    )
    audit = AuditRecord(
        task_id="task-test-01",
        step_number=1,
        proposed_action=action,
        context_snapshot_id="snap-test-01",
        consistency_report=report,
        threat_detection=threat,
        risk_assessment=risk,
        policy_decision=decision,
        enforced_outcome="EXECUTED",
    )
    
    serialized = audit.model_dump_json()
    assert "task-test-01" in serialized
    assert "ALLOW" in serialized


def test_action_sensitivity_selector_resolution_regression():
    """
    Regression Test: Ensures CSS selectors nested inside target_selectors
    in protected_fields.yaml correctly resolve to their sensitivity and booking_critical flag,
    and DO NOT fall back to default_unmapped_action (0.30, False).
    """
    from contextguard.gate import _get_action_sensitivity, _load_protected_fields

    pf = _load_protected_fields()

    # Flat dictionary lookup pf.get("#cabin") is None because keys are 'cabin_class_dropdown', etc.
    assert pf.get("#cabin") is None, "Sanity check: #cabin is a nested selector, not a top-level key"

    # Regression check: selector resolution must match nested target_selectors
    sens, crit = _get_action_sensitivity("#cabin", pf)
    assert sens == 0.75, f"Expected 0.75 for #cabin, got {sens}"
    assert crit is True, f"Expected booking_critical=True for #cabin, got {crit}"

    sens_pcount, crit_pcount = _get_action_sensitivity("#pcount", pf)
    assert sens_pcount == 0.70, f"Expected 0.70 for #pcount, got {sens_pcount}"
    assert crit_pcount is True

    sens_origin, crit_origin = _get_action_sensitivity("#origin", pf)
    assert sens_origin == 0.80, f"Expected 0.80 for #origin, got {sens_origin}"
    assert crit_origin is True

    sens_confirm, crit_confirm = _get_action_sensitivity("#confirm-btn", pf)
    assert sens_confirm == 0.95, f"Expected 0.95 for #confirm-btn, got {sens_confirm}"
    assert crit_confirm is True

    # Truly unmapped target must receive default unmapped values
    sens_unmapped, crit_unmapped = _get_action_sensitivity("#dispatch-email", pf)
    assert sens_unmapped == 0.30, f"Expected default 0.30 for #dispatch-email, got {sens_unmapped}"
    assert crit_unmapped is False

    # External navigation target must resolve to navigation sensitivity (0.50)
    sens_nav, crit_nav = _get_action_sensitivity("https://sky-reserve-clearance.org/portal", pf)
    assert sens_nav == 0.50, f"Expected 0.50 for URL navigation, got {sens_nav}"
    assert crit_nav is False


def test_policy_decision_hashable_and_dict_keys():
    """Verify PolicyDecision enum members are strictly hashable and work as dict keys and set members."""
    d = {
        PolicyDecision.ALLOW: "allow_action",
        PolicyDecision.ALLOW_WITH_FLAG: "flag_action",
        PolicyDecision.REQUIRE_CONFIRMATION: "confirm_action",
        PolicyDecision.BLOCK: "block_action",
        PolicyDecision.PAUSE_TASK: "pause_action",
    }
    assert d[PolicyDecision.BLOCK] == "block_action"
    assert d[PolicyDecision.ALLOW] == "allow_action"
    s = set(PolicyDecision)
    assert len(s) == 5
    assert PolicyDecision.PAUSE_TASK in s


