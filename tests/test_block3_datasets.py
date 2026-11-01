"""
tests/test_block3_datasets.py — Evaluation Datasets & Harness Tests (Block 3)

Tests:
1. Schema validity: Every case in attacks/ and benign/ (dev and test) validates against EvaluationCase.
2. Tuning isolation guard: Tests strictly fail with TestDataLeakError if test-split data is inspected.
3. Dataset counts: Total attacks (~400) and benign (~400) within 10% of target.
4. Domain coverage: Every one of the 5 domains has both attack and benign cases.
5. Case ID uniqueness: No duplicate case_id across all dataset files.
6. Held-out test families: Held-out attack families have 0 dev cases.
7. Uncompromised attack mechanism: ~20% of attack cases have expected allow.
8. Case execution harness: run_case outputs standard RunRecords through real gate.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from harness.case_schema import EvaluationCase
from harness.run_case import run_case
from harness.run_record import RunRecord
from harness.split import TestDataLeakError, assert_dev_only, guard_tuning_item

ROOT_DIR = Path(__file__).resolve().parent.parent
ATTACKS_DEV = ROOT_DIR / "attacks" / "dev" / "cases.jsonl"
ATTACKS_TEST = ROOT_DIR / "attacks" / "test" / "cases.jsonl"
BENIGN_DEV = ROOT_DIR / "benign" / "dev" / "cases.jsonl"
BENIGN_TEST = ROOT_DIR / "benign" / "test" / "cases.jsonl"

ALL_DOMAINS = ["flight", "banking", "ecommerce", "healthcare", "email"]
HELD_OUT_FAMILIES = {"form_action_override", "hidden_css_text", "overlay_clickjack"}


def _read_cases(path: Path) -> list[EvaluationCase]:
    assert path.is_file(), f"Expected dataset file not found: {path}"
    cases = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            data = json.loads(s)
            cases.append(EvaluationCase.model_validate(data))
    return cases


def test_schema_validity_all_cases():
    """Verify all JSONL files exist and every record strictly conforms to EvaluationCase schema."""
    for path in [ATTACKS_DEV, ATTACKS_TEST, BENIGN_DEV, BENIGN_TEST]:
        cases = _read_cases(path)
        assert len(cases) > 0, f"Dataset file {path} was empty."
        for c in cases:
            assert c.case_id
            assert c.domain in ALL_DOMAINS
            assert c.split in ("dev", "test")
            assert c.case_type in ("attack", "benign")
            assert c.expected_decision in ("allow", "block_or_ask")
            assert c.ground_truth_label in ("attack_divergent", "attack_uncompromised", "benign")
            assert c.proposed_action.action_type
            assert c.proposed_action.target


def test_tuning_data_isolation_guard_on_block3_datasets():
    """Verify standing rule: Never read test data in any tuning script."""
    dev_cases = _read_cases(ATTACKS_DEV) + _read_cases(BENIGN_DEV)
    test_cases = _read_cases(ATTACKS_TEST) + _read_cases(BENIGN_TEST)

    # 1. Dev cases must pass isolation checks cleanly
    assert_dev_only(dev_cases)
    for c in dev_cases:
        guard_tuning_item(c)

    # 2. Test cases must raise TestDataLeakError
    assert len(test_cases) > 0
    with pytest.raises(TestDataLeakError):
        assert_dev_only(test_cases)

    for c in test_cases[:5]:
        with pytest.raises(TestDataLeakError):
            guard_tuning_item(c)


def test_dataset_counts_within_10_percent_of_target():
    """Verify counts are within 10% of target (approx 400 attacks, approx 400 benign)."""
    att_dev = _read_cases(ATTACKS_DEV)
    att_test = _read_cases(ATTACKS_TEST)
    ben_dev = _read_cases(BENIGN_DEV)
    ben_test = _read_cases(BENIGN_TEST)

    total_attacks = len(att_dev) + len(att_test)
    total_benign = len(ben_dev) + len(ben_test)

    # Dataset v2 targets: dev attacks have >= 60 uncompromised, benign dev >= 400, benign test >= 200
    assert total_attacks >= 400, f"Expected total attacks >= 400, got {total_attacks}"
    assert len(ben_dev) >= 400, f"Expected benign dev >= 400, got {len(ben_dev)}"
    assert len(ben_test) >= 200, f"Expected benign test >= 200, got {len(ben_test)}"
    assert total_benign >= 600, f"Expected total benign >= 600, got {total_benign}"

    # Verify ~20% of attacks are uncompromised (Addition B)
    uncomp_attacks = sum(1 for c in (att_dev + att_test) if c.ground_truth_label == "attack_uncompromised")
    uncomp_pct = uncomp_attacks / total_attacks
    assert 0.15 <= uncomp_pct <= 0.25, f"Expected ~20% uncompromised attacks, got {uncomp_pct:.2%}"

    # Verify ~25% hard benign subset
    hard_benign = sum(1 for c in (ben_dev + ben_test) if c.family == "benign_hard")
    hard_pct = hard_benign / total_benign
    assert 0.20 <= hard_pct <= 0.30, f"Expected ~25% hard benign subset, got {hard_pct:.2%}"


def test_every_domain_has_both_attack_and_benign():
    """Verify all 5 mock domains have attack and benign cases across dev and test."""
    all_cases = (
        _read_cases(ATTACKS_DEV)
        + _read_cases(ATTACKS_TEST)
        + _read_cases(BENIGN_DEV)
        + _read_cases(BENIGN_TEST)
    )

    domain_types = {d: {"attack": 0, "benign": 0} for d in ALL_DOMAINS}
    for c in all_cases:
        domain_types[c.domain][c.case_type] += 1

    for domain, counts in domain_types.items():
        assert counts["attack"] >= 30, f"Domain {domain} has insufficient attack cases: {counts['attack']}"
        assert counts["benign"] >= 30, f"Domain {domain} has insufficient benign cases: {counts['benign']}"


def test_no_duplicate_case_ids():
    """Verify zero duplicate case_ids exist across the entire 800-case dataset."""
    all_cases = (
        _read_cases(ATTACKS_DEV)
        + _read_cases(ATTACKS_TEST)
        + _read_cases(BENIGN_DEV)
        + _read_cases(BENIGN_TEST)
    )
    case_ids = [c.case_id for c in all_cases]
    unique_ids = set(case_ids)
    assert len(case_ids) == len(unique_ids), f"Found {len(case_ids) - len(unique_ids)} duplicate case IDs!"


def test_held_out_families_strictly_in_test_only():
    """Verify that the 3 held-out attack families never leak into dev split."""
    dev_attacks = _read_cases(ATTACKS_DEV)
    for c in dev_attacks:
        assert c.family not in HELD_OUT_FAMILIES, (
            f"LEAKAGE DETECTED: Held-out family '{c.family}' appeared in dev split ({c.case_id})!"
        )


def test_harness_run_case_execution():
    """Verify run_case executes cleanly through the real gate adapter."""
    dev_attacks = _read_cases(ATTACKS_DEV)
    sample_case = dev_attacks[0]

    record = run_case(sample_case, config="zero_shot_dev", seed=42)
    assert isinstance(record, RunRecord)
    assert record.domain == sample_case.domain
    assert record.task_id == sample_case.case_id
    assert record.decision in ("allow", "warn", "ask_human", "block")
    assert record.latency_ms >= 0.0

    # Test split guard in run_case
    test_attacks = _read_cases(ATTACKS_TEST)
    with pytest.raises(TestDataLeakError):
        run_case(test_attacks[0], config="zero_shot_dev")

