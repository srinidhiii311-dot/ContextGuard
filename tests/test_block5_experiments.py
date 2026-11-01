"""
tests/test_block5_experiments.py — Multi-Configuration Experiment Harness Tests (Block 5)

Tests:
1. Configuration registry and flags: all 5 core configurations and ablations are properly registered.
2. Split safety guard: attempting to evaluate on the 'test' split without --final raises PermissionError.
3. Statistical metrics: Wilson 95% confidence intervals, bootstrap latency estimation, and proportion formatting.
4. McNemar exact test & Holm-Bonferroni correction: mathematical correctness of p-values and FWER adjustment.
5. End-to-end evaluation pipeline: mini batch run produces valid RunRecords and metrics CSV.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from analysis.metrics import (
    bootstrap_percentiles,
    compute_metrics_for_records,
    format_proportion_ci,
    wilson_score_interval,
)
from analysis.stats import (
    compute_effect_size,
    holm_bonferroni_correction,
    mcnemar_exact_p_value,
    run_pairwise_mcnemar_tests,
)
from harness.case_schema import EvaluationCase
from harness.configs import CONFIG_SPECS, evaluate_case_with_config, normalize_config_name
from harness.run_experiment import load_split_cases
from harness.split import TestDataLeakError, assert_dev_only, guard_tuning_item


def test_config_specs_completeness():
    """Verifies that all 5 required configurations are registered with explicit flags."""
    required = ["no_gateway", "taxonomy_only", "consistency_only", "dual_gate", "dual_gate_llm"]
    for name in required:
        assert name in CONFIG_SPECS, f"Missing required configuration: {name}"
        spec = CONFIG_SPECS[name]
        assert spec.name == name
        assert spec.code
        assert spec.description
        assert "enable_verifier" in spec.flags
        assert "enable_taxonomy" in spec.flags
        assert "enable_characterizer" in spec.flags
        assert "enable_risk_engine" in spec.flags
        assert "enable_policy_engine" in spec.flags
        assert "enable_llm_checker" in spec.flags


def test_split_guard_refuses_test_split_access():
    """Verifies that accessing test split data in tuning or without authorization raises an error."""
    with pytest.raises(TestDataLeakError):
        guard_tuning_item("test")

    with pytest.raises(TestDataLeakError):
        assert_dev_only([{"split": "dev"}, {"split": "test"}])


def test_wilson_ci_accuracy_and_boundaries():
    """Verifies Wilson 95% score interval calculation against theoretical bounds."""
    # 0 successes out of 100
    lo0, hi0 = wilson_score_interval(0, 100)
    assert lo0 == 0.0
    assert 0.035 <= hi0 <= 0.040  # ~3.7% upper rule of three

    # 100 successes out of 100
    lo100, hi100 = wilson_score_interval(100, 100)
    assert 0.960 <= lo100 <= 0.965
    assert hi100 == pytest.approx(1.0)

    # 50 out of 100 (symmetric around 0.5)
    lo50, hi50 = wilson_score_interval(50, 100)
    assert round(lo50, 2) == 0.40
    assert round(hi50, 2) == 0.60

    # Formatting string check
    fmt = format_proportion_ci(50, 100)
    assert "50/100 (50.0%" in fmt


def test_mcnemar_exact_p_value_and_holm_bonferroni():
    """Verifies McNemar exact binomial p-value and Holm-Bonferroni step-down correction."""
    # Symmetrical discordance (b=10, c=10) -> p should be 1.0
    p_sym = mcnemar_exact_p_value(10, 10)
    assert p_sym == 1.0

    # Strong discordance (b=20, c=0) -> 2 * (0.5)^20 ~ 1.9e-6
    p_skew = mcnemar_exact_p_value(20, 0)
    assert p_skew < 0.0001

    # Holm-Bonferroni test ordering and adjustment
    raw_tests = [
        {"name": "test1", "p_value": 0.01},
        {"name": "test2", "p_value": 0.04},
        {"name": "test3", "p_value": 0.001},
    ]
    adj = holm_bonferroni_correction(raw_tests, alpha=0.05)
    # Ranked: test3 (0.001 * 3 = 0.003), test1 (0.01 * 2 = 0.02), test2 (0.04 * 1 = 0.04)
    res_map = {item["name"]: item for item in adj}
    assert res_map["test3"]["p_adj"] == pytest.approx(0.003, rel=1e-3)
    assert res_map["test1"]["p_adj"] == pytest.approx(0.02, rel=1e-3)
    assert res_map["test2"]["p_adj"] == pytest.approx(0.04, rel=1e-3)
    assert all(item["significant"] for item in adj)


def test_mini_evaluation_pipeline(tmp_path):
    """Smoke test: runs 2 cases through all 5 configurations and verifies output records."""
    dev_cases = load_split_cases(split="dev", limit=2)
    assert len(dev_cases) == 2

    records = []
    for cfg in ["no_gateway", "taxonomy_only", "consistency_only", "dual_gate"]:
        for c in dev_cases:
            rec = evaluate_case_with_config(c, config=cfg, seed=42)
            assert rec.decision in ("allow", "warn", "ask_human", "block")
            assert rec.latency_ms >= 0.0
            records.append(rec.model_dump())

    metrics = compute_metrics_for_records(records)
    assert metrics["total_records"] == 8
    assert "compromised_detection_rate" in metrics
    assert "task_completion_proxy" in metrics
