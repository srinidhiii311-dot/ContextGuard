"""
harness/run_experiment.py — Experiment Execution CLI (Block 5)

Runs designated evaluation splits (dev | test), configurations, and seeds.
Strictly enforces test data isolation: refuses to run on 'test' unless --final is explicitly passed.
Writes run records to runs/<config>_<seed>.jsonl.

Usage:
  python -m harness.run_experiment --split dev --all-configs
  python -m harness.run_experiment --split dev --configs dual_gate no_gateway --seeds 42
  python -m harness.run_experiment --split test --final --all-configs
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from harness.case_schema import EvaluationCase
from harness.configs import CONFIG_SPECS, evaluate_case_with_config, normalize_config_name
from harness.run_record import RunRecord
from harness.split import TestDataLeakError, assert_dev_only

ATTACKS_DIR = ROOT_DIR / "attacks"
BENIGN_DIR = ROOT_DIR / "benign"
RUNS_DIR = ROOT_DIR / "runs"

MAIN_CONFIGS = [
    "no_gateway",
    "taxonomy_block",
    "taxonomy_warn",
    "consistency_only",
    "regex_only",
    "llm_judge_only",
    "tool_allowlist",
    "dual_gate",
    "dual_gate_llm",
]

ALL_CONFIGS_WITH_ABLATIONS = [
    "no_gateway",
    "taxonomy_block",
    "taxonomy_warn",
    "consistency_only",
    "regex_only",
    "llm_judge_only",
    "tool_allowlist",
    "dual_gate",
    "dual_gate_llm",
    "dual_gate_no_characterizer",
    "dual_gate_no_risk_engine",
    "dual_gate_no_c1",
    "dual_gate_no_c2",
    "dual_gate_no_c3",
    "dual_gate_no_c4",
    "dual_gate_no_c5",
    "dual_gate_no_c6",
]


def load_split_cases(split: str = "dev", limit: Optional[int] = None) -> List[EvaluationCase]:
    """
    Loads all cases for the given split (attacks + benign).
    Enforces dev isolation if split == 'dev'.
    """
    atk_file = ATTACKS_DIR / split / "cases.jsonl"
    ben_file = BENIGN_DIR / split / "cases.jsonl"

    if not atk_file.is_file():
        raise FileNotFoundError(f"Attacks case file not found: {atk_file}")
    if not ben_file.is_file():
        raise FileNotFoundError(f"Benign case file not found: {ben_file}")

    cases: List[EvaluationCase] = []
    for fpath in [atk_file, ben_file]:
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    cases.append(EvaluationCase.model_validate(json.loads(s)))

    if split == "dev":
        assert_dev_only(cases)

    if limit is not None and limit > 0:
        return cases[:limit]
    return cases


def run_single_config(
    cases: List[EvaluationCase],
    config: str,
    seed: int = 42,
    output_dir: Path = RUNS_DIR,
) -> Path:
    """
    Executes all cases under one configuration and seed.
    Writes records to runs/<config>_<seed>.jsonl.
    """
    norm_cfg = normalize_config_name(config)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / f"{norm_cfg}_{seed}.jsonl"

    print(f"\n--- Running Experiment: Config='{norm_cfg}' | Seed={seed} | Cases={len(cases)} ---")
    t0 = time.time()

    gateway_cache: Dict[str, Any] = {}
    records: List[RunRecord] = []

    with open(out_file, "w", encoding="utf-8") as f:
        for idx, case in enumerate(cases, 1):
            rec = evaluate_case_with_config(
                case=case,
                config=norm_cfg,
                seed=seed,
                gateway_cache=gateway_cache,
            )
            records.append(rec)
            f.write(rec.model_dump_json() + "\n")

            if idx % 100 == 0 or idx == len(cases):
                elapsed = time.time() - t0
                rate = idx / elapsed if elapsed > 0 else 0
                print(f"  [{norm_cfg}] {idx}/{len(cases)} processed ({elapsed:.1f}s, {rate:.1f} cases/s)...")

    elapsed = time.time() - t0
    print(f"  [COMPLETED] Config '{norm_cfg}' in {elapsed:.2f}s -> {out_file}")
    return out_file


def parse_args():
    parser = argparse.ArgumentParser(description="ContextGuard Multi-Configuration Experiment Harness (Block 5)")
    parser.add_argument(
        "--split",
        choices=["dev", "test"],
        default="dev",
        help="Dataset split to evaluate ('dev' or 'test'). Default: dev.",
    )
    parser.add_argument(
        "--configs",
        nargs="+",
        default=None,
        help="Specific configurations to run (e.g. dual_gate no_gateway).",
    )
    parser.add_argument(
        "--all-configs",
        action="store_true",
        help="Run all core configurations (no_gateway, taxonomy_only, consistency_only, dual_gate, dual_gate_llm).",
    )
    parser.add_argument(
        "--include-ablations",
        action="store_true",
        help="Include ablation configurations in the run.",
    )
    parser.add_argument(
        "--seeds",
        nargs="+",
        type=int,
        default=[42],
        help="Random seeds for execution (default: [42]).",
    )
    parser.add_argument(
        "--final",
        action="store_true",
        help="Explicit confirmation required to run against the held-out 'test' split.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of cases evaluated per configuration (for smoke testing).",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Split safety guard: strictly refuse test split unless --final is passed
    if args.split == "test" and not args.final:
        raise PermissionError(
            "TEST SPLIT ACCESS VIOLATION: Evaluating against the held-out 'test' split "
            "is strictly forbidden without the '--final' flag. "
            "Never evaluate on test data during development or tuning."
        )

    # Determine configurations to run
    configs_to_run: List[str] = []
    if args.all_configs:
        configs_to_run = list(ALL_CONFIGS_WITH_ABLATIONS if args.include_ablations else MAIN_CONFIGS)
    elif args.configs:
        configs_to_run = [normalize_config_name(c) for c in args.configs]
    else:
        configs_to_run = list(MAIN_CONFIGS)

    # Validate configurations
    for c in configs_to_run:
        if c not in CONFIG_SPECS:
            raise ValueError(f"Unknown config '{c}'. Available: {list(CONFIG_SPECS.keys())}")

    print("=" * 80)
    print(f"             CONTEXTGUARD EXPERIMENT RUNNER (BLOCK 5)")
    print("=" * 80)
    print(f" Split:         {args.split.upper()} {'(FINAL HOLD-OUT RUN)' if args.final else '(DEV TUNING)'}")
    print(f" Configs ({len(configs_to_run)}): {', '.join(configs_to_run)}")
    print(f" Seeds ({len(args.seeds)}):   {args.seeds}")
    print("=" * 80)

    # Load cases
    cases = load_split_cases(split=args.split, limit=args.limit)
    print(f"Loaded {len(cases)} cases for split '{args.split}'.")

    produced_run_files: List[Path] = []
    start_total = time.time()

    for seed in args.seeds:
        for cfg in configs_to_run:
            run_file = run_single_config(cases=cases, config=cfg, seed=seed)
            produced_run_files.append(run_file)

    total_time = time.time() - start_total
    print("\n" + "=" * 80)
    print(f"ALL EXPERIMENTS COMPLETED in {total_time:.2f}s.")
    print("Generated run files:")
    for rf in produced_run_files:
        print(f"  - {rf}")
    print("=" * 80 + "\n")

    # Generate metrics and stats automatically
    try:
        from analysis.metrics import generate_metrics_report
        from analysis.stats import generate_comparative_stats_report

        print("Computing evaluation metrics and comparative hypothesis tests...")
        metrics_df = generate_metrics_report(split=args.split, configs=configs_to_run, seeds=args.seeds)
        generate_comparative_stats_report(split=args.split, configs=configs_to_run, seeds=args.seeds)
    except Exception as e:
        print(f"Note: automatic report generation encountered: {e}")


if __name__ == "__main__":
    main()

