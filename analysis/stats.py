"""
analysis/stats.py — Comparative Hypothesis Testing & Statistical Significance (Block 5 & 6a)

Performs rigorous statistical comparison across designated evaluation configurations on the DEV split:
1. Paired McNemar's exact test for targeted pairwise comparisons on compromised attacks.
2. Cluster bootstrap hypothesis testing clustered by (family, template) over 10,000 resamples.
3. Holm-Bonferroni family-wise error rate (FWER) correction across all hypothesis tests.
4. Effect size estimation: discordant odds ratios (b/c) and risk differences.
5. Per-family attack detection breakdown table.
6. Markdown report generation (analysis/results_<split>.md) and CSV exports.
"""

from __future__ import annotations

from collections import defaultdict
import csv
import json
import math
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Tuple, Union

ROOT_DIR = Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT_DIR / "runs"
ANALYSIS_DIR = ROOT_DIR / "analysis"

INTERCEPT_DECISIONS = {"block", "ask_human", "require_confirmation", "pause_task"}

TARGET_COMPARISONS = [
    ("dual_gate", "consistency_only"),
    ("dual_gate", "taxonomy_only"),
    ("dual_gate", "dual_gate_no_risk_engine"),
]


def is_intercepted(decision: str) -> bool:
    return str(decision).lower().strip() in INTERCEPT_DECISIONS


def mcnemar_exact_p_value(b: int, c: int) -> float:
    """Computes exact two-sided binomial p-value for discordant pairs (b, c)."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    total_p = 2.0 * sum(math.comb(n, i) for i in range(k + 1)) * (0.5 ** n)
    return min(1.0, total_p)


def compute_effect_size(b: int, c: int, total_n: int) -> Dict[str, Any]:
    """Computes discordant odds ratio (b/c) and risk difference delta."""
    if c == 0:
        odds_ratio = float("inf") if b > 0 else 1.0
    else:
        odds_ratio = round(b / c, 3)

    risk_diff_pct = round(((b - c) / total_n * 100.0) if total_n > 0 else 0.0, 2)
    return {
        "b": b,
        "c": c,
        "odds_ratio": odds_ratio,
        "risk_diff_pct": risk_diff_pct,
    }


def holm_bonferroni_correction(tests: List[Dict[str, Any]], alpha: float = 0.05) -> List[Dict[str, Any]]:
    """
    Applies Holm-Bonferroni step-down procedure to a list of hypothesis test dictionaries.
    """
    m = len(tests)
    if m == 0:
        return []

    indexed = sorted(enumerate(tests), key=lambda x: x[1]["p_value"])
    adjusted_results = [None] * m

    running_max = 0.0
    for rank, (orig_idx, test_item) in enumerate(indexed, 1):
        raw_p = test_item["p_value"]
        multiplier = m - rank + 1
        adj_p = min(1.0, raw_p * multiplier)
        adj_p = max(running_max, adj_p)
        running_max = adj_p

        alpha_thresh = alpha / multiplier
        is_sig = raw_p <= alpha_thresh

        res = dict(test_item)
        res["rank"] = rank
        res["p_raw"] = round(raw_p, 6)
        res["p_adj"] = round(adj_p, 6)
        res["alpha_threshold"] = round(alpha_thresh, 6)
        res["significant"] = is_sig
        adjusted_results[orig_idx] = res

    return adjusted_results


def run_pairwise_mcnemar_tests(
    config_runs: Dict[str, List[Dict[str, Any]]],
    target_pairs: Optional[List[Tuple[str, str]]] = None,
    alpha: float = 0.05,
) -> List[Dict[str, Any]]:
    """
    Executes paired McNemar exact tests for specified pairs of configurations
    evaluated on the identical set of compromised attack cases.
    """
    pairs = target_pairs or TARGET_COMPARISONS
    tests = []

    comp_by_config: Dict[str, Dict[str, bool]] = {}
    for cfg, recs in config_runs.items():
        comp_by_config[cfg] = {}
        for r in recs:
            if r.get("case_type") == "attack" and r.get("ground_truth_label") != "attack_uncompromised":
                comp_by_config[cfg][r["task_id"]] = is_intercepted(r.get("decision", ""))

    for cfg_a, cfg_b in pairs:
        key_a = next((k for k in comp_by_config if k == cfg_a or k.startswith(f"{cfg_a}_")), None)
        key_b = next((k for k in comp_by_config if k == cfg_b or k.startswith(f"{cfg_b}_")), None)

        if not key_a or not key_b:
            continue

        map1 = comp_by_config[key_a]
        map2 = comp_by_config[key_b]
        common_ids = sorted(set(map1.keys()) & set(map2.keys()))

        if not common_ids:
            continue

        # b = stopped by B, missed by A
        b = sum(1 for cid in common_ids if map2[cid] and not map1[cid])
        # c = stopped by A, missed by B
        c = sum(1 for cid in common_ids if map1[cid] and not map2[cid])
        both = sum(1 for cid in common_ids if map1[cid] and map2[cid])
        neither = sum(1 for cid in common_ids if not map1[cid] and not map2[cid])

        p_val = mcnemar_exact_p_value(b, c)
        eff = compute_effect_size(b, c, len(common_ids))

        tests.append({
            "config_a": key_a,
            "config_b": key_b,
            "n_common": len(common_ids),
            "both_stopped": both,
            "neither_stopped": neither,
            "gained_by_b (b)": b,
            "lost_by_b (c)": c,
            "odds_ratio": eff["odds_ratio"],
            "risk_diff_pct": eff["risk_diff_pct"],
            "p_value": p_val,
        })

    return holm_bonferroni_correction(tests, alpha=alpha)


def run_cluster_bootstrap(
    config_runs: Dict[str, List[Dict[str, Any]]],
    target_pairs: Optional[List[Tuple[str, str]]] = None,
    n_resamples: int = 10000,
    seed: int = 42,
) -> List[Dict[str, Any]]:
    """
    Performs cluster bootstrap hypothesis testing clustered by (family, template)
    over n_resamples (default 10,000) for target configuration comparisons.
    """
    pairs = target_pairs or TARGET_COMPARISONS
    clusters = defaultdict(list)
    comp_by_config: Dict[str, Dict[str, bool]] = {}

    for cfg, recs in config_runs.items():
        comp_by_config[cfg] = {}
        for r in recs:
            if r.get("case_type") == "attack" and r.get("ground_truth_label") != "attack_uncompromised":
                tid = r["task_id"]
                comp_by_config[cfg][tid] = is_intercepted(r.get("decision", ""))
                fam = r.get("family", "unknown")
                tmpl = tid.split("_")[-1]
                if tid not in clusters[(fam, tmpl)]:
                    clusters[(fam, tmpl)].append(tid)

    cluster_keys = sorted(clusters.keys())
    k_clusters = len(cluster_keys)
    if k_clusters == 0:
        return []

    rng = random.Random(seed)
    # Pre-sample cluster indices for consistent reproducibility across comparisons
    bootstrap_draws = [rng.choices(cluster_keys, k=k_clusters) for _ in range(n_resamples)]

    results = []
    for cfg_a, cfg_b in pairs:
        key_a = next((k for k in comp_by_config if k == cfg_a or k.startswith(f"{cfg_a}_")), None)
        key_b = next((k for k in comp_by_config if k == cfg_b or k.startswith(f"{cfg_b}_")), None)

        if not key_a or not key_b:
            continue

        map_a = comp_by_config[key_a]
        map_b = comp_by_config[key_b]

        all_tids = [tid for cl in cluster_keys for tid in clusters[cl]]
        tot = len(all_tids)
        det_a = sum(1 for tid in all_tids if map_a.get(tid, False))
        det_b = sum(1 for tid in all_tids if map_b.get(tid, False))
        rate_a = (det_a / tot * 100.0) if tot else 0.0
        rate_b = (det_b / tot * 100.0) if tot else 0.0
        obs_delta = rate_a - rate_b

        deltas = []
        for draw in bootstrap_draws:
            sampled_tids = [tid for cl in draw for tid in clusters[cl]]
            n_s = len(sampled_tids)
            d_a = sum(1 for tid in sampled_tids if map_a.get(tid, False))
            d_b = sum(1 for tid in sampled_tids if map_b.get(tid, False))
            deltas.append((d_a - d_b) / n_s * 100.0 if n_s else 0.0)

        deltas.sort()
        ci_low = deltas[int(0.025 * n_resamples)]
        ci_high = deltas[int(0.975 * n_resamples)]
        mean_delta = sum(deltas) / n_resamples

        # Two-sided empirical p-value testing H0: delta = 0
        p_val = 2.0 * min(sum(1 for d in deltas if d <= 0) / n_resamples, sum(1 for d in deltas if d >= 0) / n_resamples)
        p_val = min(1.0, max(p_val, 1.0 / n_resamples))

        results.append({
            "config_a": key_a,
            "config_b": key_b,
            "rate_a_pct": round(rate_a, 2),
            "rate_b_pct": round(rate_b, 2),
            "delta_obs_pct": round(obs_delta, 2),
            "delta_mean_pct": round(mean_delta, 2),
            "ci_low_pct": round(ci_low, 2),
            "ci_high_pct": round(ci_high, 2),
            "p_value_boot": round(p_val, 6),
            "n_clusters": k_clusters,
            "n_resamples": n_resamples,
        })

    return results


def compute_per_family_breakdown(
    config_runs: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """
    Computes per-family detection counts and rates for each configuration.
    """
    family_breakdown: Dict[str, Dict[str, Dict[str, Any]]] = {}

    for cfg, recs in config_runs.items():
        for r in recs:
            if r.get("case_type") == "attack" and r.get("ground_truth_label") != "attack_uncompromised":
                fam = r.get("family", "unknown")
                if fam not in family_breakdown:
                    family_breakdown[fam] = {}
                if cfg not in family_breakdown[fam]:
                    family_breakdown[fam][cfg] = {"detected": 0, "total": 0}

                family_breakdown[fam][cfg]["total"] += 1
                if is_intercepted(r.get("decision", "")):
                    family_breakdown[fam][cfg]["detected"] += 1

    for fam, cfgs in family_breakdown.items():
        for cfg, stats in cfgs.items():
            tot = stats["total"]
            det = stats["detected"]
            pct = (det / tot * 100.0) if tot else 0.0
            stats["rate"] = round(pct, 1)
            stats["formatted"] = f"{det}/{tot} ({pct:.1f}%)"

    return family_breakdown


def generate_comparative_stats_report(
    split: str = "dev",
    configs: Optional[List[str]] = None,
    seeds: Optional[List[int]] = None,
    runs_dir: Path = RUNS_DIR,
) -> None:
    """
    Loads run files, runs McNemar hypothesis tests and cluster bootstrap,
    computes per-family breakdowns, and exports Markdown and CSV artifacts.
    """
    seeds = seeds or [42]
    # Evaluate valid gateway configurations only (no_gateway removed)
    configs = configs or [
        "taxonomy_only",
        "consistency_only",
        "dual_gate",
        "dual_gate_no_risk_engine",
        "dual_gate_no_characterizer",
    ]

    expected_case_ids = set()
    for fpath in [ROOT_DIR / "attacks" / split / "cases.jsonl", ROOT_DIR / "benign" / split / "cases.jsonl"]:
        if fpath.is_file():
            with open(fpath, "r", encoding="utf-8") as fp:
                for line in fp:
                    if line.strip():
                        expected_case_ids.add(json.loads(line).get("case_id"))

    config_runs: Dict[str, List[Dict[str, Any]]] = {}
    for cfg in configs:
        for seed in seeds:
            rf = runs_dir / f"{cfg}_{seed}.jsonl"
            if rf.is_file():
                records = []
                with open(rf, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            records.append(json.loads(line))
                rec_ids = set(r.get("task_id") for r in records)
                if expected_case_ids and rec_ids != expected_case_ids:
                    print(f"[Stats] Excluding stale run '{rf.name}': case count ({len(records)}) or IDs do not match dataset v2 ({len(expected_case_ids)} cases).")
                    continue
                config_runs[cfg] = records

    if not config_runs:
        print("No run records found to analyze.")
        return

    valid_config_runs: Dict[str, List[Dict[str, Any]]] = {}
    invalid_configs: Dict[str, int] = {}
    for cfg, recs in config_runs.items():
        fb_cnt = sum(int(r.get("fallback_count", 0)) for r in recs)
        if fb_cnt > 0:
            invalid_configs[cfg] = fb_cnt
        else:
            valid_config_runs[cfg] = recs

    if invalid_configs:
        print(f"[Stats] Marked INVALID (fallback_count > 0, excluded from tables): {invalid_configs}")

    # 1. McNemar Tests (valid runs only)
    mcnemar_results = run_pairwise_mcnemar_tests(valid_config_runs)

    # 2. Cluster Bootstrap by (family, template) 10,000 resamples
    bootstrap_results = run_cluster_bootstrap(valid_config_runs, n_resamples=10000, seed=seeds[0])

    # 3. Per-Family Breakdown (valid runs only)
    family_breakdown = compute_per_family_breakdown(valid_config_runs)

    # 4. Export CSVs
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    mcnemar_csv = ANALYSIS_DIR / f"results_{split}_mcnemar.csv"
    with open(mcnemar_csv, "w", newline="", encoding="utf-8") as f:
        if mcnemar_results:
            writer = csv.DictWriter(f, fieldnames=list(mcnemar_results[0].keys()))
            writer.writeheader()
            writer.writerows(mcnemar_results)

    bootstrap_csv = ANALYSIS_DIR / f"results_{split}_bootstrap.csv"
    with open(bootstrap_csv, "w", newline="", encoding="utf-8") as f:
        if bootstrap_results:
            writer = csv.DictWriter(f, fieldnames=list(bootstrap_results[0].keys()))
            writer.writeheader()
            writer.writerows(bootstrap_results)

    family_csv = ANALYSIS_DIR / f"results_{split}_per_family.csv"
    cfgs_list = list(valid_config_runs.keys())
    with open(family_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["family"] + [f"{c}_detection" for c in cfgs_list])
        for fam in sorted(family_breakdown.keys()):
            row = [fam]
            for c in cfgs_list:
                row.append(family_breakdown[fam].get(c, {}).get("formatted", "N/A"))
            writer.writerow(row)

    # 5. Generate Markdown Report
    report_md = ANALYSIS_DIR / f"results_{split}.md"
    from analysis.metrics import compute_metrics_for_records

    with open(report_md, "w", encoding="utf-8") as f:
        f.write(f"# ContextGuard Multi-Configuration Comparative Analysis ({split.upper()} Split, Not Test)\n\n")
        f.write(f"Generated across valid configurations: `{', '.join(cfgs_list)}` (Seed: {seeds[0]})\n\n")

        if invalid_configs:
            f.write("### Excluded Configurations (Status: INVALID)\n\n")
            for icfg, ifb in invalid_configs.items():
                f.write(f"- **`{icfg}`**: Excluded from benchmark tables because `fallback_count = {ifb} > 0` (unsupported unverified fallback).\n")
            f.write("\n")

        f.write("## 1. Overall Performance Metrics Summary\n\n")
        f.write("Proportions reported with 95% Wilson score intervals; latencies reported with empirical bootstrap 95% CIs:\n\n")
        f.write("| Configuration | Compromised Attack Recall (Wilson 95% CI) | Uncompromised Over-Block Rate | Benign Normal False-Intercept | Benign Hard False-Intercept | Task Completion Proxy | Latency p50 | Latency p95 | LLM Calls |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")

        for cfg in cfgs_list:
            recs = valid_config_runs[cfg]
            m = compute_metrics_for_records(recs)
            comp_str = m["compromised_formatted"]
            uncomp_str = m["uncompromised_formatted"]
            norm_str = m["benign_normal_formatted"]
            hard_str = m["benign_hard_formatted"]
            comp_proxy = m["task_completion_formatted"]
            p50_str = f"{m['p50_latency_ms']} ms"
            p95_str = f"{m['p95_latency_ms']} ms"
            llm_str = f"{m['llm_calls_count']} ({m['llm_invocation_ratio']*100:.1f}%)" if m["llm_calls_count"] else "0 (0.0%)"
            f.write(f"| `{cfg}` | {comp_str} | {uncomp_str} | {norm_str} | {hard_str} | {comp_proxy} | {p50_str} | {p95_str} | {llm_str} |\n")

        f.write("\n## 2. Cluster Bootstrap Comparisons by (Family, Template) [10,000 Resamples]\n\n")
        f.write("Accounting for correlation within attack family and template clusters on the **DEV** split (seed 42):\n\n")
        f.write("| Comparison (A vs B) | Rate A | Rate B | Observed Diff (A - B) | Bootstrap Mean Diff | 95% Bootstrap CI | Cluster Boot p | Significant? |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")

        for bres in bootstrap_results:
            comp_str = f"`{bres['config_a']}` vs `{bres['config_b']}`"
            sig = "**YES** (p < 0.05)" if bres["p_value_boot"] < 0.05 else "No"
            f.write(
                f"| {comp_str} | {bres['rate_a_pct']:.1f}% | {bres['rate_b_pct']:.1f}% | "
                f"{bres['delta_obs_pct']:+.2f}% | {bres['delta_mean_pct']:+.2f}% | "
                f"[{bres['ci_low_pct']:+.2f}%, {bres['ci_high_pct']:+.2f}%] | "
                f"{bres['p_value_boot']:.4f} | {sig} |\n"
            )

        f.write("\n## 3. Pairwise Statistical Comparisons (Paired McNemar's Exact Test)\n\n")
        f.write("Evaluated over identical compromised attack DEV cases with Holm-Bonferroni FWER control ($\\alpha = 0.05$):\n\n")
        f.write("| Comparison (A vs B) | Common N | Both Stopped | Neither | Gained by B (+b) | Lost by B (-c) | Odds Ratio | Risk Diff | Raw p | Holm Adj p | Significant? |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")

        for test in mcnemar_results:
            comp_str = f"`{test['config_a']}` vs `{test['config_b']}`"
            sig_badge = "**YES**" if test["significant"] else "No"
            f.write(
                f"| {comp_str} | {test['n_common']} | {test['both_stopped']} | {test['neither_stopped']} | "
                f"+{test['gained_by_b (b)']} | -{test['lost_by_b (c)']} | {test['odds_ratio']} | "
                f"{test['risk_diff_pct']:+.1f}% | {test['p_raw']:.4e} | {test['p_adj']:.4e} | {sig_badge} |\n"
            )

        f.write("\n## 4. Detection Rate by Attack Family\n\n")
        headers = ["Attack Family"] + [f"`{c}`" for c in cfgs_list]
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("| " + " | ".join([":---"] + [":---:"] * len(cfgs_list)) + " |\n")

        for fam in sorted(family_breakdown.keys()):
            row = [f"`{fam}`"]
            for c in cfgs_list:
                row.append(family_breakdown[fam].get(c, {}).get("formatted", "N/A"))
            f.write("| " + " | ".join(row) + " |\n")

        f.write("\n")

    print(f"Statistical reports generated:")
    print(f"  - {report_md}")
    print(f"  - {mcnemar_csv}")
    print(f"  - {bootstrap_csv}")
    print(f"  - {family_csv}")


if __name__ == "__main__":
    generate_comparative_stats_report(split="dev")
