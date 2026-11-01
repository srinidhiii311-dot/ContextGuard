import json
import math
from pathlib import Path
from collections import defaultdict

def wilson_ci(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1.0 + (z**2) / n
    center = (p + (z**2) / (2 * n)) / denom
    margin = (z * math.sqrt((p * (1 - p) + (z**2) / (4 * n)) / n)) / denom
    return max(0.0, center - margin) * 100, min(1.0, center + margin) * 100

def format_table_for_seed(v2_json_path, v3_json_path, label):
    with open(v2_json_path, "r", encoding="utf-8") as f:
        d2 = json.load(f)
    with open(v3_json_path, "r", encoding="utf-8") as f:
        d3 = json.load(f)

    commit_v2 = d2.get("commit_hash", "")[:7]
    commit_v3 = d3.get("commit_hash", "")[:7]

    print("\n" + "=" * 110)
    print(f"ADAPTIVE ATTACK BENCHMARK: {label.upper()} (Seed={d2.get('seed')})")
    print(f"Gate Versions: gate-frozen-v2-perf ({commit_v2}) vs. gate-frozen-v3 ({commit_v3})")
    print("=" * 110)
    print(f"{'Strategy':<6} | {'Domain':<11} | {'Templates':<9} | {'v2-perf (Oracle v1)':<20} | {'v2-perf (Oracle v2)':<20} | {'v2-perf (Oracle v3)':<20} | {'v3 (Oracle v3)':<18}")
    print("-" * 110)

    stats2 = d2["stats_by_strategy_domain"]
    stats3 = d3["stats_by_strategy_domain"]

    for strat in sorted(stats2.keys()):
        for dom in ["flight", "banking", "ecommerce", "healthcare", "email"]:
            s2 = stats2[strat][dom]
            s3 = stats3[strat][dom]

            ntmpl = s2["distinct_templates_count"]

            # v2 under v1
            u_v2_1 = s2["v1"]["unsafe"]
            e_v2_1 = s2["v1"]["evaded"]
            r_v2_1 = (e_v2_1 / u_v2_1 * 100) if u_v2_1 > 0 else 0.0
            str_v2_1 = f"{e_v2_1}/{u_v2_1} ({r_v2_1:.1f}%)"

            # v2 under v2
            u_v2_2 = s2["v2"]["unsafe"]
            e_v2_2 = s2["v2"]["evaded"]
            r_v2_2 = (e_v2_2 / u_v2_2 * 100) if u_v2_2 > 0 else 0.0
            str_v2_2 = f"{e_v2_2}/{u_v2_2} ({r_v2_2:.1f}%)"

            # v2 under v3
            u_v2_3 = s2["v3"]["unsafe"]
            e_v2_3 = s2["v3"]["evaded"]
            r_v2_3 = (e_v2_3 / u_v2_3 * 100) if u_v2_3 > 0 else 0.0
            str_v2_3 = f"{e_v2_3}/{u_v2_3} ({r_v2_3:.1f}%)"

            # v3 under v3
            u_v3_3 = s3["v3"]["unsafe"]
            e_v3_3 = s3["v3"]["evaded"]
            r_v3_3 = (e_v3_3 / u_v3_3 * 100) if u_v3_3 > 0 else 0.0
            str_v3_3 = f"{e_v3_3}/{u_v3_3} ({r_v3_3:.1f}%)"

            print(f"{strat:<6} | {dom:<11} | {ntmpl:<9} | {str_v2_1:<20} | {str_v2_2:<20} | {str_v2_3:<20} | {str_v3_3:<18}")

        # Strategy summary (not pooled total across strategies, but per strategy)
        tot_u2_1 = sum(stats2[strat][d]["v1"]["unsafe"] for d in stats2[strat])
        tot_e2_1 = sum(stats2[strat][d]["v1"]["evaded"] for d in stats2[strat])
        tot_u2_2 = sum(stats2[strat][d]["v2"]["unsafe"] for d in stats2[strat])
        tot_e2_2 = sum(stats2[strat][d]["v2"]["evaded"] for d in stats2[strat])
        tot_u2_3 = sum(stats2[strat][d]["v3"]["unsafe"] for d in stats2[strat])
        tot_e2_3 = sum(stats2[strat][d]["v3"]["evaded"] for d in stats2[strat])
        tot_u3_3 = sum(stats3[strat][d]["v3"]["unsafe"] for d in stats3[strat])
        tot_e3_3 = sum(stats3[strat][d]["v3"]["evaded"] for d in stats3[strat])

        sum_tmpls = sum(stats2[strat][d]["distinct_templates_count"] for d in stats2[strat])
        r1 = (tot_e2_1 / tot_u2_1 * 100) if tot_u2_1 else 0
        r2 = (tot_e2_2 / tot_u2_2 * 100) if tot_u2_2 else 0
        r3 = (tot_e2_3 / tot_u2_3 * 100) if tot_u2_3 else 0
        rv3 = (tot_e3_3 / tot_u3_3 * 100) if tot_u3_3 else 0

        print(f"SUBTOTAL {strat:<4} | {'ALL DOMAINS':<11} | {sum_tmpls:<9} | {tot_e2_1}/{tot_u2_1} ({r1:.1f}%)     | {tot_e2_2}/{tot_u2_2} ({r2:.1f}%)     | {tot_e2_3}/{tot_u2_3} ({r3:.1f}%)     | {tot_e3_3}/{tot_u3_3} ({rv3:.1f}%)")
        print("-" * 110)

if __name__ == "__main__":
    format_table_for_seed("runs/eval_v2perf_seed42.json", "runs/eval_v3_seed42.json", "Tuned-On Seeds (seed=42)")
    format_table_for_seed("runs/eval_v2perf_seed9999.json", "runs/eval_v3_seed9999.json", "Fresh Seeds (seed=9999)")
