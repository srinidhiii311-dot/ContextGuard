# ContextGuard Multi-Configuration Comparative Analysis (DEV Split, Not Test)

Generated across valid configurations: `taxonomy_only, consistency_only, dual_gate, dual_gate_no_risk_engine, dual_gate_no_characterizer` (Seed: 42)

## 1. Overall Performance Metrics Summary

Proportions reported with 95% Wilson score intervals; latencies reported with empirical bootstrap 95% CIs:

| Configuration | Compromised Attack Recall (Wilson 95% CI) | Uncompromised Over-Block Rate | Benign Normal False-Intercept | Benign Hard False-Intercept | Task Completion Proxy | Latency p50 | Latency p95 | LLM Calls |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `taxonomy_only` | 210/210 (100.0% [98.2%, 100.0%]) | 70/70 (100.0% [94.8%, 100.0%]) | 0/300 (0.0% [0.0%, 1.3%]) | 0/100 (0.0% [0.0%, 3.7%]) | 400/400 (100.0% [99.0%, 100.0%]) | 0.08 ms | 0.18 ms | 0 (0.0%) |
| `consistency_only` | 142/210 (67.6% [61.0%, 73.6%]) | 0/70 (0.0% [0.0%, 5.2%]) | 0/300 (0.0% [0.0%, 1.3%]) | 0/100 (0.0% [0.0%, 3.7%]) | 400/400 (100.0% [99.0%, 100.0%]) | 0.09 ms | 0.22 ms | 0 (0.0%) |
| `dual_gate` | 195/210 (92.9% [88.6%, 95.6%]) | 0/70 (0.0% [0.0%, 5.2%]) | 10/300 (3.3% [1.8%, 6.0%]) | 3/100 (3.0% [1.0%, 8.5%]) | 387/400 (96.8% [94.5%, 98.1%]) | 103.87 ms | 141.77 ms | 0 (0.0%) |
| `dual_gate_no_risk_engine` | 145/210 (69.0% [62.5%, 74.9%]) | 0/70 (0.0% [0.0%, 5.2%]) | 10/300 (3.3% [1.8%, 6.0%]) | 22/100 (22.0% [15.0%, 31.1%]) | 368/400 (92.0% [88.9%, 94.3%]) | 0.05 ms | 0.14 ms | 0 (0.0%) |
| `dual_gate_no_characterizer` | 180/210 (85.7% [80.3%, 89.8%]) | 0/70 (0.0% [0.0%, 5.2%]) | 10/300 (3.3% [1.8%, 6.0%]) | 3/100 (3.0% [1.0%, 8.5%]) | 387/400 (96.8% [94.5%, 98.1%]) | 112.01 ms | 144.15 ms | 0 (0.0%) |

## 2. Cluster Bootstrap Comparisons by (Family, Template) [10,000 Resamples]

Accounting for correlation within attack family and template clusters on the **DEV** split (seed 42):

| Comparison (A vs B) | Rate A | Rate B | Observed Diff (A - B) | Bootstrap Mean Diff | 95% Bootstrap CI | Cluster Boot p | Significant? |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `dual_gate` vs `consistency_only` | 92.9% | 67.6% | +25.24% | +25.31% | [+13.33%, +38.57%] | 0.0002 | **YES** (p < 0.05) |
| `dual_gate` vs `taxonomy_only` | 92.9% | 100.0% | -7.14% | -7.16% | [-16.67%, +0.00%] | 0.0866 | No |
| `dual_gate` vs `dual_gate_no_risk_engine` | 92.9% | 69.0% | +23.81% | +23.87% | [+12.38%, +36.67%] | 0.0002 | **YES** (p < 0.05) |

## 3. Pairwise Statistical Comparisons (Paired McNemar's Exact Test)

Evaluated over identical compromised attack DEV cases with Holm-Bonferroni FWER control ($\alpha = 0.05$):

| Comparison (A vs B) | Common N | Both Stopped | Neither | Gained by B (+b) | Lost by B (-c) | Odds Ratio | Risk Diff | Raw p | Holm Adj p | Significant? |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `dual_gate` vs `consistency_only` | 210 | 142 | 15 | +0 | -53 | 0.0 | -25.2% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `dual_gate` vs `taxonomy_only` | 210 | 195 | 0 | +15 | -0 | inf | +7.1% | 6.1000e-05 | 6.1000e-05 | **YES** |
| `dual_gate` vs `dual_gate_no_risk_engine` | 210 | 145 | 15 | +0 | -50 | 0.0 | -23.8% | 0.0000e+00 | 0.0000e+00 | **YES** |

## 4. Detection Rate by Attack Family

| Attack Family | `taxonomy_only` | `consistency_only` | `dual_gate` | `dual_gate_no_risk_engine` | `dual_gate_no_characterizer` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `credential_phishing_field` | 30/30 (100.0%) | 2/30 (6.7%) | 30/30 (100.0%) | 4/30 (13.3%) | 30/30 (100.0%) |
| `fake_system_banner` | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| `html_comment` | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| `multi_step_instruction` | 30/30 (100.0%) | 5/30 (16.7%) | 15/30 (50.0%) | 6/30 (20.0%) | 15/30 (50.0%) |
| `off_screen_text` | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| `url_obfuscation` | 30/30 (100.0%) | 15/30 (50.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 15/30 (50.0%) |
| `user_generated_content` | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |

