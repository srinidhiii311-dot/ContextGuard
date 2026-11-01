# ContextGuard Multi-Configuration Evaluation Report (DEV Split)

Generated across valid configurations: `no_gateway, taxonomy_only, consistency_only, dual_gate` (Seed: 42)

## 1. Overall Performance Metrics Summary

Proportions reported with 95% Wilson score intervals; latencies reported with empirical bootstrap 95% CIs:

| Configuration | Compromised Attack Recall (Wilson 95% CI) | Uncompromised Over-Block Rate | Benign Normal False-Intercept | Benign Hard False-Intercept | Task Completion Proxy | Latency p50 | Latency p95 | LLM Calls |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `no_gateway` | 0/210 (0.0% [0.0%, 1.8%]) | 0/70 (0.0% [0.0%, 5.2%]) | 0/300 (0.0% [0.0%, 1.3%]) | 0/100 (0.0% [0.0%, 3.7%]) | 400/400 (100.0% [99.0%, 100.0%]) | 0.0 ms | 0.0 ms | 0 (0.0%) |
| `taxonomy_only` | 210/210 (100.0% [98.2%, 100.0%]) | 70/70 (100.0% [94.8%, 100.0%]) | 0/300 (0.0% [0.0%, 1.3%]) | 0/100 (0.0% [0.0%, 3.7%]) | 400/400 (100.0% [99.0%, 100.0%]) | 0.08 ms | 0.18 ms | 0 (0.0%) |
| `consistency_only` | 142/210 (67.6% [61.0%, 73.6%]) | 0/70 (0.0% [0.0%, 5.2%]) | 0/300 (0.0% [0.0%, 1.3%]) | 0/100 (0.0% [0.0%, 3.7%]) | 400/400 (100.0% [99.0%, 100.0%]) | 0.09 ms | 0.22 ms | 0 (0.0%) |
| `dual_gate` | 180/210 (85.7% [80.3%, 89.8%]) | 0/70 (0.0% [0.0%, 5.2%]) | 10/300 (3.3% [1.8%, 6.0%]) | 3/100 (3.0% [1.0%, 8.5%]) | 387/400 (96.8% [94.5%, 98.1%]) | 122.24 ms | 280.86 ms | 0 (0.0%) |

## 2. Pairwise Statistical Comparisons (Paired McNemar's Exact Test)

Evaluated over identical compromised attack test cases with Holm-Bonferroni FWER control ($\alpha = 0.05$):

| Comparison (A vs B) | Common N | Both Stopped | Neither | Gained by B (+b) | Lost by B (-c) | Odds Ratio | Risk Diff | Raw p | Holm Adj p | Significant? |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `no_gateway` vs `taxonomy_only` | 210 | 0 | 0 | +210 | -0 | inf | +100.0% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `no_gateway` vs `consistency_only` | 210 | 0 | 68 | +142 | -0 | inf | +67.6% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `no_gateway` vs `dual_gate` | 210 | 0 | 30 | +180 | -0 | inf | +85.7% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `taxonomy_only` vs `consistency_only` | 210 | 142 | 0 | +0 | -68 | 0.0 | -32.4% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `taxonomy_only` vs `dual_gate` | 210 | 180 | 0 | +0 | -30 | 0.0 | -14.3% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `consistency_only` vs `dual_gate` | 210 | 142 | 30 | +38 | -0 | inf | +18.1% | 0.0000e+00 | 0.0000e+00 | **YES** |

## 3. Detection Rate by Attack Family

| Attack Family | `no_gateway` | `taxonomy_only` | `consistency_only` | `dual_gate` |
| :--- | :---: | :---: | :---: | :---: |
| `credential_phishing_field` | 0/30 (0.0%) | 30/30 (100.0%) | 2/30 (6.7%) | 30/30 (100.0%) |
| `fake_system_banner` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| `html_comment` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| `multi_step_instruction` | 0/30 (0.0%) | 30/30 (100.0%) | 5/30 (16.7%) | 15/30 (50.0%) |
| `off_screen_text` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| `url_obfuscation` | 0/30 (0.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 15/30 (50.0%) |
| `user_generated_content` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |

