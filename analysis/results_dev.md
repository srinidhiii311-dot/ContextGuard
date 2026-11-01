# ContextGuard Multi-Configuration Evaluation Report (DEV Split)

Generated across configurations: `no_gateway, taxonomy_only, consistency_only, dual_gate, dual_gate_llm` (Seed: 42)

## 1. Overall Performance Metrics Summary

Proportions reported with 95% Wilson score intervals; latencies reported with empirical bootstrap 95% CIs:

| Configuration | Compromised Attack Recall (Wilson 95% CI) | Uncompromised Over-Block Rate | Benign Normal False-Intercept | Benign Hard False-Intercept | Task Completion Proxy | Latency p50 | Latency p95 | LLM Calls |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `no_gateway` | 0/210 (0.0% [0.0%, 1.8%]) | 0/14 (0.0% [0.0%, 21.5%]) | 0/240 (0.0% [0.0%, 1.6%]) | 0/80 (0.0% [0.0%, 4.6%]) | 320/320 (100.0% [98.8%, 100.0%]) | 0.0 ms | 0.0 ms | 0 (0.0%) |
| `taxonomy_only` | 210/210 (100.0% [98.2%, 100.0%]) | 14/14 (100.0% [78.5%, 100.0%]) | 0/240 (0.0% [0.0%, 1.6%]) | 0/80 (0.0% [0.0%, 4.6%]) | 320/320 (100.0% [98.8%, 100.0%]) | 0.04 ms | 0.07 ms | 0 (0.0%) |
| `consistency_only` | 105/210 (50.0% [43.3%, 56.7%]) | 0/14 (0.0% [0.0%, 21.5%]) | 0/240 (0.0% [0.0%, 1.6%]) | 0/80 (0.0% [0.0%, 4.6%]) | 320/320 (100.0% [98.8%, 100.0%]) | 0.04 ms | 0.09 ms | 0 (0.0%) |
| `dual_gate` | 134/210 (63.8% [57.1%, 70.0%]) | 0/14 (0.0% [0.0%, 21.5%]) | 0/240 (0.0% [0.0%, 1.6%]) | 20/80 (25.0% [16.8%, 35.5%]) | 300/320 (93.8% [90.5%, 95.9%]) | 72.99 ms | 100.19 ms | 0 (0.0%) |
| `dual_gate_llm` | 134/210 (63.8% [57.1%, 70.0%]) | 0/14 (0.0% [0.0%, 21.5%]) | 0/240 (0.0% [0.0%, 1.6%]) | 20/80 (25.0% [16.8%, 35.5%]) | 300/320 (93.8% [90.5%, 95.9%]) | 72.17 ms | 116.86 ms | 95 (17.5%) |

## 2. Pairwise Statistical Comparisons (Paired McNemar's Exact Test)

Evaluated over identical compromised attack test cases with Holm-Bonferroni FWER control ($\alpha = 0.05$):

| Comparison (A vs B) | Common N | Both Stopped | Neither | Gained by B (+b) | Lost by B (-c) | Odds Ratio | Risk Diff | Raw p | Holm Adj p | Significant? |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `no_gateway` vs `taxonomy_only` | 210 | 0 | 0 | +210 | -0 | inf | +100.0% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `no_gateway` vs `consistency_only` | 210 | 0 | 105 | +105 | -0 | inf | +50.0% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `no_gateway` vs `dual_gate` | 210 | 0 | 76 | +134 | -0 | inf | +63.8% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `no_gateway` vs `dual_gate_llm` | 210 | 0 | 76 | +134 | -0 | inf | +63.8% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `taxonomy_only` vs `consistency_only` | 210 | 105 | 0 | +0 | -105 | 0.0 | -50.0% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `taxonomy_only` vs `dual_gate` | 210 | 134 | 0 | +0 | -76 | 0.0 | -36.2% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `taxonomy_only` vs `dual_gate_llm` | 210 | 134 | 0 | +0 | -76 | 0.0 | -36.2% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `consistency_only` vs `dual_gate` | 210 | 105 | 76 | +29 | -0 | inf | +13.8% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `consistency_only` vs `dual_gate_llm` | 210 | 105 | 76 | +29 | -0 | inf | +13.8% | 0.0000e+00 | 0.0000e+00 | **YES** |
| `dual_gate` vs `dual_gate_llm` | 210 | 134 | 76 | +0 | -0 | 1.0 | +0.0% | 1.0000e+00 | 1.0000e+00 | No |

## 3. Detection Rate by Attack Family

| Attack Family | `no_gateway` | `taxonomy_only` | `consistency_only` | `dual_gate` | `dual_gate_llm` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `credential_phishing_field` | 0/30 (0.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 19/30 (63.3%) | 19/30 (63.3%) |
| `fake_system_banner` | 0/30 (0.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 19/30 (63.3%) | 19/30 (63.3%) |
| `html_comment` | 0/30 (0.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 19/30 (63.3%) | 19/30 (63.3%) |
| `multi_step_instruction` | 0/30 (0.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 19/30 (63.3%) | 19/30 (63.3%) |
| `off_screen_text` | 0/30 (0.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 19/30 (63.3%) | 19/30 (63.3%) |
| `url_obfuscation` | 0/30 (0.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 20/30 (66.7%) | 20/30 (66.7%) |
| `user_generated_content` | 0/30 (0.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 19/30 (63.3%) | 19/30 (63.3%) |

