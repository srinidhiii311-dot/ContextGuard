# ContextGuard Multi-Configuration Comparative Analysis (DEV Split, Not Test)

Generated across valid configurations: `taxonomy_warn, taxonomy_block, taxonomy_only, consistency_only, dual_gate, dual_gate_no_characterizer, dual_gate_no_risk_engine, dual_gate_no_c1, dual_gate_no_c2, dual_gate_no_c3, dual_gate_no_c4` (Seed: 42)

## 1. Overall Performance Metrics Summary (DEV Split)

Proportions reported with 95% Wilson score intervals and cluster bootstrap 95% CIs (10,000 resamples by family, template):

| Configuration | ASR (Unsafe Executed) | Compromised Recall | Utility (Executed) | Uncompromised Over-Block | Benign Normal False-Intercept | Benign Hard False-Intercept | Latency p50 | Latency p95 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `taxonomy_warn` | 100.0%<br><sub>W:[98.2%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.8%]<br>B:[0.0%, 0.0%]</sub> | 100.0%<br><sub>W:[99.19%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 5.2%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 3.7%]<br>B:[0.0%, 0.0%]</sub> | 0.03 ms | 0.05 ms |
| `taxonomy_block` | 0.0%<br><sub>W:[0.0%, 1.8%]<br>B:[0.0%, 0.0%]</sub> | 100.0%<br><sub>W:[98.2%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 85.1%<br><sub>W:[81.6%, 88.04%]<br>B:[77.66%, 91.49%]</sub> | 100.0%<br><sub>W:[94.8%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 3.7%]<br>B:[0.0%, 0.0%]</sub> | 0.03 ms | 0.04 ms |
| `taxonomy_only` | 0.0%<br><sub>W:[0.0%, 1.8%]<br>B:[0.0%, 0.0%]</sub> | 100.0%<br><sub>W:[98.2%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 85.1%<br><sub>W:[81.6%, 88.04%]<br>B:[77.66%, 91.49%]</sub> | 100.0%<br><sub>W:[94.8%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 3.7%]<br>B:[0.0%, 0.0%]</sub> | 0.03 ms | 0.04 ms |
| `consistency_only` | 25.2%<br><sub>W:[19.84%, 31.52%]<br>B:[13.33%, 38.57%]</sub> | 74.8%<br><sub>W:[68.5%, 80.2%]<br>B:[61.43%, 86.67%]</sub> | 100.0%<br><sub>W:[99.19%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 5.2%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 3.7%]<br>B:[0.0%, 0.0%]</sub> | 0.04 ms | 0.09 ms |
| `dual_gate` (Canonical) | 7.1%<br><sub>W:[4.38%, 11.45%]<br>B:[0.0%, 16.67%]</sub> | 92.9%<br><sub>W:[88.5%, 95.6%]<br>B:[83.33%, 100.0%]</sub> | 100.0%<br><sub>W:[99.19%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 5.2%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 3.7%]<br>B:[0.0%, 0.0%]</sub> | 2.15 ms | 6.79 ms |
| `dual_gate_no_characterizer` | 7.1%<br><sub>W:[4.38%, 11.45%]<br>B:[0.0%, 16.67%]</sub> | 92.9%<br><sub>W:[88.5%, 95.6%]<br>B:[83.33%, 100.0%]</sub> | 100.0%<br><sub>W:[99.19%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 5.2%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 3.7%]<br>B:[0.0%, 0.0%]</sub> | 2.17 ms | 6.89 ms |
| `dual_gate_no_risk_engine` | 23.8%<br><sub>W:[18.55%, 30.01%]<br>B:[12.38%, 36.67%]</sub> | 76.2%<br><sub>W:[70.0%, 81.5%]<br>B:[63.33%, 87.62%]</sub> | 95.7%<br><sub>W:[93.52%, 97.23%]<br>B:[91.49%, 98.94%]</sub> | 0.0%<br><sub>W:[0.0%, 5.2%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 20.0%<br><sub>W:[13.3%, 28.9%]<br>B:[5.0%, 40.0%]</sub> | 0.05 ms | 0.09 ms |
| `dual_gate_no_c1` | 7.1%<br><sub>W:[4.38%, 11.45%]<br>B:[0.0%, 16.67%]</sub> | 92.9%<br><sub>W:[88.5%, 95.6%]<br>B:[83.33%, 100.0%]</sub> | 100.0%<br><sub>W:[99.19%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 5.2%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 3.7%]<br>B:[0.0%, 0.0%]</sub> | 2.16 ms | 6.80 ms |
| `dual_gate_no_c2` | 7.1%<br><sub>W:[4.38%, 11.45%]<br>B:[0.0%, 16.67%]</sub> | 92.9%<br><sub>W:[88.5%, 95.6%]<br>B:[83.33%, 100.0%]</sub> | 100.0%<br><sub>W:[99.19%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 5.2%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 3.7%]<br>B:[0.0%, 0.0%]</sub> | 2.15 ms | 6.82 ms |
| `dual_gate_no_c3` | 23.8%<br><sub>W:[18.55%, 30.01%]<br>B:[12.38%, 36.67%]</sub> | 76.2%<br><sub>W:[70.0%, 81.5%]<br>B:[63.33%, 87.62%]</sub> | 100.0%<br><sub>W:[99.19%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 5.2%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 0.0%<br><sub>W:[0.0%, 3.7%]<br>B:[0.0%, 0.0%]</sub> | 2.14 ms | 6.78 ms |
| `dual_gate_no_c4` | 0.0%<br><sub>W:[0.0%, 1.8%]<br>B:[0.0%, 0.0%]</sub> | 100.0%<br><sub>W:[98.2%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 80.9%<br><sub>W:[77.06%, 84.15%]<br>B:[73.40%, 87.23%]</sub> | 100.0%<br><sub>W:[94.8%, 100.0%]<br>B:[100.0%, 100.0%]</sub> | 0.0%<br><sub>W:[0.0%, 1.3%]<br>B:[0.0%, 0.0%]</sub> | 20.0%<br><sub>W:[13.3%, 28.9%]<br>B:[5.0%, 40.0%]</sub> | 2.15 ms | 6.81 ms |

## 2. Multi-Step Attack Detection (Episode-Level & Step-Level)

Evaluated over multi_step_instruction attacks across 5 domains (40 total cases: 30 compromised steps, 10 uncompromised steps):

| Configuration | Episode Detection (With Prep) | Step Detection (With Prep) | Episode Detection (Without Prep) | Step Detection (Without Prep) |
| :--- | :---: | :---: | :---: | :---: |
| `taxonomy_warn` | 0/5 (0.0%) | 0/30 (0.0%) | 0/5 (0.0%) | 0/15 (0.0%) |
| `taxonomy_block` | 5/5 (100.0%) | 30/30 (100.0%) | 5/5 (100.0%) | 15/15 (100.0%) |
| `taxonomy_only` | 5/5 (100.0%) | 30/30 (100.0%) | 5/5 (100.0%) | 15/15 (100.0%) |
| `consistency_only` | 5/5 (100.0%) | 5/30 (16.7%) | 5/5 (100.0%) | 5/15 (33.3%) |
| `dual_gate` | 5/5 (100.0%) | 15/30 (50.0%) | 5/5 (100.0%) | 15/15 (100.0%) |
| `dual_gate_no_characterizer` | 5/5 (100.0%) | 15/30 (50.0%) | 5/5 (100.0%) | 15/15 (100.0%) |
| `dual_gate_no_risk_engine` | 5/5 (100.0%) | 6/30 (20.0%) | 5/5 (100.0%) | 6/15 (40.0%) |

## 3. Benign False Intercepts by Template Cluster

Breakdown of benign false intercepts across configurations and template clusters (450 total benign cases: 400 normal + 50 hard):

| Configuration | Cluster | Family | Template | Affected Domains | Intercepted / Total | False-Intercept Rate | Decision Breakdown |
| :--- | :--- | :--- | :---: | :--- | :---: | :---: | :--- |
| `taxonomy_warn` | *(none)* | *(none)* | — | — | 0/450 | 0.0% | 0 Block, 0 Confirm |
| `taxonomy_block` | *(none)* | *(none)* | — | — | 0/450 | 0.0% | 0 Block, 0 Confirm |
| `taxonomy_only` | *(none)* | *(none)* | — | — | 0/450 | 0.0% | 0 Block, 0 Confirm |
| `consistency_only` | *(none)* | *(none)* | — | — | 0/450 | 0.0% | 0 Block, 0 Confirm |
| `dual_gate` | *(none)* | *(none)* | — | — | 0/450 | 0.0% | 0 Block, 0 Confirm |
| `dual_gate_no_characterizer` | *(none)* | *(none)* | — | — | 0/450 | 0.0% | 0 Block, 0 Confirm |
| `dual_gate_no_risk_engine` | `benign_hard_v61` | `benign_hard` | `v61` | banking, ecommerce, email, flight, healthcare | 5/5 | 100.0% | 5 Block, 0 Confirm |
| `dual_gate_no_risk_engine` | `benign_hard_v66` | `benign_hard` | `v66` | banking, ecommerce, email, flight, healthcare | 5/5 | 100.0% | 5 Block, 0 Confirm |
| `dual_gate_no_risk_engine` | `benign_hard_v71` | `benign_hard` | `v71` | banking, ecommerce, email, flight, healthcare | 5/5 | 100.0% | 5 Block, 0 Confirm |
| `dual_gate_no_risk_engine` | `benign_hard_v76` | `benign_hard` | `v76` | banking, ecommerce, email, flight, healthcare | 5/5 | 100.0% | 5 Block, 0 Confirm |

## 4. Cluster Bootstrap Comparisons by (Family, Template) [10,000 Resamples]

Accounting for correlation within attack family and template clusters on the **DEV** split (seed 42):

| Comparison (A vs B) | Metric | Rate A | Rate B | Observed Diff (A - B) | Bootstrap Mean Diff | 95% Bootstrap CI | Cluster Boot p | Significant? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `dual_gate` vs `consistency_only` | Attack Recall | 92.9% | 74.8% | +18.10% | +18.18% | [+7.14%, +30.00%] | 0.0012 | **YES** (p < 0.05) |
| `dual_gate` vs `taxonomy_only` | Attack Recall | 92.9% | 100.0% | -7.14% | -7.16% | [-16.67%, +0.00%] | 0.0866 | No |
| `dual_gate` vs `dual_gate_no_risk_engine` | Attack Recall | 92.9% | 76.2% | +16.67% | +16.75% | [+6.67%, +27.62%] | 0.0012 | **YES** (p < 0.05) |
| `dual_gate` vs `dual_gate_no_c3` | Attack Recall | 92.9% | 76.2% | +16.67% | +16.75% | [+6.67%, +27.62%] | 0.0012 | **YES** (p < 0.05) |
| `dual_gate` vs `dual_gate_no_c4` | Attack Recall | 92.9% | 100.0% | -7.14% | -7.16% | [-16.67%, +0.00%] | 0.0866 | No |
| `dual_gate` vs `taxonomy_block` | Utility (Executed) | 100.0% | 85.1% | +14.89% | +14.86% | [+8.51%, +22.34%] | 0.0001 | **YES** (p < 0.05) |
| `dual_gate` vs `dual_gate_no_c4` | Utility (Executed) | 100.0% | 80.9% | +19.15% | +19.15% | [+11.70%, +27.66%] | 0.0001 | **YES** (p < 0.05) |

## 5. Pairwise Statistical Comparisons (Paired McNemar's Exact Test)

Evaluated over identical compromised attack DEV cases with Holm-Bonferroni FWER control ($\alpha = 0.05$):

| Comparison (A vs B) | Common N | Both Stopped | Neither | Gained by B (+b) | Lost by B (-c) | Odds Ratio | Risk Diff | Raw p | Holm Adj p | Significant? |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `dual_gate` vs `consistency_only` | 210 | 157 | 15 | +0 | -38 | 0.0 | -18.1% | < 1e-15 | < 1e-15 | **YES** |
| `dual_gate` vs `taxonomy_only` | 210 | 195 | 0 | +15 | -0 | inf | +7.1% | 6.1000e-05 | 6.1000e-05 | **YES** |
| `dual_gate` vs `dual_gate_no_risk_engine` | 210 | 160 | 15 | +0 | -35 | 0.0 | -16.7% | < 1e-15 | < 1e-15 | **YES** |

## 6. Detection Rate by Attack Family

| Attack Family | `taxonomy_warn` | `taxonomy_block` | `taxonomy_only` | `consistency_only` | `dual_gate` | `dual_gate_no_characterizer` | `dual_gate_no_risk_engine` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `credential_phishing_field` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 2/30 (6.7%) | 30/30 (100.0%) | 30/30 (100.0%) | 4/30 (13.3%) |
| `fake_system_banner` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| `html_comment` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| `multi_step_instruction` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 5/30 (16.7%) | 15/30 (50.0%) | 15/30 (50.0%) | 6/30 (20.0%) |
| `off_screen_text` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| `url_obfuscation` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| `user_generated_content` | 0/30 (0.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
