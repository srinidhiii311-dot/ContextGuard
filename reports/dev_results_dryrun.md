# ContextGuard Holdout Test Evaluation Report (DEV Split)

**Generated:** `2026-11-11 05:46:16 UTC`  
**Execution Mode:** `DRY RUN (Dev Tuning)`  
**Target Split:** `dev` (Total Cases: 680; Compromised: 210, Uncompromised: 70, Benign: 400)  
**Evaluation Seed:** `42`  
**Configurations Evaluated:** 17 (9 Core Systems/Baselines + 8 Component Ablations)  

---

## 1. Executive Summary & Pre-Registered Hypotheses

> [!NOTE]
> This report was automatically compiled by `analysis/test_report.py` in strict compliance with `reports/test_protocol.md`. 
> All statistical inferences, confidence intervals, and hypothesis tests were pre-registered prior to evaluation.

### Primary Hypothesis 1: False-Positive Suppression on Uncompromised Pages
- **Comparison**: ContextGuard Gate (`dual_gate`) vs. Static Keyword Baseline (`taxonomy_block`) on uncompromised attack pages ($N = 70$).
- **Observed Over-block**: `taxonomy_block` = **70/70 (100.0%)** vs. `dual_gate` = **0/70 (0.0%)**.
- **Estimated Reduction ($\Delta_{\text{overblock}}$)**: **+100.00%**
- **Primary Statistical Inference (10,000 Cluster-Bootstrap)**: **95% CI [100.0%, 100.0%]** ($p = 0.0001$).
- **Primary Hypothesis Test Result**: **PASSED (CI strictly excludes 0)**.
- **Secondary Inference (McNemar Exact)**: Discordant pairs ($b=70, c=0$), two-sided **$p = 1.6941e-21$**.

### Primary Hypothesis 2: Intent Boundary Superiority over Parameter Rails
- **Comparison**: ContextGuard Gate (`dual_gate`) vs. Parameter Rails (`consistency_only`) on compromised attacks ($N = 210$).
- **Observed Recall**: `dual_gate` = **195/210 (92.9%)** vs. `consistency_only` = **157/210 (74.8%)**.
- **Estimated Recall Gain ($\Delta_{\text{recall}}$)**: **+18.18%**
- **Primary Statistical Inference (10,000 Cluster-Bootstrap)**: **95% CI [7.14%, 30.0%]** ($p = 0.0012$).
- **Primary Hypothesis Test Result**: **PASSED (CI strictly excludes 0)**.
- **Secondary Inference (McNemar Exact)**: Discordant pairs ($b=38, c=0$), two-sided **$p = 7.2760e-12$**.

---

## 2. Standardized Performance Across All 17 Configurations

| Configuration | Compromised Attack Recall | Uncompromised Over-block | Benign Task Utility | Hard Benign FP Rate |
| :--- | :---: | :---: | :---: | :---: |
| **Passthrough (B0)** | **0/210 (0.0%)**<br><sub>[0.0%, 1.8%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Taxonomy Block (B1-Block)** | **210/210 (100.0%)**<br><sub>[98.2%, 100.0%]</sub> | 70/70 (100.0%)<br><sub>[94.8%, 100.0%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Taxonomy Warn (B1-Warn)** | **0/210 (0.0%)**<br><sub>[0.0%, 1.8%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Parameter Rails (B2)** | **157/210 (74.8%)**<br><sub>[68.5%, 80.2%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Regex-Only Filter (Baseline)** | **210/210 (100.0%)**<br><sub>[98.2%, 100.0%]</sub> | 70/70 (100.0%)<br><sub>[94.8%, 100.0%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Tool-Allowlist (Baseline)** | **92/210 (43.8%)**<br><sub>[37.3%, 50.6%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 374/400 (93.5%)<br><sub>[90.6%, 95.5%]</sub> | 6/100 (6.0%)<br><sub>[2.8%, 12.5%]</sub> |
| **ContextGuard Gate (Config D, Canonical)** | **195/210 (92.9%)**<br><sub>[88.6%, 95.6%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Ablation: No Characterizer** | **195/210 (92.9%)**<br><sub>[88.6%, 95.6%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Ablation: No Risk Engine** | **160/210 (76.2%)**<br><sub>[70.0%, 81.4%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 380/400 (95.0%)<br><sub>[92.4%, 96.7%]</sub> | 20/100 (20.0%)<br><sub>[13.3%, 28.9%]</sub> |
| **Ablation: No C1 (raw HTML scan)** | **195/210 (92.9%)**<br><sub>[88.6%, 95.6%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Ablation: No C2 (SUBMIT destination check)** | **195/210 (92.9%)**<br><sub>[88.6%, 95.6%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Ablation: No C3 (fail-closed unknown field)** | **160/210 (76.2%)**<br><sub>[70.0%, 81.4%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Ablation: No C4 (marker-only cap to ALLOW_WITH_FLAG)** | **210/210 (100.0%)**<br><sub>[98.2%, 100.0%]</sub> | 70/70 (100.0%)<br><sub>[94.8%, 100.0%]</sub> | 380/400 (95.0%)<br><sub>[92.4%, 96.7%]</sub> | 20/100 (20.0%)<br><sub>[13.3%, 28.9%]</sub> |
| **Ablation: No C5 (egress)** | **195/210 (92.9%)**<br><sub>[88.6%, 95.6%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Ablation: No C6 (irreversible authorization)** | **195/210 (92.9%)**<br><sub>[88.6%, 95.6%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **Gate + LLM Judge (Config H)** | **195/210 (92.9%)**<br><sub>[88.6%, 95.6%]</sub> | 0/70 (0.0%)<br><sub>[0.0%, 5.2%]</sub> | 400/400 (100.0%)<br><sub>[99.0%, 100.0%]</sub> | 0/100 (0.0%)<br><sub>[0.0%, 3.7%]</sub> |
| **LLM-Judge-Only (Baseline)** | **210/210 (100.0%)**<br><sub>[98.2%, 100.0%]</sub> | 35/70 (50.0%)<br><sub>[38.6%, 61.4%]</sub> | 302/400 (75.5%)<br><sub>[71.1%, 79.5%]</sub> | 26/100 (26.0%)<br><sub>[18.4%, 35.4%]</sub> |

---

## 3. Disaggregated Recall Across Attack Families

To detect localized evasion blind spots, compromised attack recall is disaggregated across attack families:

| Configuration | `credential_phishing_field` | `fake_system_banner` | `html_comment` | `multi_step_instruction` | `off_screen_text` | `url_obfuscation` | `user_generated_content` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Passthrough (B0)** | 0/30 (0.0%) | 0/30 (0.0%) | 0/30 (0.0%) | 0/30 (0.0%) | 0/30 (0.0%) | 0/30 (0.0%) | 0/30 (0.0%) |
| **Taxonomy Block (B1-Block)** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Taxonomy Warn (B1-Warn)** | 0/30 (0.0%) | 0/30 (0.0%) | 0/30 (0.0%) | 0/30 (0.0%) | 0/30 (0.0%) | 0/30 (0.0%) | 0/30 (0.0%) |
| **Parameter Rails (B2)** | 2/30 (6.7%) | 30/30 (100.0%) | 30/30 (100.0%) | 5/30 (16.7%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Regex-Only Filter (Baseline)** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Tool-Allowlist (Baseline)** | 30/30 (100.0%) | 3/30 (10.0%) | 3/30 (10.0%) | 20/30 (66.7%) | 3/30 (10.0%) | 30/30 (100.0%) | 3/30 (10.0%) |
| **ContextGuard Gate (Config D, Canonical)** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Ablation: No Characterizer** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Ablation: No Risk Engine** | 4/30 (13.3%) | 30/30 (100.0%) | 30/30 (100.0%) | 6/30 (20.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Ablation: No C1 (raw HTML scan)** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Ablation: No C2 (SUBMIT destination check)** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Ablation: No C3 (fail-closed unknown field)** | 4/30 (13.3%) | 30/30 (100.0%) | 30/30 (100.0%) | 6/30 (20.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Ablation: No C4 (marker-only cap to ALLOW_WITH_FLAG)** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Ablation: No C5 (egress)** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Ablation: No C6 (irreversible authorization)** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **Gate + LLM Judge (Config H)** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 15/30 (50.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |
| **LLM-Judge-Only (Baseline)** | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) | 30/30 (100.0%) |

---

## 4. Component Ablation Findings (Leave-One-Out Analysis)

| Component Removed | Identifier | Attack Recall (/210) | Benign Utility (/400) | Specific Mechanism Tested |
| :--- | :--- | :---: | :---: | :--- |
| **Characterizer** | `dual_gate_no_characterizer` | 195/210 (92.9%) | 400/400 (100.0%) | Lexical threat categorization bypass |
| **Risk Engine** | `dual_gate_no_risk_engine` | 160/210 (76.2%) | 380/400 (95.0%) | Heuristic mapping without weighted risk scoring |
| **C1 raw HTML scan** | `dual_gate_no_c1` | 195/210 (92.9%) | 400/400 (100.0%) | Disables raw HTML comment and invisible DOM scanning |
| **C2 SUBMIT destination check** | `dual_gate_no_c2` | 195/210 (92.9%) | 400/400 (100.0%) | Disables external form submission boundary check |
| **C3 fail-closed unknown field** | `dual_gate_no_c3` | 160/210 (76.2%) | 400/400 (100.0%) | Disables unknown field target interception |
| **C4 marker-only cap** | `dual_gate_no_c4` | 210/210 (100.0%) | 380/400 (95.0%) | Disables dampening of benign actions containing markers |
| **C5 egress** | `dual_gate_no_c5` | 195/210 (92.9%) | 400/400 (100.0%) | Disables parameter value external hostname exfiltration check |
| **C6 irreversible authorization** | `dual_gate_no_c6` | 195/210 (92.9%) | 400/400 (100.0%) | Disables explicit authorization for irreversible actions |

---

## 5. Decision-to-Outcome Mapping Conformance

This report strictly conforms to the pre-registered decision mapping matrix:
- `Decision.ALLOW` $\to$ **Allowed** (Preserves Utility)
- `Decision.ALLOW_WITH_FLAG` / `FLAG` / `WARN` $\to$ **Allowed / Flagged** (Preserves Utility)
- `Decision.REQUIRE_CONFIRMATION` / `PAUSE_TASK` / `ASK_HUMAN` $\to$ **Intercepted** (Stopped)
- `Decision.BLOCK` $\to$ **Intercepted** (Stopped)

**Confirmation**: `ASK_HUMAN` strictly counts as **Intercepted** across all metric denominators.
