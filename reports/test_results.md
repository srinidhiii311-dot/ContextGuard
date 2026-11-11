# ContextGuard Holdout Test Evaluation Report (TEST Split)

**Generated:** `2026-11-11 06:19:27 UTC`  
**Execution Mode:** `FINAL HOLDOUT EVALUATION`  
**Target Split:** `test` (Total Cases: 420; Compromised: 190, Uncompromised: 30, Benign: 200)  
**Evaluation Seed:** `42`  
**Configurations Evaluated:** 17 (9 Core Systems/Baselines + 8 Component Ablations)  

---

## 1. Executive Summary & Pre-Registered Hypotheses

> [!NOTE]
> This report was automatically compiled by `analysis/test_report.py` in strict compliance with `reports/test_protocol.md`. 
> All statistical inferences, confidence intervals, and hypothesis tests were pre-registered prior to evaluation.

### Primary Hypothesis 1: False-Positive Suppression on Uncompromised Pages
- **Comparison**: ContextGuard Gate (`dual_gate`) vs. Static Keyword Baseline (`taxonomy_block`) on uncompromised attack pages ($N = 30$).
- **Observed Over-block**: `taxonomy_block` = **30/30 (100.0%)** vs. `dual_gate` = **0/30 (0.0%)**.
- **Estimated Reduction ($\Delta_{\text{overblock}}$)**: **+100.00%**
- **Primary Statistical Inference (10,000 Cluster-Bootstrap)**: **95% CI [100.0%, 100.0%]** ($p = 0.0001$).
- **Primary Hypothesis Test Result**: **PASSED (CI strictly excludes 0)**.
- **Secondary Inference (McNemar Exact)**: Discordant pairs ($b=30, c=0$), two-sided **$p = 1.8626e-09$**.

### Primary Hypothesis 2: Intent Boundary Superiority over Parameter Rails
- **Comparison**: ContextGuard Gate (`dual_gate`) vs. Parameter Rails (`consistency_only`) on compromised attacks ($N = 190$).
- **Observed Recall**: `dual_gate` = **177/190 (93.2%)** vs. `consistency_only` = **135/190 (71.1%)**.
- **Estimated Recall Gain ($\Delta_{\text{recall}}$)**: **+22.18%**
- **Primary Statistical Inference (10,000 Cluster-Bootstrap)**: **95% CI [10.0%, 35.79%]** ($p = 0.0001$).
- **Primary Hypothesis Test Result**: **PASSED (CI strictly excludes 0)**.
- **Secondary Inference (McNemar Exact)**: Discordant pairs ($b=42, c=0$), two-sided **$p = 4.5475e-13$**.

---

## 2. Standardized Performance Across All 17 Configurations

| Configuration | Compromised Attack Recall | Uncompromised Over-block | Benign Task Utility | Hard Benign FP Rate |
| :--- | :---: | :---: | :---: | :---: |
| **Passthrough (B0)** | **0/190 (0.0%)**<br><sub>[0.0%, 2.0%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Taxonomy Block (B1-Block)** | **190/190 (100.0%)**<br><sub>[98.0%, 100.0%]</sub> | 30/30 (100.0%)<br><sub>[88.6%, 100.0%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Taxonomy Warn (B1-Warn)** | **0/190 (0.0%)**<br><sub>[0.0%, 2.0%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Parameter Rails (B2)** | **135/190 (71.1%)**<br><sub>[64.2%, 77.0%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Regex-Only Filter (Baseline)** | **190/190 (100.0%)**<br><sub>[98.0%, 100.0%]</sub> | 30/30 (100.0%)<br><sub>[88.6%, 100.0%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Tool-Allowlist (Baseline)** | **118/190 (62.1%)**<br><sub>[55.0%, 68.7%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 187/200 (93.5%)<br><sub>[89.2%, 96.2%]</sub> | 3/50 (6.0%)<br><sub>[2.1%, 16.2%]</sub> |
| **ContextGuard Gate (Config D, Canonical)** | **177/190 (93.2%)**<br><sub>[88.6%, 96.0%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Ablation: No Characterizer** | **177/190 (93.2%)**<br><sub>[88.6%, 96.0%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Ablation: No Risk Engine** | **164/190 (86.3%)**<br><sub>[80.7%, 90.5%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 190/200 (95.0%)<br><sub>[91.0%, 97.3%]</sub> | 10/50 (20.0%)<br><sub>[11.2%, 33.0%]</sub> |
| **Ablation: No C1 (raw HTML scan)** | **177/190 (93.2%)**<br><sub>[88.6%, 96.0%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Ablation: No C2 (SUBMIT destination check)** | **177/190 (93.2%)**<br><sub>[88.6%, 96.0%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Ablation: No C3 (fail-closed unknown field)** | **164/190 (86.3%)**<br><sub>[80.7%, 90.5%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Ablation: No C4 (marker-only cap to ALLOW_WITH_FLAG)** | **190/190 (100.0%)**<br><sub>[98.0%, 100.0%]</sub> | 30/30 (100.0%)<br><sub>[88.6%, 100.0%]</sub> | 190/200 (95.0%)<br><sub>[91.0%, 97.3%]</sub> | 10/50 (20.0%)<br><sub>[11.2%, 33.0%]</sub> |
| **Ablation: No C5 (egress)** | **177/190 (93.2%)**<br><sub>[88.6%, 96.0%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Ablation: No C6 (irreversible authorization)** | **174/190 (91.6%)**<br><sub>[86.8%, 94.8%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **Gate + LLM Judge (Config H)** | **177/190 (93.2%)**<br><sub>[88.6%, 96.0%]</sub> | 0/30 (0.0%)<br><sub>[0.0%, 11.4%]</sub> | 200/200 (100.0%)<br><sub>[98.1%, 100.0%]</sub> | 0/50 (0.0%)<br><sub>[0.0%, 7.1%]</sub> |
| **LLM-Judge-Only (Baseline)** | **158/190 (83.2%)**<br><sub>[77.2%, 87.8%]</sub> | 18/30 (60.0%)<br><sub>[42.3%, 75.4%]</sub> | 151/200 (75.5%)<br><sub>[69.1%, 80.9%]</sub> | 13/50 (26.0%)<br><sub>[15.9%, 39.6%]</sub> |

---

## 3. Disaggregated Recall Across Attack Families

To detect localized evasion blind spots, compromised attack recall is disaggregated across attack families:

| Configuration | `form_action_override` | `hidden_css_text` | `overlay_clickjack` |
| :--- | :---: | :---: | :---: |
| **Passthrough (B0)** | 0/40 (0.0%) | 0/40 (0.0%) | 0/40 (0.0%) |
| **Taxonomy Block (B1-Block)** | 40/40 (100.0%) | 40/40 (100.0%) | 40/40 (100.0%) |
| **Taxonomy Warn (B1-Warn)** | 0/40 (0.0%) | 0/40 (0.0%) | 0/40 (0.0%) |
| **Parameter Rails (B2)** | 40/40 (100.0%) | 40/40 (100.0%) | 0/40 (0.0%) |
| **Regex-Only Filter (Baseline)** | 40/40 (100.0%) | 40/40 (100.0%) | 40/40 (100.0%) |
| **Tool-Allowlist (Baseline)** | 40/40 (100.0%) | 4/40 (10.0%) | 40/40 (100.0%) |
| **ContextGuard Gate (Config D, Canonical)** | 40/40 (100.0%) | 40/40 (100.0%) | 27/40 (67.5%) |
| **Ablation: No Characterizer** | 40/40 (100.0%) | 40/40 (100.0%) | 27/40 (67.5%) |
| **Ablation: No Risk Engine** | 40/40 (100.0%) | 40/40 (100.0%) | 27/40 (67.5%) |
| **Ablation: No C1 (raw HTML scan)** | 40/40 (100.0%) | 40/40 (100.0%) | 27/40 (67.5%) |
| **Ablation: No C2 (SUBMIT destination check)** | 40/40 (100.0%) | 40/40 (100.0%) | 27/40 (67.5%) |
| **Ablation: No C3 (fail-closed unknown field)** | 40/40 (100.0%) | 40/40 (100.0%) | 27/40 (67.5%) |
| **Ablation: No C4 (marker-only cap to ALLOW_WITH_FLAG)** | 40/40 (100.0%) | 40/40 (100.0%) | 40/40 (100.0%) |
| **Ablation: No C5 (egress)** | 40/40 (100.0%) | 40/40 (100.0%) | 27/40 (67.5%) |
| **Ablation: No C6 (irreversible authorization)** | 40/40 (100.0%) | 40/40 (100.0%) | 24/40 (60.0%) |
| **Gate + LLM Judge (Config H)** | 40/40 (100.0%) | 40/40 (100.0%) | 27/40 (67.5%) |
| **LLM-Judge-Only (Baseline)** | 40/40 (100.0%) | 40/40 (100.0%) | 8/40 (20.0%) |

---

## 4. Component Ablation Findings (Leave-One-Out Analysis)

| Component Removed | Identifier | Attack Recall (/190) | Benign Utility (/200) | Specific Mechanism Tested |
| :--- | :--- | :---: | :---: | :--- |
| **Characterizer** | `dual_gate_no_characterizer` | 177/190 (93.2%) | 200/200 (100.0%) | Lexical threat categorization bypass |
| **Risk Engine** | `dual_gate_no_risk_engine` | 164/190 (86.3%) | 190/200 (95.0%) | Heuristic mapping without weighted risk scoring |
| **C1 raw HTML scan** | `dual_gate_no_c1` | 177/190 (93.2%) | 200/200 (100.0%) | Disables raw HTML comment and invisible DOM scanning |
| **C2 SUBMIT destination check** | `dual_gate_no_c2` | 177/190 (93.2%) | 200/200 (100.0%) | Disables external form submission boundary check |
| **C3 fail-closed unknown field** | `dual_gate_no_c3` | 164/190 (86.3%) | 200/200 (100.0%) | Disables unknown field target interception |
| **C4 marker-only cap** | `dual_gate_no_c4` | 190/190 (100.0%) | 190/200 (95.0%) | Disables dampening of benign actions containing markers |
| **C5 egress** | `dual_gate_no_c5` | 177/190 (93.2%) | 200/200 (100.0%) | Disables parameter value external hostname exfiltration check |
| **C6 irreversible authorization** | `dual_gate_no_c6` | 174/190 (91.6%) | 200/200 (100.0%) | Disables explicit authorization for irreversible actions |

---

## 5. Decision-to-Outcome Mapping Conformance

This report strictly conforms to the pre-registered decision mapping matrix:
- `Decision.ALLOW` $\to$ **Allowed** (Preserves Utility)
- `Decision.ALLOW_WITH_FLAG` / `FLAG` / `WARN` $\to$ **Allowed / Flagged** (Preserves Utility)
- `Decision.REQUIRE_CONFIRMATION` / `PAUSE_TASK` / `ASK_HUMAN` $\to$ **Intercepted** (Stopped)
- `Decision.BLOCK` $\to$ **Intercepted** (Stopped)

**Confirmation**: `ASK_HUMAN` strictly counts as **Intercepted** across all metric denominators.
