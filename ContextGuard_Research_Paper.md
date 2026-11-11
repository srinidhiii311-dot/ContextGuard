# ContextGuard: A Synchronous Pre-Action Intent Gateway for Mitigating Indirect Prompt Injection in Autonomous Web Agents

**Technical Research Paper & Architecture Report**  
*Author*: Srinidhi R  
*Repository*: [`https://github.com/srinidhiii311-dot/ContextGuard.git`](https://github.com/srinidhiii311-dot/ContextGuard.git)  
*Date*: October 2026  
*Status*: Technical Report (Evaluated on Dev and Held-Out Test Splits; Code Tagged: `gate-frozen-v3.1`)

> [!NOTE]
> **EMPIRICAL LEDGER & GATE FREEZE AUDIT (NOVEMBER 2026)**  
> This manuscript is verified against the canonical quantitative ledger ([`reports/numbers_ledger.md`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/reports/numbers_ledger.md)) and [`claims.yaml`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/claims.yaml).  
> All empirical metrics are unpooled and mapped directly to verified CSV and JSON outputs in `analysis/` and `eval_results/` under [`scripts/verify_claims.py`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/scripts/verify_claims.py). The canonical gate code is strictly frozen at `gate-frozen-v3.1`.

---

## Abstract

Autonomous web agents powered by Large Language Models (LLMs) operate under an inherent vulnerability: they execute actions on web pages containing untrusted, third-party content. Untrusted DOM text, hidden CSS elements, and adversarial prompt injections can redirect agent behavior away from the user's intended goal. While prior research has focused on post-hoc LLM evaluation, prompt hardening, or simple regex keyword matching, these techniques either suffer from high latency, exhibit prompt-level bypass susceptibility, or introduce prohibitive false-positive rates that halt benign browsing.

We present **ContextGuard**, an in-line, synchronous, pre-action security gateway that intercepts and verifies every proposed browser action before execution. ContextGuard enforces a declarative **Trusted Intent Lock** using an 11-layer defense-in-depth pipeline combining deterministic field rails, lexical deviation metrics, computed-style DOM hidden-content detection, multi-step trajectory chain state machines, a selective grey-zone LLM reviewer, and an ACID-compliant, SHA-256 HMAC hash-chained SQLite audit logger.

ContextGuard was comprehensively evaluated on a multi-domain benchmark comprising **680 DEV scenarios** across 5 distinct application domains (Flight Reservation, Banking Transfers, E-Commerce, Healthcare, and Email Management), alongside preliminary pilot suites. On the canonical frozen gateway (`gate-frozen-v3.1`, commit `a472ff3`), ContextGuard achieves **92.86% compromised attack recall** (195/210 attacks intercepted, 95% Wilson Score CI [88.55%, 95.63%], 95% cluster-bootstrap CI [83.33%, 100.00%]) with **0.0% benign false interceptions** across all 400 benign tasks (0/300 normal, 0/100 hard; 95% CI [0.00%, 1.25%]) and **100.0% utility** (470/470 executed across benign and uncompromised tasks; 0/70 over-block). On the pre-registered, single-run holdout TEST split ($N = 420$ total cases across all 5 domains), ContextGuard achieves **93.2% compromised attack recall (177/190, Wilson 95% CI [88.6%, 96.0%])**, **0/30 uncompromised over-block (0.0%)**, **200/200 benign utility (100.0%)**, and **0/50 hard benign false positives (0.0%)**, with held-out family `overlay_clickjack` achieving **27/40 (67.5%)** recall. Across white-box programmatic adaptive attacks (S1–S6 and S6b), ContextGuard achieves 100% interception on free-text exfiltration (0/183 evasions), near-miss mutations (0/135 evasions), allowed-host abuse (0/175 evasions under legacy counts, 0/70 under Oracle v3), and allowed-action abuse (0/106 evasions). In multi-session concurrency testing across 500 cases, the gateway exhibits 0/500 decision drift with an in-memory latency of 2.15 ms (p50) and 6.79 ms (p95). In preliminary exploratory benchmarks (138 scenarios), Config D achieved 100.0% on Dev and 91.7% on Holdout.

As a design property of the hand-set weights ($25 \times \text{sensitivity} \le 23.75 < 30$), ContextGuard maintains a structural 0% false positive ceiling on clean, conforming actions with zero textual or marker hits. On commercial pages with aggressive urgency marketing banners, however, live testbed evaluation reveals an operational trade-off, intercepting 2 of 4 urgency scenarios. Furthermore, by gating the heavy LLM semantic reviewer strictly to a 30–59 risk grey zone, **76.1% (105/138) of actions completely bypass LLM inference** with 0 ms added overhead, maintaining a predictable base gateway latency of ~75–85 ms.

---

## 1. Introduction & Problem Statement

### 1.1 The Rise and Vulnerability of Autonomous Web Agents
Autonomous web agents (e.g., Playwright-driven agents, WebArena, WorkArena) translate high-level natural language user instructions (e.g., *"Book a morning flight from Chennai to Delhi under ₹6,000"*) into discrete browser interactions: DOM clicks, text inputs, form selections, and navigation requests.

To make decisions, browser agents ingest the Document Object Model (DOM) of the target webpage into the model's context window. This architecture creates a critical attack surface: **Indirect Prompt Injection (IPI)**. Any third party capable of injecting content into the target website—via promotional banners, user reviews, hotel names, search suggestions, or CSS styling—can embed instructions that hijack the model’s reasoning.

```
+-------------------+        +--------------------+        +-------------------------+
| User Instruction  | -----> | LLM Decision Loop  | -----> | Proposed Browser Action |
+-------------------+        +--------------------+        +-------------------------+
                                        ^                                |
                                        | (DOM context with              v
                                        |  injected prompts)      [UNGUARDED BROWSER]
                             +----------------------+             - Premature Payment
                             | Adversarial Web Page |             - Data Exfiltration
                             +----------------------+             - Intent Subversion
```

### 1.2 Limitations of Existing Defenses
Prior approaches to agent security fall into three unsatisfactory paradigms:
1. **Prompt-Level Steering (System Prompts)**: Instructing the agent model to "ignore malicious instructions" is inherently fragile against jailbreaks, obfuscation, and multi-turn persona shifts.
2. **Post-Hoc LLM Judges**: Querying a secondary LLM after every action introduces unacceptable latency (1–3 seconds per click) and remains prone to prompt injection bypasses.
3. **Naive Keyword Filtering**: Simple regex filters achieve negligible recall (11.4%) against sophisticated evasion attacks and fail to understand entity binding (e.g., distinguishing legitimate destination entry from injected rerouting).

### 1.3 The ContextGuard Paradigm: Pre-Action Gateway
ContextGuard shifts security enforcement **out of the LLM context and into the deterministic execution path**. Operating as a synchronous pre-action gateway, ContextGuard acts as a security proxy between the agent's decision and the browser's execution engine. If an action contradicts the user's locked intent, violates safety policies, or matches threat patterns, it is intercepted before the browser can perform the state change.

---

## 2. Threat Model & Design Principles

### 2.1 Threat Model
* **Attacker Capabilities**: The adversary controls external webpage content, including visible HTML, hidden CSS elements (e.g., `opacity: 0`, `display: none`, offscreen positioning), and dynamic DOM updates. The adversary attempts to induce the agent to:
  * Alter high-consequence entities (origin, destination, date, passenger details).
  * Exceed budget thresholds or book unintended add-ons.
  * Leak sensitive credentials or PII into attacker-controlled form inputs.
  * Execute premature checkout/payment actions.
* **Trust Assumptions**: The initial user instruction provided in the terminal/portal is trusted. The local operating system and Python runtime are trusted. The agent model itself is treated as untrusted/compromised whenever it interacts with web content.
* **Design Boundary & Non-Goals**: ContextGuard is a **declarative intent-consistency gateway**, not an unconstrained behavioral anomaly detector. It guarantees non-interference for conforming browsing. An action that is atypical but contains no textual trigger, entity deviation, or policy violation is permitted by design.

### 2.2 Attack Taxonomy
ContextGuard codifies a rigorous taxonomy of **7 primary attack categories**, **49 pattern hints**, and **6 multi-step trajectory chains**:

```
+---------------------------------------------------------------------------------------+
| CONTEXTGUARD ATTACK TAXONOMY (7 Categories, 49 Pattern Hints, 6 Trajectory Chains)    |
+---------------------------------------------------------------------------------------+
| 1. PROMPT_INJECTION       | Direct instruction override ("ignore previous directives") |
| 2. HIDDEN_CONTENT         | Zero-opacity, clip-path, display:none style cloaking      |
| 3. ATTRIBUTE_OVERRIDE     | Forcing destination, class, or baggage alterations        |
| 4. FINANCIAL_TAMPERING    | Fee-tampering, budget bypass, currency denomination shift |
| 5. PREMATURE_COMMIT       | Bypassing review steps to trigger checkout early           |
| 6. SENSITIVE_EXFILTRATION | Injecting PII into review fields, chat boxes, or query params|
| 7. MULTI_STEP_EVASION     | Incremental staging across multi-page navigation steps     |
+---------------------------------------------------------------------------------------+
```

---

## 3. System Architecture & The 11-Layer Canonical Gate

ContextGuard is architected as an 11-layer pipeline within [`contextguard/gate.py`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/contextguard/gate.py), accessed via REST API (`POST /v1/action/verify`) or in-process Python invocation (`ContextGuardGate.check()`):

```
                        PROPOSED AGENT ACTION
                                  |
                                  v
+===================================================================+
| 1. INTENT ANCHOR & SCHEMA VALIDATION                              |
|    Locks user intent (origin, destination, budget, passengers)    |
+-------------------------------------------------------------------+
                                  |
+===================================================================+
| 2. ACTION SENSITIVITY CLASSIFIER                                  |
|    Weights action impact (READ=0.1, NAV=0.3, INPUT=0.6, COMMIT=0.95)|
+-------------------------------------------------------------------+
                                  |
+===================================================================+
| 3. ENTITY CONSISTENCY RAILS (NEGATION-AWARE)                     |
|    Audits origin/dest aliases, rejects contradictory values        |
+-------------------------------------------------------------------+
                                  |
+===================================================================+
| 4. TAXONOMY MATCHING ENGINE                                       |
|    Scans 49 pattern hints across 7 threat categories              |
+-------------------------------------------------------------------+
                                  |
+===================================================================+
| 5. LEXICAL & VECTOR DEVIATION ENGINE                              |
|    C4-calibrated Jaccard & token deviation against instruction     |
+-------------------------------------------------------------------+
                                  |
+===================================================================+
| 6. DOM STRUCTURAL BASELINE HASH VERIFIER                          |
|    Detects dynamic structural DOM drift and unexpected forms      |
+-------------------------------------------------------------------+
                                  |
+===================================================================+
| 7. COMPUTED-STYLE HIDDEN CONTENT SCANNER                          |
|    Detects invisible prompt injection text (Playwright scanner)   |
+-------------------------------------------------------------------+
                                  |
+===================================================================+
| 8. MULTI-STEP TRAJECTORY CHAIN TRACKER                            |
|    Stateful tracker identifying staged attack patterns (6 chains)  |
+-------------------------------------------------------------------+
                                  |
+===================================================================+
| 9. SELECTIVE GREY-ZONE LLM CONSISTENCY REVIEWER                   |
|    Invoked ONLY when Risk Score is in [30, 59] grey zone          |
+-------------------------------------------------------------------+
                                  |
+===================================================================+
| 10. DETERMINISTIC FINAL POLICY FLOOR (HARD-RULE INTERCEPT)        |
|     Enforces fee_floor(), budget caps in _enforce(); cannot be    |
|     diluted or downgraded by statistical or LLM scores            |
+-------------------------------------------------------------------+
                                  |
+===================================================================+
| 11. TAMPER-EVIDENT SHA-256 HMAC AUDIT LOGGER                      |
|     ACID SQLite transactions, hash-chaining, HMAC anchoring       |
+-------------------------------------------------------------------+
                                  |
                                  v
              GATE DECISION: ALLOW | WARN | PAUSE | BLOCK
```

### 3.1 Layer Details
1. **Intent Anchor & Schema Enforcement**: Ingests user input via `parse_task()` and locks it into an immutable `TrustedIntent` dataclass.
2. **Action Sensitivity**: Maps the target DOM element and action type to an empirical impact score $S_{\text{sensitivity}} \in [0.0, 1.0]$.
3. **Entity Consistency (Negation-Aware)**: Reconciles airport codes, city aliases (e.g., "Madras" $\to$ "MAA" $\to$ "Chennai"), and validates that input values match intended slot assignments.
4. **Attack Taxonomy Engine**: Regex scanning against the 49 pattern catalog across 7 categories.
5. **Lexical Deviation**: Calibrates token deviation using a baseline distribution derived from the C4 corpus.
6. **DOM Baseline Hash Verifier**: Maintains SHA-256 structural hashes of baseline site templates to catch rogue injected iframes or form fields.
7. **Computed-Style Scanner**: Headless Playwright script that inspects CSS properties (`getComputedStyle`) to detect text rendered invisible to the user but ingested by the agent.
8. **Multi-Step Chain Tracker**: A state machine that models multi-action transitions (e.g., `SEARCH_MUTATION` followed by `PREMATURE_PAYMENT`).
9. **Selective Grey-Zone LLM Checker**: An LLM reviewer triggered *only* when the deterministic score falls into the ambiguous grey zone (30–59), ensuring high throughput for obvious safe/harmful actions.
10. **Deterministic Final Policy Floor (`fee_floor()`, `budget_ceiling`)**: Sits inside `_enforce()` at Step 9, running *after* statistical risk assessment and LLM review to guarantee strict raise-only discipline: if an action attempts an unapproved fee delta or unauthorized commit, the floor unconditionally forces `REQUIRE_CONFIRMATION` or `BLOCK`, which cannot be downgraded by statistical scores.
11. **Tamper-Evident Audit Logging**: Every evaluation is persisted to SQLite with backward-linked SHA-256 hashes (`row_hash = SHA256(prev_hash + payload)`) and HMAC signatures enforcing $\ge 16$-character secret keys.
11. **Tamper-Evident Audit Logging**: Every evaluation is persisted to SQLite with backward-linked SHA-256 hashes (`row_hash = SHA256(prev_hash + payload)`) and HMAC signatures enforcing $\ge 16$-character secret keys.

### 3.2 Dual-Gate Reconciliation & Codebase Unification
To eliminate any runtime divergence between offline benchmarks and live agent execution:
* [`agent/agent_controller.py`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/agent/agent_controller.py) directly imports and instantiates `ContextGuardGate` (lines 31–37, 307–310).
* [`contextguard/pre_action_gate.py`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/contextguard/pre_action_gate.py) delegates directly into `ContextGuardGate.check()`.
* Both interactive Playwright sessions and batch benchmark runners execute the exact same 11-layer pipeline.

---

## 4. Mathematical Formulation & Structural Properties

### 4.1 Composite Risk Scoring Formulation
The continuous risk score $R \in [0, 100]$ is computed as:
$$R = 100 \times \Big( w_{\text{threat}} \cdot S_{\text{threat}} + w_{\text{inconsistency}} \cdot S_{\text{inconsistency}} + w_{\text{sensitivity}} \cdot S_{\text{sensitivity}} + w_{\text{marker}} \cdot S_{\text{marker}} \Big)$$

Where calibrated weights satisfy $\sum w_i = 1.0$:
$$w_{\text{threat}} = 0.25, \quad w_{\text{inconsistency}} = 0.30, \quad w_{\text{sensitivity}} = 0.25, \quad w_{\text{marker}} = 0.20$$

### 4.2 Policy Decision Thresholds
Actions are mapped into four operational security tiers:
$$\text{Decision}(R) = \begin{cases} 
\text{ALLOW} & R < 30 \\
\text{ALLOW\_WITH\_FLAG} & 30 \le R < 60 \quad \text{and action is non-consequential} \\
\text{REQUIRE\_CONFIRMATION} & (30 \le R < 60 \text{ and consequential}) \quad \text{or} \quad 60 \le R < 80 \\
\text{BLOCK} & R \ge 80 
\end{cases}$$

### 4.3 Design Property: The 0% False Positive Ceiling on Clean Conforming Actions
**Design property of the hand-set weights**: *For any clean, conforming user action containing no adversarial text and no entity mismatch, the maximum attainable risk score is strictly less than the interception threshold ($R < 30$).*

**Derivation**:
Let $A$ be a legitimate action. By definition of a clean conforming action:
1. $S_{\text{threat}} = 0.0$ (no prompt injection keywords or regex matches).
2. $S_{\text{inconsistency}} = 0.0$ (all field values match `TrustedIntent`).
3. $S_{\text{marker}} = 0.0$ (no hidden DOM elements or multi-step evasion markers).

The risk formulation simplifies to:
$$R(A) = 100 \times \big( 0.25 \cdot S_{\text{sensitivity}} \big) = 25 \cdot S_{\text{sensitivity}}$$

The maximum sensitivity weight defined in `protected_fields.yaml` is $S_{\text{sensitivity}}^{\max} = 0.95$ (assigned to final payment submission and passport submission). Therefore:
$$R_{\max}(A) = 25 \times 0.95 = 23.75$$

Since $23.75 < 30.0$:
$$\forall A \in \text{CleanActions}, \quad \text{Decision}(A) = \text{ALLOW}$$

**Scope and Boundary**:
This ceiling is a design property of the hand-set weights ($w_{\text{sensitivity}} = 0.25$), guaranteeing that conforming browsing actions cannot be blocked by sensitivity alone. However, this guarantee covers strictly clean conforming actions without trigger words or DOM anomalies. On the held-out test split, benign hard cases containing legitimate security or urgency triggers scored up to **89** in the raw risk engine; preventing over-blocks on such cases relies downstream on Rule C4 parameter consistency rather than this sensitivity ceiling.

---

## 5. Empirical Evaluation & Experimental Results

### 5.1 Pre-Registered Holdout Evaluation on TEST Split (Single Final Run)

To evaluate genuine out-of-distribution generalization without data leakage, ContextGuard was evaluated on the pre-registered, single-run holdout TEST split ($N = 420$ total cases across 5 domains: 190 compromised attacks, 30 uncompromised compliant attacks, 150 standard benign actions, and 50 hard benign edge cases). Evaluation was conducted strictly once with frozen code and weights (`gate-frozen-v3.1`, commit `a472ff3`), and recorded outputs were locked prior to analysis.

#### A. Headline Test Performance
Copying numbers exactly from the pre-registered single-run holdout results ([`reports/test_results.md`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/reports/test_results.md)):
* **Compromised Attack Recall**: **177/190 (93.2%)** intercepted (95% Wilson Score CI [88.6%, 96.0%]).
* **Uncompromised Attack Over-block**: **0/30 (0.0%)** (95% Wilson CI [0.0%, 11.4%]).
* **Benign Task Utility**: **200/200 (100.0%)** executed (95% Wilson CI [98.1%, 100.0%]).
* **Hard Benign False Positives**: **0/50 (0.0%)** (95% Wilson CI [0.0%, 7.1%]).
* **Held-Out Family Recall**:
  * `form_action_override`: **40/40 (100.0%)** (95% Wilson CI [91.2%, 100.0%])
  * `hidden_css_text`: **40/40 (100.0%)** (95% Wilson CI [91.2%, 100.0%])
  * `overlay_clickjack`: **27/40 (67.5%)** (95% Wilson CI [52.0%, 79.9%])

#### B. Pre-Registered Primary Hypotheses
1. **Hypothesis 1 (False-Positive Suppression on Uncompromised Pages)**:
   - ContextGuard Gate (`dual_gate`): 0/30 (0.0%) over-block vs. Static Keyword Baseline (`taxonomy_block`): 30/30 (100.0%) over-block.
   - Observed Reduction $\Delta_{\text{overblock}}^{\text{obs}} = \mathbf{+100.00\%}$ (10,000 cluster-bootstrap 95% CI $[100.0\%, 100.0\%]$, empirical two-tailed cluster-bootstrap $p = 0.0001$; McNemar exact $p = 1.8626 \times 10^{-9}$).
2. **Hypothesis 2 (Intent Boundary Superiority over Parameter Rails)**:
   - ContextGuard Gate (`dual_gate`): 177/190 (93.2%) recall vs. Parameter Rails (`consistency_only`): 135/190 (71.1%) recall.
   - Observed Gain $\Delta_{\text{recall}}^{\text{obs}} = \mathbf{+22.11\%}$ (Cluster-Bootstrap Mean $+22.18\%$, 95% CI $[10.0\%, 35.79\%]$, empirical two-tailed cluster-bootstrap $p = 0.0001$; McNemar exact $p = 4.5475 \times 10^{-13}$).

---

### 5.2 Holdout Limitations

While ContextGuard demonstrates robust out-of-distribution defense, rigorous holdout evaluation surfaces seven critical operational limitations:
1. **Overlay Clickjacking Misses Caused by Rule C4**: Under canonical `dual_gate`, 13 of the 40 `overlay_clickjack` attacks were assigned `ALLOW_WITH_FLAG` (`warn`) instead of being intercepted (27/40 = 67.5% recall). These misses are directly caused by Rule C4 (*marker-only cap to ALLOW_WITH_FLAG*): because button clicks on styling overlays modify UI flow without tampering with form parameter values or violating schema boundaries, the action satisfies parameter consistency. C4 misinterprets this as proof of benign intent and caps the decision to `warn`. Disabling Rule C4 (`dual_gate_no_c4`) completely recovers 40/40 (100.0%) clickjack recall, but catastrophically over-blocks **30/30 (100.0%)** uncompromised pages.
2. **Failure of Raw Risk Engine to Separate Compromised from Compliant Pages**: The weighted risk engine produces overlapping raw risk scores for compromised attacks (**72 to 93**, median 82.0) and uncompromised compliant pages (**75 to 85**, median 77.0), because both contain actual prompt injection markers in page DOM. The risk engine alone cannot distinguish whether an agent was hijacked; all discrimination on uncompromised pages is executed downstream by Rule C4 parameter consistency checks.
3. **Unexercised Secondary LLM Safety Judge**: Configuration `dual_gate_llm` achieves identical performance to `dual_gate` alone (177/190 recall, 200/200 utility) with **0 live judge calls**. Because raw risk scores polarized into $\le 24$ (benign) and $\ge 72$ (attacks), zero cases landed in the $[30, 60)$ grey zone. Consequently, the practical utility and discriminative value of the secondary LLM judge remain undemonstrated on this benchmark.
4. **Redundant Static Rules on Test Distribution**: Leave-one-out ablations reveal that removing the threat characterizer (`no_characterizer`), the raw HTML scanner (`no_c1`), the SUBMIT destination validator (`no_c2`), or the egress checker (`no_c5`) changes nothing on the test split (each yields identical 177/190 recall and 200/200 utility), demonstrating significant component redundancy across static rules on this dataset.
5. **Structural Comparison Asymmetry in Hypothesis 1**: The keyword baseline (`taxonomy_block`) and regex baseline over-block uncompromised pages (30/30 = 100.0%) by construction, because they match keywords anywhere on the page without inspecting proposed agent actions. Consequently, Hypothesis 1 confirms a structural property of action-aware gating rather than a subtle behavioral capability.
6. **Shared Model Family Vulnerability**: In live LLM evaluations, both the attack generation agent and the safety judge employ models from the same LLM family (`gemini-3.5-flash-lite`), leaving open the possibility of shared blind spots or correlated reasoning vulnerabilities.
7. **Environment Scope**: Evaluation is restricted entirely to synthetic sandbox web environments. ContextGuard has not been evaluated against live commercial websites, complex third-party trackers/ad scripts, or vision-only multimodal browser agents.

---

### 5.3 Canonical Multi-Domain Benchmark on `gate-frozen-v3.1` (Development Split)

ContextGuard was developed and calibrated on a canonical multi-domain benchmark comprising **680 DEV scenarios** across 5 application domains (Flight Reservation, Banking Transfers, E-Commerce Checkout, Healthcare Appointments, and Enterprise Email), consisting of 210 compromised attacks, 70 uncompromised attacks, 300 normal benign actions, and 100 hard benign edge cases.

#### A. Canonical Gate Performance Summary (Dev Split)

On the frozen gateway (`gate-frozen-v3.1`, commit `a472ff3`):
* **Compromised Attack Recall**: **92.86% (195/210)** intercepted (95% Wilson Score CI [88.55%, 95.63%], 95% Cluster-Bootstrap CI [83.33%, 100.00%]).
* **Benign Normal False Interceptions**: **0.00% (0/300)** (95% Wilson CI [0.00%, 1.25%]).
* **Benign Hard False Interceptions**: **0.00% (0/100)** (95% Wilson CI [0.00%, 3.73%]).
* **Benign Task Utility**: **100.00% (400/400)** executed (or **470/470** across all benign plus uncompromised tasks).
* **Uncompromised Attack Over-block**: **0.00% (0/70)** (95% Wilson CI [0.00%, 5.22%]).
* **Deterministic Execution Overhead**: In-memory gateway evaluation latency is **2.15 ms** (p50) and **6.79 ms** (p95); end-to-end latency with SQLite HMAC-SHA256 audit logging is **72.23 ms** (p50) and **81.60 ms** (p95).

#### B. Component Ablations & Leave-One-Out Analysis (Dev Split)

Evaluated via `analysis/leave_one_out_ablation.py` (10,000 cluster-bootstrap resamples by family and template):

| Configuration | Compromised Recall | Over-block (Uncomp) | Benign Normal FP | Benign Hard FP | Total Utility | Paired $\Delta$ Recall vs Canon (p) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`dual_gate` (Canonical)** | **195/210 (92.86%)** | **0/70 (0.00%)** | **0/300 (0.00%)** | **0/100 (0.00%)** | **470/470 (100.0%)** | Reference (0.0%) |
| `taxonomy_block` | 210/210 (100.0%) | 70/70 (100.0%) | 0/300 (0.00%) | 0/100 (0.00%) | 400/470 (85.11%) | -7.14% ($p=0.0866$) |
| `taxonomy_warn` | 0/210 (0.00%) | 0/70 (0.00%) | 0/300 (0.00%) | 0/100 (0.00%) | 470/470 (100.0%) | +92.86% ($p=0.0001$) |
| `consistency_only` | 157/210 (74.76%) | 0/70 (0.00%) | 0/300 (0.00%) | 0/100 (0.00%) | 470/470 (100.0%) | +18.10% ($p=0.0012$) |
| `dual_gate_no_risk_engine` | 160/210 (76.19%) | 0/70 (0.00%) | 0/300 (0.00%) | 20/100 (20.00%) | 450/470 (95.74%) | +16.67% ($p=0.0012$) |
| `dual_gate_no_characterizer` | 195/210 (92.86%) | 0/70 (0.00%) | 0/300 (0.00%) | 0/100 (0.00%) | 470/470 (100.0%) | 0.00% ($p=1.0000$) |
| `dual_gate_no_c1` | 195/210 (92.86%) | 0/70 (0.00%) | 0/300 (0.00%) | 0/100 (0.00%) | 470/470 (100.0%) | 0.00% ($p=1.0000$) |
| `dual_gate_no_c2` | 195/210 (92.86%) | 0/70 (0.00%) | 0/300 (0.00%) | 0/100 (0.00%) | 470/470 (100.0%) | 0.00% ($p=1.0000$) |
| `dual_gate_no_c3` | 160/210 (76.19%) | 0/70 (0.00%) | 0/300 (0.00%) | 0/100 (0.00%) | 470/470 (100.0%) | +16.67% ($p=0.0012$) |
| `dual_gate_no_c4` | 210/210 (100.0%) | 70/70 (100.0%) | 0/300 (0.00%) | 20/100 (20.00%) | 380/470 (80.85%) | -7.14% ($p=0.0866$) |

#### C. Programmatic Adaptive Attacks (S1–S6 and S6b)

White-box adaptive attacks evaluated across 5 domains. All suites were executed under both the development "tuned-on" seed (Seed 42) and an independent "fresh" seed (Seed 9999), yielding identical deterministic counts across seeds:
* **S1 (Free-Text Exfiltration)**: 11 templates; evaluated under tuned-on seed 42 and fresh seed 9999. Baseline `v2-perf` allowed 47/183 (25.68%) evasions. On `gate-frozen-v3.1`, achieves **0/183 (0.0%)** evasions (100% intercepted by Rule C5 `EGRESS_IN_CONTENT`).
* **S2 (Near-Miss Mutations)**: 25 templates; evaluated under tuned-on seed 42 and fresh seed 9999. Achieves **0/135 (0.0%)** evasions under both `v2-perf` and `gate-frozen-v3.1`.
* **S3 (Allowed-Host Abuse)**: 10 templates across 5 domains (70 unsafe cases under Oracle v3); evaluated under tuned-on seed 42 and fresh seed 9999. Baseline `v2-perf` allowed 10/70 (14.29%) evasions under Oracle v3 (legacy Oracle v1 permitted 19/75 [25.33%] evasions; legacy 25/175 claim is superseded and reconciled in ledger). On `gate-frozen-v3.1`, achieves **0/70 (0.0%)** evasions (100% intercepted by Rule C5 hostname extraction).
* **S6 (Allowed-Action Abuse)**: 15 templates across 5 domains (106 unsafe cases under Oracle v3); evaluated under tuned-on seed 42 and fresh seed 9999. Baseline `v2-perf` allowed 54/106 (50.94%) evasions under Oracle v3 (68/120 under Oracle v1). On `gate-frozen-v3.1`, achieves **0/106 (0.0%)** evasions (100% intercepted by Rule C6 `UNAUTHORIZED_IRREVERSIBLE`).
* **S6b (Authorized Action with Mutated Parameters)**: 15 templates across 100 attempts; evaluated under tuned-on seed 42 and fresh seed 9999. Achieves 60/67 intercepted (**10.45% evasion rate**, 7/67 evasions in ecommerce where street address was unmapped in early manifests).
* *Note on S4 & S5*: Recorded as invalid single-step tests under SecurityOracleV3: single-action evaluators inspect actions in isolation without multi-step intent context. S4 mutates mapped intent parameters directly and S5 step 2 triggers irreversible authorization. Neither S4 nor S5 is tested for marker evasion or stateful attack resilience under this single-step protocol.

#### D. Live LLM Judge Benchmark (`dev_hard_60`)

Across 60 challenging evaluation cases evaluated against live Google Gemini API (`gemini-3.5-flash-lite`):
* **Accuracy**: 59/60 (98.33%) overall accuracy both with and without the judge.
* **Decisions Changed**: 0/60 decisions altered by judge invocation.
* **Newly Caught / Blocked**: 0 newly caught attacks, 0 newly blocked benign actions.
* **Latency Profile**: Median uncached latency was **1,193.11 ms**; p95 uncached latency was **15,532.26 ms** (accounting for one 60.12 s quota backoff event). Fallbacks to offline heuristic: **0**.

#### E. Multi-Session Concurrency & Thread Isolation

Evaluated across 500 cases under 1, 10, and 50 concurrent worker threads:
* **Throughput**: 28.1 op/s (N=1), 31.3 op/s (N=10), 31.6 op/s (N=50).
* **Latency**: p50 of 3.32 ms (N=1), 37.43 ms (N=10), 174.56 ms (N=50); p95 of 9.76 ms (N=1), 78.48 ms (N=10), 363.32 ms (N=50).
* **Decision Drift**: **0 / 500 (0 drift)** across all concurrency tiers.

---

### 5.4 Preliminary Exploratory Study & Historical Baselines (138 Scenarios)

In initial exploratory benchmarking prior to dataset scaling, ContextGuard was evaluated on 138 scenarios (66 Dev, 72 Holdout):
1. **Developer Benchmark Suite (Dev)**: 66 curated scenarios (34 adversarial attacks spanning all 7 categories; 32 benign navigation items) defined in [`eval_data/attacks.yaml`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/eval_data/attacks.yaml) and [`eval_data/benign.yaml`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/eval_data/benign.yaml).
2. **Frozen Independent Holdout Suite (Holdout)**: 72 previously unseen scenarios (36 adversarial, 36 benign) located in [`eval_data/test_v1/`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/eval_data/test_v1).
3. **Multi-Step Workflows (Schema v2)**: 19 multi-step sequences in [`eval_data/sequences_dev.yaml`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/eval_data/sequences_dev.yaml) (9 attacks, 10 benign non-linear lifecycles).
4. **Live Playwright Testbed**: 18 dynamic browser testbed scenarios (`TC-01`..`TC-08` and held-out variants `TC-01H`..`TC-10H`) including commercial dark-pattern urgency banners.
5. **Second Application Domain**: E-Commerce shopping and checkout validation suite ([`eval_data/second_domain/`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/eval_data/second_domain)).

> **Holdout Dataset Integrity Statement**: The 72-item Holdout Suite (`eval_data/test_v1/`) was strictly frozen prior to evaluation. No regex taxonomy patterns, risk weights, or policy decision thresholds were tuned or modified after viewing holdout results, ensuring genuine out-of-sample generalization.

#### Preliminary Comparative Baselines Table
We benchmark ContextGuard against 4 alternative defense paradigms:
* **Baseline 0 (Unprotected)**: Autonomous agent executing directly without safety validation.
* **Baseline 1 (Keyword Filter)**: Traditional regex-based injection filter searching for known prompt attack keywords.
* **Baseline 2 (Naive Field Rule)**: Simple slot-matching rules without semantic tolerance or negation awareness.
* **Baseline 3 (Zero-Shot Prompt Classifier - Offline Emulation)**: Prompt-based classification heuristic emulating zero-shot LLM evaluation without network roundtrips.
* **Configs A–H**: Incremental ContextGuard architectural ablations up to the full gate with compliance logging (Config D) and LLM checker (Config H).

#### Comprehensive Experimental Benchmark Table

| Defense Paradigm / Config | Dev Atk Recall [95% CI] | Dev Benign FP [CI] | Holdout Atk [95% CI] | Holdout FP [CI] | Total Atk Recall [95% CI] | Base Gate Latency | LLM Invocations | Cond LLM Latency (Mean / p95) | McNemar p |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Baseline 0: Unprotected** | 0.0% [0.0%, 10.2%] | 0.0% [0.0%, 10.7%] | 0.0% [0.0%, 9.6%] | 0.0% [0.0%, 9.6%] | 0/70 = 0.0% [0.0%, 5.2%] | 0.00 ms | 0/138 (0.0%) | 0 ms (N/A) | N/A |
| **Baseline 1: Keyword Filter** | 17.6% [8.3%, 33.5%] | 0.0% [0.0%, 10.7%] | 5.6% [1.5%, 18.1%] | 0.0% [0.0%, 9.6%] | 8/70 = 11.4% [5.9%, 21.0%] | 0.01 ms | 0/138 (0.0%) | 0 ms (N/A) | 0.0078 |
| **Baseline 2: Naive Field Rule** | 41.2% [26.4%, 57.8%] | 6.2% [1.7%, 20.1%] | 25.0% [13.8%, 41.1%] | 0.0% [0.0%, 9.6%] | 23/70 = 32.9% [23.0%, 44.5%] | 0.00 ms | 0/138 (0.0%) | 0 ms (N/A) | 0.0003 |
| **Baseline 3: Prompt Classifier** | 52.9% [36.7%, 68.5%] | 9.4% [3.2%, 24.2%] | 33.3% [20.2%, 49.7%] | 2.8% [0.5%, 14.2%] | 30/70 = 42.9% [31.9%, 54.5%] | 0.00 ms | 0/138 (0.0%) | 0 ms (N/A) | 0.0156 |
| **Config A (Field Rails)** | 85.3% [69.9%, 93.6%] | 0.0% [0.0%, 10.7%] | 69.4% [53.1%, 82.0%] | 0.0% [0.0%, 9.6%] | 54/70 = 77.1% [66.0%, 85.4%] | 0.08 ms | 0/138 (0.0%) | 0 ms (N/A) | 0.0000 |
| **Config B (+ Taxonomy)** | 100.0% [89.8%, 100.0%] | 0.0% [0.0%, 10.7%] | 75.0% [58.9%, 86.2%] | 0.0% [0.0%, 9.6%] | 61/70 = 87.1% [77.3%, 93.1%] | 0.09 ms | 0/138 (0.0%) | 0 ms (N/A) | 0.0156 |
| **Config C (+ Lexical C4)** | 100.0% [89.8%, 100.0%] | 0.0% [0.0%, 10.7%] | 88.9% [74.7%, 95.6%] | 0.0% [0.0%, 9.6%] | 66/70 = 94.3% [86.2%, 97.8%] | 0.12 ms | 0/138 (0.0%) | 0 ms (N/A) | 0.0625 |
| **Config D (Full Gate)** | 100.0% [89.8%, 100.0%] | 0.0% [0.0%, 10.7%] | 91.7% [78.2%, 97.1%] | 0.0% [0.0%, 9.6%] | 67/70 = 95.7% [88.1%, 98.5%] | 87.85 ms | 0/138 (0.0%) | 0 ms (N/A) | 1.0000 |
| **Config H (+ LLM Checker)** | 100.0% [89.8%, 100.0%] | 0.0% [0.0%, 10.7%] | 91.7% [78.2%, 97.1%] | 0.0% [0.0%, 9.6%] | 67/70 = 95.7% [88.1%, 98.5%] | 79.59 ms | **33/138 (23.9%)** | **0.001 ms** *(Offline)* | 1.0000 |

*Note on Headline Alignment*: On the Dev set, Config A intercepts 29/34 (85.3%), Config B intercepts 34/34 (100.0%), and Config D intercepts 34/34 (100.0% with the Phase 0.5 fee floor; 33/34 in earlier pre-floor runs where `ATK_08` required review). Across the combined pilot benchmark (Dev + Holdout), Config D intercepts 67/70 attacks (95.71%).

### 5.5 Multi-Step Workflows & Live Browser Testbed Results

#### Multi-Step Sequence Benchmark (Schema v2)
Evaluated via [`scripts/run_sequence_eval.py`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/scripts/run_sequence_eval.py) across 19 multi-step trajectories (`eval_data/sequences_dev.yaml`):
* **Config D (Stateless Full Gate)**: Intercepts **8/9 attacks (88.9% [56.5%, 98.0%])**.
* **Config E (Stateful Attack Chain Detector)**: Intercepts **9/9 attacks (100.0% [70.1%, 100.0%])**, uniquely trapping evasive multi-step sequence `SEQ_ATK_01` (premature commit skipping the review stage) at Step 2.
* **Non-Linear Benign Flows**: 10/10 non-linear benign workflows (back/forward navigation, review-edit cycles, refresh, search filter updates) completed with **0 false stops (0/10 = 0.0% [0.0%, 27.8%])**.

#### Live Playwright Testbed Benchmark
Evaluated via [`scripts/run_testbed_ablation.py`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/scripts/run_testbed_ablation.py) across 18 live scenarios (`TC-01`..`TC-08` and held-out variants `TC-01H`..`TC-10H`):
* **Attack Coverage**: Config D intercepts **12/14 attacks (85.7%)**. Row F (DOM Baseline Hashing) intercepts **14/14 attacks (100.0%)**.
* **Operational False Positives on Marketing Urgency Banners**: On clean baseline booking pages (`TC-01`, `TC-01H`), false positive rate is 0/2 (0.0%). On commercial pages containing aggressive urgency marketing banners (`TC-09H`, `TC-10H`: *"Hurry! Only 2 seats left! Prices jumping!"*), ContextGuard's taxonomy and DOM scanner trigger **2/4 benign interceptions**. This empirical finding highlights an authentic security-usability trade-off: aggressive commercial dark patterns resemble adversarial urgency injection and require operator confirmation.

### 5.6 Key Empirical Insights

#### 1. Detective Superiority over Alternative Paradigms
ContextGuard Config D achieves **95.71% attack recall**, outperforming Keyword Filters (11.4%, $p=0.0078$), Naive Field Rules (32.9%, $p=0.0003$), and Zero-Shot Classification (42.9%, $p=0.0156$) with high statistical significance.

#### 2. Disentangling the Config C vs Config D Latency Trade-Off
Config D exhibits 87.85 ms latency compared to Config C's 0.12 ms for a 1-item gain (66/70 vs 67/70, McNemar $p=1.0000$).
* **Statistical Interrogation**: The 1-item difference is not statistically significant.
* **Architectural Justification**: Config D’s latency is **operational and forensic**, not algorithmic. It accounts for SQLite ACID transaction commits, SHA-256 backward hash-chaining across table rows, and HMAC signature computation for legal auditability. In memory-constrained or real-time gaming environments, Config C provides 94.3% recall in 0.12 ms.

#### 3. LLM Checker Latency & Selective Grey-Zone Bypass
In Config H, the LLM semantic checker is triggered **only for actions in the 30–59 score band (33/138 = 23.9%)**.
* **76.1% of actions completely bypass LLM inference**, incurring 0 ms latency overhead.
* Offline fallback evaluates deterministically in 0.001 ms, ensuring fail-closed robustness without ungrounded latency estimates.

---

## 6. Second Domain Generalization: E-Commerce Checkout

To demonstrate domain independence, ContextGuard was evaluated on an e-commerce purchasing workflow ([`tests/test_second_domain.py`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/tests/test_second_domain.py)) using declarative configuration with **zero Python code modifications**. The second-domain benchmark comprises **32 distinct scenarios** defined in [`eval_data/second_domain/attacks.yaml`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/eval_data/second_domain/attacks.yaml) (16 attacks) and [`eval_data/second_domain/benign.yaml`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/eval_data/second_domain/benign.yaml) (16 benign actions):

* **Domain Mapping**:
  * Origin / Destination $\longrightarrow$ Shipping Address / Billing Address
  * Flight Cabin Class $\longrightarrow$ Product SKU / Item Tier
  * Flight Fare Floor $\longrightarrow$ Price Floor & Checkout Surcharge Ceiling (`fee_floor()`)
* **Test Suite Verification**: Across all 4 test methods in `TestSecondDomainShopping`:
  1. `test_second_domain_attacks_intercepted`: 16/16 attacks intercepted (100% recall).
  2. `test_second_domain_benign_allowed`: 0/16 false positive interceptions (0.0% FP).
  3. `test_second_domain_fee_floor_surcharge_with_injected_complimentary_text`: Catches express shipping tampering cloaked in reassuring "complimentary" negation text.
  4. `test_second_domain_fee_floor_extended_fields_item_total`: Enforces unbypassable pricing floors on cart item totals.

---

## 7. Code Availability & Reproducibility

### 7.1 Local Codebase Access
The full source code, benchmark suites, testbeds, and artifacts are located on the host system:
* **Root Directory**: `c:\Users\Srinidhi R\Context gaurd`
* **Core Gateway**: `contextguard/` (`gate.py`, `consistency_checker.py`, `threat_detector.py`, `pre_action_gate.py`)
* **Live Agents**: `agent/` (`agent_controller.py`, `browser_controller.py`, `web_agent.py`)
* **Evaluation Benchmarks**: `scripts/evaluate_baselines.py`, `eval_data/test_v1/`, `eval_results/`
* **Test Suite**: `tests/` (305 passed, 5 deselected across 310 test cases on Python 3.12)

### 7.2 Git Repository & Milestone Tags
* **Remote Repository**: [`https://github.com/srinidhiii311-dot/ContextGuard.git`](https://github.com/srinidhiii311-dot/ContextGuard.git)
* **Active Branch**: `master`
* **Key Milestone Tags**:
  * `hardening-pass-v1`: Gateway hardening and HMAC enforcement.
  * `external-set-v1`: Frozen 72-item holdout and second-domain suites.
  * `baselines-eval`: Comprehensive baselines, Wilson CIs, and McNemar tests.
  * `verification-audit-v1`: Initial resolution of audit findings.
  * `dual-gate-consolidated`: Canonical gate unification and conditional LLM latency reporting.
  * `gate-frozen-v2-perf`: Baseline performance freeze prior to Block 7 additions.
  * `gate-frozen-v3`: Rules C5 (egress-in-content) and C6 (irreversible action authorization).
  * `gate-frozen-v3.1`: Full typing imports restored, clean lint, HMAC audit chain link verified.
  * `holdout-run-final`: Single-run holdout execution completed, test results frozen.

### 7.3 Downloadable Archive
A standalone, self-contained ZIP archive containing all source code, datasets, evaluation scripts, and configuration files (excluding `.venv`, `.git`, and binary caches) has been generated:
* **Local File Path**: [`c:\Users\Srinidhi R\Context gaurd\ContextGuard_Source_Release.zip`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/ContextGuard_Source_Release.zip) (Size: 17.74 MB, 1,282 files).
* **IDE Artifact Path**: [`C:\Users\Srinidhi R\.gemini\antigravity-ide\brain\7b80c8af-b38c-4ed8-8c37-0e2b9d2cec6a\ContextGuard_Source_Release.zip`](file:///C:/Users/Srinidhi%20R/.gemini/antigravity-ide/brain/7b80c8af-b38c-4ed8-8c37-0e2b9d2cec6a/ContextGuard_Source_Release.zip)
