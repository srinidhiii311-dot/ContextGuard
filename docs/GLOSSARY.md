# ContextGuard Canonical Architecture Glossary (G7)

This glossary establishes the single source of truth for all naming conventions, layer identifiers, defensive configurations, and comparative baselines across ContextGuard code, documentation, benchmarks, and research manuscripts.

---

## 1. Canonical Layer Identifiers (L0 – L11)

| Layer ID | Constant Name | Canonical Name | Implementation File | What it actually computes / executes |
|---|---|---|---|---|
| **L0** | `LAYER_L0_EGRESS_GUARD` | Egress & Dispatch Guard | `agent/browser_controller.py` | Playwright `context.route` network egress filter, intent origin allowlist, popup/download blocker. |
| **L1** | `LAYER_L1_INTENT_LOCK` | Intent Anchor & Schema Lock | `contextguard/gate.py` | Ingests initial user prompt into immutable `TrustedIntent` dataclass; locks origin, destination, cabin class, date, budget. |
| **L2** | `LAYER_L2_THREAT_TAXONOMY` | Known Threat Taxonomy Classifier | `contextguard/threat_detector.py` | Regex and pattern hint matcher across 7 threat categories and 49 attack pattern indicators. |
| **L3** | `LAYER_L3_LEXICAL_DEVIATION` | Lexical n-gram Vector Deviation | `contextguard/threat_characterizer.py` | Tokenizes words and character 3-grams, computing log-frequency vector space cosine distance $D_{\cos} = 1 - \frac{u \cdot v}{\|u\| \|v\|}$. *(Note: Deterministic n-gram lexical cosine metric, NOT a neural foundation model embedding).* |
| **L4** | `LAYER_L4_DOM_BASELINE` | DOM Baseline Region Hash Verifier | `contextguard/dom_baseline.py` | SHA-256 structural region hash comparison with dynamic attribute masking (`id`, timestamps, session tokens) to detect rogue iframe/form drift. |
| **L5** | `LAYER_L5_HIDDEN_CONTENT` | Computed-Style Hidden Content Scanner | `contextguard/hidden_content.py` | Headless Playwright script querying computed styles (`opacity: 0`, `display: none`, `visibility: hidden`, offscreen coordinates) to catch invisible text injections. |
| **L6** | `LAYER_L6_CHAIN_DETECTOR` | Stateful Trajectory Chain Detector | `contextguard/chain_detector.py` | Multi-step sliding window state machine detecting staged evasion patterns across action sequences. |
| **L7** | `LAYER_L7_LLM_CHECKER` | Selective Grey-Zone LLM Reviewer | `contextguard/llm_checker.py` | Invoked strictly when continuous risk score is in the ambiguous 30–59 band. Executes structured JSON prompt review; operates in raise-only mode. |
| **L8** | `LAYER_L8_HARD_RULE_FLOOR` | Deterministic Hard-Rule Floor & Price Cap | `contextguard/consistency_checker.py` | Unconditional final checks: navigation boundary lock, origin/destination field matching, and `fee_floor()` price delta verification. Cannot be downgraded by ML/LLM scores. |
| **L9** | `LAYER_L9_POLICY_ENGINE` | Continuous Risk & Policy Engine | `contextguard/risk_engine.py`, `contextguard/policy_engine.py` | Multi-factor weighted score calculation ($R \in [0, 100]$) and mapping to graduated decisions: `ALLOW`, `ALLOW_WITH_FLAG`, `REQUIRE_CONFIRMATION`, `BLOCK`. |
| **L10** | `LAYER_L10_HUMAN_APPROVAL` | Human-in-the-Loop Approval State Machine | `contextguard/approvals.py` | Role-based authorization (JWT RBAC), two-person rule for high risk ($R \ge 80$), and fail-closed timeout-to-deny. |
| **L11** | `LAYER_L11_AUDIT_LOG` | Tamper-Evident SHA-256 HMAC Audit Log | `contextguard/audit_log.py` | Append-only ACID SQLite transactions with backward-linked SHA-256 chain hashes and periodic external HMAC checkpoints. |

---

## 2. Defensive Configurations (Configs A – H)

| Config ID | Constant Name | Name & Components Included |
|---|---|---|
| **Config A** | `CONFIG_A_FIELD_RAILS` | **Field Rails Only**: Intent lock (L1) + Basic field checking (L8 partial). |
| **Config B** | `CONFIG_B_TAXONOMY` | **Field Rails + Taxonomy**: Config A + Known Threat Taxonomy Classifier (L2). |
| **Config C** | `CONFIG_C_LEXICAL` | **Config B + Lexical Deviation**: Config B + Lexical n-gram cosine deviation (L3). |
| **Config D** | `CONFIG_D_FULL_GATE` | **Canonical Full Gate**: Config C + ML Risk Engine (L9) + Deterministic Hard Floor (L8) + Tamper-Evident Audit Logging (L11). |
| **Config E** | `CONFIG_E_CHAIN` | **Config D + Chain Detector**: Config D + Stateful Multi-Step Trajectory Chain Detector (L6). |
| **Config F** | `CONFIG_F_DOM_HASH` | **Config D + DOM Baseline**: Config D + Live DOM Baseline Region Hashing (L4). |
| **Config G** | `CONFIG_G_HIDDEN_SCAN` | **Config D + Hidden Content**: Config D + Computed-Style Hidden Content Scanner (L5). |
| **Config H** | `CONFIG_H_LLM` | **Config D + LLM Reviewer**: Config D + Selective Grey-Zone LLM Reviewer (L7). |

---

## 3. Comparative Baselines (Baselines 0 – 5)

| Baseline ID | Constant Name | Canonical Name | True Nature & Definition |
|---|---|---|---|
| **Baseline 0** | `BASELINE_0_UNPROTECTED` | Unprotected Agent | Direct browser execution without any pre-action inspection or filtering. |
| **Baseline 1** | `BASELINE_1_KEYWORD_FILTER` | Keyword Filter | Regex search across page text looking for prompt injection phrases ("ignore previous", "system prompt"). |
| **Baseline 2** | `BASELINE_2_NAIVE_FIELD_RULE` | Naive Field Rule | Simple string equality on action value vs intent field; lacks alias resolution, airport codes, or negation handling. |
| **Baseline 3** | `BASELINE_3_HEURISTIC_CLASSIFIER` | Heuristic Prompt Classifier | Offline pattern-based heuristic evaluator mimicking prompt-classification heuristics. *(Previously mislabelled "Zero-Shot Prompt Judge" despite 0.00 ms runtime and no model calls).* |
| **Baseline 4** | `BASELINE_4_REAL_LLM_JUDGE` | Real Local LLM Judge | Independent LLM evaluation calling a local model (Ollama / Llama-3-8B); logs real execution latency and records calls to `eval_results/llm_calls.csv`. |
| **Baseline 5** | `BASELINE_5_INTENT_ALLOWLIST` | Strict Intent Allowlist | Strict structural allowlist permitting only actions whose target and value are explicitly declared in the locked intent. |

---

## 4. Prohibited & Retired Terminology (Banned Phrases)

The following terms are formally retired and must not appear in benchmark headers, published documentation, or paper drafts:

1. **"Vector Embedding" for L3**:  
   *Reason*: Misleads reviewers into expecting dense embeddings from neural foundation models (e.g., text-embedding-ada-002, BERT).  
   *Replacement*: **"Lexical n-gram vector deviation"** or **"Lexical token deviation"**.

2. **"Zero-Shot LLM Judge" for Baseline 3**:  
   *Reason*: Baseline 3 ran in 0.00 ms via an offline regex/heuristic rule without querying any LLM.  
   *Replacement*: **"Heuristic Prompt Classifier"**. (Reserve "LLM Judge" strictly for Baseline 4 with actual logged calls).

3. **"Overall Attack Recall" or "Pooled Recall"**:  
   *Reason*: Conflates a tuned developer dataset (34 items) with a frozen holdout dataset (36 items), violating statistical separation.  
   *Replacement*: Report **"Dev (tuned) Recall"** and **"Holdout Recall"** in separate columns. Headline numbers must quote holdout/test data only.

4. **"Zero-Code Generalization" for Domain 2 (E-Commerce)**:  
   *Reason*: E-commerce evaluation required adding schema field handlers (`cart_total`, `shipping_fee`, `gift_wrap`) into `consistency_checker.py`.  
   *Replacement*: **"Domain Adaptation Study"**.
