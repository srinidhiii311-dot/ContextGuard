# ContextGuard Dataset Specification & Validity Audit (Block 6d)

This document records the structural audit, canonical sandbox route reconciliation, and selective regeneration of the ContextGuard benchmark datasets across `dev` and `test` splits.

---

## 1. Audit Context and Strict Integrity Guarantees

> [!IMPORTANT]
> **Audit Timing & Test Isolation**:
> 1. The structural validity audit and corrections were performed **after** the exploratory dev analysis (Block 6c) and strictly **before** any evaluation or execution of the frozen gate on the test split.
> 2. The test split was **never** evaluated by the gate during this audit. Test split inspection was restricted strictly to automated aggregate rule/domain violation counts via `analysis/validity_check.py` without logging or inspecting case content, targets, values, or model predictions.
> 3. **Gate Freeze**: Zero gate or policy code was modified. The gate remains strictly frozen at `gate-frozen-v2-perf`.
> 4. **Selective Regeneration**: Only cases failing structural validity rules were regenerated using deterministic seeds. Valid cases were preserved **byte-identical** from original files. Original datasets and hashes are backed up in `data_original/`.

---

## 2. Structural Validity Rules Checked

Every case across attacks and benign for dev and test was audited structurally without gate calls against four invariant rules:

| Rule | Description | Validation Logic |
| :--- | :--- | :--- |
| **Rule a: Real Route** | `page_url` must be an authentic route in the domain's sandbox application | Checked against canonical endpoints in `backend/mock_site/routes.py` and `sandboxes/*/app.py` |
| **Rule b: Snapshot Consistency** | `page_snapshot_ref` must align with `page_url` path | Format `<path>#<slot_or_none>` must have `<path> == urlparse(page_url).path` |
| **Rule c: Target Existence** | Action target selector must exist on that page or be a declared injection slot / neutral field | Checked against `PAGE_SELECTORS[domain][path]`, declared injection slots, and neutral field sets |
| **Rule d: Value Types** | Typed values must match field semantics | Positive numbers for `#amount`, valid email regex for `#*-email`, valid identifiers for `#*-account` |

---

## 3. Violations Detected in Original Datasets (`data_original/`)

### Initial Audit Summary (Pre-Correction)

| Dataset File | Total Cases | Invalid Cases | Rule a (Route) | Rule b (Snapshot) | Rule c (Target) | Rule d (Type) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`attacks/dev/cases.jsonl`** | 280 | 219 (78.2%) | 24 | 219 | 0 | 0 |
| **`benign/dev/cases.jsonl`** | 400 | 321 (80.2%) | 13 | 321 | 0 | 0 |
| **`attacks/test/cases.jsonl`** | 220 | 187 (85.0%) | 56 | 187 | 0 | 0 |
| **`benign/test/cases.jsonl`** | 200 | 155 (77.5%) | 6 | 155 | 6 | 0 |
| **Total** | **1,100** | **882 (80.2%)** | **99** | **882** | **6** | **0** |

### Root Causes Identified
1. **Flight Sandbox Route Discrepancy**: The generator previously assigned `#confirm-booking` to `http://127.0.0.1:8000/book`. However, in the real flight sandbox (`sandboxes/flight/manifest.json` and `backend/mock_site/routes.py`), `/book` does not exist; the flight booking review page is `/review`, where `#confirm-booking` resides.
2. **Snapshot Reference Decoupling**: The generator cycled `page_snapshot_ref` using modulo indexing on domain page lists independently of `proposed_action.page_url`. This caused hundreds of cases where the snapshot path indicated one page while the action occurred on another.
3. **Domain Route Mismatches for Adversarial Families**:
   - `form_action_override`: Set `page_url` to `/checkout` across non-flight domains; banking, healthcare, and email have no `/checkout`.
   - `overlay_clickjack`: Set `page_url` to `/transfer` across non-ecommerce domains; flight, healthcare, and email have no `/transfer`.
   - `url_obfuscation` & `multi_step_instruction`: Defaulted `page_url` to `/`; in banking and healthcare, `/` 404s (landing pages are `/login`, `/accounts`, or `/dashboard`).
4. **Target Selector Mismatch on `/book`**: In `benign/test`, 6 cases attempted `#confirm-booking` on `/book`, failing target existence because `/book` is not a registered route.

---

## 4. Generator Corrections & Selective Regeneration

The generator in `harness/build_datasets.py` was updated systematically:
- **Canonical Domain Routes**: `DOMAIN_SPECS["flight"]` updated with real pages `["/", "/search", "/results", "/passenger", "/review", "/confirm"]` and `#confirm-booking` on `/review`.
- **Domain-Specific Adversarial Routing**:
  - `form_action_override`: flight $\to$ `/review`, ecommerce $\to$ `/checkout`, banking $\to$ `/transfer`, healthcare $\to$ `/appointments`, email $\to$ `/compose`.
  - `overlay_clickjack`: ecommerce $\to$ `/checkout`, banking $\to$ `/transfer`, flight $\to$ `/review`, healthcare $\to$ `/appointments`, email $\to$ `/compose`.
  - `url_obfuscation` & `multi_step_instruction`: banking $\to$ `/accounts`, healthcare $\to$ `/dashboard`, email $\to$ `/inbox`, flight/ecommerce $\to$ `/`.
- **Deterministic Snapshot Binding**: `page_snapshot_ref` is derived directly from `urlparse(proposed_action.page_url).path`.
- **Review Step DOM Representation**: For flight review actions, page state HTML and visible text include review context (`"Review your flight reservation details below."`).
- **Selective Merge**: Cases that previously passed all validity rules were preserved byte-for-byte; only invalid cases were replaced.

### Post-Correction Validity Audit (`analysis/validity_check.py`)

| Dataset File | Total Cases | Invalid Cases | Preserved (Byte-Identical) | Regenerated (Clean) | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`attacks/dev/cases.jsonl`** | 280 | **0** | 61 (21.8%) | 219 (78.2%) | **PASSED** |
| **`benign/dev/cases.jsonl`** | 400 | **0** | 79 (19.8%) | 321 (80.2%) | **PASSED** |
| **`attacks/test/cases.jsonl`** | 220 | **0** | 33 (15.0%) | 187 (85.0%) | **PASSED** |
| **`benign/test/cases.jsonl`** | 200 | **0** | 45 (22.5%) | 155 (77.5%) | **PASSED** |
| **Total Benchmark** | **1,100** | **0** | **218 (19.8%)** | **882 (80.2%)** | **100% VALID** |

---

## 5. Denominator Reconciliation

Every denominator across splits satisfies exact structural equality:

```text
Reconciliation: DEV 400 (benign) + 70 (uncompromised) + 210 (compromised) == 680 (split size) [TRUE]
Reconciliation: TEST 200 (benign) + 30 (uncompromised) + 190 (compromised) == 420 (split size) [TRUE]
```

### Detailed Breakdown Table

| Split | Benign Standard | Benign Hard | Benign Total | Attack Uncompromised | Attack Compromised | Attack Total | Split Total |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **DEV** | 300 | 100 (25.0%) | 400 | 70 | 210 | 280 | **680** |
| **TEST** | 150 | 50 (25.0%) | 200 | 30 | 190 | 220 | **420** |
| **Total** | **450** | **150 (25.0%)** | **600** | **100** | **400** | **500** | **1,100** |

---

## 6. Dataset Cryptographic SHA-256 Hashes

### Current Active Hashes (`dataset_hashes.json`)
```json
{
  "attacks_dev_sha256": "93468f64f316f05479bdba9ffd8f73108ccfabc39991529e8a518a8d75a9b850",
  "attacks_test_sha256": "daa2f8bd158bba40ea94f19e2d731b9ce6b7d533a70bf09cda581c48baecee24",
  "benign_dev_sha256": "41c15f618268461cb4bee13d8860de1a7792f0213530f82b9c8526463cf73f4c",
  "benign_test_sha256": "66f900c52b91b2b509729b8fc03bef10619e716ab339242bb8298a03589c8c29"
}
```

> [!NOTE]
> During Block 7c (gate-frozen-v3), `authorized_actions` was populated on `locked_intent` in the dataset generator (`harness/build_datasets.py`) for user tasks requesting legitimate execution (e.g. flight booking, email sending), leaving all non-irreversible cases byte-identical.


### Original Baseline Hashes (`data_original/dataset_hashes.json`)
```json
{
  "attacks_dev_sha256": "efd94860ce1feefb7b7f835e3084adabf4c5f025df81bb93fdb3a59412c6fc28",
  "attacks_test_sha256": "e5847a75185d3eb5e6857e8a3263fd42e0d266a762f8133bc7f25b0bb93383dc",
  "benign_dev_sha256": "9d82f88fb4ee7bb09782e7499ac5f9c0df4479ee107ce3e6107ce8acd764f4b8",
  "benign_test_sha256": "54864e6db6d6702ce364db264b01642f24b7eeb697df95893ffbd04132f65989"
}
```

---

## 7. Dev Split Impact: Before vs After Re-Evaluation

The frozen gate (`gate-frozen-v2-perf`) was re-evaluated on the corrected DEV split (`seed=42`).

### Key Findings
1. **Compromised Attack Detection & ASR are strictly identical**:
   - `dual_gate`: Recall remains **92.86% (195/210)**, ASR remains **7.14% (15/210)**.
   - Attack cases retained their exact divergent/uncompromised behaviors.
2. **Benign False Intercepts drop to 0.0%**:
   - `benign_normal_fp_rate`: dropped from **3.33% (10/300)** to **0.0% (0/300)**.
   - `benign_hard_fp_rate`: dropped from **3.00% (3/100)** to **0.0% (0/100)**.
   - All 13 flight false intercepts were completely eliminated.
3. **Utility reaches 100.0%**:
   - `utility_rate`: increased from **97.23% (457/470)** to **100.0% (470/470)**.
4. **Resolution of Flight Intercepts**:
   - Confirms that the earlier 13 false intercepts were entirely caused by the dataset generator placing `#confirm-booking` on `/book` instead of `/review`. With the action routed to `/review`, `PROCESS_INTEGRITY` (Check 4a) correctly allows the confirmation action without any modifications to gate logic.

