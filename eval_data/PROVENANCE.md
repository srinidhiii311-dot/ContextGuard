# Evaluation Datasets Provenance & Audit Ledger (`eval_data/PROVENANCE.md`)

This document records the origin, authorship, creation date, generative tools, access history, and methodological status of all benchmark datasets in `eval_data/`, fulfilling requirement **E4** of the [Improvement & Completion Plan](docs/IMPROVEMENT_PLAN.md).

---

## Cryptographic Baseline Hashes (Tamper-Proof Ledger — Gap 5)

Any change to these frozen datasets will cause CI to fail immediately via [`tests/test_frozen_datasets_integrity.py`](file:///c:/Users/Srinidhi%20R/Context%20gaurd/tests/test_frozen_datasets_integrity.py):

| Dataset Path | Role / Status | SHA-256 Digest |
|---|:---:|---|
| `eval_data/test_v1/attacks.yaml` | Holdout v1 (Burned) | `eb396c6ec5f6e857ac456d0fa64e7eafb1d4d1243cae304d2e477f065e7898e8` |
| `eval_data/test_v1/benign.yaml` | Holdout v1 (Burned) | `b62a573106077c508a905b8d8061f2a535da4307db6ec54ff15f3b7371c98622` |
| `eval_data/holdout_attacks.yaml` | Holdout v1 (Burned) | `eb396c6ec5f6e857ac456d0fa64e7eafb1d4d1243cae304d2e477f065e7898e8` |
| `eval_data/holdout_benign.yaml` | Holdout v1 (Burned) | `b62a573106077c508a905b8d8061f2a535da4307db6ec54ff15f3b7371c98622` |
| `eval_data/second_domain/attacks.yaml` | E-Commerce Adaptation | `4805919b97485bfbebefc2a976e56f5fafded6d81ab8c85b2b99b2191bd60d89` |
| `eval_data/second_domain/benign.yaml` | E-Commerce Adaptation | `fcba6c4cc5c056722657d43641c4f6e793467b9c3285e2b3b8591d5e4422bdd2` |

---

## 1. Developer Suite: `eval_data/attacks.yaml` & `eval_data/benign.yaml`

- **Domain**: Flight Reservation & Airline Booking.
- **Dataset Size**: 34 attack scenarios, 32 benign user actions (+ 12 urgency marketing benign testbed scenarios).
- **Author**: Srinidhi R & project contributors.
- **Date Created**: September 2026.
- **Tools Used**: Manual scenario authoring, Playwright DOM inspector, synthetic prompt injection generator.
- **Role**: **Development & Calibration (Tuned)**.
- **Observation Status**: Seen by defensive rule developers during initial gate tuning. Rules in `contextguard/gate.py`, `contextguard/consistency_checker.py`, and `contextguard/threat_detector.py` were iteratively tested and tuned against these scenarios.
- **Reporting Label**: Must always be reported with the explicit label: `"dev (tuned)"`. Never quoted as headline recall without holdout qualification.

---

## 2. Independent Holdout Suite v1: `eval_data/test_v1/` & `eval_data/holdout_*.yaml`

- **Files**:
  - `eval_data/test_v1/attacks.yaml` (36 items) / `eval_data/holdout_attacks.yaml`
  - `eval_data/test_v1/benign.yaml` (36 items) / `eval_data/holdout_benign.yaml`
- **Domain**: Flight Reservation & Ancillary Booking.
- **Dataset Size**: 72 total items (36 adversarial evasion, 36 benign lifecycle actions).
- **Author**: Autonomous generation harness with external seed variation.
- **Date Created**: October 2026.
- **Tools Used**: LLM-assisted scenario synthesis with randomized slot assignments, novel evasion wrappers, and dark-pattern urgency banners.
- **Original Role**: Out-of-sample holdout validation.
- **Current Status**: **BURNED / USED** (Archived).
  - *Reason for Burned Status*: During October 2026 verification audits, diagnostics scripts loaded `holdout_attacks.yaml`, inspected borderline risk scores (30–59 band), and generated failure breakdowns. Because gate developers observed these specific item IDs and grey-zone behaviors, `test_v1` can no longer serve as an uncompromised pristine holdout.
- **Permitted Usage**: Regression and historical comparison only. Reruns permitted; **no gate rules, thresholds, or regex patterns may be altered to accommodate test_v1 failures**.
- **Reporting Label**: Must be reported as `"holdout (v1, used)"`.

---

## 3. Multi-Step Trajectories: `eval_data/sequences_dev.yaml`

- **Domain**: Flight Reservation (Schema v2 stateful sequences).
- **Dataset Size**: 19 multi-step sequence trajectories (9 multi-step attack chains, 10 non-linear benign flows).
- **Author**: Srinidhi R.
- **Date Created**: October 2026.
- **Tools Used**: Scripted trajectory simulator (`scripts/run_sequence_eval.py`).
- **Role**: **Development Trajectories ("dev (tuned)")**.
- **Observation Status**: Used to develop and calibrate `contextguard/chain_detector.py` (L6 state machines).
- **Future Requirement**: Needs an independently authored held-out sequence set ($\ge 20$ held-out sequences) for Phase P8.

---

## 4. Second Domain: `eval_data/second_domain/`

- **Files**:
  - `eval_data/second_domain/attacks.yaml` (16 items)
  - `eval_data/second_domain/benign.yaml` (16 items)
- **Domain**: E-Commerce Shopping & Checkout (Product tiers, cart subtotals, shipping surcharges, gift-wrapping fees).
- **Dataset Size**: 32 total items.
- **Author**: Project evaluation contributors.
- **Date Created**: October 2026.
- **Role**: **Domain Adaptation Study**.
- **Observation Status**: Required domain-specific schema definitions (`cart_total`, `shipping_fee`, `gift_wrap`) added to `contextguard/consistency_checker.py`.
- **Reporting Label**: Reported strictly as an **"adaptation study"**, NOT "zero-code generalization".

---

## 5. Borderline Suite: `eval_data/borderline_items.yaml`

- **Domain**: Ambiguous flight reservation requests (30–59 risk grey zone).
- **Dataset Size**: 12 curated borderline scenarios.
- **Author**: Srinidhi R.
- **Date Created**: October 2026.
- **Role**: Unit and integration testing for Layer L7 (`contextguard/llm_checker.py`).
- **Observation Status**: Specifically designed to stress the transition boundary between `ALLOW_WITH_FLAG` and `REQUIRE_CONFIRMATION`.
