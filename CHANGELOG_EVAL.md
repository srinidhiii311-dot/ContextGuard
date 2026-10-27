# ContextGuard Evaluation Dataset Changelog (`CHANGELOG_EVAL.md`)

This changelog records all creation, versioning, freeze, and retirement events for evaluation datasets in `eval_data/`, adhering strictly to Standing Rule 2 of the [Improvement & Completion Plan](docs/IMPROVEMENT_PLAN.md):
> *"Never edit an existing dev item to make it pass. Log any dataset change and its reason in `CHANGELOG_EVAL.md`."*

---

## Dataset Inventory & Roles (as of October 27, 2026)

| Dataset Path | Item Count | Role | May Tune On It? | Status |
|---|:---:|---|:---:|:---:|
| `eval_data/attacks.yaml` | 34 | Dev Adversarial Attacks (Flight) | Yes (label "dev (tuned)") | Active (v1.0) |
| `eval_data/benign.yaml` | 32 | Dev Benign Actions (Flight) | Yes (label "dev (tuned)") | Active (v1.0) |
| `eval_data/sequences_dev.yaml` | 19 | Dev Multi-Step Sequences (Flight) | Yes (label "dev (tuned)") | Active (v1.0) |
| `eval_data/test_v1/` | 72 (36 atk, 36 ben) | Independent Holdout Suite v1 | **NO** | **Burned / Used** (diagnostics read; never tune) |
| `eval_data/holdout_attacks.yaml` | 36 | Duplicate of `test_v1/attacks.yaml` | **NO** | **Burned / Used** |
| `eval_data/holdout_benign.yaml` | 36 | Duplicate of `test_v1/benign.yaml` | **NO** | **Burned / Used** |
| `eval_data/second_domain/` | 32 (16 atk, 16 ben) | E-Commerce Shopping Checkout | No | Active (Adaptation study) |
| `eval_data/borderline_items.yaml` | 12 | Borderline Grey-Zone Items | Yes | Active (L7 evaluation) |
| `eval_data/test_v2/` | Target: 80 (40 atk, 40 ben) | Independent Holdout Suite v2 | **NO** | Planned (Commissioned for P8) |

---

## Log of Changes

### 2026-10-27: P0 Baseline Freeze & Provenance Audit
- **Action**: Formally archived `eval_data/test_v1/` and `eval_data/holdout_*.yaml` as **"burned / used"** per Problem E4. Diagnostics in prior audit rounds loaded these files and analyzed borderline items; therefore, out-of-sample purity is degraded. Reruns permitted for historical tracking only; no gate rules or thresholds may be modified against them.
- **Action**: Created `eval_data/PROVENANCE.md` documenting authors, dates, tools, and observation boundaries for all datasets.
- **Action**: Established strict lock on existing dev items in `eval_data/attacks.yaml` and `eval_data/benign.yaml`. Any new edge cases must be added to a new `hard_dev.yaml` generated via the adaptive attacker (Phase P6).
