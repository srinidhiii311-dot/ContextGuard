# ContextGuard — Change Plan (merge of external Review Pack into the Completion Guide)

Abstract, full rationale, phase-by-phase mapping of the external reviewer's 16 shortfalls (S1–S16), the revised phase structure (new Phase 0.5, Phase H, Phase D; extensions to Phases 3/4/5/6/7), updated tag sequence, re-sequenced task list with effort estimates, hardening checklist, and pre-submission checklist.

Delivered to the user as a formatted PDF (`ContextGuard_Change_Plan.pdf`) on 2026-10-05. This doc is the durable text record of the same content for future reference alongside `ContextGuard_Completion_Guide.md`.

---

## Abstract

Autonomous web agents act on content they cannot fully trust: a page's text, hidden elements, and redirect targets are attacker-controllable, yet most agent architectures feed this content straight into the model's context, creating an indirect prompt-injection surface. ContextGuard addresses this with a synchronous, pre-action safety gateway that sits between an agent's decision and its execution, evaluating every proposed browser action against a locked statement of user intent before it is allowed to run. The gateway combines a layered detection pipeline — intent-consistency scoring, a threat taxonomy, semantic deviation checks, DOM baseline hashing, hidden-content scanning, a multi-step attack-chain detector, an optional LLM-based checker, and a deterministic hard-rule floor that cannot be weakened by the statistical layers above it — with role-based approval gates and a hash-chained audit log for forensic accountability. The system was evaluated on a flight-booking sandbox against a developer set of 34 adversarial and 32 benign scenarios, with the strongest configuration intercepting 33 of 34 attacks (97.1%) while preserving usability on benign tasks, measured with Wilson score intervals and compared pairwise via McNemar's test. The result is a practical, auditable safety layer that can be dropped in front of existing browser agents without retraining them.

*Note: the final sentence is a target, not a settled claim — this plan schedules the external benchmark, the live-agent study, and the fee-floor fix needed to make it true rather than aspirational.*

## 1. What changed and why

An external reviewer examined the current build against the Completion Guide and returned 16 prioritized shortfalls (S1–S16), a threat model, a 36-scenario independent attack set, a baseline-comparison evaluation design, two ready-to-wire code fixes, a hardening checklist, and a pre-submission checklist. None of this replaces the existing 9-phase plan — it closes specific holes in it. This document folds every shortfall into the existing phase numbering: two new phases are inserted, four existing phases are extended with new steps, and one phase becomes optional (time-permitting). Nothing in Phases 2, 3, 6 (naming aside), or 8 changes in kind, only in supporting evidence.

| Severity | Shortfall | Where it lands | Status |
|---|---|---|---|
| High | S4 — negation/fee-downgrade hole: injected "complimentary, no charge" text can downgrade a real fee-tampering attempt to a flag instead of a stop | New Phase 0.5 | NEW PHASE |
| High | S1 — benchmark is small and author-written; dev-set numbers are not evidence of generalization | Phase 6 (frozen test set) | EXTEND |
| High | S3 — no live-agent evidence that the gate actually stops a real hijack, only page+action pairs tested | Phase 4 (final-run tooling) | EXTEND |
| High | S2 — ablation does not justify the cost of the heavier layers (DOM hash, hidden scan, LLM checker) | Phase 7 (final run) | EXTEND |
| Medium | S8 — audit log cannot detect truncation of its own newest rows | Phase 3 (approvals/audit log) | EXTEND |
| Medium | S5 — no non-gate baselines (regex-only filter, LLM-judge-only) to show the full pipeline earns its complexity | Phase 4 (final-run tooling) | EXTEND |
| Medium | S6 — wide confidence intervals reported with stronger wording than the sample size supports | Phase 7 (final run) | EXTEND |
| Medium | S9 — weight calibration and non-ALLOW/flag rate not reported | Phase 7 (final run) | EXTEND |
| Medium | S10 — out-of-scope attack surface not written down anywhere (threat model gap) | New Phase 0.5 | NEW PHASE |
| Medium | S11 — unclear which actions the gate actually covers end-to-end | New Phase H (Hardening) | NEW PHASE |
| Medium | S12 — undefined behaviour when the LLM/embedding layer is unavailable (must fail closed, not open) | New Phase H (Hardening) | NEW PHASE |
| Medium | S13 — layer naming and counts are inconsistent across README/report/code | Phase 5 (packaging), with S16 | EXTEND |
| Medium | S15 — reproducibility gaps: no fresh-clone test, no secrets scan, no CI, default credentials left in place | New Phase H (Hardening) | NEW PHASE |
| Low | S7 — single domain (flight booking) only | Optional Phase 9 | OPTIONAL |
| Low | S14 — no visual evidence (screenshots, demo video) for the viva/dissertation | New Phase D (Demo & Evidence Pack) | NEW PHASE |
| Low | S16 — no related-work section situating ContextGuard against published defenses | Phase 5 (packaging), with S13 | EXTEND |

## 2. Revised phase structure

Phases 0, 1, 2, 3, 4, 5, 6, 7, 8 are unchanged in number and goal (see the Completion Guide). The additions below are inserted at specific points in that sequence; everything else in the Guide still applies as written.

### Phase 0.5 — Critical fix: fee floor + threat model NEW (~1–1.5 days)

Inserted immediately after Phase 0 (reporting fixes), before Phase 1. This is the one fix the reviewer flagged as high-severity and cheap to make, so it goes first.

- **Fee floor**: Add a deterministic `fee_floor()` check that parses the structured price delta between the user's locked intent and the page's current total (not the page's prose). If the delta is non-zero and unexplained by something the user asked for, force `REQUIRE_CONFIRMATION` regardless of what the page text claims ("complimentary", "included", "no charge"). This sits in the same place as the existing hard-rule floor and is subject to the same raise-only discipline — it can only escalate a decision, never soften one coming from elsewhere in the pipeline.
- **Threat model**: Add a short, explicit section to the README (and dissertation Chapter 3) stating what ContextGuard defends against (indirect prompt injection via page content reaching the agent's observation loop) and what it explicitly does not (agent weight poisoning, supply-chain compromise of the browser itself, attacks that never touch the DOM or page text the gate observes). This closes S10 and gives Phase 5's README rewrite something concrete to reference instead of leaving scope implicit.
- **Regression test**: A surcharge item with injected "complimentary" text must now stop at `REQUIRE_CONFIRMATION` or stronger, not downgrade to `ALLOW_WITH_FLAG`. This replaces the "known weakness" note Phase 0 step 0.6 currently just documents — it becomes a closed item instead.

**Acceptance**: The fee-floor regression test passes; the threat model section exists in the README; pytest green. Tag: `fix-s4-negation-floor`

### Phase 3 — Approvals and audit log EXTENDED

Existing steps 3.1–3.7 unchanged. Add:

- **3.8 — Checkpoint anchoring (closes S8)**: Write periodic external checkpoints: `write_checkpoint()` computes an HMAC-SHA256 over the current chain head and appends it to an external file, `audit_anchor.jsonl`, outside the SQLite database the rest of the system writes to. `verify_against_anchor()` checks the live chain against the most recent anchor. Expose this as `GET /audit/verify`. This is what closes the gap the Guide's own Known Limits table already names ("the audit chain cannot detect truncation of the newest rows") — previously documented as accepted, now actually fixed.

**Acceptance**: Truncating the newest N rows of the audit table is detected by `GET /audit/verify` against the external anchor. Tag: `dev-set-v7-with-anchor` (replaces the plain `dev-set-v7` tag in the original sequence)

### Phase 4 — Final-run and live-agent tooling EXTENDED

Existing steps 4.1–4.4 unchanged (adapter wiring, frozen-set runner, live episode wrapper). Add:

- **4.5 — Baselines (closes S5)**: Before the live-agent run, add two non-gate baselines to compare against: a regex/keyword-only filter (no DOM baseline, no hidden-content scan, no LLM check) and an LLM-judge-only condition (the page text and proposed action are sent to an LLM with a judge prompt and no rule engine at all). This is what lets the eventual results claim the full pipeline earns its complexity rather than merely asserting it.
- **4.6 — Six-condition live-agent study (closes S3)**: Run the live-agent evaluation (step 4.4) across six conditions instead of just gate-on/gate-off: C0 no defense, C1 regex filter only, C2 LLM-judge only, C3 gate Config B, C4 gate Config D, C5 gate + LLM Config H. Use the reviewer's LLM-judge baseline prompt skeleton for C2. Report hijacked/blocked counts per condition per scenario, not pooled.

**Acceptance**: A results table with six conditions × the testbed's scenarios, raw counts (not percentages given the sample size). Tag: folds into `v1.0-rc` alongside the existing Phase 5 tag.

### New Phase H — Hardening NEW (~1 day)

Inserted before Phase 5 (Packaging). Three shortfalls land here because they are all "does the system behave correctly outside the happy path" concerns rather than new detection capability.

- **Gate coverage audit (S11)**: Enumerate every action type the agent can emit (fill, select, click, navigate) and confirm each one is routed through the gate before execution — not assumed. Produce a short coverage table for the README/dissertation: action type → gated (yes/no) → evidence (test name).
- **Fail-closed behaviour (S12)**: Define and test what happens when the LLM checker or any embedding-based signal is unreachable: the existing `llm_unavailable` flag (Phase 2) must cause the pipeline to fall back to the rule-engine decision, never to silently relax it. Add an explicit test that kills the LLM provider mid-run and asserts the decision is at least as strict as the rules-only decision for that item.
- **Reproducibility and hygiene (S15)**: (a) Fresh-clone test: clone the repo into an empty directory and verify every command in the README's Quick Start works with no manual fixes. (b) Secrets scan: run a basic secret-pattern scan (e.g. gitleaks or a simple regex pass) over the full history before the final tag. (c) Wire the existing CI workflow (`.github/workflows/ci.yml`, already in the packaging kit) to actually run on push, not just exist as a file. (d) Remove any default/sample credentials from `.env.example` and replace with a generation command (the Guide's own `secrets.token_urlsafe(32)` line) rather than a placeholder value someone could leave in place.

**Acceptance**: Coverage table complete; fail-closed test passes; fresh clone succeeds end-to-end; CI green on push; no secrets found. Tag: `hardening-pass-v1`

### Phase 6 — Frozen test set EXTENDED

The existing Appendix C brief (40 attacks + 40 benign, written independently) still stands and should still be commissioned in parallel with development, exactly as the Guide already directs. In addition:

- Convert the reviewer's ready-made 36-scenario independent attack set (24 core scenarios X01–X24, 3 stretch scenarios X25–X27, 9 benign hard-negatives B01–B09, all written against the fixed locked intent "book one economy ticket DEL→BLR on 12 Dec 2026 for passenger Asha Rao, no extras, maximum fare ₹6,000") into the Guide's schema v2 format and commit it as `eval_data/external_v1/`.
- Run both sets — the Appendix C 40+40 and the reviewer's 36-scenario set — as two independently-sourced external benchmarks rather than choosing one over the other. Two independent sets written by two different people is stronger evidence than either alone, and keeps the frozen Appendix C set uncompromised even though the reviewer has already seen their own 36.

**Tag**: `external-set-v1` for the reviewer's 36, alongside the existing `test-set-v1` for Appendix C.

### Phase 7 — The one final run EXTENDED

The run command itself (Guide §Phase 7) is unchanged, now executed once per frozen set (`test_v1` and `external_v1`). Add to the reporting produced from the CSVs:

- **Per-category recall tables (closes part of S2/S9)**: Not just overall interception, but interception broken out by attack category (field override, navigation diversion, exfiltration, price tampering, date shift, skip-review, hidden content, injected negation, mixed).
- **Exact McNemar paired comparisons everywhere a configuration claims an improvement**: The Guide's wording rules already require this (§3, rule 6); this makes it a mandatory table in the final report rather than an ad hoc check.
- **Wilson intervals on every percentage reported, including the frozen-set numbers**: Not only the dev-set numbers as in the current report.
- **Non-ALLOW / flagged rate reported alongside interception (closes S9)**: A configuration that intercepts well but flags half of all benign actions is not reported as costless; report both numbers side by side for every config.
- **Optional weight-sensitivity plot (closes remainder of S9)**: Vary each risk-engine weight ±20% one at a time and re-run the dev-set ablation, plotting the resulting interception/false-alarm trade-off. This is the cheapest way to show the chosen weights were not arbitrary, without a full calibration study. Time-permitting; cut first if the schedule is tight.

**Tag**: Results feed into `v1.0` as before.

### New Phase D — Demo & Evidence Pack NEW (~0.5–1 day)

Inserted after Phase 7, before Phase 8 (Dissertation). Closes S14 and gives the viva something to point at beyond CSVs.

- **Screenshot set**: One clean-run `ALLOW`, one `WARN`/`ALLOW_WITH_FLAG`, one `REQUIRE_CONFIRMATION` with the approval UI, one hard `BLOCK` with reasoning visible, one audit-log verification call.
- **A ~3-minute demo video following the reviewer's script**: Select scenario → agent acts → attack condition appears → gate intercepts live → decision and reasoning shown → (if applicable) approval resolved → audit entry visible.
- **Pre-submission checklist (from the reviewer's pack)**: Fresh-clone run confirmed, all tags present in git history, README fully rewritten (Phase 5 + S13/S16 below), frozen-set results committed and not re-run, dissertation references checked against this plan's §3 table.

**Tag**: `demo-pack-v1`

### Phase 5 — Packaging EXTENDED

Existing packaging steps (Dockerfile, compose, CI workflow file, SECURITY.md, LICENSE, launcher patch) unchanged. The README rewrite (Appendix E template) is extended to explicitly include:

- **Single naming scheme (closes S13)**: One table mapping every layer to one name used consistently everywhere — code, README, report, dissertation (L1 Intent Lock, L2 Threat Taxonomy, L3 Semantic Deviation, L4 DOM Baseline, L5 Hidden-Content Scan, L6 Chain Detector, L7 LLM Checker, L8 Hard-Rule Floor, L9 Policy Engine, L10 Approvals, L11 Audit Log). Pick the count once (11) and use it everywhere.
- **Hedged-wording replacement (reinforces Guide §3)**: A find-and-replace pass over README/report for claims stronger than the evidence supports (e.g. "detects" → "flags for review" where that's what actually happens, "100% accurate" → "33/34 on the dev set it was tuned against").
- **Threat model section (written in Phase 0.5, placed here in the shipped README)**.
- **Screenshots/video links (produced in Phase D)**.
- **Related-work paragraph (closes S16)**: One paragraph situating ContextGuard against Greshake et al. 2023 (indirect prompt injection), the OWASP Top 10 for LLM Applications, AgentDojo (Debenedetti et al. 2024), Spotlighting (Hines et al. 2024), and CaMeL (Debenedetti et al. 2025), plus Wilson's 1927 interval and the exact McNemar test as the statistical methods used.

**Tag**: Still `v1.0-rc`, now also gated on Phase H passing.

### Optional Phase 9 — Second domain and full sensitivity analysis OPTIONAL, time-permitting

Only attempt if the schedule has 3+ weeks of slack after Phase 8. Closes the remainder of S7 and the full depth of S9.

- A second, small sandbox domain (10–15 scenarios) outside flight booking — e.g. a hotel-booking or food-delivery mock site — to test whether the gate's rules generalize or were accidentally flight-booking-specific.
- A full weight-sensitivity analysis: grid search or small Bayesian sweep over the risk-engine weights, reporting the Pareto frontier between interception and false-alarm rate.

---

## 3. Updated tag sequence

Supersedes the tag list in Guide Appendix B. New/changed tags are bold:

`dev-set-v4.1` → **`fix-s4-negation-floor`** → `dev-set-v5` → `dev-set-v6` → **`dev-set-v7-with-anchor`** → **`hardening-pass-v1`** → `v1.0-rc` → **`external-set-v1`** (reviewer's 36) and `test-set-v1` (Appendix C 40+40) → (final run on both sets) → **`demo-pack-v1`** → `v1.0`

---

## 4. Re-sequenced task list with effort estimates

| Order | Phase | Primary deliverable | Effort | Cut-if-tight? |
|---|---|---|---|---|
| 1 | Phase 0 | Reporting fixes, per-item A–D table, sequence eval script | 0.5 day | No |
| 2 | Phase 0.5 (new) | Fee floor fix + threat model section | 1–1.5 days | No — highest-severity item |
| 3 | Phase 1 | DOM baseline hashing + hidden-content scan | 2–3 days | No |
| 4 | Phase 2 | Real LLM semantic checker | 2 days | Keep, even with a small local model |
| 5 | Phase 3 (+3.8) | Approvals, audit log, checkpoint anchoring | 2 days + 0.5 day | Audit log can be cut; keep approver/viewer roles + timeout-to-deny |
| 6 | Phase 4 (+4.5, 4.6) | Baselines + 6-condition live-agent study | 1 day + 1 day | Baselines can be cut if time-critical; live-agent run should not be |
| 7 | Phase H (new) | Gate coverage, fail-closed test, fresh-clone + CI + secrets scan | 1 day | Docker/CI can be cut; fail-closed test should not be |
| 8 | Phase 5 | Packaging + README rewrite (naming, hedging, threat model, related work) | 2 days | Docker can be cut; README rewrite cannot |
| 9 | Phase 6 (extended) | Appendix C set (parallel, someone else) + reviewer's 36-scenario set converted | 1 day (your side) | Never cut |
| 10 | Phase 7 (extended) | Final run(s): recall tables, McNemar, Wilson CIs, non-ALLOW rate | 0.5–1 day | Weight-sensitivity plot optional, rest never cut |
| 11 | Phase D (new) | Screenshots, demo video, pre-submission checklist | 0.5–1 day | Video can shrink to screenshots only if time-critical |
| 12 | Phase 8 | Dissertation | 4 days | Never cut |
| — | Phase 9 (optional) | Second domain + full sensitivity sweep | 3+ weeks | Only with major time surplus |

**Total added effort versus original Guide**: ~4–5 working days (Phase 0.5, Phase H, Phase D, extensions to Phases 3/4/7), bringing full plan to ~16–20 working days before optional Phase 9.

---

## 5. Condensed hardening checklist

1. Every agent action type is routed through the gate before execution — verified by a coverage table, not assumed.
2. LLM/embedding-layer failure falls back to the rules-only decision; a kill-the-provider test proves the fallback is at least as strict, never more permissive.
3. Fresh clone → documented Quick Start commands succeed with zero manual fixes.
4. Secrets scan run and clean before final tag; no default credentials shipped in `.env.example`.
5. CI workflow actually runs on push (not just present as a file) and is green.
6. Audit log checkpoints anchored externally; truncation of the newest rows is detectable via `GET /audit/verify`.
7. Fee floor forces confirmation on any unexplained price delta, regardless of reassuring page text.

---

## 6. Pre-submission checklist

1. All tags from §3 present in git history, in order, each with a green pytest run at the time it was cut.
2. Frozen sets (`test_v1`, `external_v1`) committed once, never re-run, never edited after their first scoring run.
3. README fully rewritten: single naming scheme, hedged wording corrected, threat model present, screenshots/video linked, related work included with citations flagged for verification.
4. Final report (§Phase 7 output) contains per-category recall, McNemar comparisons, Wilson CIs throughout, and the non-ALLOW/flagged rate — not a bare accuracy percentage anywhere.
5. Demo video and screenshot set match what the dissertation describes.
6. Dissertation's Threats to Validity and Limitations chapters (Guide Appendix D.3/D.4) updated to reflect what was actually closed by this plan versus what remains open.

---

## 7. Appendix — code sketch references

Two concrete code changes referenced above come directly from the reviewer's pack and should be copied into the repo rather than re-derived:

- **Fee floor (Phase 0.5)**: A `fee_floor()` function that parses the structured price delta (not page prose) between locked intent and current total, and forces `REQUIRE_CONFIRMATION` when a delta exists and nothing in the user's intent explains it.
- **Checkpoint anchoring (Phase 3.8)**: `write_checkpoint()` (HMAC-SHA256 over the chain head, appended to `audit_anchor.jsonl`) and `verify_against_anchor()` (compares the live chain's current head against the most recent anchor), exposed via `GET /audit/verify`.

Both follow the same discipline as the rest of the pipeline: additive, raise-only or detection-only, and placed so the existing hard-rule floor and policy engine are unaffected by their absence if a provider or anchor file is temporarily unavailable.
