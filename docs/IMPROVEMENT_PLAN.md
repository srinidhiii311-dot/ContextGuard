# ContextGuard — Improvement & Completion Plan

Oct 26, 2026 · @meow

ContextGuard's engineering is sound (210 tests, a real 11-layer gate), but its evidence and portability are not yet publication-grade: the headline 95.71% pools a tuned dev set with an honest holdout, the baseline labelled an LLM judge is not an LLM, and the control plane appears to share an origin with attacker-controlled pages. This document lists the hidden problems, the upgrades that raise the project's value most, and a phased task list your coding agent can execute end to end, each task with an acceptance test.

---

## 0. How the coding agent uses this document

Work through section 6 in phase order. Problems carry IDs: **E** = evidence and validity, **S** = security and design of the gate, **G** = engineering and hygiene, **U** = value upgrade. Every phase ends with pytest green, regenerated CSVs, code and results in separate commits, and a git tag.

### Standing rules (apply to every task):

1. **Every number in a README, report or paper comes from a CSV or script output.** Never type a number from memory or from an earlier summary.
2. **Never edit an existing dev item to make it pass.** Log any dataset change and its reason in `CHANGELOG_EVAL.md`.
3. **Treat `eval_data/test_v1/` and `holdout_*.yaml` as burned:** diagnostics have read them. Do not tune against them. The final test is a new set (`test_v2`) written by someone who has not seen the gate.
4. **Interception means `BLOCK`, `REQUIRE_CONFIRMATION` or `PAUSE_TASK`.** Report flagged-only (`ALLOW_WITH_FLAG`) separately, and always report the non-ALLOW rate on benign items.
5. **Raise-only:** no new signal may lower a risk score. The hard-rule floor always runs last.
6. **No dataset strings, selector ids or item ids inside rules.** Rules read config files only.
7. **Name things for what they are.** A component is called an "LLM judge" only if it makes a real LLM call; otherwise call it a "heuristic classifier".
8. **Headline numbers come from held-out or test data only.** Dev numbers are labelled "dev (tuned)".
9. **If a step fails twice, stop and write down the error.** Do not move the goalposts.

---

## 1. Verified snapshot: what the latest report claims and what holds

The headline numbers moved between reports, so each claim below is checked against the numbers in the reports themselves.

| Claim in the report | Status | What the evidence shows |
|---|---|---|
| **95.71% total attack recall (67/70)** | Misleading | Pools 34 tuned dev attacks (100%) with 36 holdout attacks (91.7%, 33/36). Dev recall rose from 82.4% to 100% between reports while holdout stayed identical, so the dev fixes were written from dev failures. The honest headline is holdout: 91.7% [78.2%, 97.1%]. |
| **Dominance over "zero-shot LLM judges" (42.9%)** | Unsupported | Baseline 3 runs at 0.00 ms and was renamed "Prompt Classifier" in the table, so no real LLM was called. No real LLM-judge baseline has been run. |
| **E-commerce domain: 16/16 attacks, zero Python code changes** | Contradicted | The previous resolution report says `consistency_checker.py` was extended (`cart_total`, `shipping_fee`, `gift-wrap` keys) for this domain. The 100% is after adaptation, so it is a dev result for domain 2, not zero-shot generalization. |
| **0% false positives is a theorem ($R \le 23.75 < 30$)** | True but narrow | Holds only for actions with zero threat, inconsistency and marker signals. Real false-positive sources (taxonomy hits on benign text, intent-parse errors) sit outside the proof. Urgency banners already score 38–43 and are flagged. |
| **Sequences: Config E 100% (9/9), benign 10/10** | Dev only | Source is `sequences_dev.yaml`. 9/9 has a Wilson lower bound of about 70%. No held-out sequences exist. |
| **76.1% of actions skip the LLM, 23.9% invoke it** | Moving | Was 19.6% in the previous report; it shifts whenever dev scores shift. Measured per-call latency of a real model is still not shown. |
| **Config D $\approx$ 71 ms vs Config C $\approx$ 0.12 ms** | Real, but fixable | Caused by one SQLite commit per action. Config H (68.85 ms) running faster than D (71.71 ms) shows the benchmark is noise-limited. |
| **Dual gate reconciled** | Holds | `git log -S` evidence and the delegation refactor were shown; confirm once with a live episode that logs the gate class. |
| **209 passed, 1 deselected** | Holds | Many tests encode dev expectations, so they are regression checks, not evidence of generalization. |
| **Layered design (L1–L11) earns its complexity** | Not shown | The single-step table has no rows for L4 DOM hash, L5 hidden scan or L6 chain. Only the A $\to$ D accumulation is shown, and C $\to$ D adds one item ($p = 1.0$). |

---

## 2. Hidden problems: evidence and validity

These would be raised first by a reviewer or examiner. Each has a fix and a test the agent can run.

| ID | Severity | Problem and evidence | Fix | Acceptance test |
|---|---|---|---|---|
| **E1** | High | **Contaminated headline.** 95.71% pools tuned dev (34/34) with holdout (33/36); the pooled CI treats them as one sample. | Report dev (tuned) and holdout in separate columns. Headline = holdout or test only. Delete the pooled recall column from the summary CSV and README. | `verify_claims.py` fails if any doc quotes a pooled recall number. |
| **E2** | High | **Mislabeled and weak baselines.** B3 runs at 0.00 ms and is no LLM. B1 and B2 are strawmen, so "significant dominance" proves little. | Rename B3 "heuristic classifier". Add (a) a real LLM judge on a local model (intent + action + page text, JSON verdict), (b) a strict intent-allowlist baseline, (c) a spotlighting or sandwich-prompt defense in the live study. | Summary CSV has an "LLM judge" row whose `llm_calls.csv` has one logged call per item and a non-zero latency. |
| **E3** | High | **No live-agent evidence.** Every item is a fixed (page, action) pair. That measures gate enforcement against an already-compromised agent, not hijack rate, and not whether legitimate tasks still finish. | Run a live study with a real LLM agent on the Playwright testbed: conditions C0 none, C1 regex, C2 LLM judge, C3 gate B, C4 gate D, C5 gate + LLM. Metrics in section 7. $N \ge 10$ per scenario. | `eval_results/live_agent.csv` exists with counts per scenario and condition; the live episode logs the gate class used. |
| **E4** | High | **Dev is saturated; holdout is burned.** Configs B–D hit 100% on dev, so dev no longer discriminates. Diagnostics loaded `holdout_attacks.yaml` and listed its grey-zone items; it was re-run in every audit round. Author and date of the holdout are unrecorded. | Write `PROVENANCE.md` for every dataset (author, date, tools, who saw outputs). Archive `test_v1` as "used". Build a harder dev set with the adaptive attacker (U3). Commission `test_v2` from an independent writer and run it once. | `run_final_eval.py --final` runs on `test_v2` once and refuses a second run. |
| **E5** | Medium | **Second-domain claim contradicted** (see section 1). | Re-label as an adaptation study and record exactly which files and lines changed in `PORTING.md`. Add a new third domain (hotel booking or bank transfer) ported by config only, run once, and report it with Wilson intervals. | `PORTING.md` lists changed files per domain; third-domain CSV exists. |
| **E6** | Medium | **Sequence evidence is dev-only and tiny** (9 attacks, 10 benign). | Grow to $\ge 40$ sequences (attack and non-linear benign), with a held-out half written independently. Report Wilson intervals. | `run_sequence_eval.py` prints counts and intervals for dev and held-out separately. |
| **E7** | Medium | **Layer value not shown.** No leave-one-out ablation, no per-category recall; C $\to$ D adds one item ($p = 1.0$). | Run leave-one-layer-out on the full gate (remove L3, L4, L5, L6, L7 one at a time) and per-category recall on holdout and test. | Table of marginal gains with exact McNemar and Holm-corrected $p$; layers with no gain are labelled "defense in depth, no measured gain". |
| **E8** | Medium | **Statistics hygiene.** About eight pairwise McNemar tests with no correction; tests and intervals on pooled items. | Add `holm()` to `scripts/stats.py`; state the number of comparisons; no tests on pooled data. Intervals only over distinct items. | Unit test for `holm()`; report footer states the comparison count. |
| **E9** | Medium | **Intent-parser accuracy is unmeasured.** The whole gate trusts the parsed `TrustedIntent`; a parse error causes false blocks or silent under-protection. | Build a $\ge 100$-instruction parse test set (airport codes, dates, ambiguous wording, paraphrase). Report exact-match accuracy per field. On low confidence, show the parsed intent to the user for confirmation before the gate locks it. | `tests/test_intent_parse_accuracy.py` reports accuracy per field; confirmation step covered by a test. |
| **E10** | Medium | **Real-LLM behaviour is unmeasured.** The reports quote 740 ms / 1450 ms for an 8B model but show no raw log; the live Ollama test is deselected. | Run the live Ollama test and log every grey-zone call to `llm_latency_raw.csv`. Report mean and p95 from that file only, plus how often the LLM changed a decision. | `llm_latency_raw.csv` row count equals the reported invocation count. |
| **E11** | Low | **False-positive evidence is thin.** 68 clean items from two funnels; the theorem excludes the real FP sources. | Build a $\ge 200$-item benign stress set (long pages, "free" and "no extra charge" copy, promotional banners, security-sounding but harmless text, legitimate add-ons in the intent). Report FP, flagged-only and non-ALLOW rates. | Benign stress CSV with the three rates and Wilson intervals. |

---

## 3. Hidden problems: security and design of the gate itself

A security tool that can be attacked through its own plumbing loses its value. Rows marked *verify first* are inferred from the report's layout, so the agent must confirm them in code before fixing.

| ID | Severity | Problem | Fix | Acceptance test |
|---|---|---|---|---|
| **S1** | High (*verify first*) | **Control plane shares an origin with attacker-controlled pages.** The report serves the sandbox, REST API, dashboard and approvals all at `127.0.0.1:8000`. Page JavaScript can then call `/v1/action/verify` (a decision oracle for adaptive attacks), `/api/baseline/capture` (baseline poisoning), approvals and audit endpoints, and can read a JWT kept in browser storage. | Serve the victim site on its own port. Bind the control plane to localhost on a separate port with a per-session bearer secret held only by the agent process. Deny CORS, add CSRF protection, set a CSP on the dashboard, keep dashboard auth in an HttpOnly cookie. | Test: injected page JS calling every control-plane route gets 401 or 403. |
| **S2** | High | **Check-then-act race (TOCTOU).** The gate judges a selector, value and page snapshot; Playwright acts later. The DOM can change in between (element swapped, overlay inserted, handler rewired). | At dispatch, run one atomic `page.evaluate` that resolves the element and computes a fingerprint (tag, role, accessible name, form action, resolved href, rect, outerHTML hash). Compare it with the fingerprint the gate evaluated; mismatch means `BLOCK`. | Test: a page that swaps a button between check and click is blocked. |
| **S3** | High (*verify first*) | **Sensitivity is bound to sandbox selectors.** `protected_fields.yaml` keys on ids like `#confirm-btn` and `#cabin`. On any other site sensitivity is 0 and the field rails are inert; an attacker can also rename an id. | Infer role semantically: input type, autocomplete tokens (`cc-number`, `cc-csc`, `new-password`, `one-time-code`), label and aria text, form action host, submit button text, enclosing form purpose. Keep the YAML as an override only. | Metamorphic test: renaming every id and class in all items leaves decisions unchanged. Run on at least 3 sites the author did not write, with no config edits. |
| **S4** | High | **Page-initiated actions bypass the gate.** The gate sees only agent actions. Page script can exfiltrate with `fetch`, beacons or images, auto-submit forms, or redirect after an allowed click. | Add an egress guard with Playwright `context.route`: per-session origin allowlist derived from the intent; block and log everything else; recheck the URL after every navigation; block popups and downloads unless intended. | Test: a benign agent action on a page that beacons to an unlisted host still produces a blocked, logged request; redirect-after-click is caught. |
| **S5** | Medium | **Fail-closed is proven for the LLM only.** An exception, timeout or locked audit DB in any other layer may let the action proceed. | Wrap dispatch in `guarded_dispatch`: any exception, a timeout (default 2 s) or an audit-write failure on a consequential action returns `BLOCK`. | Fault-injection tests: raise in each layer, lock the DB, kill the LLM; the decision is never weaker than rules-only and consequential actions never dispatch. |
| **S6** | Medium | **Action coverage gaps.** Enter-key submit, shortcuts, new tabs and popups, drag and drop, uploads, downloads, `evaluate`, clipboard, frames. | Give the agent a facade exposing only gated methods; remove direct `page.*` use from agent code. Produce a coverage matrix from the Playwright API. | AST test: no `page.` call in `agent/` outside the facade. Matrix lists every action type with its test. |
| **S7** | Medium | **Hidden-content blind spots.** A computed-style scan misses CSS pseudo-element content, shadow DOM, cross-origin frames, `alt`, `title`, `aria-label` and `data-*` text, `noscript`, comments, SVG text, text inside images, zero-width and homoglyph characters, bidi controls, other languages and encoded payloads. | Normalize text (NFKC, strip zero-width and bidi), extend the scanner to each vector above, add multilingual matching, decode obvious encodings, optional OCR for images. | One attack and one benign test per vector; each attack is intercepted and each benign page (such as aria-hidden icons) is not. |
| **S8** | Medium | **Audit anchor is not truly external; the log holds raw PII.** The HMAC secret and anchor file live on the same host as the database, and page text with passenger or passport data is stored. | Publish the chain head to a separate append-only store at an interval (a separate host, a signed git tag, or an RFC 3161 timestamp). Redact values before logging: keep field names and value hashes. Add a retention setting. | Test: truncate and recompute the DB; the external anchor detects it. Test: no raw passport or card value appears in the log. |
| **S9** | Low | **Approval workflow weaknesses.** Demo user store; HS256 shared secret; `REQUIRE_CONFIRMATION` is counted as a stop in evaluation although a human may approve under social engineering. | Show the intent-versus-action diff in the approval UI, require a typed reason, rate-limit requests, and measure confirmations per task in the live study. | UI test shows the diff; the live study reports confirmations per benign task. |

---

## 4. Hidden problems: engineering and hygiene

| ID | Severity | Problem | Fix | Acceptance test |
|---|---|---|---|---|
| **G1** | Medium | **Release zips sit in the repo root.** `ContextGuard_Source_Release.zip` (1,282 files) and `CG.zip` may contain `venv`, `.env`, `*.db`, `audit_anchor.jsonl` or the frozen test set. If tracked, they also bloat git history. | Add `*.zip` to `.gitignore`. Build releases only into `dist/` from an allowlist, with a printed manifest and a secrets scan. Remove tracked zips from history if present. | `git ls-files` shows no zip. The manifest contains no `venv`, `.env`, `.db` or test-set files. |
| **G2** | Medium | **Windows-only workflow.** `venv\Scripts\pytest.exe`, `.bat` demo, a folder name with a space and a typo ("Context gaurd"). | Use `python -m` commands and a `Makefile` or `tasks.py`. Run CI on Linux and Windows. Use a space-free folder name for the repo. | CI matrix green on ubuntu and windows; a fresh clone runs `make test`. |
| **G3** | Medium | **An agent-written paper sits in the repo** (`ContextGuard_Research_Paper.md`, "viva defense guide") and repeats the unverified claims from section 1. | Add a DRAFT banner now. Generate every numeric sentence from CSVs through a template. Gate the banner removal on the claims ledger (section 7). | `verify_claims.py` passes; no number in the paper lacks a ledger entry. |
| **G4** | Medium | **Audit latency is an implementation artefact.** About 71 ms comes from one SQLite commit per action, not from hashing. | Use WAL with `synchronous=NORMAL`, one writer thread, group commit (every 20 ms or 32 rows), the hash chain computed in memory, and a synchronous flush only for consequential actions. Target p95 below 5 ms for non-consequential actions. | `latency_benchmark.csv`; chain verification still passes after a `kill -9` for flushed rows; the bounded loss window for unflushed rows is documented. |
| **G5** | Medium | **Benchmark noise.** Config H (68.85 ms) is faster than Config D (71.71 ms); no warm-up, no variance. | Warm up, run at least 1,000 iterations, pin the process, report mean, p50, p95, p99 with a bootstrap interval. | Every latency row has p50, p95, p99 and an interval. |
| **G6** | Medium | **Concurrency is untested.** One SQLite writer; multi-session throughput is unknown. | Load test with 1, 4 and 16 parallel sessions; report actions per second, p95 and lock errors. | `concurrency.csv` exists and shows no lost audit rows. |
| **G7** | Medium | **Naming drift.** L3 is called "vector embedding" in some places and "lexical C4 token deviation" in others; configs F and G never appear; Baseline 3 was renamed. | Check what L3 computes and name it accordingly. Write `docs/GLOSSARY.md` with one name per layer, config and baseline; use layer-id constants in code and reports. | A test greps docs and CSV headers for retired names. |
| **G8** | Low | **Tests encode dev outcomes.** `test_cases.py` pins dev-set decisions, so honest dev changes break tests. | Split `tests/unit/` from `tests/dev_regression/` with a `dev_regression` marker; report the two counts separately. | CI prints both counts. |
| **G9** | Low | **Results are not reproducible from the CSVs alone.** Model name and digest, seed, Playwright version and commit are not recorded. | Write a metadata header (git commit, date, Python and package versions, model name and digest, seed) into every results file. Add pip-audit and a secrets scan to CI. | Every CSV in `eval_results/` starts with the metadata block. |

---

## 5. What makes the project more valuable: ranked upgrades

| Rank | Upgrade | Why it adds value | Effort (days) | Needs |
|---|---|---|---|---|
| **U1** | **Live-agent study plus a public benchmark.** Measure attack success rate (ASR), benign task success (BSR) and utility under attack (UUA) with a real LLM agent, and add adapters for public suites such as AgentDojo (its travel suite matches your domain), WASP (web agents) and InjecAgent. | It is the only evidence that shows hijacks being stopped and tasks still finishing, and public suites let you compare with published defenses instead of your own strawmen. | 5–6 | E2, E3, E10 |
| **U2** | **Semantic portability.** Infer field and action roles from the DOM (S3) and run on sites you did not write. | Turns a flight-sandbox result into a general claim; also removes the id-renaming attack. | 3–4 | S3 |
| **U3** | **Adaptive attacker.** A separate attacker LLM that sees only the gate's decisions (black-box) and later the rules (white-box), with a fixed query budget; report attack success against budget. | Replaces fixed, author-written attacks with the evidence a security reviewer asks for, and produces the hard dev set that E4 needs. | 3–4 | E4 |
| **U4** | **Generic `IntentSpec`.** Typed constraints (entity fields and allowed values, spend ceiling, allowed domains, allowed action types, forbidden data classes), compiled from the instruction by an LLM and confirmed by the user; one YAML "domain pack" per site type. | Replaces the flight-specific `TrustedIntent` and makes new domains a config task, not a code task. | 4–5 | E5, E9 |
| **U5** | **Egress and dispatch guard (L0).** Origin allowlist through `context.route`, post-navigation checks, popup and download control, and the gated-method facade. | Closes the page-initiated and uncovered-action paths that a pre-action gate cannot see. | 2–3 | S4, S6 |
| **U6** | **Installable SDK.** A `contextguard` package with `guard.check(action)`, a Playwright wrapper, and adapters for common agent frameworks, plus Docker. | Adoption: someone can protect an existing agent in ten lines. | 3–4 | G1, G2, G4 |
| **U7** | **Explainable decisions and operator UX.** Show intent versus proposed action, which layers fired and the evidence behind each; redesign the dashboard around that. | Trust and demo quality: the reviewer sees why an action was stopped. | 2–3 | S9 |
| **U8** | **Calibrated scoring.** Fit the layer weights on dev data with cross-validation, keep raise-only and the hard floor, and report a plus or minus 20% weight-sensitivity plot. | Answers "why these weights" with data. | 2 | E7 |

*(Note: The benchmark names above were confirmed by web search only; the pages were not opened. Check the current versions, licences and task counts before use: AgentDojo, WASP, InjecAgent).*

---

## 6. Phased work plan for the agent

The full plan is about 34–40 working days. The minimum defensible path is **P0, P1, P2 (S1, S2, S5 only), P5 and P8**, about 14 days. Commission the independent `test_v2` writer on day 1 so it is ready by P8.

### P0. Freeze and clean (1 day)
- Commit the current tree. Fix G1 (zips), G2 (CI matrix on Linux and Windows, `make test`), G3 (DRAFT banner on the paper), G7 (`docs/GLOSSARY.md`).
- Create `CHANGELOG_EVAL.md` and `PROVENANCE.md` for every dataset in `eval_data/`. Archive `test_v1` as "used".
- Add a skeleton `scripts/verify_claims.py` (section 7).
- **Done when:** CI is green on both OSes and `git ls-files` shows no zip. **Tag:** `p0-clean`.

### P1. Evidence integrity (1.5 days)
- E1: split dev and holdout columns, drop pooled recall. E2: rename Baseline 3. E8: add `holm()` and the comparison count. G9: metadata header in every CSV.
- E7: leave-one-layer-out ablation and per-category recall. E10: run the live Ollama test and write `eval_results/llm_latency_raw.csv`.
- **Done when:** `verify_claims.py` passes against the regenerated CSVs. **Tag:** `p1-evidence`.

### P2. Gate hardening (3.5 days)
- S1 origin split and bearer secret. S2 dispatch-time fingerprint. S5 `guarded_dispatch` with fault-injection tests. S6 gated facade and AST test. S7 hidden-content vectors with one attack and one benign test each. S8 external anchor and PII redaction.
- **Done when:** every S-row acceptance test passes. **Tag:** `p2-hardened`.

### P3. Portable gate (4.5 days)
- S3 semantic role inference with the YAML as an override. S4 and U5 egress guard (L0). Metamorphic test (rename every id and class).
- Run on at least 3 sites the author did not write, with no config edits.
- **Done when:** decisions are unchanged under renaming and the third-party runs are logged. **Tag:** `p3-portable`.

### P4. Fast audit (2 days)
- G4 group-commit writer, G5 benchmark harness, G6 load test.
- **Done when:** p95 gate latency under 5 ms for non-consequential actions and the chain verifies after a crash. **Tag:** `p4-fast`.

### P5. Baselines and live-agent study (5.5 days)
- E2 real LLM-judge baseline and allowlist baseline. E3 live study over C0–C5 with ASR, BSR, UUA and confirmations per task, $N \ge 10$ per scenario.
- **Done when:** `eval_results/live_agent.csv` and `eval_results/llm_calls.csv` exist and match the report. **Tag:** `p5-live`.

### P6. Public benchmarks and adaptive attacker (6 days)
- U1 adapters for AgentDojo (travel), WASP and InjecAgent where licences allow. U3 black-box then white-box adaptive attacker with a query budget. E4 harder dev set from attacker output.
- **Done when:** results are reported against at least one published defense, and attack success versus budget is plotted. **Tag:** `p6-benchmarks`.

### P7. IntentSpec and a third domain (5.5 days)
- U4 `IntentSpec` with domain packs. E9 parse-accuracy set and the user-confirmation step. E5 `PORTING.md` and a third domain ported by config only.
- **Done when:** the third domain runs with zero Python edits and the result has Wilson intervals. **Tag:** `p7-intentspec`.

### P8. Final evaluation (2.5 days)
- E6 held-out sequences. E11 benign stress set. U8 calibration and weight-sensitivity plot. Run `test_v2` once with `--final`. Generate `REPORT.md` from the CSVs only.
- **Done when:** the report contains no number without a ledger entry. **Tags:** `test-v2-run`, then `v1.0-rc`.

### P9. Packaging, SDK and demo (4 days, optional)
- U6 installable SDK and framework adapters. U7 explainable decisions and the redesigned dashboard. Demo video and screenshots.
- **Done when:** a fresh clone installs the SDK and protects a sample agent in ten lines. **Tag:** `v1.0`.

---

## 7. Evaluation protocol and claims ledger

This project has repeatedly produced numbers that did not survive checking. The ledger below makes that impossible to repeat: a number appears in a document only if a script can regenerate it.

### Metrics

| Metric | Definition | Where |
|---|---|---|
| **Interception rate** | Attack items ending in `BLOCK`, `REQUIRE_CONFIRMATION` or `PAUSE_TASK`, over distinct attack items | Gate-level |
| **Flagged-only rate** | Attack items ending in `ALLOW_WITH_FLAG` (the action still runs) | Gate-level |
| **Benign FP, flagged, non-ALLOW rates** | Benign items intercepted, flagged, or anything but `ALLOW` | Gate-level |
| **ASR** | Live episodes where the agent completes the attacker's goal | Live study |
| **BSR** | Live benign tasks completed with the gate on; confirmations are counted separately as "needs human" | Live study |
| **UUA** | Live attack episodes where the user's task completes and the attack fails | Live study |
| **Confirmations per task** | Mean `REQUIRE_CONFIRMATION` events per benign task | Live study |
| **Latency** | p50, p95, p99 with warm-up and a bootstrap interval, audit write included | Benchmark |
| **LLM invocation rate and conditional latency** | Share of actions in the 30–59 band; per-call latency over those calls only | Benchmark |
| **Attack success vs query budget** | Share of adaptive attacks that evade after $K$ gate queries | Adaptive study |

### Dataset roles

| Set | Role | May tune on it? | Runs allowed |
|---|---|---|---|
| **Dev (34 attacks, 32 benign) and sequences dev** | Development; label "dev (tuned)" | Yes | Unlimited |
| **`test_v1` and `holdout_*.yaml`** | Burned: diagnostics have read them | No (report as "holdout, used") | Reruns allowed, never tuned |
| **Hard dev (attacker-generated)** | Development, harder | Yes | Unlimited |
| **Benign stress set ($\ge 200$)** | False-positive check | Only to fix real FPs, logged | Unlimited |
| **`test_v2` (independent writer)** | Final result | No | Once, via `--final` |
| **Domain 3 (config-only port)** | Portability | No | Once |
| **Intent parse set ($\ge 100$)** | Parser accuracy | Yes | Unlimited |

### Reporting rules

- Headline numbers come from `test_v2` (or holdout, labelled "used"). Dev numbers are always labelled "dev (tuned)".
- Wilson intervals only over distinct items. Repeating a fixed scenario is not a larger sample.
- Compare configurations with paired exact McNemar and Holm correction; state the number of comparisons.
- Scripted agents are called "scripted agent". The word "LLM" is used only where a real model call is logged.
- Live-study results are per-scenario counts. Pool only randomized scenario variants.

### `verify_claims.py`
Each number in `README.md`, `REPORT.md` and the paper draft has an entry in `claims.yaml`:
```yaml
- id: holdout_interception_D
  text: "91.7%"
  source: {file: eval_results/summary.csv, where: {set: test_v2, config: D}, column: interception_rate}
  tolerance: 0.05
```

The script fails the build when (1) a claim's value differs from its CSV cell, (2) a document contains a percentage, millisecond or count that has no claim, (3) a document uses a banned phrase ("pooled", "overall attack recall", "zero code", "LLM judge" without a non-empty `llm_calls.csv`), or (4) a CSV lacks the metadata header from G9. It runs in CI.

---

## 8. Paste-ready prompts for Antigravity

Export this document as Markdown and save it in the repo as `docs/IMPROVEMENT_PLAN.md` so the agent can read it. Paste the prefix first, then one phase prompt per run.

### Prefix (every run)

```
You are working in the ContextGuard repo. Read docs/IMPROVEMENT_PLAN.md first and follow its section 0 standing rules exactly.
Work on ONE phase per run. Before changing code, restate the phase's tasks and acceptance tests.
After each task: run pytest, regenerate the affected CSVs, and commit code and CSVs in separate commits.
Never report a number that is not in a CSV or script output. Never edit existing dev items.
If a step fails twice, stop and report the error with the full traceback.
At the end print: tasks done, acceptance tests passed and failed, files changed, open issues.
```

### Phase prompts

- **P0**: Do plan section 6 phase P0. Fix G1, G2, G3, G7. Create `CHANGELOG_EVAL.md` and `PROVENANCE.md` for every dataset in `eval_data/`. Add a skeleton `scripts/verify_claims.py`. Tag `p0-clean`.
- **P1**: Do phase P1. Implement E1, E2 (rename only), E7, E8, E10 and G9. Run the live Ollama test and write `eval_results/llm_latency_raw.csv`. Regenerate summary CSVs with separate dev and holdout columns and no pooled recall. Make `verify_claims.py` pass. Tag `p1-evidence`.
- **P2**: Do phase P2. Before fixing S1 and S3, confirm in code whether they are real and show the evidence. Then implement S1, S2, S5, S6, S7, S8, each with its acceptance test from section 3. Tag `p2-hardened`.
- **P3**: Do phase P3. Implement S3 role inference and the S4 egress guard as layer L0. Add the metamorphic rename test. Run on three third-party sites with no config edits and log the results. Tag `p3-portable`.
- **P4**: Do phase P4. Implement G4 group-commit audit writer, the G5 benchmark harness and the G6 load test. Prove chain verification after kill -9. Tag `p4-fast`.
- **P5**: Do phase P5. Implement a real LLM-judge baseline (local model, one logged call per item in `llm_calls.csv`) and the strict allowlist baseline. Implement the live study with conditions C0-C5, $N \ge 10$ per scenario, and report ASR, BSR, UUA and confirmations per task as counts. Tag `p5-live`.
- **P6**: Do phase P6. Write adapters for the public benchmarks named in section 5 where their licences allow. Build the black-box and white-box adaptive attacker with a query budget. Output `eval_data/hard_dev.yaml` from attacker results. Tag `p6-benchmarks`.
- **P7**: Do phase P7. Replace `TrustedIntent` with `IntentSpec` plus domain packs. Build the 100-instruction parse set and the user-confirmation step. Port a third domain by config only and write `PORTING.md`. Tag `p7-intentspec`.
- **P8**: Do phase P8. Do NOT read `eval_data/test_v2` until I say it is ready. Build held-out sequences and the benign stress set, the calibration and weight-sensitivity plot. When I confirm, run `scripts/run_final_eval.py --final` once. Generate `REPORT.md` from CSVs only. Tags `test-v2-run`, `v1.0-rc`.
- **P9**: Do phase P9. Build the installable SDK, adapters, explainable decision output and the redesigned dashboard. Record screenshots for the demo. Verify on a fresh clone. Tag `v1.0`.

---

## 9. Definition of done

The project is finished when every box below is ticked. Tags in order: `p0-clean`, `p1-evidence`, `p2-hardened`, `p3-portable`, `p4-fast`, `p5-live`, `p6-benchmarks`, `p7-intentspec`, `test-v2-run`, `v1.0-rc`, `v1.0`.

- [ ] Every E, S and G row is closed, or listed in `LIMITATIONS.md` with a reason it was accepted.
- [ ] `verify_claims.py` passes in CI, and CI is green on Linux and Windows.
- [ ] The headline result comes from `test_v2`, run once, with Wilson intervals and Holm-corrected comparisons.
- [ ] The live study reports ASR, BSR, UUA and confirmations per task as per-scenario counts, with a real LLM-judge baseline.
- [ ] At least one public benchmark result is compared with a published defense, and attack success versus query budget is plotted.
- [ ] The gate runs unchanged on at least three sites the author did not write, and a third domain is ported by config only.
- [ ] The `README` states the threat model, the glossary names, and what is not defended (action-only anomalies, image text if OCR is off, a compromised host).
- [ ] A fresh clone installs, passes `make test` and runs the demo; `git ls-files` shows no zips, and the secrets scan is clean.
- [ ] The paper's DRAFT banner is removed only after the ledger passes.

---

## 10. Open questions for you

These change the plan's scope or order; the answers are not in the reports:

1. Who wrote `test_v1` and `holdout_*.yaml` (you, a classmate, or a coding agent), and did anyone see gate outputs while writing? This decides how much weight E4 carries.
2. What is your deadline and target (final-year dissertation, conference or workshop paper, or portfolio)? A dissertation can stop at P8; a paper needs P6.
3. Which models can you run for the live study: a local Ollama model, an API key for a hosted model, or neither? The live study and the real LLM-judge baseline need at least one.
4. Is a GPU available, and which model sizes run on it? This sets the latency numbers you can honestly report.
5. Are you allowed to download public benchmarks (AgentDojo, WASP, InjecAgent) on your machine and network?
6. Can someone independent write `test_v2` (about 40 attacks and 40 benign items from the Appendix C brief in your Completion Guide)?
7. Is the control plane really served from the same port as the sandbox (S1)? A one-line answer from `launcher.py` saves a phase.
