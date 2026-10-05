# ContextGuard: Runtime Safety Gateway for AI Web Agents

## What it is

ContextGuard is an end-to-end research platform and runtime safety gateway for autonomous AI web agents. It couples an automated, instrumented web sandbox demonstrating how malicious page content can hijack an AI agent with a synchronous pre-action safety gate (`ContextGuardGate`) that intercepts every proposed agent action before browser dispatch. ContextGuard combines multi-factor risk assessment, DOM baseline region hashing, computed-style hidden content scanning, optional LLM semantic consistency checking, a deterministic hard-rule floor, multi-step attack chain detection, and a role-based approval engine backed by a SHA-256 tamper-evident hash-chained audit log.

---

## Architecture

```
              +-------------------------------------------------------------+
              |                   AI Agent Perception Loop                  |
              +-------------------------------------------------------------+
                                             |
                                 1. Propose Action (observe -> decide)
                                             v
+========================================================================================+
|                                ContextGuard Pre-Action Gate                            |
|                                                                                        |
|  [Step 1: Context Capture]                                                             |
|    - LockedIntent (immutable ground truth locked once at task initialization)          |
|    - Action sensitivity & booking criticality resolution                               |
|                                                                                        |
|  [Step 2: Signal Synthesis]                                                            |
|    - Rail 1: Intent Verification Rail (field mismatch, navigation boundary)            |
|    - Rail 2: Known Threat Taxonomy Classifier (Component 3 keyword hints)              |
|    - Rail 3: Semantic Characterization & Vector Embedding (Component 4)                |
|    - Rail 4: DOM Baseline Region Hash Comparison (BaselineStore, masks & drift score)  |
|    - Rail 5: Computed-Style Hidden Content Scanner (hidden_content.py style checks)     |
|                                                                                        |
|  [Step 3: Multi-Factor Continuous Risk Engine (0-100 score & tiers)]                   |
|    - fused_score = combine(base_score, extra_signals)  [Raise-Only]                    |
|                                                                                        |
|  [Step 4: Real LLM Semantic Consistency Checker (Optional / Phase 2)]                  |
|    - Invoked only in the grey zone (score 30-59, never over BLOCK)                     |
|    - Random-nonce delimited prompt; strict JSON; raise-only apply_verdict()             |
|                                                                                        |
|  [Step 5: Policy Engine & Declarative Policy Matrix]                                   |
|    - ALLOW / ALLOW_WITH_FLAG / REQUIRE_CONFIRMATION / BLOCK / PAUSE_TASK               |
|                                                                                        |
|  [Step 6: Stateful Attack Chain Detector (Component 8)]                               |
|    - Multi-step pattern windows in SQLite: INJECTION_SEEN -> FIELD_CHANGE -> NAV       |
|                                                                                        |
|  [Step 7: Deterministic Hard-Rule Floor (Unconditionally Runs Last)]                  |
|    - Floor cannot be bypassed or weakened by statistical, ML, or LLM layers           |
+========================================================================================+
                                             |
                   +-------------------------+-------------------------+
                   | (ALLOW / FLAG)          | (REQUIRE_CONFIRMATION)  | (BLOCK / PAUSE)
                   v                         v                         v
              Dispatch to              Human-in-the-Loop           Abort Action /
            Browser Session            Approval Service            Pause Agent
                                     (Role-based JWT auth:
                                      viewer/analyst/approver,
                                      >=80 requires 2 approvers,
                                      timeout defaults to DENY)
                                             |
                                             v
                           Append-Only SHA-256 Audit Log
                             (Tamper-evident hash chain)
```

---

## Quick Start (Local & Docker)

### Local Environment (Windows / Linux / macOS)

```bash
# 1. Set up virtual environment
python -m venv venv
# Windows: venv\Scripts\activate | Unix: source venv/bin/activate

# 2. Install pinned dependencies and Playwright Chromium
pip install -r requirements.txt
playwright install chromium

# 3. Configure environment
cp packaging/.env.example .env
# Edit .env to set JWT_SECRET (>= 16 chars) and optional LLM_PROVIDER

# 4. Start the platform
python launcher.py
```

Options:
- `python launcher.py` — Start all services (Booking Sandbox + API + Dashboard)
- `python launcher.py --headless` — Run browser controller headlessly
- `python launcher.py --api-only` — Start backend API server only
- `python launcher.py --bench` — Run evaluation benchmark then exit

The platform runs at **http://127.0.0.1:8000**:
- `/` — Interactive flight booking sandbox
- `/dashboard` — Security dashboard with pending approvals panel
- `/portal` — Mission control launchpad
- `/docs` — OpenAPI / Swagger documentation

### Docker Compose

```bash
# Start ContextGuard application alongside Ollama
docker compose up -d

# Verify platform health
curl http://localhost:8000/api/health
```

---

## Running the Tests and Evaluation

### Test Suite (Pytest)

```bash
# Run unit and integration tests (excluding live LLM integration)
pytest -m "not llm" -v

# Run full test suite including live Ollama test (if Ollama is running)
pytest -v
```

### Dataset Ablation Benchmark

```bash
python scripts/run_dataset_ablation.py
```

### Multi-Step Sequence Evaluation (Config D vs Config E)

```bash
python scripts/run_sequence_eval.py
```

### Live Testbed Scenarios Ablation (Rows F & G)

```bash
python scripts/run_testbed_ablation.py
```

### Live Agent Evaluation (Dry Run)

```bash
python scripts/run_live_agent_eval.py --adapter live_adapter:run_episode --scenarios prompt_injection,context_manipulation --runs 2 --dry-run
```

---

## Evaluation Summary

All evaluations adhere to methodological standards:
- **Strict Interception Definition**: `Interception := {BLOCK, REQUIRE_CONFIRMATION, PAUSE_TASK}`. `ALLOW_WITH_FLAG` is reported strictly separately as "flagged only".
- **Statistical Inference**: Exact two-sided 95% Wilson Score Confidence Intervals computed over distinct benchmark items.
- **Combined Dataset**: 66 distinct items (34 Attacks: 18 Adversarial Evasion + 16 Taxonomy; 32 Benign Tasks across booking lifecycle).

| Config | Defensive Architecture Stack | Interception Recall (95% CI) | Flagged Only Rate | Clean FP Interception (95% CI) | Clean Non-ALLOW Rate (95% CI) | Mean Latency | p95 Latency |
|---|---|---|---|---|---|---|---|
| **Config A** | Field checks only (Step 2 Verification Rail) | 29/34 (85.3% [69.9%, 93.6%]) | 0/34 (0.0%) | 0/32 (0.0% [0.0%, 10.7%]) | 0/32 (0.0% [0.0%, 10.7%]) | 0.08 ms | 0.11 ms |
| **Config B** | Config A + Keyword taxonomy (Component 3) | 33/34 (97.1% [85.1%, 99.5%]) | 0/34 (0.0%) | 0/32 (0.0% [0.0%, 10.7%]) | 0/32 (0.0% [0.0%, 10.7%]) | 0.09 ms | 0.12 ms |
| **Config C** | Config B + Semantic characterization (Comp 4) | 33/34 (97.1% [85.1%, 99.5%]) | 0/34 (0.0%) | 1/32 (3.1% [0.6%, 15.7%]) | 1/32 (3.1% [0.6%, 15.7%]) | 0.13 ms | 0.24 ms |
| **Config D** | Full Gate (All 7 Components + ML Risk + Policy) | 33/34 (97.1% [85.1%, 99.5%]) | 0/34 (0.0%) | 0/32 (0.0% [0.0%, 10.7%]) | 1/32 (3.1% [0.6%, 15.7%]) | 67.59 ms | 75.55 ms |
| **Config H** | Config D + Real LLM Checker (Row H) | 33/34 (97.1% [85.1%, 99.5%]) | 0/34 (0.0%) | 0/32 (0.0% [0.0%, 10.7%]) | 1/32 (3.1% [0.6%, 15.7%]) | 82.91 ms | 98.10 ms |

Detailed per-item decision audit trails, failure breakdowns, and confusion matrices are documented in [eval_results/REPORT.md](eval_results/REPORT.md).

---

## Threat Model & Security Scope (Phase 0.5 / S10)

ContextGuard operates under an explicit threat model defining the security boundary between untrusted web content and the autonomous browser agent:

### In-Scope Threats Defended Against
- **Indirect Prompt Injection**: Malicious instructions embedded in webpage text, HTML attributes, DOM comments, or CSS-hidden containers that enter the agent's observation context to hijack task execution.
- **Unauthorized Parameter Mutation**: Adversarial tampering with protected booking intent fields (origin, destination, cabin class, passenger count, travel date, authorized contact email).
- **Navigation Boundary Divergence**: Redirection or deep-linking to unapproved external origins, phishing portals, or credential harvesting servers.
- **Unmapped Fee Tampering & Tariff Inflation**: Stealthy insertion of surcharges, excessive baggage tiers, catering banquets, exit-row seat fees, or insurance opt-ins violating `addons_allowed: none`.
- **Multi-Step Attack Chains**: Sequences that stage an injection to bypass verification steps (e.g., skipping review directly to booking confirmation).

### Explicitly Out-of-Scope
- **Model Weight Poisoning**: Pre-training or fine-tuning backdoors embedded directly into the agent's foundation model weights.
- **Browser & OS Supply-Chain Compromise**: Compromised browser binaries, malicious browser extensions, kernel rootkits, or hypervisor escapes.
- **Side-Channel & Out-of-Band Attacks**: Attacks that never touch the DOM, HTTP traffic, or page text observed by the gateway (e.g., side-channel network timing attacks).
- **Insider Threat / Rogue Approvers**: Malicious actions explicitly approved by authenticated supervisors holding legitimate multi-role signing keys.

---

## Security Assumptions

1. **Independent Pre-Action Gate**: ContextGuard monitors and policy evaluation execute out-of-band and synchronously before the browser controller dispatches the proposed action.
2. **Untrusted Page Content**: All text and markup retrieved from web pages are strictly treated as untrusted data. External page content may escalate or trigger warnings, but can never downgrade a hard security violation to `ALLOW`.
3. **Immutable User Intent**: `TrustedIntent` is parsed and immutably locked once from the user's initial natural-language instruction at task initialization.
4. **Environment-Sourced Secrets**: All cryptographic keys (`JWT_SECRET`, API tokens) must be provided via environment variables, never checked into version control.

---

## Limitations

- **Single-Domain Benchmark**: Dev datasets and live testbed scenarios are focused on airline reservation and travel booking workflows; cross-domain validation on e-commerce, banking, and SaaS agents is subject to ongoing research.
- **Author-Written Datasets**: Synthetic dev benchmarks and attack variants were constructed for testing defense mechanisms; validation on externally authored, frozen datasets (`eval_data/test_v1/`) is required for unbiased external generalization.
- **Scripted vs LLM Agents**: The core evaluation evaluates the pre-action safety gate against deterministic actions and simulated agent trajectories; live agent susceptibility evaluations are reported separately.
- **Model Weights Calibration**: Default runtime logistic weights were calibrated on reference samples; while effective for demonstrative scoring, production deployment requires continuous telemetry training.
- **Component 4 Context-Length Sensitivity**: Semantic cosine deviation relies on embedding representations whose sensitivity can degrade on extremely long or noisy DOM pages.
- **Fee Floor Negation Mitigation (Phase 0.5 Closed)**: Surcharge attacks with injected negation phrases ('complimentary, at no charge') are deterministically intercepted at `REQUIRE_CONFIRMATION` or `BLOCK` via `fee_floor()`, which parses structured price deltas and ignores reassuring prose. Actions with zero price delta on pages mentioning fee keywords remain calibrated at `ALLOW_WITH_FLAG`.
- **Lexical Instruction Patterns**: Hidden content scoring identifies directive keywords using domain patterns; obfuscated or novel instruction formats without imperative verbs require auxiliary vision or LLM inspection.
- **Audit Log Truncation**: While the SHA-256 hash chain detects in-place record modification or intermediate row deletion, it cannot detect truncation of the most recent tail records unless the latest block hash is anchored externally.

---

## Threats to Validity

1. **DOM Negation Masking**: Adversaries controlling webpage content may inject negation language ("free", "complimentary") to evade fee alerts. ContextGuard closes this loophole via the deterministic `fee_floor()` check, which parses structured price deltas between locked intent and page state, strictly requiring confirmation on any unexplained fee delta regardless of reassuring page prose.
2. **Generalization across Dynamic Ontologies**: Target field mappings and ancillary fee lexicons are informed by domain concepts. Adapting to arbitrary web applications requires schema mapping layers or few-shot semantic alignment.

---

## Project Layout

```
ContextGuard/
├── backend/                   FastAPI server, database schema, websocket manager, API routers
│   ├── main.py                Unified server entrypoint (sandbox, REST API, approvals router)
│   ├── database/db.py         SQLite task and security event storage
│   ├── api/                   v1 execution pipeline, sessions, test cases, audit routes
│   └── websocket/             Live broadcast manager
├── frontend/                  Flight booking UI (5-page SPA) and control HUDs
├── agent/                     Autonomous AI browser agent
│   ├── task_parser.py         Natural language instruction parser
│   ├── browser_controller.py  Playwright DOM observation, computed-style hidden scan, action execution
│   └── agent_controller.py    Observe -> decide -> act control loop with intervention hooks
├── contextguard/              Synchronous runtime safety gate and defense-in-depth components
│   ├── gate.py                Synchronous 11-step pre-action gate (ALLOW/FLAG/CONFIRM/BLOCK/PAUSE)
│   ├── models.py              Structured intent, action, and report dataclasses
│   ├── consistency_checker.py Verification rail (field tampering, navigation boundary, pricing)
│   ├── threat_detector.py     Taxonomy pattern-hint classifier (Component 3)
│   ├── threat_characterizer.py Semantic deviation embedding analyzer (Component 4)
│   ├── dom_baseline.py        Region hashing, dynamic masking, and drift detection (Phase 1)
│   ├── hidden_content.py      Computed-style and CSS-hidden content scanner (Phase 1)
│   ├── llm_checker.py         Real LLM semantic consistency reviewer (Phase 2)
│   ├── chain_detector.py      Stateful multi-step attack chain detector (Component 8)
│   ├── risk_engine.py         Continuous 0-100 risk scoring engine
│   ├── policy_engine.py       Graduated policy matrix and hard-rule floor
│   ├── approvals.py           Role-based approval state machine and JWT authentication (Phase 3)
│   ├── approvals_api.py       FastAPI router for approvals and audit log verification
│   ├── approvals_cli.py       Admin-seeding and user creation CLI
│   ├── audit_log.py           Tamper-evident SHA-256 hash-chained audit log
│   └── intervention.py        Agent pause and asynchronous approval polling hook
├── eval_data/                 Adversarial evaluation datasets
│   ├── attacks.yaml           34 distinct attack scenarios (18 evasion + 16 taxonomy)
│   ├── benign.yaml            32 distinct benign tasks across booking lifecycle
│   └── sequences_dev.yaml     Schema-v2 multi-step attack and benign sequences
├── eval_results/              CSV evaluation reports, ablations, and sequence logs
├── scripts/                   Evaluation, ablation, latency benchmarking, and stats runners
├── tests/                     Unit, acceptance, and integration test suites (180+ tests)
├── packaging/                 Docker, compose, CI workflows, and licensing templates
├── launcher.py                Single-command orchestrator
├── dashboard.html             Security dashboard with approvals management
├── Dockerfile                 Docker container definition pinned to Playwright 1.44.0
├── docker-compose.yml         Container orchestration for app + Ollama
└── requirements.txt           Pinned dependency versions
```

---

## License

MIT License. Copyright (c) 2026 Srinidhi R. See [LICENSE](LICENSE) for details.
