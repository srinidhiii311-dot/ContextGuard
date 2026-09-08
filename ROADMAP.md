# AI Web Agent Security Testing Platform — Implementation Roadmap

This roadmap breaks the project into 7 phases, each split into checkpoints.
Every checkpoint has: a goal, concrete deliverables, and a "done when" test
you can run to prove it works before moving on. Do not start a checkpoint
until the previous one passes its test — this project fails most often
when people build ContextGuard before the agent reliably does normal tasks.

Suggested pace for a semester project: Phase 1–2 = weeks 1–3,
Phase 3–4 = weeks 4–6, Phase 5 = weeks 7–9, Phase 6 = week 10,
Phase 7 = weeks 11–12, buffer/report = weeks 13–14.

---

## PHASE 1 — Flight Booking Website (the sandbox)

**Goal:** A human can complete a mock flight booking end-to-end. This is the
"victim" application the agent and attacker will both act on.

### Checkpoint 1.1 — Backend skeleton
- FastAPI app boots, SQLite created, mock flight data seeded.
- `GET /api/flights/search?origin=&destination=&date=&class=` returns flights.
- Done when: `curl` the search endpoint and get JSON results.

### Checkpoint 1.2 — Booking flow endpoints
- `POST /api/bookings` (select flight, passenger info) → returns booking id + state.
- `GET /api/bookings/{id}` → current booking state (origin, destination, class, status).
- `POST /api/bookings/{id}/confirm` → mock confirm, no real payment.
- Done when: a full booking can be created and confirmed via API calls alone.

### Checkpoint 1.3 — Frontend pages
- Search page → results page → passenger details → review → confirmation.
- Every page reflects the booking id's state from the backend (no hidden client-only state).
- Done when: a human, using only the browser, completes a booking.

**Phase 1 exit test:** Two people can independently book two different
itineraries in the same running instance without state bleeding between them.

---

## PHASE 2 — AI Web Agent (baseline, no security yet)

**Goal:** The agent takes a plain-English instruction and completes the same
flow a human did in Phase 1, using Playwright to actually drive the browser
(not just calling your own API — the point is it perceives the DOM like a
real agent would, so later attacks are meaningful).

### Checkpoint 2.1 — Task parser
- `task_parser.py`: LLM call that turns "Book an economy flight from Chennai
  to Delhi for one passenger" into structured intent:
  `{origin, destination, date, passengers, cabin_class}`.
- Done when: 10 varied phrasings of the same task all parse to the same structured intent.

### Checkpoint 2.2 — Agent loop + browser controller
- `browser_controller.py` wraps Playwright: `observe()` returns a simplified
  DOM/accessibility snapshot; `act(action)` executes CLICK/TYPE/SELECT/SUBMIT.
- `agent_controller.py` runs the loop: observe → decide next action (LLM call
  with structured intent + current page state) → act → repeat until booking
  reaches "review" or a max step count.
- Done when: given the Ph.1 site running locally, the agent completes a
  booking unattended, matching the original instruction's parameters.

### Checkpoint 2.3 — Agent memory / action log
- Every action the agent takes is stored with a timestamp and the page state
  at that moment (this data feed is what ContextGuard will consume later —
  build it now so you don't retrofit it).
- Done when: after a run, you can print a full transcript of observe→action pairs.

**Phase 2 exit test:** Run the agent on 5 different task phrasings back to
back; all 5 bookings match their instructions with zero manual intervention.

---

## PHASE 3 — Real-Time Agent Monitoring (plumbing, not security yet)

**Goal:** The dashboard shows what the agent is doing live. This phase is
just the WebSocket pipe — no attack/security logic yet.

### Checkpoint 3.1 — WebSocket channel
- Backend pushes an event on every agent action: `{type: "action", action, page_url, timestamp}`.
- Done when: opening the dashboard in a browser while the agent runs shows
  actions appearing live, in order, with no page refresh.

### Checkpoint 3.2 — Agent status panel
- Dashboard shows current page, last action, previous action, agent state (RUNNING/DONE/ERROR).
- Done when: you can watch an entire booking happen from the dashboard alone.

**Phase 3 exit test:** Kill and restart the backend mid-run; dashboard
reconnects and resumes showing live status without a full page reload.

---

## PHASE 4 — Attack Simulation Engine

**Goal:** A tester can inject each attack type into the live page the agent
is about to observe, and the injection is logged with a timestamp/type.

### Checkpoint 4.1 — Injection mechanism
- Backend endpoint `POST /api/attack/inject {attack_type, target_page}` that
  mutates the served HTML/DOM for the target page (e.g. injects a `<div>`
  with fake instructions, or rewrites a form's hidden value).
- Done when: injecting while the agent is paused visibly changes the page
  the agent will next observe.

### Checkpoint 4.2 — Implement each attack module
Build these as separate small modules (`attacks/*.py`), each just producing
an HTML/DOM mutation function:
- `prompt_injection.py` — visible "instruction for AI agent" text block.
- `context_manipulation.py` — fake "updated user preference" block.
- `hidden_content.py` — `display:none` instruction block.
- `dom_manipulation.py` — silently changes a form's selected value.
- `navigation_attack.py` — injects/rewrites a link to an unexpected URL.
- Done when: each attack, triggered individually, can be verified in the
  raw HTML via a simple test script (`tests/test_cases.py`).

### Checkpoint 4.3 — Attack panel UI + logging
- Dashboard buttons to fire each attack; every injection writes a row to
  the `Attacks` table with type/payload/timestamp.
- Done when: firing an attack from the UI, running the agent, and then
  checking `GET /logs` shows the attack event correctly ordered against
  the agent's actions.

**Phase 4 exit test:** With ContextGuard not yet built, run the agent with
Prompt Injection active and confirm (by reading the transcript) whether the
baseline agent got fooled — this becomes your "before" baseline for the
final report.

---

## PHASE 5 — ContextGuard (the core contribution)

**Goal:** Continuous comparison of trusted context vs. observed
context/action, producing a risk score and alerts.

### Checkpoint 5.1 — Context snapshot capture
- `context_store.py`: on every agent action AND every 1s tick, capture
  `{user_intent, current_url, dom_hash/summary, agent_action, agent_context}`
  and store as a `Context Snapshot` row.
- Done when: a normal, unattacked run produces a clean snapshot stream with
  no gaps > ~1.5s.

### Checkpoint 5.2 — Individual monitors
- `url_monitor.py` — flags URL/domain changes not part of expected flow.
- `dom_monitor.py` — diffs DOM against previous snapshot, flags unexpected
  large changes or newly-appeared instruction-like text (simple heuristic:
  keywords like "ignore previous", "system update", "AI agent" + diff size).
- `action_analyzer.py` — flags when the agent's proposed action's parameter
  (e.g. cabin class) doesn't match the last known-good structured intent.
- Done when: unit tests feeding each monitor a synthetic "before/after" pair
  correctly flag the 5 attack types from Phase 4 and correctly stay silent
  on normal state changes (this is your real test suite — write it before
  wiring things together).

### Checkpoint 5.3 — Consistency checker + risk engine
- `consistency_checker.py` combines monitor outputs into a structured
  inconsistency list (what changed, expected vs actual).
- `risk_engine.py` maps inconsistencies to a 0–100 score and a
  SAFE/SUSPICIOUS/HIGH RISK status, using simple weighted rules to start
  (e.g. cabin-class mismatch = +40, hidden instruction text detected = +50,
  unexpected domain = +60). Note in your report that a rule-based engine is
  the MVP and LLM-based semantic comparison is the stated future work — you
  don't need to build the LLM version to have a complete project.
- Done when: replaying the Phase 4 attack logs through the risk engine
  reproduces the expected HIGH/SUSPICIOUS classifications consistently.

### Checkpoint 5.4 — Intervention hook
- When risk crosses a threshold, ContextGuard can signal the agent
  controller to PAUSE before the next action executes (not just log it).
- Done when: with intervention enabled, a Prompt Injection attack that
  previously fooled the baseline agent (Phase 4 exit test) now gets
  paused before the wrong action is taken.

**Phase 5 exit test:** Run all 5 attack types with ContextGuard active;
each produces a correctly-typed alert, correct risk score, and (with
intervention on) prevents the wrong outcome.

---

## PHASE 6 — Security Dashboard (final UI)

### Checkpoint 6.1 — Live ContextGuard panel
- Shows last scan time, current URL + trust status, user intent vs agent
  context side by side, DOM change summary, risk score, SAFE/SUSPICIOUS/HIGH status.

### Checkpoint 6.2 — Alert feed + intervention controls
- Scrolling alert feed with attack type, affected parameter, expected vs
  proposed value, risk level; a manual "Resume agent" button after a pause.

**Phase 6 exit test:** A second person, with no prior explanation, can watch
the dashboard during a live attacked run and correctly say what happened and
when, using only what's on screen.

---

## PHASE 7 — Testing & Evaluation

- Build a fixed test matrix: {5 attack types} × {normal run baseline} ×
  {ContextGuard on/off}, run each combination 3–5 times.
- Record for each run: detected (Y/N), time-to-detect, risk score, whether
  the wrong action was actually prevented.
- Summarize as a table + a couple of charts (detection rate, risk score
  distribution) — this becomes the results section of your report.

---

## MVP cutline (if time runs short)

If you're short on time, the truthful, still-impressive MVP is:
Phase 1 (full) + Phase 2 (checkpoints 2.1–2.2) + Phase 3.1 +
Phase 4 (prompt injection + context manipulation only) +
Phase 5 (checkpoints 5.1–5.3, skip 5.4 intervention) + Phase 6.1.
That is a complete, demoable story: agent does a task, gets attacked twice,
ContextGuard visibly catches both. Intervention and the other 3 attack types
are the "future work" slide if needed.
