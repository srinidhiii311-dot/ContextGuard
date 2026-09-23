"""
backend/database/db.py
SQLite setup, schema, and mock flight data for all 7 phases.

Tables
------
flights          Phase 1 — searchable flight catalogue
bookings         Phase 1 — booking lifecycle (REVIEW → CONFIRMED)
tasks            Phase 2 — agent task records
agent_actions    Phase 2/3 — every observe→act step the agent takes
attacks          Phase 4 — injected attack records with payload + type
security_events  Phase 5 — ContextGuard alerts (risk score, status)
context_snapshots Phase 5 — trusted vs observed context diff snapshots
"""

from __future__ import annotations

import datetime
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).parent / "platform.db"


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Schema creation
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS flights (
    flight_id      TEXT PRIMARY KEY,
    airline        TEXT NOT NULL,
    origin         TEXT NOT NULL,
    destination    TEXT NOT NULL,
    date           TEXT NOT NULL,
    departure_time TEXT NOT NULL,
    arrival_time   TEXT NOT NULL,
    cabin_class    TEXT NOT NULL,
    price          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bookings (
    booking_id      TEXT PRIMARY KEY,
    flight_id       TEXT NOT NULL,
    origin          TEXT NOT NULL,
    destination     TEXT NOT NULL,
    date            TEXT NOT NULL,
    cabin_class     TEXT NOT NULL,
    passenger_name  TEXT NOT NULL,
    passenger_count INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'REVIEW',
    total_price     INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id          TEXT PRIMARY KEY,
    user_instruction TEXT NOT NULL,
    parsed_intent    TEXT,
    status           TEXT NOT NULL DEFAULT 'PENDING',
    result_booking_id TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_actions (
    action_id      TEXT PRIMARY KEY,
    task_id        TEXT NOT NULL,
    step_number    INTEGER NOT NULL DEFAULT 0,
    action_type    TEXT NOT NULL,
    action_details TEXT,
    page_url       TEXT,
    dom_snapshot   TEXT,
    result         TEXT,
    timestamp      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attacks (
    attack_id       TEXT PRIMARY KEY,
    task_id         TEXT,
    attack_type     TEXT NOT NULL,
    target_page     TEXT NOT NULL,
    payload         TEXT NOT NULL,
    active          INTEGER NOT NULL DEFAULT 1,
    injection_time  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id     TEXT PRIMARY KEY,
    task_id      TEXT,
    threat_type  TEXT NOT NULL,
    details      TEXT NOT NULL,
    risk_score   INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'OPEN',
    action_taken TEXT,
    timestamp    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS context_snapshots (
    snapshot_id    TEXT PRIMARY KEY,
    task_id        TEXT NOT NULL,
    step_number    INTEGER NOT NULL DEFAULT 0,
    user_intent    TEXT,
    current_url    TEXT,
    dom_hash       TEXT,
    dom_summary    TEXT,
    agent_context  TEXT,
    agent_action   TEXT,
    risk_score     INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'CLEAN',
    timestamp      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_results (
    verification_id        TEXT PRIMARY KEY,
    task_id                TEXT NOT NULL,
    step_number            INTEGER NOT NULL DEFAULT 0,
    is_consistent          INTEGER NOT NULL,
    consistency_score      REAL NOT NULL DEFAULT 1.0,
    inconsistency_severity REAL NOT NULL DEFAULT 0.0,
    inconsistencies        TEXT,
    marker_presence        INTEGER NOT NULL DEFAULT 0,
    marker_hit             TEXT,
    timestamp              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_detections (
    detection_id           TEXT PRIMARY KEY,
    task_id                TEXT NOT NULL,
    step_number            INTEGER NOT NULL DEFAULT 0,
    is_threat              INTEGER NOT NULL DEFAULT 0,
    is_known_path          INTEGER NOT NULL DEFAULT 1,
    attack_type            TEXT,
    confidence             REAL NOT NULL DEFAULT 0.0,
    characterization_label TEXT,
    deviation_signal       REAL NOT NULL DEFAULT 0.0,
    normalized_deviation   REAL NOT NULL DEFAULT 0.0,
    timestamp              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_assessments (
    assessment_id               TEXT PRIMARY KEY,
    task_id                     TEXT NOT NULL,
    step_number                 INTEGER NOT NULL DEFAULT 0,
    risk_score                  INTEGER NOT NULL,
    risk_tier                   TEXT NOT NULL,
    threat_signal_contrib       REAL NOT NULL DEFAULT 0.0,
    inconsistency_contrib       REAL NOT NULL DEFAULT 0.0,
    action_sensitivity_contrib  REAL NOT NULL DEFAULT 0.0,
    marker_contrib              REAL NOT NULL DEFAULT 0.0,
    action_sensitivity          REAL NOT NULL DEFAULT 0.3,
    booking_critical            INTEGER NOT NULL DEFAULT 0,
    timestamp                   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id                 TEXT PRIMARY KEY,
    task_id                     TEXT NOT NULL,
    step_number                 INTEGER NOT NULL DEFAULT 0,
    decision                    TEXT NOT NULL,
    reason                      TEXT NOT NULL,
    escalated_from_prior_flags  INTEGER NOT NULL DEFAULT 0,
    requires_human_confirmation INTEGER NOT NULL DEFAULT 0,
    timestamp                   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id            TEXT PRIMARY KEY,
    task_id             TEXT NOT NULL,
    step_number         INTEGER NOT NULL DEFAULT 0,
    action_type         TEXT NOT NULL,
    action_target       TEXT NOT NULL,
    action_value        TEXT,
    page_url            TEXT,
    snapshot_id         TEXT,
    verification_id     TEXT,
    detection_id        TEXT,
    assessment_id       TEXT,
    decision_id         TEXT,
    decision            TEXT NOT NULL,
    enforced_outcome    TEXT NOT NULL,
    full_chain_json     TEXT NOT NULL,
    timestamp           TEXT NOT NULL
);

-- ===========================================================================
-- ContextGuard Architectural Redesign Isolated Tables
-- ===========================================================================

CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'INITIALIZED', -- INITIALIZED | RUNNING | PAUSED | COMPLETED | BLOCKED
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- ISOLATED TESTBED TABLE: Testbed ground truth metadata (Ground truth ONLY)
-- Strict Software Boundary: ContextGuardRuntimeDAO has ZERO access to this table!
CREATE TABLE IF NOT EXISTS testbed_runs (
    run_id              TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL,
    testbed_scenario    TEXT NOT NULL, -- baseline | prompt_injection | unexpected_navigation | etc.
    attack_type         TEXT,
    target_page         TEXT,
    ground_truth_label  INTEGER NOT NULL DEFAULT 0, -- 0 = benign/normal, 1 = abnormal/adversarial
    injection_timestamp TEXT NOT NULL,
    metadata            TEXT
);

CREATE TABLE IF NOT EXISTS browser_states (
    state_id        TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    step_number     INTEGER NOT NULL DEFAULT 0,
    timestamp       TEXT NOT NULL,
    url             TEXT NOT NULL,
    domain          TEXT NOT NULL,
    page_title      TEXT,
    dom_hash        TEXT,
    text_length     INTEGER NOT NULL DEFAULT 0,
    forms_json      TEXT,
    inputs_json     TEXT,
    buttons_json    TEXT,
    links_json      TEXT,
    screenshot_path TEXT
);

CREATE TABLE IF NOT EXISTS state_transitions (
    transition_id    TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL,
    step_number      INTEGER NOT NULL DEFAULT 0,
    prev_state_id    TEXT,
    curr_state_id    TEXT,
    url_changed      INTEGER NOT NULL DEFAULT 0,
    domain_changed   INTEGER NOT NULL DEFAULT 0,
    dom_diff_json    TEXT,
    semantic_distance REAL NOT NULL DEFAULT 0.0,
    agent_action_id  TEXT,
    timestamp        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS model_predictions (
    prediction_id             TEXT PRIMARY KEY,
    session_id                TEXT NOT NULL,
    step_number               INTEGER NOT NULL DEFAULT 0,
    phase                     TEXT NOT NULL, -- PRE_ACTION | POST_ACTION
    risk_score                INTEGER NOT NULL,
    model_confidence          REAL NOT NULL DEFAULT 0.0,
    contributing_features_json TEXT,
    latency_ms                REAL NOT NULL DEFAULT 0.0,
    timestamp                 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions_v2 (
    decision_id        TEXT PRIMARY KEY,
    session_id         TEXT NOT NULL,
    step_number        INTEGER NOT NULL DEFAULT 0,
    phase              TEXT NOT NULL, -- PRE_ACTION | POST_ACTION
    decision           TEXT NOT NULL, -- ALLOW | WARN | PAUSE | BLOCK
    reason             TEXT NOT NULL,
    risk_score         INTEGER NOT NULL DEFAULT 0,
    action_sensitivity REAL NOT NULL DEFAULT 0.0,
    enforced_action    TEXT,
    timestamp          TEXT NOT NULL
);
"""


def init_db() -> None:
    """Create all tables and seed flight data if empty."""
    conn = get_conn()
    conn.executescript(_SCHEMA)
    conn.commit()

    cur = conn.execute("SELECT COUNT(*) FROM flights")
    if cur.fetchone()[0] == 0:
        _seed_flights(conn)

    conn.close()


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

def _seed_flights(conn: sqlite3.Connection) -> None:
    routes = [
        ("Chennai", "Delhi"),
        ("Chennai", "Mumbai"),
        ("Chennai", "Bangalore"),
        ("Bangalore", "Chennai"),
        ("Delhi", "Mumbai"),
        ("Bangalore", "Delhi"),
        ("Mumbai", "Bangalore"),
        ("Delhi", "Chennai"),
    ]
    airlines = ["IndiGo", "Air India", "Vistara", "SpiceJet"]
    cabins   = ["Economy", "Business"]
    base_date = (datetime.date.today() + datetime.timedelta(days=7)).isoformat()

    rows: List[tuple] = []
    for origin, dest in routes:
        for i, airline in enumerate(airlines):
            for cabin in cabins:
                base_price = 4500 if cabin == "Economy" else 15000
                dep = f"{6 + i * 3:02d}:00"
                arr = f"{8 + i * 3:02d}:15"
                rows.append((
                    str(uuid.uuid4()), airline,
                    origin, dest, base_date, dep, arr,
                    cabin, base_price + i * 300,
                ))

    conn.executemany(
        """INSERT INTO flights
           (flight_id, airline, origin, destination, date,
            departure_time, arrival_time, cabin_class, price)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Convenience CRUD helpers used by main.py and contextguard/
# ---------------------------------------------------------------------------

def insert_task(instruction: str) -> str:
    task_id = str(uuid.uuid4())
    ts = now_iso()
    conn = get_conn()
    conn.execute(
        "INSERT INTO tasks (task_id, user_instruction, status, created_at, updated_at)"
        " VALUES (?, ?, 'PENDING', ?, ?)",
        (task_id, instruction, ts, ts),
    )
    conn.commit()
    conn.close()
    return task_id


def update_task(task_id: str, **kwargs: Any) -> None:
    kwargs["updated_at"] = now_iso()
    sets = ", ".join(f"{k}=?" for k in kwargs)
    vals = list(kwargs.values()) + [task_id]
    conn = get_conn()
    conn.execute(f"UPDATE tasks SET {sets} WHERE task_id=?", vals)
    conn.commit()
    conn.close()


def insert_agent_action(
    task_id: str,
    step_number: int,
    action_type: str,
    action_details: str = "",
    page_url: str = "",
    dom_snapshot: str = "",
    result: str = "",
) -> str:
    action_id = str(uuid.uuid4())
    conn = get_conn()
    conn.execute(
        """INSERT INTO agent_actions
           (action_id, task_id, step_number, action_type, action_details,
            page_url, dom_snapshot, result, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (action_id, task_id, step_number, action_type,
         action_details, page_url, dom_snapshot, result, now_iso()),
    )
    conn.commit()
    conn.close()
    return action_id


def insert_attack(
    attack_type: str,
    target_page: str,
    payload: str,
    task_id: str = "",
) -> str:
    attack_id = str(uuid.uuid4())
    conn = get_conn()
    conn.execute(
        """INSERT INTO attacks
           (attack_id, task_id, attack_type, target_page, payload, active, injection_time)
           VALUES (?, ?, ?, ?, ?, 1, ?)""",
        (attack_id, task_id, attack_type, target_page, payload, now_iso()),
    )
    conn.commit()
    conn.close()
    return attack_id


def get_active_attacks(target_page: str) -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM attacks WHERE target_page=? AND active=1",
        (target_page,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_attacks(target_page: str) -> None:
    conn = get_conn()
    conn.execute(
        "UPDATE attacks SET active=0 WHERE target_page=?", (target_page,)
    )
    conn.commit()
    conn.close()


def insert_security_event(
    task_id: str,
    threat_type: str,
    details: str,
    risk_score: int,
    status: str = "OPEN",
) -> str:
    event_id = str(uuid.uuid4())
    conn = get_conn()
    conn.execute(
        """INSERT INTO security_events
           (event_id, task_id, threat_type, details, risk_score, status, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (event_id, task_id, threat_type, details, risk_score, status, now_iso()),
    )
    conn.commit()
    conn.close()
    return event_id


def insert_context_snapshot(
    task_id: str,
    step_number: int,
    user_intent: str,
    current_url: str,
    dom_hash: str,
    dom_summary: str,
    agent_context: str,
    agent_action: str,
    risk_score: int = 0,
    status: str = "CLEAN",
) -> str:
    snap_id = str(uuid.uuid4())
    conn = get_conn()
    conn.execute(
        """INSERT INTO context_snapshots
           (snapshot_id, task_id, step_number, user_intent, current_url,
            dom_hash, dom_summary, agent_context, agent_action,
            risk_score, status, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (snap_id, task_id, step_number, user_intent, current_url,
         dom_hash, dom_summary, agent_context, agent_action,
         risk_score, status, now_iso()),
    )
    conn.commit()
    conn.close()
    return snap_id


def get_logs(task_id: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
    conn = get_conn()
    q_filter = "WHERE task_id=?" if task_id else ""
    params   = (task_id,) if task_id else ()

    actions = [dict(r) for r in conn.execute(
        f"SELECT * FROM agent_actions {q_filter} ORDER BY timestamp DESC LIMIT ?",
        (*params, limit),
    ).fetchall()]

    attacks = [dict(r) for r in conn.execute(
        f"SELECT * FROM attacks {q_filter} ORDER BY injection_time DESC LIMIT ?",
        (*params, limit),
    ).fetchall()]

    events = [dict(r) for r in conn.execute(
        f"SELECT * FROM security_events {q_filter} ORDER BY timestamp DESC LIMIT ?",
        (*params, limit),
    ).fetchall()]

    snapshots = [dict(r) for r in conn.execute(
        f"SELECT * FROM context_snapshots {q_filter} ORDER BY timestamp DESC LIMIT ?",
        (*params, limit),
    ).fetchall()]

    audit_logs = [dict(r) for r in conn.execute(
        f"SELECT * FROM audit_log {q_filter} ORDER BY timestamp DESC LIMIT ?",
        (*params, limit),
    ).fetchall()]

    conn.close()
    return {
        "agent_actions":      actions,
        "attacks":            attacks,
        "security_events":    events,
        "context_snapshots":  snapshots,
        "audit_log":          audit_logs,
    }


# ---------------------------------------------------------------------------
# ContextGuard Phase 2: Traceable Decision Chain CRUD Helpers
# ---------------------------------------------------------------------------

def insert_verification_result(
    verification_id: str,
    task_id: str,
    step_number: int,
    is_consistent: bool,
    consistency_score: float,
    inconsistency_severity: float,
    inconsistencies: List[Dict[str, Any]],
    marker_presence: bool,
    marker_hit: Optional[str] = None,
) -> str:
    conn = get_conn()
    conn.execute(
        """INSERT INTO verification_results
           (verification_id, task_id, step_number, is_consistent, consistency_score,
            inconsistency_severity, inconsistencies, marker_presence, marker_hit, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            verification_id,
            task_id,
            step_number,
            1 if is_consistent else 0,
            consistency_score,
            inconsistency_severity,
            json.dumps(inconsistencies),
            1 if marker_presence else 0,
            marker_hit,
            now_iso(),
        ),
    )
    conn.commit()
    conn.close()
    return verification_id


def insert_threat_detection(
    detection_id: str,
    task_id: str,
    step_number: int,
    is_threat: bool,
    is_known_path: bool,
    attack_type: Optional[str],
    confidence: float,
    characterization_label: Optional[str],
    deviation_signal: float,
    normalized_deviation: float,
) -> str:
    conn = get_conn()
    conn.execute(
        """INSERT INTO threat_detections
           (detection_id, task_id, step_number, is_threat, is_known_path,
            attack_type, confidence, characterization_label, deviation_signal,
            normalized_deviation, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            detection_id,
            task_id,
            step_number,
            1 if is_threat else 0,
            1 if is_known_path else 0,
            attack_type,
            confidence,
            characterization_label,
            deviation_signal,
            normalized_deviation,
            now_iso(),
        ),
    )
    conn.commit()
    conn.close()
    return detection_id


def insert_risk_assessment(
    assessment_id: str,
    task_id: str,
    step_number: int,
    risk_score: int,
    risk_tier: str,
    threat_signal_contrib: float,
    inconsistency_contrib: float,
    action_sensitivity_contrib: float,
    marker_contrib: float,
    action_sensitivity: float,
    booking_critical: bool,
) -> str:
    conn = get_conn()
    conn.execute(
        """INSERT INTO risk_assessments
           (assessment_id, task_id, step_number, risk_score, risk_tier,
            threat_signal_contrib, inconsistency_contrib, action_sensitivity_contrib,
            marker_contrib, action_sensitivity, booking_critical, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            assessment_id,
            task_id,
            step_number,
            risk_score,
            risk_tier,
            threat_signal_contrib,
            inconsistency_contrib,
            action_sensitivity_contrib,
            marker_contrib,
            action_sensitivity,
            1 if booking_critical else 0,
            now_iso(),
        ),
    )
    conn.commit()
    conn.close()
    return assessment_id


def insert_policy_decision(
    decision_id: str,
    task_id: str,
    step_number: int,
    decision: str,
    reason: str,
    escalated_from_prior_flags: bool,
    requires_human_confirmation: bool,
) -> str:
    conn = get_conn()
    conn.execute(
        """INSERT INTO policy_decisions
           (decision_id, task_id, step_number, decision, reason,
            escalated_from_prior_flags, requires_human_confirmation, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            decision_id,
            task_id,
            step_number,
            decision,
            reason,
            1 if escalated_from_prior_flags else 0,
            1 if requires_human_confirmation else 0,
            now_iso(),
        ),
    )
    conn.commit()
    conn.close()
    return decision_id


def insert_audit_record(
    audit_id: str,
    task_id: str,
    step_number: int,
    action_type: str,
    action_target: str,
    action_value: Optional[str],
    page_url: str,
    snapshot_id: str,
    verification_id: str,
    detection_id: str,
    assessment_id: str,
    decision_id: str,
    decision: str,
    enforced_outcome: str,
    full_chain_json: str,
) -> str:
    conn = get_conn()
    conn.execute(
        """INSERT INTO audit_log
           (audit_id, task_id, step_number, action_type, action_target,
            action_value, page_url, snapshot_id, verification_id,
            detection_id, assessment_id, decision_id, decision,
            enforced_outcome, full_chain_json, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            audit_id,
            task_id,
            step_number,
            action_type,
            action_target,
            action_value,
            page_url,
            snapshot_id,
            verification_id,
            detection_id,
            assessment_id,
            decision_id,
            decision,
            enforced_outcome,
            full_chain_json,
            now_iso(),
        ),
    )
    conn.commit()
    conn.close()
    return audit_id


def get_audit_log(task_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_conn()
    q_filter = "WHERE task_id=?" if task_id else ""
    params   = (task_id,) if task_id else ()

    records = [dict(r) for r in conn.execute(
        f"SELECT * FROM audit_log {q_filter} ORDER BY timestamp ASC LIMIT ?",
        (*params, limit),
    ).fetchall()]
    conn.close()
    return records


# ===========================================================================
# ISOLATION ARCHITECTURE: Separate Data Access Interfaces
# ===========================================================================

class ContextGuardRuntimeDAO:
    """
    Data Access Object strictly for ContextGuard runtime operations.
    
    SECURITY BOUNDARY:
    ContextGuardRuntimeDAO has access ONLY to runtime observable states,
    actions, transitions, predictions, and policy decisions.
    It contains ZERO methods or queries for 'testbed_runs' or ground-truth labels!
    """

    @staticmethod
    def create_task(instruction: str, parsed_intent: Optional[Dict[str, Any]] = None) -> str:
        task_id = str(uuid.uuid4())
        ts = now_iso()
        conn = get_conn()
        conn.execute(
            """INSERT INTO tasks (task_id, user_instruction, parsed_intent, status, created_at, updated_at)
               VALUES (?, ?, ?, 'PENDING', ?, ?)""",
            (task_id, instruction, json.dumps(parsed_intent or {}), ts, ts),
        )
        conn.commit()
        conn.close()
        return task_id

    @staticmethod
    def get_task(task_id: str) -> Optional[Dict[str, Any]]:
        conn = get_conn()
        row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        if d.get("parsed_intent"):
            try:
                d["parsed_intent"] = json.loads(d["parsed_intent"])
            except Exception:
                pass
        return d

    @staticmethod
    def create_session(task_id: str) -> str:
        session_id = str(uuid.uuid4())
        ts = now_iso()
        conn = get_conn()
        conn.execute(
            """INSERT INTO sessions (session_id, task_id, status, created_at, updated_at)
               VALUES (?, ?, 'INITIALIZED', ?, ?)""",
            (session_id, task_id, ts, ts),
        )
        conn.commit()
        conn.close()
        return session_id

    @staticmethod
    def update_session_status(session_id: str, status: str) -> None:
        conn = get_conn()
        conn.execute(
            "UPDATE sessions SET status=?, updated_at=? WHERE session_id=?",
            (status, now_iso(), session_id),
        )
        conn.commit()
        conn.close()

    @staticmethod
    def get_session(session_id: str) -> Optional[Dict[str, Any]]:
        conn = get_conn()
        row = conn.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    @staticmethod
    def record_browser_state(
        session_id: str,
        step_number: int,
        url: str,
        domain: str,
        page_title: str = "",
        dom_hash: str = "",
        text_length: int = 0,
        forms: Optional[List[Any]] = None,
        inputs: Optional[List[Any]] = None,
        buttons: Optional[List[Any]] = None,
        links: Optional[List[Any]] = None,
        screenshot_path: str = "",
    ) -> str:
        state_id = str(uuid.uuid4())
        conn = get_conn()
        conn.execute(
            """INSERT INTO browser_states
               (state_id, session_id, step_number, timestamp, url, domain,
                page_title, dom_hash, text_length, forms_json, inputs_json,
                buttons_json, links_json, screenshot_path)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                state_id, session_id, step_number, now_iso(), url, domain,
                page_title, dom_hash, text_length,
                json.dumps(forms or []), json.dumps(inputs or []),
                json.dumps(buttons or []), json.dumps(links or []),
                screenshot_path,
            ),
        )
        conn.commit()
        conn.close()
        return state_id

    @staticmethod
    def get_latest_browser_states(session_id: str, limit: int = 2) -> List[Dict[str, Any]]:
        conn = get_conn()
        rows = conn.execute(
            "SELECT * FROM browser_states WHERE session_id=? ORDER BY step_number DESC, timestamp DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            for f in ("forms_json", "inputs_json", "buttons_json", "links_json"):
                if d.get(f):
                    try:
                        d[f] = json.loads(d[f])
                    except Exception:
                        pass
            results.append(d)
        return results

    @staticmethod
    def record_state_transition(
        session_id: str,
        step_number: int,
        prev_state_id: Optional[str],
        curr_state_id: str,
        url_changed: bool,
        domain_changed: bool,
        dom_diff: Optional[Dict[str, Any]] = None,
        semantic_distance: float = 0.0,
        agent_action_id: Optional[str] = None,
    ) -> str:
        trans_id = str(uuid.uuid4())
        conn = get_conn()
        conn.execute(
            """INSERT INTO state_transitions
               (transition_id, session_id, step_number, prev_state_id, curr_state_id,
                url_changed, domain_changed, dom_diff_json, semantic_distance,
                agent_action_id, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                trans_id, session_id, step_number, prev_state_id, curr_state_id,
                1 if url_changed else 0, 1 if domain_changed else 0,
                json.dumps(dom_diff or {}), semantic_distance,
                agent_action_id, now_iso(),
            ),
        )
        conn.commit()
        conn.close()
        return trans_id

    @staticmethod
    def record_agent_action(
        session_id: str,
        step_number: int,
        action_type: str,
        selector: str = "",
        value: Optional[str] = None,
        action_sensitivity: float = 0.0,
    ) -> str:
        action_id = str(uuid.uuid4())
        conn = get_conn()
        conn.execute(
            """INSERT INTO agent_actions
               (action_id, task_id, step_number, action_type, action_details, page_url, dom_snapshot, result, timestamp)
               VALUES (?, ?, ?, ?, ?, '', '', '', ?)""",
            (
                action_id, session_id, step_number, action_type,
                json.dumps({"selector": selector, "value": value, "sensitivity": action_sensitivity}),
                now_iso(),
            ),
        )
        conn.commit()
        conn.close()
        return action_id

    @staticmethod
    def record_model_prediction(
        session_id: str,
        step_number: int,
        phase: str,
        risk_score: int,
        model_confidence: float,
        contributing_features: Optional[Dict[str, Any]] = None,
        latency_ms: float = 0.0,
    ) -> str:
        pred_id = str(uuid.uuid4())
        conn = get_conn()
        conn.execute(
            """INSERT INTO model_predictions
               (prediction_id, session_id, step_number, phase, risk_score,
                model_confidence, contributing_features_json, latency_ms, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                pred_id, session_id, step_number, phase, risk_score,
                model_confidence, json.dumps(contributing_features or {}),
                latency_ms, now_iso(),
            ),
        )
        conn.commit()
        conn.close()
        return pred_id

    @staticmethod
    def record_policy_decision(
        session_id: str,
        step_number: int,
        phase: str,
        decision: str,
        reason: str,
        risk_score: int = 0,
        action_sensitivity: float = 0.0,
        enforced_action: Optional[str] = None,
    ) -> str:
        dec_id = str(uuid.uuid4())
        conn = get_conn()
        conn.execute(
            """INSERT INTO policy_decisions_v2
               (decision_id, session_id, step_number, phase, decision,
                reason, risk_score, action_sensitivity, enforced_action, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                dec_id, session_id, step_number, phase, decision,
                reason, risk_score, action_sensitivity, enforced_action, now_iso(),
            ),
        )
        conn.commit()
        conn.close()
        return dec_id

    @staticmethod
    def get_session_audit_trail(session_id: str) -> Dict[str, Any]:
        conn = get_conn()
        session = conn.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        states = conn.execute("SELECT * FROM browser_states WHERE session_id=? ORDER BY step_number ASC", (session_id,)).fetchall()
        transitions = conn.execute("SELECT * FROM state_transitions WHERE session_id=? ORDER BY step_number ASC", (session_id,)).fetchall()
        predictions = conn.execute("SELECT * FROM model_predictions WHERE session_id=? ORDER BY step_number ASC, phase ASC", (session_id,)).fetchall()
        decisions = conn.execute("SELECT * FROM policy_decisions_v2 WHERE session_id=? ORDER BY step_number ASC, phase ASC", (session_id,)).fetchall()
        actions = conn.execute("SELECT * FROM agent_actions WHERE task_id=? ORDER BY step_number ASC", (session_id,)).fetchall()
        conn.close()

        return {
            "session": dict(session) if session else {},
            "states": [dict(s) for s in states],
            "transitions": [dict(t) for t in transitions],
            "predictions": [dict(p) for p in predictions],
            "decisions": [dict(d) for d in decisions],
            "actions": [dict(a) for a in actions],
        }


class TestbedDAO:
    """
    Data Access Object strictly for the independent Testbed environment.
    Stores ground truth metadata for offline post-run evaluation.
    """

    @staticmethod
    def record_testbed_run(
        session_id: str,
        testbed_scenario: str,
        attack_type: Optional[str] = None,
        target_page: Optional[str] = None,
        ground_truth_label: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        run_id = str(uuid.uuid4())
        conn = get_conn()
        conn.execute(
            """INSERT INTO testbed_runs
               (run_id, session_id, testbed_scenario, attack_type, target_page,
                ground_truth_label, injection_timestamp, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id, session_id, testbed_scenario, attack_type, target_page,
                ground_truth_label, now_iso(), json.dumps(metadata or {}),
            ),
        )
        conn.commit()
        conn.close()
        return run_id

    @staticmethod
    def get_testbed_run(session_id: str) -> Optional[Dict[str, Any]]:
        conn = get_conn()
        row = conn.execute("SELECT * FROM testbed_runs WHERE session_id=?", (session_id,)).fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        if d.get("metadata"):
            try:
                d["metadata"] = json.loads(d["metadata"])
            except Exception:
                pass
        return d

    @staticmethod
    def get_latest_testbed_run() -> Optional[Dict[str, Any]]:
        conn = get_conn()
        row = conn.execute("SELECT * FROM testbed_runs ORDER BY rowid DESC LIMIT 1").fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        if d.get("metadata"):
            try:
                d["metadata"] = json.loads(d["metadata"])
            except Exception:
                pass
        return d


class EvaluationDAO:
    """
    Post-run evaluation engine comparing ContextGuard predictions against Testbed ground truth.
    Runs strictly OFFLINE after session completion.
    """

    @staticmethod
    def get_session_evaluation(session_id: str) -> Dict[str, Any]:
        conn = get_conn()
        tb = conn.execute("SELECT * FROM testbed_runs WHERE session_id=?", (session_id,)).fetchone()
        preds = conn.execute("SELECT * FROM model_predictions WHERE session_id=? ORDER BY step_number ASC", (session_id,)).fetchall()
        decs = conn.execute("SELECT * FROM policy_decisions_v2 WHERE session_id=? ORDER BY step_number ASC", (session_id,)).fetchall()
        conn.close()

        if not tb:
            return {"error": f"No testbed ground truth found for session {session_id}"}

        testbed_data = dict(tb)
        ground_truth = testbed_data.get("ground_truth_label", 0) # 0 = benign, 1 = attack

        pred_list = [dict(p) for p in preds]
        dec_list = [dict(d) for d in decs]

        max_risk = max([p["risk_score"] for p in pred_list], default=0)
        avg_risk = sum([p["risk_score"] for p in pred_list]) / max(1, len(pred_list))
        latencies = [p["latency_ms"] for p in pred_list if p.get("latency_ms")]
        avg_latency = sum(latencies) / max(1, len(latencies))

        blocked_count = sum(1 for d in dec_list if d["decision"] in ("BLOCK", "PAUSE"))
        warn_count = sum(1 for d in dec_list if d["decision"] == "WARN")
        allow_count = sum(1 for d in dec_list if d["decision"] == "ALLOW")

        # Classification outcome
        predicted_positive = max_risk >= 50 or blocked_count > 0
        actual_positive = ground_truth == 1

        if actual_positive and predicted_positive:
            classification = "TRUE_POSITIVE"
        elif not actual_positive and not predicted_positive:
            classification = "TRUE_NEGATIVE"
        elif not actual_positive and predicted_positive:
            classification = "FALSE_POSITIVE"
        else:
            classification = "FALSE_NEGATIVE"

        return {
            "session_id": session_id,
            "testbed_scenario": testbed_data.get("testbed_scenario"),
            "attack_type": testbed_data.get("attack_type"),
            "ground_truth_label": ground_truth,
            "ground_truth_meaning": "Adversarial" if ground_truth == 1 else "Benign",
            "classification": classification,
            "max_risk_score": max_risk,
            "avg_risk_score": round(avg_risk, 1),
            "decisions_summary": {
                "allowed": allow_count,
                "warned": warn_count,
                "blocked_or_paused": blocked_count,
            },
            "latency": {
                "mean_ms": round(avg_latency, 2),
                "samples": len(latencies),
            },
            "timeline": pred_list,
        }

