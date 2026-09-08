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

    conn.close()
    return {
        "agent_actions":      actions,
        "attacks":            attacks,
        "security_events":    events,
        "context_snapshots":  snapshots,
    }
