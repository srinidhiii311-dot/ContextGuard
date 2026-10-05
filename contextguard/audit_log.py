"""Tamper-evident audit log: each row stores prev_hash and hash (SHA-256 chain).

Detects: edited rows, deleted/inserted rows in the middle of the chain.
Does NOT detect: truncation of the newest rows. Export head() to an external place
(file, other DB, email) periodically to cover that, and say so in the write-up.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Optional

GENESIS = "0" * 64


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    first_bad_id: Optional[int] = None
    reason: str = ""


def _digest(prev: str, ts: float, event: str, actor: str, payload: str) -> str:
    return hashlib.sha256(f"{prev}|{ts!r}|{event}|{actor}|{payload}".encode()).hexdigest()


class AuditLog:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, event TEXT NOT NULL,
            actor TEXT NOT NULL, payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL)""")
        conn.commit()

    def head(self) -> str:
        r = self.conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        return r[0] if r else GENESIS

    def append(self, event: str, actor: str, payload: dict, ts: Optional[float] = None) -> str:
        ts = time.time() if ts is None else ts
        body = json.dumps(payload, sort_keys=True, default=str)
        self.conn.execute("BEGIN IMMEDIATE") if not self.conn.in_transaction else None
        prev = self.head()
        h = _digest(prev, ts, event, actor, body)
        self.conn.execute("INSERT INTO audit_log(ts,event,actor,payload,prev_hash,hash) VALUES(?,?,?,?,?,?)",
                          (ts, event, actor, body, prev, h))
        self.conn.commit()
        return h

    def verify(self) -> VerifyResult:
        prev, n = GENESIS, 0
        for row in self.conn.execute("SELECT id,ts,event,actor,payload,prev_hash,hash FROM audit_log ORDER BY id"):
            i, ts, ev, ac, pl, ph, h = row
            if ph != prev:
                return VerifyResult(False, n, i, "prev_hash does not match previous row")
            if _digest(prev, ts, ev, ac, pl) != h:
                return VerifyResult(False, n, i, "row content does not match its hash")
            prev, n = h, n + 1
        return VerifyResult(True, n)
