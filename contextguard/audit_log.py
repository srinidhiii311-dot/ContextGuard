"""Tamper-evident audit log: each row stores prev_hash and hash (SHA-256 chain).

Detects: edited rows, deleted/inserted rows in the middle of the chain.
Does NOT detect: truncation of the newest rows. Export head() to an external place
(file, other DB, email) periodically to cover that, and say so in the write-up.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import time
from dataclasses import dataclass
from typing import Optional, Union

GENESIS = "0" * 64
DEFAULT_ANCHOR_FILE = Path("audit_anchor.jsonl")
DEFAULT_HMAC_SECRET = os.getenv("AUDIT_HMAC_SECRET", "contextguard-audit-anchor-hmac-secret-key-2026").encode()


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

    def write_checkpoint(
        self,
        anchor_path: Optional[Union[Path, str]] = None,
        secret: Optional[bytes] = None,
    ) -> dict:
        """
        Step 3.8 / Shortfall S8 Fix:
        Computes HMAC-SHA256 over current chain head and row count,
        and appends checkpoint anchor to an external file outside SQLite.
        """
        p = Path(anchor_path) if anchor_path else DEFAULT_ANCHOR_FILE
        sec = secret or (os.getenv("AUDIT_HMAC_SECRET", "").encode() or DEFAULT_HMAC_SECRET)
        head_h = self.head()
        r = self.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        row_count = int(r[0]) if r else 0
        ts = time.time()
        msg = f"{head_h}|{row_count}|{ts!r}"
        sig = hmac.new(sec, msg.encode(), hashlib.sha256).hexdigest()
        record = {
            "ts": ts,
            "head_hash": head_h,
            "row_count": row_count,
            "hmac": sig,
        }
        if p.parent and str(p.parent) != ".":
            p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def verify_against_anchor(
        self,
        anchor_path: Optional[Union[Path, str]] = None,
        secret: Optional[bytes] = None,
    ) -> VerifyResult:
        """
        Step 3.8 / Shortfall S8 Fix:
        Verifies live chain against external HMAC-signed checkpoint anchor.
        Detects middle-row modification, intermediate deletion, and tail truncation.
        """
        base_res = self.verify()
        if not base_res.ok:
            return base_res

        p = Path(anchor_path) if anchor_path else DEFAULT_ANCHOR_FILE
        if not p.exists() or p.stat().st_size == 0:
            return VerifyResult(True, base_res.checked, reason="no external anchor file; internal chain valid")

        last_line = ""
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line.strip()

        if not last_line:
            return VerifyResult(True, base_res.checked, reason="anchor file empty; internal chain valid")

        try:
            anchor = json.loads(last_line)
            anchor_head = str(anchor["head_hash"])
            anchor_count = int(anchor["row_count"])
            anchor_ts = float(anchor["ts"])
            anchor_hmac = str(anchor["hmac"])
        except (ValueError, KeyError) as e:
            return VerifyResult(False, base_res.checked, reason=f"malformed anchor record: {e}")

        sec = secret or (os.getenv("AUDIT_HMAC_SECRET", "").encode() or DEFAULT_HMAC_SECRET)
        expected_sig = hmac.new(sec, f"{anchor_head}|{anchor_count}|{anchor_ts!r}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(anchor_hmac, expected_sig):
            return VerifyResult(False, base_res.checked, reason="external anchor HMAC signature invalid")

        # Live count check: detects truncation of newest rows
        r = self.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        live_count = int(r[0]) if r else 0
        if live_count < anchor_count:
            return VerifyResult(
                False,
                live_count,
                reason=f"audit chain truncated: database has {live_count} rows, anchor expected {anchor_count}"
            )

        if anchor_count > 0:
            row = self.conn.execute(
                "SELECT hash FROM audit_log ORDER BY id LIMIT 1 OFFSET ?",
                (anchor_count - 1,)
            ).fetchone()
            if not row or row[0] != anchor_head:
                return VerifyResult(
                    False,
                    live_count,
                    reason=f"audit chain head mismatch at anchor point (row {anchor_count})"
                )

        return VerifyResult(True, live_count, reason="chain verified against external anchor")
