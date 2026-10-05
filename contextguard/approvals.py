"""Role-based approval workflow: users, roles, JWT (HS256, stdlib), approvals, audit.

States: PENDING -> APPROVED | DENIED | EXPIRED.  Timeout defaults to DENY: only
APPROVED lets the action proceed; EXPIRED counts as a stop.
Rules enforced here (each has a test)
- only role >= approver may decide; a reason is mandatory;
- one decision per user per approval; any DENY ends the request;
- risk_score >= two_approver_threshold needs two DISTINCT approvers;
- every event is appended to the hash-chained audit log.
Secrets come from the environment only (JWT_SECRET, >= 16 chars).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from typing import Callable, Dict, List, Optional

from .audit_log import AuditLog

ROLE_RANK = {"viewer": 0, "analyst": 1, "approver": 2, "admin": 3}


class StateError(Exception):
    pass


def connect(path: str = "contextguard.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.isolation_level = ""          # back to implicit transactions
    return conn


def has_role(role: str, minimum: str) -> bool:
    return ROLE_RANK.get(role, -1) >= ROLE_RANK[minimum]


# ---------- passwords and tokens ----------
def hash_password(password: str, n: int = 2 ** 14, r: int = 8, p: int = 1) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                              n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc.hex(), dk)
    except (ValueError, TypeError):
        return False


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def secret_from_env() -> str:
    s = os.getenv("JWT_SECRET", "")
    if len(s) < 16:
        raise RuntimeError("JWT_SECRET must be set (at least 16 characters)")
    return s


def issue_token(username: str, role: str, secret: str, ttl: int = 3600,
                now: Optional[float] = None) -> str:
    now = time.time() if now is None else now
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps({"sub": username, "role": role, "exp": int(now + ttl)}).encode())
    sig = _b64(hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


def verify_token(token: str, secret: str, now: Optional[float] = None) -> Optional[dict]:
    try:
        head, body, sig = token.split(".")
        if json.loads(_unb64(head)).get("alg") != "HS256":
            return None
        good = _b64(hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good):
            return None
        claims = json.loads(_unb64(body))
        if claims["exp"] < (time.time() if now is None else now):
            return None
        return claims
    except (ValueError, KeyError, TypeError):
        return None


# ---------- service ----------
class ApprovalService:
    def __init__(self, conn: sqlite3.Connection, audit: Optional[AuditLog] = None,
                 clock: Callable[[], float] = time.time,
                 two_approver_threshold: int = 80) -> None:
        self.conn, self.clock = conn, clock
        self.audit = audit or AuditLog(conn)
        self.two_at = two_approver_threshold
        self.lock = threading.RLock()
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS approvals(
            id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL, step INTEGER,
            action TEXT NOT NULL, risk_score REAL NOT NULL, status TEXT NOT NULL,
            required INTEGER NOT NULL, requested_at REAL NOT NULL, expires_at REAL NOT NULL,
            resolved_at REAL);
        CREATE TABLE IF NOT EXISTS approval_decisions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, approval_id INTEGER NOT NULL REFERENCES approvals(id),
            username TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, ts REAL NOT NULL,
            UNIQUE(approval_id, username));""")
        conn.commit()

    # users
    def create_user(self, username: str, password: str, role: str = "viewer") -> None:
        if role not in ROLE_RANK:
            raise ValueError(f"unknown role {role!r}")
        with self.lock:
            self.conn.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                              (username, hash_password(password), role, self.clock()))
            self.conn.commit()
            self.audit.append("user_created", "system", {"username": username, "role": role})

    def authenticate(self, username: str, password: str) -> Optional[dict]:
        r = self.conn.execute("SELECT username,password_hash,role,active FROM users WHERE username=?",
                              (username,)).fetchone()
        ok = bool(r) and r[3] == 1 and verify_password(password, r[1])
        if not r:
            verify_password(password, hash_password("x", n=2 ** 10))   # equalise timing
        self.audit.append("login_ok" if ok else "login_failed", username, {})
        return {"username": r[0], "role": r[2]} if ok else None

    def get_user(self, username: str) -> Optional[dict]:
        r = self.conn.execute("SELECT username,role,active FROM users WHERE username=?", (username,)).fetchone()
        return {"username": r[0], "role": r[1]} if r and r[2] == 1 else None

    # approvals
    def request(self, task_id: str, step: int, action: dict, risk_score: float,
                ttl_seconds: int = 300) -> int:
        now = self.clock()
        required = 2 if risk_score >= self.two_at else 1
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO approvals(task_id,step,action,risk_score,status,required,requested_at,expires_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (task_id, step, json.dumps(action, sort_keys=True, default=str), risk_score,
                 "PENDING", required, now, now + ttl_seconds))
            self.conn.commit()
            aid = cur.lastrowid
            self.audit.append("approval_requested", "gate",
                              {"approval_id": aid, "task_id": task_id, "step": step,
                               "risk_score": risk_score, "required": required})
        return aid

    def _expire(self, aid: int) -> None:
        r = self.conn.execute("SELECT status,expires_at FROM approvals WHERE id=?", (aid,)).fetchone()
        if r and r[0] == "PENDING" and self.clock() >= r[1]:
            self.conn.execute("UPDATE approvals SET status='EXPIRED', resolved_at=? WHERE id=?",
                              (self.clock(), aid))
            self.conn.commit()
            self.audit.append("approval_expired", "system", {"approval_id": aid})

    def status(self, aid: int) -> Optional[dict]:
        with self.lock:
            self._expire(aid)
            r = self.conn.execute("SELECT id,task_id,step,action,risk_score,status,required,requested_at,"
                                  "expires_at,resolved_at FROM approvals WHERE id=?", (aid,)).fetchone()
            if not r:
                return None
            ds = self.conn.execute("SELECT username,decision,reason,ts FROM approval_decisions "
                                   "WHERE approval_id=? ORDER BY id", (aid,)).fetchall()
        keys = ["id", "task_id", "step", "action", "risk_score", "status", "required",
                "requested_at", "expires_at", "resolved_at"]
        d = dict(zip(keys, r))
        d["action"] = json.loads(d["action"])
        d["decisions"] = [dict(zip(["username", "decision", "reason", "ts"], x)) for x in ds]
        return d

    def list(self, status: Optional[str] = None) -> List[dict]:
        ids = [r[0] for r in self.conn.execute("SELECT id FROM approvals ORDER BY id DESC")]
        out = [self.status(i) for i in ids]
        return [o for o in out if o and (status is None or o["status"] == status)]

    def decide(self, aid: int, username: str, decision: str, reason: str) -> dict:
        decision = decision.upper()
        if decision not in ("APPROVE", "DENY"):
            raise ValueError("decision must be APPROVE or DENY")
        if not reason or not reason.strip():
            raise ValueError("a reason is mandatory")
        with self.lock:
            user = self.get_user(username)
            if not user or not has_role(user["role"], "approver"):
                self.audit.append("decision_rejected", username, {"approval_id": aid, "why": "role"})
                raise PermissionError("approver role required")
            self._expire(aid)
            row = self.conn.execute("SELECT status,required FROM approvals WHERE id=?", (aid,)).fetchone()
            if not row:
                raise KeyError(aid)
            if row[0] != "PENDING":
                raise StateError(f"approval is {row[0]}")
            try:
                self.conn.execute("INSERT INTO approval_decisions(approval_id,username,decision,reason,ts)"
                                  " VALUES(?,?,?,?,?)", (aid, username, decision, reason.strip(), self.clock()))
            except sqlite3.IntegrityError:
                self.conn.rollback()
                raise ValueError("this user already decided on this approval")
            n_ok = self.conn.execute("SELECT COUNT(*) FROM approval_decisions WHERE approval_id=? "
                                     "AND decision='APPROVE'", (aid,)).fetchone()[0]
            new = None
            if decision == "DENY":
                new = "DENIED"
            elif n_ok >= row[1]:
                new = "APPROVED"
            if new:
                self.conn.execute("UPDATE approvals SET status=?, resolved_at=? WHERE id=?",
                                  (new, self.clock(), aid))
            self.conn.commit()
            self.audit.append("approval_decision", username,
                              {"approval_id": aid, "decision": decision, "reason": reason.strip(),
                               "result": new or "PENDING"})
        return self.status(aid)

    def outcome(self, aid: int) -> str:
        """ALLOWED only if APPROVED. DENIED/EXPIRED -> STOPPED. Still open -> PENDING."""
        s = self.status(aid)["status"]
        return "ALLOWED" if s == "APPROVED" else ("PENDING" if s == "PENDING" else "STOPPED")
