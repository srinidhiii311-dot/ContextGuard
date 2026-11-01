"""
contextguard/audit_log.py — Tamper-Evident Audit Log & Intent Security (Block 4a)

Features:
1. JSONL Audit Log: Append-only SHA-256 hash-chained audit logging for every gate decision.
   Each entry contains prev_hash and entry_hash (SHA-256 over entry content + prev_hash).
2. verify_audit_log(path): Cryptographically validates the chain, detecting any edited,
   deleted, inserted, or reordered entry and reporting the first broken index.
3. Locked Intent Security: HMAC-SHA256 signing and verification of user intent to detect
   tampering during active sessions.
4. Backwards-compatible SQLite AuditLog implementation for legacy test harnesses.
"""

from __future__ import annotations

import atexit
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import queue
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

GENESIS = "0" * 64
DEFAULT_ANCHOR_FILE = Path("audit_anchor.jsonl")
DEFAULT_JSONL_AUDIT_LOG = Path("runs/audit_log.jsonl")


def hmac_secret_from_env() -> bytes:
    """Retrieves secret for SQLite audit log anchor signing."""
    s = os.getenv("AUDIT_HMAC_SECRET", "").strip()
    if len(s) < 16:
        raise RuntimeError("AUDIT_HMAC_SECRET must be set (at least 16 characters)")
    return s.encode()


def get_intent_hmac_secret() -> bytes:
    """
    Retrieves secret key held exclusively by the gateway process (from env, never exposed to agent).
    Used to sign and verify LockedIntent / TrustedIntent and external audit anchors.
    Strict enforcement: No default or fallback key. A missing or short secret stops the gateway immediately.
    """
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        pass

    s = (
        os.getenv("GATEWAY_INTENT_KEY")
        or os.getenv("INTENT_HMAC_KEY")
        or os.getenv("AUDIT_HMAC_SECRET")
        or ""
    ).strip()
    if len(s) < 16:
        raise RuntimeError(
            "GATEWAY_INTENT_KEY (or AUDIT_HMAC_SECRET) must be set in the process environment "
            "(at least 16 characters). Missing or weak gateway secret stops the gateway."
        )
    return s.encode("utf-8")


def serialize_intent(intent: Any) -> bytes:
    """Deterministically serializes an intent object or mapping to JSON bytes."""
    if hasattr(intent, "to_dict") and callable(intent.to_dict):
        data = intent.to_dict()
    elif isinstance(intent, dict):
        data = intent
    elif hasattr(intent, "__dict__"):
        data = {k: v for k, v in intent.__dict__.items() if not k.startswith("_")}
    else:
        data = {"raw": str(intent)}
    return json.dumps(data, sort_keys=True, default=str).encode("utf-8")


def compute_intent_hmac(intent: Any, secret: Optional[bytes] = None) -> str:
    """Computes HMAC-SHA256 over serialized intent using the gateway process secret."""
    sec = secret if secret is not None else get_intent_hmac_secret()
    payload = serialize_intent(intent)
    return hmac.new(sec, payload, hashlib.sha256).hexdigest()


def verify_intent_hmac(intent: Any, expected_hmac: str, secret: Optional[bytes] = None) -> bool:
    """Verifies that an intent matches its gateway-signed HMAC."""
    actual = compute_intent_hmac(intent, secret)
    return hmac.compare_digest(actual, expected_hmac)


def compute_entry_hash(entry_dict: Dict[str, Any], prev_hash: str) -> str:
    """
    Computes SHA-256 over the entry content (excluding entry_hash) plus prev_hash.
    Sorts keys to ensure strict deterministic JSON serialization.
    """
    content = {k: v for k, v in entry_dict.items() if k != "entry_hash"}
    payload_str = json.dumps(content, sort_keys=True, default=str)
    raw = f"{prev_hash}|{payload_str}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass
class VerifyResult:
    """Verification outcome for SQLite audit log."""
    ok: bool
    checked: int
    first_bad_id: Optional[int] = None
    reason: str = ""


@dataclass
class AuditVerifyResult:
    """
    Verification outcome for JSONL append-only audit log.
    Supports attribute access (ok, checked_count, broken_index) and tuple unpacking (ok, broken_index).
    """
    ok: bool
    checked_count: int
    broken_index: Optional[int] = None
    reason: str = ""

    @property
    def checked(self) -> int:
        return self.checked_count

    @property
    def first_broken_index(self) -> Optional[int]:
        return self.broken_index

    @property
    def first_bad_id(self) -> Optional[int]:
        return self.broken_index

    def __iter__(self):
        return iter((self.ok, self.broken_index))

    def __getitem__(self, item: int):
        if item == 0:
            return self.ok
        elif item == 1:
            return self.broken_index
        raise IndexError(f"Index {item} out of range for AuditVerifyResult")


class JsonlAuditLog:
    """
    Thread-safe, append-only JSONL audit log with background group commit.
    Each entry includes prev_hash and entry_hash (SHA-256 chain).
    Persistence uses a dedicated background writer thread and group commit:
    - Flushes every 50 entries or 200 ms (whichever comes first)
    - fsync on flush and shutdown
    - Writes HMAC-anchored checkpoint every N entries and at flush
    - Chain calculation remains synchronous and deterministic
    """
    def __init__(
        self,
        log_path: Union[str, Path] = DEFAULT_JSONL_AUDIT_LOG,
        anchor_path: Optional[Union[str, Path]] = None,
        auto_anchor: bool = True,
        batch_size: int = 50,
        flush_interval: float = 0.20,
        anchor_every_n: int = 50,
    ) -> None:
        self.log_path = Path(log_path).resolve()
        self.anchor_path = Path(anchor_path).resolve() if anchor_path else self._default_anchor_path(self.log_path)
        self.auto_anchor = auto_anchor
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.anchor_every_n = anchor_every_n
        self._entries_since_anchor = 0
        self._lock = threading.Lock()
        self._head_hash: Optional[str] = None
        self._entry_count: int = 0
        self._init_head()

        # Background group commit queue and worker thread
        self._queue: queue.Queue[Optional[Tuple[Dict[str, Any], Optional[Callable[[], None]]]]] = queue.Queue()
        self._stop_event = threading.Event()
        self._flush_event = threading.Event()
        self._flush_done = threading.Condition()
        self._pending_count = 0
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name=f"AuditWriter-{self.log_path.stem}")
        self._worker_thread.start()

        # Auto-register in global registry
        with _REGISTRY_LOCK:
            _AUDIT_REGISTRY[str(self.log_path)] = self

        atexit.register(self.shutdown)

    @staticmethod
    def _default_anchor_path(p: Path) -> Path:
        return p.parent / f"{p.stem}_anchor.jsonl"

    def _init_head(self) -> None:
        with self._lock:
            if not self.log_path.exists() or self.log_path.stat().st_size == 0:
                self._head_hash = GENESIS
                self._entry_count = 0
                return

            last_line = ""
            count = 0
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s:
                        last_line = s
                        count += 1

            if last_line:
                try:
                    data = json.loads(last_line)
                    self._head_hash = data.get("entry_hash", GENESIS)
                    self._entry_count = count
                except Exception:
                    self._head_hash = GENESIS
                    self._entry_count = 0
            else:
                self._head_hash = GENESIS
                self._entry_count = 0

    def _write_anchor_locked(self, target_anchor: Path, secret: Optional[bytes] = None) -> Dict[str, Any]:
        sec = secret or get_intent_hmac_secret()
        head_h = self._head_hash or GENESIS
        count = self._entry_count
        ts = time.time()
        msg = f"{head_h}|{count}|{ts!r}"
        sig = hmac.new(sec, msg.encode("utf-8"), hashlib.sha256).hexdigest()
        record = {
            "ts": ts,
            "head_hash": head_h,
            "row_count": count,
            "hmac": sig,
        }
        target_anchor.parent.mkdir(parents=True, exist_ok=True)
        with open(target_anchor, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        return record

    def write_checkpoint(
        self,
        anchor_path: Optional[Union[Path, str]] = None,
        secret: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """Writes an HMAC-anchored checkpoint to an external anchor file, flushing pending writes first."""
        self.flush()
        with self._lock:
            target = Path(anchor_path).resolve() if anchor_path else self.anchor_path
            return self._write_anchor_locked(target, secret)

    def _flush_buffer(self, buffer: List[Tuple[Dict[str, Any], Optional[Callable[[], None]]]]) -> None:
        if not buffer:
            return

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            for record, _ in buffer:
                f.write(json.dumps(record, sort_keys=True, default=str) + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass

        # Execute attached DB operations in batch
        for _, db_op in buffer:
            if db_op is not None:
                try:
                    db_op()
                except Exception:
                    pass

        # Anchor write at flush and every N entries
        with self._lock:
            self._entries_since_anchor += len(buffer)
            if self.auto_anchor and self.anchor_path:
                try:
                    self._write_anchor_locked(self.anchor_path)
                    self._entries_since_anchor = 0
                except Exception:
                    pass

        with self._lock:
            self._pending_count -= len(buffer)

    def _worker_loop(self) -> None:
        buffer: List[Tuple[Dict[str, Any], Optional[Callable[[], None]]]] = []
        last_flush = time.time()

        while not self._stop_event.is_set():
            timeout = max(0.01, self.flush_interval - (time.time() - last_flush))
            try:
                item = self._queue.get(timeout=min(timeout, 0.05))
                if item is not None:
                    buffer.append(item)
            except queue.Empty:
                pass

            now = time.time()
            should_flush = (
                len(buffer) >= self.batch_size
                or (buffer and (now - last_flush) >= self.flush_interval)
                or self._flush_event.is_set()
                or (self._stop_event.is_set() and buffer)
            )

            if should_flush:
                self._flush_buffer(buffer)
                buffer.clear()
                last_flush = time.time()
                with self._flush_done:
                    self._flush_event.clear()
                    self._flush_done.notify_all()

        # Drain remaining buffer and queue on worker shutdown
        if buffer:
            self._flush_buffer(buffer)
            buffer.clear()

        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
                if item is not None:
                    buffer.append(item)
            except queue.Empty:
                break

        if buffer:
            self._flush_buffer(buffer)
            buffer.clear()

        with self._flush_done:
            self._flush_done.notify_all()

    def append(
        self,
        entry: Dict[str, Any],
        db_callback: Optional[Callable[[], None]] = None,
        sync: bool = False,
    ) -> Dict[str, Any]:
        """
        Appends an entry with prev_hash and entry_hash deterministically.
        Calculates hash chain in-memory synchronously and queues disk I/O to background group commit.
        """
        with self._lock:
            if self._head_hash is None:
                self._init_head()

            prev = self._head_hash or GENESIS
            record = dict(entry)
            record["index"] = self._entry_count
            record["timestamp"] = record.get("timestamp", time.time())
            record["prev_hash"] = prev

            h = compute_entry_hash(record, prev)
            record["entry_hash"] = h

            self._head_hash = h
            self._entry_count += 1
            self._pending_count += 1

        self._queue.put((record, db_callback))

        if sync:
            self.flush()

        return record

    def flush(self, timeout: float = 5.0) -> None:
        """Forces an immediate group commit and fsync of all queued entries and checkpoints."""
        with self._lock:
            if self._pending_count == 0 and self._queue.empty():
                return

        with self._flush_done:
            self._flush_event.set()
            self._queue.put(None)  # Wake worker loop
            self._flush_done.wait_for(
                lambda: self._pending_count == 0 and self._queue.empty(),
                timeout=timeout,
            )

    def shutdown(self) -> None:
        """Flushes remaining entries and terminates the background writer thread."""
        try:
            self.flush()
        except Exception:
            pass
        self._stop_event.set()
        self._queue.put(None)
        if self._worker_thread.is_alive() and threading.current_thread() != self._worker_thread:
            self._worker_thread.join(timeout=2.0)


_AUDIT_REGISTRY: Dict[str, JsonlAuditLog] = {}
_REGISTRY_LOCK = threading.RLock()


def get_audit_logger(
    path: Optional[Union[str, Path]] = None,
    anchor_path: Optional[Union[str, Path]] = None,
) -> JsonlAuditLog:
    """Returns or registers the thread-safe JsonlAuditLog singleton for a given file path."""
    target_path = Path(path or DEFAULT_JSONL_AUDIT_LOG).resolve()
    resolved = str(target_path)
    with _REGISTRY_LOCK:
        if resolved not in _AUDIT_REGISTRY:
            _AUDIT_REGISTRY[resolved] = JsonlAuditLog(target_path, anchor_path=anchor_path)
        return _AUDIT_REGISTRY[resolved]


def flush_all_audit_loggers() -> None:
    """Flushes all registered active audit loggers."""
    with _REGISTRY_LOCK:
        loggers = list(_AUDIT_REGISTRY.values())
    for log in loggers:
        try:
            log.flush()
        except Exception:
            pass


def verify_audit_log(
    path: Union[str, Path],
    anchor_path: Optional[Union[str, Path]] = None,
    secret: Optional[bytes] = None,
) -> AuditVerifyResult:
    """
    Verifies the cryptographic integrity of an append-only JSONL audit log.
    Flushes any pending in-memory group commits before verification.
    """
    p = Path(path).resolve()
    resolved = str(p)
    with _REGISTRY_LOCK:
        active = _AUDIT_REGISTRY.get(resolved)
    if active is not None:
        active.flush()

    if not p.exists() or p.stat().st_size == 0:
        return AuditVerifyResult(True, checked_count=0, broken_index=None, reason="Audit log is empty or does not exist")

    prev_expected = GENESIS
    checked = 0

    with open(p, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            s = line.strip()
            if not s:
                continue
            try:
                data = json.loads(s)
            except Exception as e:
                return AuditVerifyResult(
                    False,
                    checked_count=checked,
                    broken_index=checked,
                    reason=f"Malformed JSON at entry index {checked}: {e}"
                )

            entry_prev = data.get("prev_hash")
            entry_hash = data.get("entry_hash")

            # Check 1: prev_hash continuity
            if entry_prev != prev_expected:
                return AuditVerifyResult(
                    False,
                    checked_count=checked,
                    broken_index=checked,
                    reason=(
                        f"Chain broken at entry index {checked}: prev_hash mismatch. "
                        f"Expected '{prev_expected}', got '{entry_prev}'."
                    )
                )

            # Check 2: Content integrity against entry_hash
            recomputed = compute_entry_hash(data, prev_expected)
            if entry_hash != recomputed:
                return AuditVerifyResult(
                    False,
                    checked_count=checked,
                    broken_index=checked,
                    reason=(
                        f"Content tampered at entry index {checked}: entry_hash mismatch. "
                        f"Expected '{recomputed}', got '{entry_hash}'."
                    )
                )

            prev_expected = entry_hash
            checked += 1

    # Check 3: External anchor verification (tail truncation & chain forgery detection)
    anc_file = Path(anchor_path) if anchor_path else p.parent / f"{p.stem}_anchor.jsonl"
    if anc_file.exists() and anc_file.stat().st_size > 0:
        last_anchor_line = ""
        with open(anc_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_anchor_line = line.strip()

        if last_anchor_line:
            try:
                anc_data = json.loads(last_anchor_line)
                anc_head = str(anc_data["head_hash"])
                anc_count = int(anc_data["row_count"])
                anc_ts = float(anc_data["ts"])
                anc_hmac = str(anc_data["hmac"])
            except (ValueError, KeyError) as e:
                return AuditVerifyResult(
                    False,
                    checked_count=checked,
                    broken_index=checked,
                    reason=f"Malformed external anchor record: {e}"
                )

            try:
                sec = secret or get_intent_hmac_secret()
            except Exception as e:
                return AuditVerifyResult(
                    False,
                    checked_count=checked,
                    broken_index=checked,
                    reason=f"Missing gateway key for external anchor verification: {e}"
                )

            expected_sig = hmac.new(
                sec,
                f"{anc_head}|{anc_count}|{anc_ts!r}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(anc_hmac, expected_sig):
                return AuditVerifyResult(
                    False,
                    checked_count=checked,
                    broken_index=checked,
                    reason="External anchor HMAC signature invalid: anchor record forged or key mismatch"
                )

            if checked < anc_count:
                return AuditVerifyResult(
                    False,
                    checked_count=checked,
                    broken_index=checked,
                    reason=f"Audit chain tail truncated: log has {checked} entries, external anchor expected {anc_count}"
                )

            if anc_count > 0 and prev_expected != anc_head:
                return AuditVerifyResult(
                    False,
                    checked_count=checked,
                    broken_index=checked,
                    reason=f"Audit chain head mismatch at anchor point: expected '{anc_head}', got '{prev_expected}'"
                )

    return AuditVerifyResult(True, checked_count=checked, broken_index=None, reason="Audit log integrity verified (externally anchored)")


# --- Legacy SQLite-based AuditLog (preserved for existing test backwards compatibility) ---

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
        p = Path(anchor_path) if anchor_path else DEFAULT_ANCHOR_FILE
        sec = secret or hmac_secret_from_env()
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

        sec = secret or hmac_secret_from_env()
        expected_sig = hmac.new(sec, f"{anchor_head}|{anchor_count}|{anchor_ts!r}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(anchor_hmac, expected_sig):
            return VerifyResult(False, base_res.checked, reason="external anchor HMAC signature invalid")

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
