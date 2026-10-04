"""
contextguard/chain_detector.py — Stage 2 (Component 8): Multi-Step Attack Chain Detector

Specification:
- Stages: INJECTION_SEEN, PROTECTED_FIELD_CHANGE, OFF_DOMAIN_NAV, SKIPPED_STEP, UNEXPECTED_SUBMIT
- Derived strictly from gate signals (verification rails, taxonomy detectors, semantic characterization,
  url_monitor page-order progression, and process integrity), NEVER from raw keyword matching in page text.
- Stateful per-task event audit log in SQLite.
- Declarative pattern definitions in chains.yaml with temporal step-window matching.
- Escalation: partial progression escalates alerts; full sequence triggers chain-level BLOCK / INTERCEPTION.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

from contextguard.url_monitor import EXPECTED_FLOW, url_monitor
from contextguard.models import ConsistencyReport, ProposedAction, LockedIntent

CONFIG_DIR = Path(__file__).parent / "config"
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "backend" / "database" / "platform.db"


class ChainStage(str, Enum):
    INJECTION_SEEN         = "INJECTION_SEEN"
    PROTECTED_FIELD_CHANGE = "PROTECTED_FIELD_CHANGE"
    OFF_DOMAIN_NAV         = "OFF_DOMAIN_NAV"
    SKIPPED_STEP           = "SKIPPED_STEP"
    UNEXPECTED_SUBMIT      = "UNEXPECTED_SUBMIT"


class ChainDetector:
    """
    Component 8: Multi-Step Attack Chain Detector.
    Tracks stateful workflow progression and identifies multi-action attack trajectories.
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        db_path: Optional[str | Path] = None,
    ):
        self.config_path = config_path or (CONFIG_DIR / "chains.yaml")
        raw_db = db_path or DEFAULT_DB_PATH
        self.db_path = str(raw_db)
        self.chains: List[Dict[str, Any]] = []
        self._task_verified_steps: Dict[str, Set[str]] = {}
        self._load_config()
        if self.db_path == ":memory:":
            self._persistent_conn = sqlite3.connect(":memory:")
        else:
            self._persistent_conn = None
        self._init_sqlite()

    def _get_conn(self) -> sqlite3.Connection:
        if self._persistent_conn is not None:
            return self._persistent_conn
        return sqlite3.connect(self.db_path)

    def _load_config(self) -> None:
        if self.config_path.exists():
            cfg = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
            self.chains = cfg.get("chains", [])
        else:
            self.chains = []

    def _init_sqlite(self) -> None:
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chain_detector_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                step_number INTEGER NOT NULL,
                stage TEXT NOT NULL,
                timestamp REAL NOT NULL,
                action_type TEXT,
                target TEXT,
                details TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_chain_events_task_step 
            ON chain_detector_events(task_id, step_number)
        """)
        conn.commit()
        if self._persistent_conn is None:
            conn.close()


    def derive_stages(
        self,
        action: ProposedAction,
        consistency_report: ConsistencyReport,
        threat_result: Any,
        current_page: str,
        previous_page: Optional[str] = None,
        verified_steps: Optional[Set[str]] = None,
        task_id: str = "",
    ) -> List[ChainStage]:

        """
        Derives security stages strictly from gate signals and state machines.
        No raw page-text keyword searching.
        """
        stages: List[ChainStage] = []

        # 1. INJECTION_SEEN signal
        is_injection = False
        if getattr(consistency_report, "marker_presence", False) or getattr(consistency_report, "marker_hit", None):
            is_injection = True
        if any(getattr(inc, "check_type", "") == "INJECTION_MARKER" for inc in consistency_report.inconsistencies):
            is_injection = True
        atk_type = getattr(threat_result, "attack_type", "")
        if atk_type in ("PROMPT_INJECTION", "CONTEXT_MANIPULATION", "HIDDEN_INSTRUCTION", "FAKE_SYSTEM_MESSAGE", "DOM_MANIPULATION"):
            is_injection = True
        char_label = getattr(threat_result, "characterization_label", "")
        if char_label in ("unknown_instruction_manipulation", "prompt_injection_directive"):
            is_injection = True

        if is_injection:
            stages.append(ChainStage.INJECTION_SEEN)

        # 2. PROTECTED_FIELD_CHANGE signal
        is_field_change = any(
            getattr(inc, "check_type", "") == "FIELD_MISMATCH"
            for inc in consistency_report.inconsistencies
        )
        if is_field_change:
            stages.append(ChainStage.PROTECTED_FIELD_CHANGE)

        # 3. OFF_DOMAIN_NAV signal
        is_off_domain = any(
            getattr(inc, "check_type", "") == "NAVIGATION_BOUNDARY"
            for inc in consistency_report.inconsistencies
        )
        if not is_off_domain and action.action_type == "NAVIGATE":
            target_url = action.value or action.target or ""
            if target_url.startswith("http") and "127.0.0.1:8000" not in target_url and "localhost:8000" not in target_url:
                is_off_domain = True
        if is_off_domain:
            stages.append(ChainStage.OFF_DOMAIN_NAV)

        # 4. SKIPPED_STEP signal (reusing url_monitor page order and plan integrity)
        is_skipped_step = False
        # (a) Page progression check
        clean_curr = current_page.strip("/").split("/")[-1] if current_page else ""
        clean_prev = previous_page.strip("/").split("/")[-1] if previous_page else ""
        if clean_prev in EXPECTED_FLOW and clean_curr in EXPECTED_FLOW:
            prev_idx = EXPECTED_FLOW.index(clean_prev)
            curr_idx = EXPECTED_FLOW.index(clean_curr)
            if curr_idx > prev_idx + 1:
                is_skipped_step = True
        # (b) Plan integrity exfiltration / process bypass check
        if char_label == "unknown_instruction_manipulation" and "review" in clean_curr.lower():
            is_skipped_step = True
        if any(getattr(inc, "check_type", "") == "PROCESS_INTEGRITY" for inc in consistency_report.inconsistencies):
            is_skipped_step = True

        if is_skipped_step:
            stages.append(ChainStage.SKIPPED_STEP)

        # 5. UNEXPECTED_SUBMIT signal
        is_submit_action = False
        target_low = (action.target or "").lower()
        if action.action_type == "CLICK" and any(k in target_low for k in ("confirm", "submit", "finalize", "pay-now", "checkout")):
            is_submit_action = True

        v_steps = verified_steps if verified_steps is not None else self._task_verified_steps.get(task_id, set())
        if is_submit_action:
            # Check if review phase was skipped or unverified
            clean_curr_page = clean_curr.lower()
            if clean_curr_page != "review" and clean_curr_page != "checkout":
                # Premature submit from non-review page
                stages.append(ChainStage.UNEXPECTED_SUBMIT)
            elif (len(v_steps) > 0 or (previous_page is not None and previous_page != current_page)) and not {"#terms-checkbox"}.issubset(v_steps):
                # Review page terms / verification steps bypassed in multi-step sequence
                stages.append(ChainStage.SKIPPED_STEP)
                stages.append(ChainStage.UNEXPECTED_SUBMIT)


        # Track verified action targets for lifecycle
        if task_id:
            self._task_verified_steps.setdefault(task_id, set()).add(action.target)

        return stages


    def record_and_evaluate(
        self,
        task_id: str,
        step_number: int,
        action: ProposedAction,
        consistency_report: ConsistencyReport,
        threat_result: Any,
        current_page: str,
        previous_page: Optional[str] = None,
        verified_steps: Optional[Set[str]] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Records the step's stages in SQLite and evaluates active attack chains.
        Returns: (is_chain_matched, matched_chain_id, escalation_decision)
        """
        stages = self.derive_stages(
            action=action,
            consistency_report=consistency_report,
            threat_result=threat_result,
            current_page=current_page,
            previous_page=previous_page,
            verified_steps=verified_steps,
            task_id=task_id,
        )


        now = time.time()
        conn = self._get_conn()
        for st in stages:
            conn.execute(
                "INSERT INTO chain_detector_events (task_id, step_number, stage, timestamp, action_type, target, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (task_id, step_number, st.value, now, action.action_type, action.target, f"Page: {current_page}"),
            )
        conn.commit()

        # Evaluate against configured chains
        matched_result = (False, None, None)
        for chain in self.chains:
            chain_id = chain["id"]
            req_stages = chain.get("stages", [])
            window = int(chain.get("step_window", 4))
            escalation = chain.get("action_escalation", "BLOCK")

            if not req_stages:
                continue

            # Query events for this task within step window
            min_step = max(1, step_number - window + 1)
            cursor = conn.execute(
                "SELECT id, step_number, stage FROM chain_detector_events "
                "WHERE task_id = ? AND step_number >= ? AND step_number <= ? "
                "ORDER BY step_number ASC, id ASC",
                (task_id, min_step, step_number),
            )
            history = cursor.fetchall()

            # Verify ordered sequence matching: stage_0 before stage_1
            if self._matches_sequence(history, req_stages):
                matched_result = (True, chain_id, escalation)
                break

        if self._persistent_conn is None:
            conn.close()

        return matched_result

    def _matches_sequence(self, history: List[Tuple[int, int, str]], target_stages: List[str]) -> bool:
        """
        Verifies that target_stages appear in chronological sequence in the event history.
        Strictly requires ordered appearance (out-of-order stages do not match).
        """
        if not target_stages:
            return False

        target_idx = 0
        last_id = -1

        for event_id, step_num, stage in history:
            if stage == target_stages[target_idx]:
                if last_id == -1 or event_id > last_id:
                    last_id = event_id
                    target_idx += 1
                    if target_idx == len(target_stages):
                        return True

        return False

    def clear_task_history(self, task_id: str) -> None:
        """Cleans up SQLite history for a completed task."""
        self._task_verified_steps.pop(task_id, None)
        conn = self._get_conn()
        conn.execute("DELETE FROM chain_detector_events WHERE task_id = ?", (task_id,))
        conn.commit()
        if self._persistent_conn is None:
            conn.close()


