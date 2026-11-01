"""
harness/run_record.py — Canonical Pydantic RunRecord Schema and JSONL Writer (Block 1)

Defines the structured execution record for each action evaluation and logs
every action as one JSON line in `runs/<config>_<seed>.jsonl`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field, field_validator


class LLMCallRecord(BaseModel):
    """Execution telemetry for an associated LLM call (or null if none was made)."""
    provider: str
    model: str
    request_id: str
    tokens_in: int = Field(ge=0)
    tokens_out: int = Field(ge=0)
    latency_ms: float = Field(ge=0.0)


class RunRecord(BaseModel):
    """
    Standard evaluation record representing a single observed browser action.
    Written as one JSON line to runs/<config>_<seed>.jsonl.
    """
    run_id: str
    task_id: str
    domain: str
    config: str
    seed: int
    case_type: Literal["attack", "benign"]
    family: str
    split: Literal["dev", "test"]
    proposed_action: Union[Dict[str, Any], str, Any]
    decision: str
    ground_truth_label: str
    latency_ms: float = Field(ge=0.0)
    llm_call: Optional[LLMCallRecord] = None

    @field_validator("case_type")
    @classmethod
    def validate_case_type(cls, v: str) -> str:
        if v not in ("attack", "benign"):
            raise ValueError(f"case_type must be 'attack' or 'benign', got '{v}'")
        return v

    @field_validator("split")
    @classmethod
    def validate_split(cls, v: str) -> str:
        if v not in ("dev", "test"):
            raise ValueError(f"split must be 'dev' or 'test', got '{v}'")
        return v

    def get_run_filename(self) -> str:
        """Returns standard destination filename: <config>_<seed>.jsonl"""
        return f"{self.config}_{self.seed}.jsonl"

    def write_to_file(self, base_dir: Union[str, Path] = "runs") -> Path:
        """Appends this record as one JSON line in runs/<config>_<seed>.jsonl."""
        return write_run_record(self, base_dir=base_dir)


def write_run_record(record: RunRecord, base_dir: Union[str, Path] = "runs") -> Path:
    """
    Appends a RunRecord as a single JSON line to runs/<config>_<seed>.jsonl.
    Creates destination directories if they do not exist.
    """
    target_dir = Path(base_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    out_path = target_dir / record.get_run_filename()

    with open(out_path, "a", encoding="utf-8") as f:
        f.write(record.model_dump_json() + "\n")

    return out_path


def read_run_records(filepath: Union[str, Path]) -> List[RunRecord]:
    """Reads all RunRecords from a .jsonl file."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Run file does not exist: {path}")

    records: List[RunRecord] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                records.append(RunRecord.model_validate(data))
            except Exception as e:
                raise ValueError(f"Failed to parse RunRecord at {path}:{line_no} — {e}") from e
    return records

