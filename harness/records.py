"""
harness/records.py — Re-exports RunRecord and LLMCallRecord for convenience.
"""

from harness.run_record import (
    LLMCallRecord,
    RunRecord,
    read_run_records,
    write_run_record,
)

__all__ = [
    "LLMCallRecord",
    "RunRecord",
    "read_run_records",
    "write_run_record",
]

