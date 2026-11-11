#!/usr/bin/env python3
"""CLI utility to verify HMAC SHA-256 audit log cryptographic chain."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextguard.audit_log import verify_audit_log


def main(argv=None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(description="Verify HMAC SHA-256 audit log cryptographic chain.")
    parser.add_argument("path", nargs="?", default="runs/audit_log.jsonl", help="Path to audit log JSONL file.")
    parser.add_argument("anchor", nargs="?", default=None, help="Optional anchor path.")
    parser.add_argument("--expected", type=int, default=None, help="Assert exact entry count in audit log.")
    parsed = parser.parse_args(args)

    result = verify_audit_log(parsed.path, anchor_path=parsed.anchor)
    if not result.ok:
        print(f"[FAIL] Cryptographic audit log validation failed at index {result.broken_index}: {result.reason}")
        return 1

    if parsed.expected is not None and result.checked_count != parsed.expected:
        print(f"[FAIL] Cryptographic audit log entry count mismatch: expected {parsed.expected}, got {result.checked_count} ({parsed.path}).")
        return 1

    print(f"[PASS] Cryptographic audit log verified: {result.checked_count} entries intact ({parsed.path}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
