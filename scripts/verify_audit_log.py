#!/usr/bin/env python3
"""CLI utility to verify HMAC SHA-256 audit log cryptographic chain."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextguard.audit_log import verify_audit_log


def main(argv=None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    path = args[0] if len(args) > 0 else "runs/audit_log.jsonl"
    anchor = args[1] if len(args) > 1 else None

    result = verify_audit_log(path, anchor_path=anchor)
    if result.ok:
        print(f"[PASS] Cryptographic audit log verified: {result.checked_count} entries intact ({path}).")
        return 0
    else:
        print(f"[FAIL] Cryptographic audit log validation failed at index {result.broken_index}: {result.reason}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
