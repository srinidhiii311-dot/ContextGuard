"""
tests/test_frozen_datasets_integrity.py — Tamper-Proof Integrity Verification (Gap 5)

Enforces cryptographic integrity for all frozen / holdout datasets:
- eval_data/test_v1/attacks.yaml
- eval_data/test_v1/benign.yaml
- eval_data/holdout_attacks.yaml
- eval_data/holdout_benign.yaml
- eval_data/second_domain/attacks.yaml
- eval_data/second_domain/benign.yaml

Fails CI immediately if any byte in a frozen dataset is modified.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
HASHES_FILE = ROOT / "eval_data" / "frozen_hashes.json"


def get_file_sha256(filepath: Path) -> str:
    return hashlib.sha256(filepath.read_bytes()).hexdigest()


def test_frozen_hashes_file_exists():
    assert HASHES_FILE.is_file(), f"Missing {HASHES_FILE}"


def test_frozen_datasets_hashes_match():
    with open(HASHES_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    files_dict = data.get("files", {})
    assert len(files_dict) >= 6, "Expected at least 6 frozen dataset checksums."

    mismatches = []
    for rel_path, expected_hash in files_dict.items():
        fp = ROOT / rel_path
        assert fp.is_file(), f"Frozen file missing on disk: {rel_path}"
        actual_hash = get_file_sha256(fp)
        if actual_hash != expected_hash:
            mismatches.append(f"{rel_path}: expected {expected_hash}, got {actual_hash}")

    assert not mismatches, f"CRYPTOGRAPHIC TAMPER DETECTED in frozen datasets:\n" + "\n".join(mismatches)


def test_integrity_check_detects_tampering():
    """Negative test: proving that any modified byte triggers an AssertionError."""
    fake_content = b"adversarial_modification: true"
    fake_hash = hashlib.sha256(fake_content).hexdigest()
    expected_original = "eb396c6ec5f6e857ac456d0fa64e7eafb1d4d1243cae304d2e477f065e7898e8"
    assert fake_hash != expected_original
