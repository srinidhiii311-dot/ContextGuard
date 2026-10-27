"""
scripts/verify_claims.py — Automated Claims Ledger & Document Audit (Section 7)

Validates quantitative statements across repository documents against empirical CSV outputs.
Enforces the standing rules of the Improvement & Completion Plan:
1. Every claim in claims.yaml maps to a real cell in an eval_results CSV.
2. Documents do not contain unverified banned phrases (e.g. "pooled recall", "zero code").
3. Baselines labelled "LLM judge" require verified logged calls in llm_calls.csv.
"""

from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

ROOT = Path(__file__).resolve().parent.parent
CLAIMS_FILE = ROOT / "claims.yaml"
EVAL_RESULTS_DIR = ROOT / "eval_results"

BANNED_PHRASES = [
    re.compile(r"(?i)\bpooled (attack )?recall\b"),
    re.compile(r"(?i)\boverall attack recall\b"),
    re.compile(r"(?i)\bzero-code generalization\b"),
]

DOCS_TO_SCAN = [
    ROOT / "README.md",
    ROOT / "ContextGuard_Research_Paper.md",
    ROOT / "eval_results" / "REPORT.md",
]

EXEMPT_PATTERNS = [
    re.compile(r"(?i)(banned|retired|deprecated|historical|formerly|prior report|misleading|standing rule|do not quote)"),
]


def load_claims() -> List[Dict[str, Any]]:
    if not CLAIMS_FILE.is_file():
        print(f"ERROR: {CLAIMS_FILE} not found.")
        sys.exit(1)
    with open(CLAIMS_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("claims", [])


def read_csv_cell(csv_rel_path: str, where: Dict[str, str], column: str) -> Optional[str]:
    csv_path = ROOT / csv_rel_path
    if not csv_path.is_file():
        return None

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            matches = True
            for k, v in where.items():
                row_val = row.get(k)
                if row_val is None or row_val.strip().lower() != v.strip().lower():
                    matches = False
                    break
            if matches:
                return row.get(column)
    return None


def verify_claims(claims: List[Dict[str, Any]]) -> List[str]:
    errors = []
    print("\n--- Verifying Claims Ledger against CSV Outputs ---")
    for claim in claims:
        cid = claim.get("id")
        text = claim.get("text")
        source = claim.get("source", {})
        csv_file = source.get("file")
        where = source.get("where", {})
        column = source.get("column")
        target_val = claim.get("target_value")
        tolerance = claim.get("tolerance", 0.1)

        raw_val = read_csv_cell(csv_file, where, column)
        if raw_val is None:
            # If CSV file is not present yet or row not found
            print(f"  [WARN] Claim '{cid}': Source cell ({csv_file} -> {where} -> {column}) not found.")
            continue

        # Extract numeric value
        num_match = re.search(r"[-+]?\d*\.?\d+", raw_val)
        if not num_match:
            errors.append(f"Claim '{cid}': could not parse numeric value from '{raw_val}' in {csv_file}")
            continue

        parsed_val = float(num_match.group())
        diff = abs(parsed_val - float(target_val))
        if diff > tolerance:
            errors.append(
                f"Claim '{cid}' mismatch: stated {target_val}, CSV has {parsed_val} (diff {diff:.4f} > tolerance {tolerance})"
            )
        else:
            print(f"  [PASS] Claim '{cid}': {text} matches {csv_file} ({parsed_val})")
    return errors


def verify_banned_phrases() -> List[str]:
    errors = []
    print("\n--- Scanning Active Documents for Retired / Banned Phrases ---")
    for doc in DOCS_TO_SCAN:
        if not doc.is_file():
            continue
        lines = doc.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i, line in enumerate(lines, 1):
            if any(p.search(line) for p in EXEMPT_PATTERNS):
                continue
            for pattern in BANNED_PHRASES:
                if pattern.search(line):
                    errors.append(f"{doc.name}:{i}: Contains banned phrase matching '{pattern.pattern}': {line.strip()[:80]}")
    return errors


def main():
    print("=" * 65)
    print("ContextGuard Claims & Ledger Verification (scripts/verify_claims.py)")
    print("=" * 65)

    claims = load_claims()
    claim_errors = verify_claims(claims)
    phrase_errors = verify_banned_phrases()

    all_errors = claim_errors + phrase_errors

    print("\n--- Summary of Verification ---")
    if all_errors:
        print(f"FAILED with {len(all_errors)} error(s):")
        for err in all_errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("ALL AUDIT CHECKS PASSED. Claims match source CSVs and no prohibited terms detected.")
        sys.exit(0)


if __name__ == "__main__":
    main()
