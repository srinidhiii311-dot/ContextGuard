"""
scripts/create_eval_bundle.py — Reviewer Evaluation & Reproduction Bundle Builder (Gap 6)

Packages all datasets (including frozen suites and hashes), evaluation scripts,
core gate modules, tests, and claims ledgers into dist/ContextGuard_Eval_Bundle.zip.
Enables independent reviewers to reproduce all empirical benchmark results with `make reproduce`.
"""

from __future__ import annotations

import hashlib
import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = ROOT / "dist"

EVAL_DIRS = [
    "eval_data",
    "eval_results",
    "scripts",
    "contextguard",
    "agent",
    "backend",
    "tests",
    "docs",
]

EVAL_FILES = [
    "claims.yaml",
    "Makefile",
    "tasks.py",
    "requirements.txt",
    "pytest.ini",
    "README.md",
    "LICENSE",
    "CHANGELOG_EVAL.md",
]


def build_eval_bundle(archive_name: str = "ContextGuard_Eval_Bundle.zip") -> Path:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    out_path = DIST_DIR / archive_name

    packed_count = 0
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in EVAL_FILES:
            fp = ROOT / f
            if fp.is_file():
                zf.write(fp, arcname=f"ContextGuard/{f}")
                packed_count += 1

        for d in EVAL_DIRS:
            dp = ROOT / d
            if not dp.is_dir():
                continue
            for root, dirs, files in os.walk(dp):
                # Exclude runtime caches
                dirs[:] = [sub for sub in dirs if sub not in ("__pycache__", ".pytest_cache")]
                for file in files:
                    if file.endswith((".pyc", ".pyo", ".log", ".db", ".sqlite")):
                        continue
                    fp = Path(root) / file
                    rel = fp.relative_to(ROOT)
                    zf.write(fp, arcname=f"ContextGuard/{str(rel).replace('\\', '/')}")
                    packed_count += 1

    sha256 = hashlib.sha256(out_path.read_bytes()).hexdigest()
    print(f"\n[Eval Bundle] Generated {out_path} ({packed_count} files, {out_path.stat().st_size / (1024*1024):.2f} MB)")
    print(f"Bundle SHA-256: {sha256}")
    return out_path


if __name__ == "__main__":
    build_eval_bundle()
