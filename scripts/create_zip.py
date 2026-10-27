"""
scripts/create_zip.py — Secure Clean Release Builder (G1 Fix)

Builds clean, self-contained distribution archives strictly into dist/ from an allowlist.
Performs an automated pre-archive secrets and forbidden files scan.
Ensures zero inclusion of venv, .env, *.db, testbed logs, or frozen test sets (test_v1, test_v2).
"""

from __future__ import annotations

import os
import re
import sys
import zipfile
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = ROOT / "dist"

# Allowed directories to include in release archive
ALLOWLIST_DIRS = [
    "contextguard",
    "backend",
    "agent",
    "frontend",
    "tests",
    "scripts",
    "eval_data",
    "eval_results",
    "docs",
]

# Allowed top-level files
ALLOWLIST_FILES = [
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "ROADMAP.md",
    "CHANGELOG_EVAL.md",
    "requirements.txt",
    "launcher.py",
    "dashboard.html",
    "portal.html",
    "Dockerfile",
    "docker-compose.yml",
    "pytest.ini",
    "Makefile",
    "tasks.py",
    ".env.example",
    "claims.yaml",
]

# Hard forbidden path patterns (regex / substrings)
FORBIDDEN_PATTERNS = [
    r"(^|[\\/])venv([\\/]|$)",
    r"(^|[\\/])\.venv([\\/]|$)",
    r"(^|[\\/])\.git([\\/]|$)",
    r"(^|[\\/])__pycache__([\\/]|$)",
    r"(^|[\\/])\.pytest_cache([\\/]|$)",
    r"(^|[\\/])logs([\\/]|$)",
    r"(^|[\\/])screenshots([\\/]|$)",
    r"(^|[\\/])eval_data[\\/]test_v1([\\/]|$)",
    r"(^|[\\/])eval_data[\\/]test_v2([\\/]|$)",
    r"holdout_.*\.ya?ml$",
    r"\.env$",
    r"\.env\.(?!example$)",
    r"\.db(-wal|-shm)?$",
    r"\.sqlite$",
    r"audit_anchor\.jsonl$",
    r"\.log$",
    r"\.zip$",
    r"\.lnk$",
]

# Suspected secret regex patterns
SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret[_-]?key|private[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
]


def is_forbidden(rel_path_str: str) -> bool:
    norm = rel_path_str.replace("\\", "/")
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, norm):
            return True
    return False


def scan_file_for_secrets(filepath: Path) -> List[str]:
    findings = []
    if filepath.stat().st_size > 5 * 1024 * 1024:
        return findings
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        for pattern in SECRET_PATTERNS:
            if pattern.search(content):
                findings.append(f"Potential secret match ({pattern.pattern[:30]}...)")
    except Exception:
        pass
    return findings


def build_release_zip(archive_name: str = "ContextGuard_Release.zip") -> Path:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    out_path = DIST_DIR / archive_name

    manifest: List[Tuple[str, int]] = []
    secret_alerts: List[Tuple[str, List[str]]] = []

    files_to_pack: List[Path] = []

    # 1. Collect allowlisted top-level files
    for filename in ALLOWLIST_FILES:
        fp = ROOT / filename
        if fp.is_file() and not is_forbidden(str(fp.relative_to(ROOT))):
            files_to_pack.append(fp)

    # 2. Collect files in allowlisted directories
    for dirname in ALLOWLIST_DIRS:
        dp = ROOT / dirname
        if not dp.is_dir():
            continue
        for root, dirs, files in os.walk(dp):
            dirs[:] = [d for d in dirs if not is_forbidden(str((Path(root) / d).relative_to(ROOT)))]
            for file in files:
                fp = Path(root) / file
                rel = fp.relative_to(ROOT)
                if not is_forbidden(str(rel)):
                    files_to_pack.append(fp)

    print(f"\n[Manifest Scan] Collected {len(files_to_pack)} candidate files. Auditing...")

    for fp in files_to_pack:
        rel = fp.relative_to(ROOT)
        rel_str = str(rel).replace("\\", "/")
        # Acceptance test checks: no venv, no database files, no frozen eval test sets
        forbidden_hits = [
            p for p in ["/venv/", "\\venv\\", ".db", "eval_data/test_v1", "eval_data\\test_v1", "eval_data/test_v2", "eval_data\\test_v2"]
            if p in rel_str.lower()
        ]
        assert not forbidden_hits, f"VIOLATION: Forbidden file pattern {forbidden_hits} detected in release package: {rel_str}"
        assert rel.name != ".env" and not (rel.name.startswith(".env.") and rel.name != ".env.example"), (
            f"VIOLATION: Non-example .env file detected in release package: {rel_str}"
        )

        secrets = scan_file_for_secrets(fp)
        if secrets:
            secret_alerts.append((rel_str, secrets))
        manifest.append((rel_str, fp.stat().st_size))

    if secret_alerts:
        print("\n[WARNING] Potential secret indicators found during scan:")
        for rel_str, alerts in secret_alerts:
            print(f"  - {rel_str}: {', '.join(alerts)}")

    total_uncompressed = sum(size for _, size in manifest)

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_str, _ in manifest:
            full_path = ROOT / rel_str
            zf.write(full_path, arcname=f"ContextGuard/{rel_str}")

    compressed_size = out_path.stat().st_size

    print(f"\n[Release Manifest] Successfully generated {out_path}")
    print(f"Total Files Packed : {len(manifest)}")
    print(f"Uncompressed Size  : {total_uncompressed / (1024 * 1024):.2f} MB")
    print(f"Compressed Size    : {compressed_size / (1024 * 1024):.2f} MB")
    print("\nVerified Clean: Zero venv, .env, .db, or frozen test sets (test_v1, test_v2) included.")
    return out_path


if __name__ == "__main__":
    archive = "CG.zip" if "--short" in sys.argv else "ContextGuard_Release.zip"
    build_release_zip(archive)
