"""
scripts/record_test_run.py — Commit-Anchored Test Suite Verification Logger (Gap 7)

Ties automated test suite execution directly to an immutable Git commit hash and tag.
Executes pytest, captures full output, and persists:
- eval_results/test_run_log.txt (human-readable test log with git metadata)
- eval_results/test_run_manifest.json (machine-readable test run metadata)
"""

from __future__ import annotations

import datetime
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVAL_RESULTS_DIR = ROOT / "eval_results"


def get_git_info() -> dict:
    info = {"commit": "unknown", "tag": "none", "branch": "unknown", "dirty": False}
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ROOT)).decode().strip()
        info["commit"] = commit
    except Exception:
        pass

    try:
        tag = subprocess.check_output(["git", "describe", "--tags", "--exact-match"], cwd=str(ROOT), stderr=subprocess.DEVNULL).decode().strip()
        info["tag"] = tag
    except Exception:
        try:
            nearest_tag = subprocess.check_output(["git", "describe", "--tags"], cwd=str(ROOT)).decode().strip()
            info["tag"] = f"nearest:{nearest_tag}"
        except Exception:
            info["tag"] = "none"

    try:
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=str(ROOT)).decode().strip()
        info["branch"] = branch
    except Exception:
        pass

    try:
        status = subprocess.check_output(["git", "status", "-s"], cwd=str(ROOT)).decode().strip()
        info["dirty"] = bool(status)
    except Exception:
        pass

    return info


def run_and_record_tests():
    EVAL_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    git_info = get_git_info()
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    print(f"\n[Test Run Logger] Recording test suite for commit {git_info['commit'][:10]} (tag: {git_info['tag']})...")

    # Run pytest
    cmd = [sys.executable, "-m", "pytest", "-m", "not llm", "-q"]
    start_time = datetime.datetime.now()
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    duration_s = (datetime.datetime.now() - start_time).total_seconds()

    output = proc.stdout + "\n" + proc.stderr

    log_path = EVAL_RESULTS_DIR / "test_run_log.txt"
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("=" * 75 + "\n")
        f.write(f"ContextGuard Test Suite Execution Log (Gap 7)\n")
        f.write("=" * 75 + "\n")
        f.write(f"Timestamp        : {timestamp}\n")
        f.write(f"Git Commit Hash  : {git_info['commit']}\n")
        f.write(f"Git Tag          : {git_info['tag']}\n")
        f.write(f"Git Branch       : {git_info['branch']}\n")
        f.write(f"Working Tree Dirty: {git_info['dirty']}\n")
        f.write(f"Python Version   : {platform.python_version()}\n")
        f.write(f"Platform / OS    : {platform.platform()}\n")
        f.write(f"Test Duration (s): {duration_s:.2f}\n")
        f.write(f"Exit Code        : {proc.returncode}\n")
        f.write("=" * 75 + "\n\n")
        f.write(output)

    manifest_path = EVAL_RESULTS_DIR / "test_run_manifest.json"
    manifest = {
        "timestamp": timestamp,
        "git": git_info,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "duration_seconds": duration_s,
        "exit_code": proc.returncode,
        "passed": proc.returncode == 0,
        "log_file": "eval_results/test_run_log.txt",
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[Test Run Logger] Saved test run log to {log_path}")
    print(f"[Test Run Logger] Saved test manifest to {manifest_path}")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(run_and_record_tests())
