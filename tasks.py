"""
tasks.py — Cross-Platform Command Runner (G2 fix)

Provides a standard command-line interface for running tests, linters,
claims verification, and release builds across Windows, Linux, and macOS
without requiring GNU Make.

Usage:
    python tasks.py test
    python tasks.py test-all
    python tasks.py lint
    python tasks.py verify
    python tasks.py release
    python tasks.py clean
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run_cmd(args: list[str]) -> int:
    cmd_str = " ".join(args)
    print(f"\n>> {cmd_str}")
    res = subprocess.run(args, cwd=str(ROOT))
    if res.returncode != 0:
        print(f"FAILED (exit code {res.returncode}): {cmd_str}")
    return res.returncode


def task_test() -> int:
    """Run test suite excluding live LLM daemon tests."""
    return run_cmd([sys.executable, "-m", "pytest", "-m", "not llm", "-q"])


def task_record_test() -> int:
    """Run test suite and record output anchored to git commit hash and tag."""
    return run_cmd([sys.executable, str(ROOT / "scripts" / "record_test_run.py")])


def task_test_all() -> int:
    """Run entire test suite including live Ollama tests."""
    return run_cmd([sys.executable, "-m", "pytest", "-v"])


def task_lint() -> int:
    """Run ruff static checks (or syntax compile check if ruff is not installed)."""
    try:
        import ruff  # noqa: F401
        has_ruff = True
    except ImportError:
        has_ruff = False

    if has_ruff:
        return run_cmd([
            sys.executable, "-m", "ruff", "check",
            "contextguard", "backend", "agent", "tests", "scripts",
            "--select", "E9,F63,F7,F82"
        ])
    else:
        print("ruff not installed in current environment. Running py_compile syntax verification...")
        import py_compile
        errors = 0
        for pyfile in ROOT.rglob("*.py"):
            if "venv" in pyfile.parts or ".git" in pyfile.parts:
                continue
            try:
                py_compile.compile(str(pyfile), doraise=True)
            except py_compile.PyCompileError as e:
                print(f"Syntax error: {e}")
                errors += 1
        if errors == 0:
            print("Syntax check passed for all repository Python files.")
            return 0
        return 1


def task_verify() -> int:
    """Verify document claims against evaluation results."""
    return run_cmd([sys.executable, str(ROOT / "scripts" / "verify_claims.py")])


def task_reproduce() -> int:
    """Run baseline evaluations, sequences, and verify claims ledger in one command."""
    print("--- Reproducing Evaluation Benchmarks ---")
    c1 = run_cmd([sys.executable, str(ROOT / "scripts" / "evaluate_baselines.py")])
    if c1 != 0:
        return c1
    c2 = run_cmd([sys.executable, str(ROOT / "scripts" / "run_sequence_eval.py")])
    if c2 != 0:
        return c2
    return run_cmd([sys.executable, str(ROOT / "scripts" / "verify_claims.py")])


def task_release() -> int:
    """Build clean release archive in dist/."""
    c1 = run_cmd([sys.executable, str(ROOT / "scripts" / "create_zip.py")])
    if c1 != 0:
        return c1
    return run_cmd([sys.executable, str(ROOT / "scripts" / "create_eval_bundle.py")])


def task_clean() -> int:
    """Clean __pycache__ and temporary test artifacts."""
    print("Cleaning temporary files and caches...")
    count = 0
    for p in ROOT.rglob("__pycache__"):
        if p.is_dir() and "venv" not in p.parts:
            import shutil
            shutil.rmtree(p, ignore_errors=True)
            count += 1
    for p in ROOT.rglob("*.pyc"):
        if p.is_file() and "venv" not in p.parts:
            p.unlink(missing_ok=True)
            count += 1
    print(f"Cleaned {count} cache directories/files.")
    return 0


TASKS = {
    "test": task_test,
    "record-test": task_record_test,
    "test-all": task_test_all,
    "lint": task_lint,
    "verify": task_verify,
    "reproduce": task_reproduce,
    "release": task_release,
    "clean": task_clean,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print("Usage: python tasks.py <task>")
        print("\nAvailable tasks:")
        for name, fn in TASKS.items():
            print(f"  {name:<12} {fn.__doc__ or ''}")
        sys.exit(0)

    task_name = sys.argv[1].lower()
    if task_name not in TASKS:
        print(f"Error: Unknown task '{task_name}'. Available: {list(TASKS.keys())}")
        sys.exit(1)

    code = TASKS[task_name]()
    sys.exit(code)


if __name__ == "__main__":
    main()
