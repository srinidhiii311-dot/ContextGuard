"""
app/services/startup_checks.py — ContextGuard

Pre-launch checks run before any service starts.
Verifies Python version, required packages, free ports, and DB access.
Returns a structured report so the launcher can show a clear status table.
"""

from __future__ import annotations

import importlib
import socket
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str


@dataclass
class StartupReport:
    checks: List[CheckResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def critical_failures(self) -> List[CheckResult]:
        return [c for c in self.checks if not c.passed]

    def add(self, name: str, passed: bool, message: str) -> None:
        self.checks.append(CheckResult(name, passed, message))


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_python_version(report: StartupReport) -> None:
    major, minor = sys.version_info[:2]
    ok = (major == 3 and minor >= 11)
    report.add(
        "Python version",
        ok,
        f"Python {major}.{minor} {'✓ OK' if ok else '✗ requires 3.11+'}",
    )


def check_packages(report: StartupReport) -> None:
    required = [
        ("fastapi",       "FastAPI"),
        ("uvicorn",       "Uvicorn"),
        ("sqlalchemy",    "SQLAlchemy"),
        ("pydantic",      "Pydantic"),
        ("jinja2",        "Jinja2"),
        ("flask",         "Flask"),
        ("playwright",    "Playwright"),
        ("httpx",         "HTTPX"),
    ]
    for module, label in required:
        try:
            importlib.import_module(module)
            report.add(f"Package: {label}", True, f"{label} installed ✓")
        except ImportError:
            report.add(
                f"Package: {label}", False,
                f"{label} NOT installed — run: pip install -r requirements.txt",
            )


def check_port_free(report: StartupReport, port: int, service: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        result = s.connect_ex(("127.0.0.1", port))
    if result == 0:
        report.add(
            f"Port {port} ({service})",
            False,
            f"Port {port} is already in use — stop the conflicting process first.",
        )
    else:
        report.add(
            f"Port {port} ({service})",
            True,
            f"Port {port} free ✓",
        )


def check_database(report: StartupReport, db_path: Path) -> None:
    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute("SELECT 1")
        conn.close()
        report.add("Database", True, f"SQLite accessible ✓  ({db_path.name})")
    except Exception as exc:
        report.add("Database", False, f"Database error: {exc}")


def check_project_files(report: StartupReport, root: Path) -> None:
    critical = [
        root / "main.py",
        root / "requirements.txt",
        root / "app" / "database" / "database.py",
        root / "verifier" / "verifier.py",
        root / "attack_sim" / "flight_site.py",
        root / "attack_sim" / "ecommerce_site.py",
        root / "benchmark" / "benchmark.json",
        root / "templates" / "dashboard.html",
    ]
    missing = [str(p.relative_to(root)) for p in critical if not p.exists()]
    if missing:
        report.add(
            "Project files",
            False,
            f"Missing files: {', '.join(missing)}",
        )
    else:
        report.add("Project files", True, "All required files present ✓")


# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------

def run_all_checks(root: Path) -> StartupReport:
    report = StartupReport()
    check_python_version(report)
    check_packages(report)
    check_port_free(report, 8000, "ContextGuard API")
    check_port_free(report, 5001, "Flight Site")
    check_port_free(report, 5002, "E-Commerce Site")
    check_database(report, root / "contextguard.db")
    check_project_files(report, root)
    return report
