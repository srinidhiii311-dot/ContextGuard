"""
launcher.py -- AI Web Agent Security Testing Platform

Starts all platform services in one command:

  Service 1 -- Platform API + Booking UI + Dashboard   http://127.0.0.1:8000
  Service 2 -- (Optional) Ollama LLM                   http://127.0.0.1:11434

Usage:
    python launcher.py              # start API (everything in one server)
    python launcher.py --bench      # run pytest + evaluation report then exit
    python launcher.py --eval       # run evaluation report only (no server)
    python launcher.py --help

Press Ctrl+C to stop.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import threading
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    os.system("chcp 65001 >nul 2>&1")

ROOT   = Path(__file__).parent
PYTHON = sys.executable


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
_A = {
    "green":  "\033[92m", "red":   "\033[91m", "yellow": "\033[93m",
    "cyan":   "\033[96m", "bold":  "\033[1m",  "dim":    "\033[2m",
    "reset":  "\033[0m",
}
def _c(col, s): return f"{_A[col]}{s}{_A['reset']}"
def sp(s=""): 
    try: print(s, flush=True)
    except UnicodeEncodeError: print(s.encode("ascii","replace").decode(), flush=True)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = """
  ============================================================
   AI Web Agent Security Testing Platform
   ContextGuard -- Runtime Safety Gateway
   7-Phase Architecture
  ============================================================
"""

_NOISE = (
    "NotImplementedError","raise NotImplementedError",
    "Task exception","playwright._impl","_transport.py",
    "create_subprocess_exec","_make_subprocess_transport",
)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class Service:
    def __init__(self, name: str, cmd: List[str], url: str,
                 health: str = "", critical: bool = True) -> None:
        self.name        = name
        self.cmd         = cmd
        self.url         = url
        self.health_url  = url + health if health else ""
        self.critical    = critical
        self.proc        = None
        self.start_time  = 0.0
        self.status      = "stopped"

    def start(self) -> None:
        env = {**os.environ, "PYTHONUNBUFFERED":"1",
               "PYTHONIOENCODING":"utf-8", "PYTHONPATH": str(ROOT)}
        self.proc = subprocess.Popen(
            self.cmd, cwd=str(ROOT),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            encoding="utf-8", errors="replace", bufsize=1, env=env,
        )
        self.start_time = time.time()
        self.status     = "starting"
        # Background log drain — suppress Playwright noise
        def _drain():
            for line in self.proc.stdout:
                if line.strip() and not any(n in line for n in _NOISE):
                    pass   # logs visible in terminal when run directly
        threading.Thread(target=_drain, daemon=True).start()

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try: self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired: self.proc.kill()
        self.status = "stopped"

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def ping(self) -> bool:
        if not self.health_url:
            return self.is_running()
        try:
            r = urllib.request.urlopen(self.health_url, timeout=2)
            return r.status == 200
        except Exception:
            return False

    def uptime(self) -> str:
        if not self.start_time: return "-"
        s = int(time.time() - self.start_time)
        return f"{s//60}m {s%60:02d}s" if s >= 60 else f"{s}s"


# ---------------------------------------------------------------------------
# Port helpers
# ---------------------------------------------------------------------------

def _port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0

def _kill_port(port: int) -> None:
    if sys.platform != "win32" or not _port_in_use(port):
        return
    try:
        r = subprocess.run(["netstat","-ano"], capture_output=True, text=True)
        pid = None
        for line in r.stdout.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                parts = line.split()
                if parts: pid = parts[-1]; break
        if pid and pid.isdigit():
            subprocess.run(["taskkill","/F","/PID",pid], capture_output=True)
            sp(_c("dim", f"  [INFO] Freed port {port} (PID {pid})"))
    except Exception: pass


# ---------------------------------------------------------------------------
# Status display
# ---------------------------------------------------------------------------

def _print_status(services: List[Service]) -> None:
    os.system("cls" if sys.platform == "win32" else "clear")
    sp(_c("bold", "\n  Platform Services"))
    sp("  " + "="*56)
    for svc in services:
        alive = svc.ping()
        svc.status = "running" if alive else ("starting" if svc.is_running() else "stopped")
        tag    = _c("green","[ON] ") if alive else (_c("yellow","[..] ") if svc.is_running() else _c("red","[OFF]"))
        status = _c("green","RUNNING ") if alive else (_c("yellow","STARTING") if svc.is_running() else _c("red","STOPPED "))
        sp(f"\n  {tag} {_c('bold', svc.name):<28}  {status}  ({svc.uptime()})")
        sp(f"        URL: {svc.url}")
    sp("\n  " + "="*56)
    sp(_c("dim", "  Press Ctrl+C to stop\n"))


# ---------------------------------------------------------------------------
# Pre-launch checks
# ---------------------------------------------------------------------------

def _run_checks() -> bool:
    sp(_c("bold", "\n  Pre-launch checks:"))
    ok = True
    checks = [
        ("Python 3.11+", sys.version_info >= (3,11),
         f"Python {sys.version_info.major}.{sys.version_info.minor}"),
        ("backend/main.py", (ROOT/"backend"/"main.py").exists(), ""),
        ("backend/database/db.py", (ROOT/"backend"/"database"/"db.py").exists(), ""),
        ("frontend/index.html",  (ROOT/"frontend"/"index.html").exists(), ""),
        ("contextguard/",        (ROOT/"contextguard"/"__init__.py").exists(), ""),
        ("attacks/",             (ROOT/"attacks"/"__init__.py").exists(), ""),
        ("dashboard.html",       (ROOT/"dashboard.html").exists(), ""),
    ]
    for label, passed, extra in checks:
        icon = _c("green","[OK]") if passed else _c("red","[!!]")
        sp(f"    {icon}  {label} {extra}")
        if not passed: ok = False

    # FastAPI import check
    try:
        import fastapi, uvicorn, sqlalchemy, pydantic
        sp(f"    {_c('green','[OK]')}  Core packages importable")
    except ImportError as e:
        sp(_c("red", f"    [!!]  Missing package: {e}"))
        sp(_c("yellow", "         Run: pip install -r requirements.txt"))
        ok = False

    if not ok:
        sp()
        ans = input("  Some checks failed. Continue anyway? (y/n): ").strip().lower()
        return ans == "y"
    return True


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

def launch() -> None:
    sp(BANNER)
    sp(_c("bold", f"  Starting  --  {datetime.now().strftime('%H:%M:%S  %d %b %Y')}"))

    if not _run_checks():
        sp(_c("red","  Aborted.")); sys.exit(1)

    services = [
        Service(
            name     = "Platform API",
            cmd      = [PYTHON, "-m", "uvicorn", "backend.main:app",
                        "--host", "127.0.0.1", "--port", "8000",
                        "--log-level", "warning"],
            url      = "http://127.0.0.1:8000",
            health   = "/api/health",
            critical = True,
        ),
    ]

    sp(_c("bold","\n  Clearing port 8000..."))
    _kill_port(8000)
    time.sleep(0.5)

    sp(_c("bold","\n  Starting services...\n"))
    for svc in services:
        sp(f"  [>>]  {svc.name}...")
        svc.start()
        time.sleep(0.5)

    # Wait for API
    sp(f"\n  Waiting for API", end="", flush=True)
    for _ in range(40):
        if services[0].ping(): break
        sp(".", end="", flush=True)
        time.sleep(0.5)
    sp()

    sp(_c("green","\n  [OK] Platform is running!\n"))
    sp("  " + "-"*56)
    sp(f"  Booking App    ->  http://127.0.0.1:8000/")
    sp(f"  Dashboard      ->  http://127.0.0.1:8000/dashboard")
    sp(f"  API Docs       ->  http://127.0.0.1:8000/docs")
    sp("  " + "-"*56)
    sp(_c("dim","\n  Open http://127.0.0.1:8000/dashboard in your browser."))
    sp(_c("dim",  "  Press Ctrl+C to stop.\n"))

    try:
        while True:
            time.sleep(4)
            _print_status(services)
            for svc in services:
                if svc.critical and not svc.is_running():
                    sp(_c("yellow", f"\n  [!!] {svc.name} stopped -- restarting..."))
                    svc.start()
    except KeyboardInterrupt:
        sp(_c("yellow","\n\n  Shutting down...\n"))
        for svc in reversed(services):
            sp(f"  [x]  Stopping {svc.name}...")
            svc.stop()
        sp(_c("green","\n  Stopped.\n"))


# ---------------------------------------------------------------------------
# Benchmark / evaluation
# ---------------------------------------------------------------------------

def run_benchmark() -> None:
    sp(BANNER)
    sp(_c("bold","\n  Running test suite + evaluation report...\n"))
    subprocess.run(
        [PYTHON, "-m", "pytest", "tests/test_cases.py", "-v", "--tb=short"],
        cwd=str(ROOT),
    )
    sp(_c("bold","\n  Evaluation matrix:\n"))
    subprocess.run([PYTHON, "tests/test_cases.py"], cwd=str(ROOT))


def run_eval_only() -> None:
    sp(BANNER)
    sp(_c("bold","\n  Evaluation report:\n"))
    subprocess.run([PYTHON, "tests/test_cases.py"], cwd=str(ROOT))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(description="AI Agent Security Platform Launcher")
    p.add_argument("--bench", action="store_true",
                   help="Run pytest + evaluation report then exit")
    p.add_argument("--eval",  action="store_true",
                   help="Run evaluation report only then exit")
    args = p.parse_args()

    if args.bench: run_benchmark(); return
    if args.eval:  run_eval_only(); return
    launch()


if __name__ == "__main__":
    main()
