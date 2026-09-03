"""
launcher.py -- ContextGuard Application Launcher

Starts all ContextGuard services in one command:

  Service 1 -- ContextGuard API + Dashboard   http://127.0.0.1:8000
  Service 2 -- Flight Booking Mock Site       http://127.0.0.1:5001
  Service 3 -- E-Commerce Mock Site           http://127.0.0.1:5002

Usage
-----
    python launcher.py              # start everything
    python launcher.py --no-sites   # API only
    python launcher.py --bench      # run offline benchmark then exit

Press Ctrl+C to stop all services cleanly.
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

# ---------------------------------------------------------------------------
# Force UTF-8 stdout/stderr on Windows BEFORE any print() calls.
# This prevents UnicodeEncodeError when the console is cp1252.
# ---------------------------------------------------------------------------
os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )
    # Switch console code page to UTF-8 so the terminal can render it
    os.system("chcp 65001 >nul 2>&1")

ROOT   = Path(__file__).parent
PYTHON = sys.executable

# ---------------------------------------------------------------------------
# Safe colour helpers -- all output goes through safe_print()
# ---------------------------------------------------------------------------
_ANSI = {
    "green":  "\033[92m",
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
    "reset":  "\033[0m",
}

def _c(colour: str, text: str) -> str:
    return f"{_ANSI[colour]}{text}{_ANSI['reset']}"

def safe_print(msg: str = "") -> None:
    """Print with automatic fallback for non-UTF-8 consoles."""
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", errors="replace").decode("ascii"), flush=True)


# ---------------------------------------------------------------------------
# Banner -- plain ASCII only, no box-drawing, no emoji
# ---------------------------------------------------------------------------
BANNER = """
  ============================================================
   ContextGuard
   Runtime Safety Gateway for Web Agents
   Context Manipulation and Plan Injection Defence
  ============================================================
"""


# ---------------------------------------------------------------------------
# Service descriptor
# ---------------------------------------------------------------------------

class Service:
    def __init__(
        self,
        name: str,
        cmd: List[str],
        url: str,
        health_path: str = "",
        critical: bool = True,
    ) -> None:
        self.name        = name
        self.cmd         = cmd
        self.url         = url
        self.health_url  = url + health_path if health_path else ""
        self.critical    = critical
        self.proc: Optional[subprocess.Popen] = None
        self.start_time  = 0.0
        self.last_status = "stopped"

    def start(self) -> None:
        env = {
            **os.environ,
            "PYTHONUNBUFFERED":  "1",
            "PYTHONIOENCODING":  "utf-8",
            "PYTHONPATH":        str(ROOT),
        }
        self.proc = subprocess.Popen(
            self.cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
        )
        self.start_time  = time.time()
        self.last_status = "starting"

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.last_status = "stopped"

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def ping(self) -> bool:
        if not self.health_url:
            return self.is_running()
        try:
            req = urllib.request.urlopen(self.health_url, timeout=2)
            return req.status == 200
        except Exception:
            return False

    def uptime(self) -> str:
        if not self.start_time:
            return "-"
        secs = int(time.time() - self.start_time)
        m, s = divmod(secs, 60)
        return f"{m}m {s:02d}s" if m else f"{s}s"


# ---------------------------------------------------------------------------
# Log collector
# ---------------------------------------------------------------------------

_NOISE = (
    "NotImplementedError",
    "raise NotImplementedError",
    "Task exception was never retrieved",
    "playwright._impl",
    "_transport.py",
    "create_subprocess_exec",
    "_make_subprocess_transport",
    "asyncio.runners",
)

class LogCollector:
    def __init__(self, service: Service, max_lines: int = 8) -> None:
        self.service   = service
        self.lines: List[str] = []
        self.max_lines = max_lines
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self) -> None:
        proc = self.service.proc
        if not proc or not proc.stdout:
            return
        for raw in proc.stdout:
            line = raw.rstrip()
            if line and not any(n in line for n in _NOISE):
                self.lines.append(line)
                if len(self.lines) > self.max_lines:
                    self.lines.pop(0)

    def latest(self, n: int = 3) -> List[str]:
        return self.lines[-n:]


# ---------------------------------------------------------------------------
# Port helpers
# ---------------------------------------------------------------------------

def _port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _kill_port(port: int) -> None:
    """Kill the process occupying a port on Windows."""
    if sys.platform != "win32":
        return
    if not _port_in_use(port):
        return
    try:
        # Step 1: find the PID
        r = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True
        )
        pid = None
        for line in r.stdout.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                parts = line.split()
                if parts:
                    pid = parts[-1]
                    break
        # Step 2: kill it
        if pid and pid.isdigit():
            subprocess.run(
                ["taskkill", "/F", "/PID", pid],
                capture_output=True
            )
            safe_print(f"  [INFO] Freed port {port} (PID {pid})")
    except Exception as exc:
        safe_print(f"  [WARN] Could not free port {port}: {exc}")


# ---------------------------------------------------------------------------
# Startup checks
# ---------------------------------------------------------------------------

def run_startup_checks() -> bool:
    try:
        from app.services.startup_checks import run_all_checks
        report = run_all_checks(ROOT)
    except Exception as exc:
        safe_print(f"  [SKIP] Startup checks unavailable: {exc}")
        return True

    safe_print(_c("bold", "\n  Pre-launch checks:"))
    for chk in report.checks:
        icon = "[OK]" if chk.passed else "[!!]"
        colour = "green" if chk.passed else ("yellow" if "Port" in chk.name else "red")
        safe_print(f"    {_c(colour, icon)}  {chk.message}")

    failures = [f for f in report.critical_failures
                if "Port" not in f.name and "Package" not in f.name]
    if failures:
        safe_print("")
        for f in failures:
            safe_print(_c("red", f"  FAIL: {f.message}"))
        ans = input("  Some checks failed. Continue anyway? (y/n): ").strip().lower()
        return ans == "y"
    return True


# ---------------------------------------------------------------------------
# Status display
# ---------------------------------------------------------------------------

def _clear() -> None:
    os.system("cls" if sys.platform == "win32" else "clear")


def print_status(services: List[Service], logs: Dict[str, LogCollector]) -> None:
    _clear()
    safe_print(_c("bold", "\n  ContextGuard -- Live Status"))
    safe_print("  " + "=" * 56)

    for svc in services:
        alive = svc.ping()
        if alive:
            svc.last_status = "running"
            tag    = _c("green",  "[ON] ")
            status = _c("green",  "RUNNING ")
        elif svc.is_running():
            svc.last_status = "starting"
            tag    = _c("yellow", "[..]  ")
            status = _c("yellow", "STARTING")
        else:
            svc.last_status = "stopped"
            tag    = _c("red",    "[OFF] ")
            status = _c("red",    "STOPPED ")

        safe_print(f"\n  {tag} {_c('bold', svc.name):<28}  {status}  ({svc.uptime()})")
        safe_print(f"        URL: {svc.url}")

    safe_print("\n  " + "=" * 56)
    safe_print(_c("dim", "  Press Ctrl+C to stop all services\n"))

    shown = 0
    for svc in services:
        lc = logs.get(svc.name)
        if not lc:
            continue
        for line in lc.latest(2):
            if shown < 6:
                label = f"[{svc.name[:10]}]"
                safe_print(_c("dim", f"  {label:<14} {line[:80]}"))
                shown += 1


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def run_benchmark() -> None:
    safe_print(_c("bold", "\n  Running offline benchmark...\n"))
    subprocess.run(
        [PYTHON, "-m", "benchmark.run_experiments",
         "--offline", "--modes", "baseline", "rule_only"],
        cwd=str(ROOT),
    )
    results_csv = ROOT / "benchmark" / "experiment_results" / "results_rule_only.csv"
    if results_csv.exists():
        safe_print(_c("bold", "\n  Generating metrics report...\n"))
        subprocess.run(
            [PYTHON, "-m", "benchmark.metrics",
             "--csv", str(results_csv), "--save"],
            cwd=str(ROOT),
        )
    safe_print(_c("green", "\n  Done. Results in benchmark/experiment_results/\n"))


# ---------------------------------------------------------------------------
# Build service list
# ---------------------------------------------------------------------------

def build_services(no_sites: bool = False) -> List[Service]:
    services = [
        Service(
            name="ContextGuard API",
            cmd=[PYTHON, "-m", "uvicorn", "main:app",
                 "--host", "127.0.0.1", "--port", "8000",
                 "--log-level", "warning"],
            url="http://127.0.0.1:8000",
            health_path="/api/health",
            critical=True,
        ),
    ]
    if not no_sites:
        services += [
            Service(
                name="Flight Booking Site",
                cmd=[PYTHON, str(ROOT / "attack_sim" / "flight_site.py")],
                url="http://127.0.0.1:5001",
                health_path="/status",
                critical=False,
            ),
            Service(
                name="E-Commerce Site",
                cmd=[PYTHON, str(ROOT / "attack_sim" / "ecommerce_site.py")],
                url="http://127.0.0.1:5002",
                health_path="/status",
                critical=False,
            ),
        ]
    return services


# ---------------------------------------------------------------------------
# Main launch flow
# ---------------------------------------------------------------------------

def launch(no_sites: bool = False) -> None:
    safe_print(BANNER)
    safe_print(_c("bold",
        f"  Starting ContextGuard -- {datetime.now().strftime('%H:%M:%S  %d %b %Y')}"))

    if not run_startup_checks():
        safe_print(_c("red", "  Aborted."))
        sys.exit(1)

    services = build_services(no_sites)

    # Free ports before starting
    safe_print(_c("bold", "\n  Clearing ports..."))
    ports = [8000] + ([] if no_sites else [5001, 5002])
    for port in ports:
        _kill_port(port)
    time.sleep(0.8)

    # Start all processes
    safe_print(_c("bold", "\n  Starting services...\n"))
    for svc in services:
        safe_print(f"  [>>]  {svc.name}...")
        svc.start()
        time.sleep(0.5)

    log_collectors: Dict[str, LogCollector] = {
        svc.name: LogCollector(svc) for svc in services
    }

    # Wait for API health endpoint
    api = services[0]
    safe_print(f"\n  Waiting for API to be ready ", end="")
    for _ in range(40):
        if api.ping():
            break
        safe_print(".", end="", flush=True)
        time.sleep(0.5)
    safe_print()

    # Startup summary
    safe_print(_c("green", "\n  [OK] ContextGuard is running!\n"))
    safe_print("  " + "-" * 56)
    safe_print(f"  Dashboard      ->  http://127.0.0.1:8000")
    safe_print(f"  API Docs       ->  http://127.0.0.1:8000/docs")
    if not no_sites:
        safe_print(f"  Flight Site    ->  http://127.0.0.1:5001")
        safe_print(f"  E-Commerce     ->  http://127.0.0.1:5002")
        safe_print(f"  Attack Demo    ->  http://127.0.0.1:5001/review?attack=plan_injection_2")
    safe_print("  " + "-" * 56)
    safe_print(_c("dim", "\n  Open http://127.0.0.1:8000 in your browser."))
    safe_print(_c("dim",   "  Press Ctrl+C to stop all services.\n"))

    # Live status loop
    try:
        while True:
            time.sleep(4)
            print_status(services, log_collectors)
            # Auto-restart critical services that crashed
            for svc in services:
                if svc.critical and not svc.is_running():
                    safe_print(_c("yellow",
                        f"\n  [!!] {svc.name} stopped -- restarting..."))
                    svc.start()
                    log_collectors[svc.name] = LogCollector(svc)

    except KeyboardInterrupt:
        safe_print(_c("yellow", "\n\n  Shutting down...\n"))
        for svc in reversed(services):
            safe_print(f"  [x]  Stopping {svc.name}...")
            svc.stop()
        safe_print(_c("green", "\n  All services stopped.\n"))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(description="ContextGuard Launcher")
    p.add_argument("--no-sites",  action="store_true",
                   help="Start API only (skip mock sites)")
    p.add_argument("--api-only",  action="store_true",
                   help="Alias for --no-sites")
    p.add_argument("--bench",     action="store_true",
                   help="Run offline benchmark then exit")
    args = p.parse_args()

    if args.bench:
        safe_print(BANNER)
        run_benchmark()
        return

    launch(no_sites=args.no_sites or args.api_only)


if __name__ == "__main__":
    main()
