"""
launcher.py — ContextGuard Application Launcher

Single entry point that starts all ContextGuard services:

  Service 1 — ContextGuard API + Dashboard   http://127.0.0.1:8000
  Service 2 — Flight Booking Mock Site       http://127.0.0.1:5001
  Service 3 — E-Commerce Mock Site           http://127.0.0.1:5002

Usage
-----
    python launcher.py              # start everything
    python launcher.py --no-sites   # API only (no mock sites)
    python launcher.py --bench      # run offline benchmark then exit
    python launcher.py --help       # show all options

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
from typing import List, Optional

ROOT = Path(__file__).parent
PYTHON = sys.executable

# ---------------------------------------------------------------------------
# ANSI colours (work on Windows 10+ with ANSI enabled)
# ---------------------------------------------------------------------------
def _enable_ansi():
    if sys.platform == "win32":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

_enable_ansi()

G  = "\033[92m";  R  = "\033[91m";  Y  = "\033[93m"
C  = "\033[96m";  B  = "\033[1m";   DIM = "\033[2m";  E = "\033[0m"
BG_DARK = "\033[40m"

def green(s):  return f"{G}{s}{E}"
def red(s):    return f"{R}{s}{E}"
def yellow(s): return f"{Y}{s}{E}"
def cyan(s):   return f"{C}{s}{E}"
def bold(s):   return f"{B}{s}{E}"
def dim(s):    return f"{DIM}{s}{E}"


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = f"""
{C}{B}
  ██████╗ ██████╗ ███╗   ██╗████████╗███████╗██╗  ██╗████████╗
 ██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔════╝╚██╗██╔╝╚══██╔══╝
 ██║     ██║   ██║██╔██╗ ██║   ██║   █████╗   ╚███╔╝    ██║
 ██║     ██║   ██║██║╚██╗██║   ██║   ██╔══╝   ██╔██╗    ██║
 ╚██████╗╚██████╔╝██║ ╚████║   ██║   ███████╗██╔╝ ██╗   ██║
  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝
{E}{C}           Runtime Safety Gateway for Web Agents{E}
{DIM}           Context Manipulation & Plan Injection Defence{E}
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
        colour: str = C,
        critical: bool = True,
    ) -> None:
        self.name         = name
        self.cmd          = cmd
        self.url          = url
        self.health_url   = url + health_path if health_path else ""
        self.colour       = colour
        self.critical     = critical
        self.proc: Optional[subprocess.Popen] = None
        self.started      = False
        self.start_time   = 0.0
        self.last_status  = "stopped"

    def start(self) -> None:
        env = {**os.environ, "PYTHONUNBUFFERED": "1",
               "PYTHONPATH": str(ROOT)}
        self.proc = subprocess.Popen(
            self.cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
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
            return "—"
        secs = int(time.time() - self.start_time)
        m, s = divmod(secs, 60)
        return f"{m}m {s:02d}s" if m else f"{s}s"


# ---------------------------------------------------------------------------
# Log collector (runs in background thread)
# ---------------------------------------------------------------------------

class LogCollector:
    def __init__(self, service: Service, max_lines: int = 6) -> None:
        self.service   = service
        self.lines: List[str] = []
        self.max_lines = max_lines
        self._thread   = threading.Thread(target=self._collect, daemon=True)
        self._thread.start()

    def _collect(self) -> None:
        proc = self.service.proc
        if not proc or not proc.stdout:
            return
        # Lines to suppress from the live display (noise / known non-errors)
        _SUPPRESS = (
            "NotImplementedError",
            "raise NotImplementedError",
            "Task exception was never retrieved",
            "playwright._impl",
            "_transport.py",
            "create_subprocess_exec",
            "subprocess_exec",
            "_make_subprocess_transport",
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line and not any(s in line for s in _SUPPRESS):
                self.lines.append(line)
                if len(self.lines) > self.max_lines:
                    self.lines.pop(0)

    def latest(self, n: int = 3) -> List[str]:
        return self.lines[-n:]


# ---------------------------------------------------------------------------
# Startup check runner (inline, no import needed if package missing)
# ---------------------------------------------------------------------------

def run_startup_checks() -> bool:
    try:
        from app.services.startup_checks import run_all_checks
        report = run_all_checks(ROOT)
    except Exception as exc:
        print(yellow(f"  Startup checks skipped: {exc}"))
        return True

    print(f"\n{bold('  Pre-launch checks:')}")
    for c in report.checks:
        icon = green("✓") if c.passed else red("✗")
        print(f"    {icon}  {c.message}")

    if not report.all_passed:
        print()
        for f in report.critical_failures:
            print(red(f"  FAIL: {f.message}"))
        print()
        # Port conflicts are warnings, not hard stops
        non_port = [f for f in report.critical_failures
                    if "Port" not in f.name and "Package" not in f.name]
        if non_port:
            ans = input(yellow("  Some checks failed. Continue anyway? (y/n): ")).strip().lower()
            return ans == "y"
    return True


# ---------------------------------------------------------------------------
# Status display
# ---------------------------------------------------------------------------

def _clear_lines(n: int) -> None:
    for _ in range(n):
        print("\033[1A\033[2K", end="")


def print_status_table(services: List[Service], logs: dict) -> int:
    """Print the live status table. Returns number of lines printed."""
    lines: List[str] = []

    lines.append(f"\n{bold(cyan('  Services'))}")
    lines.append(f"  {'─'*62}")

    for svc in services:
        alive = svc.ping()
        svc.last_status = "running" if alive else ("starting" if svc.is_running() else "stopped")

        if svc.last_status == "running":
            dot = green("●")
            status = green("RUNNING")
        elif svc.last_status == "starting":
            dot = yellow("◐")
            status = yellow("STARTING")
        else:
            dot = red("○")
            status = red("STOPPED")

        col = svc.colour
        lines.append(
            f"  {dot}  {col}{bold(svc.name):<30}{E}  "
            f"{status:<20}  {dim(svc.uptime())}"
        )
        if svc.url:
            lines.append(f"      {dim('→')} {cyan(svc.url)}")

    lines.append(f"  {'─'*62}")
    lines.append(f"  {dim('Press Ctrl+C to stop all services')}")
    lines.append("")

    # Recent log tail
    for svc in services:
        recent = logs.get(svc.name, LogCollector(svc)).latest(2)
        for ln in recent:
            ln = ln[:80]
            lines.append(f"  {dim('[' + svc.name[:12] + ']')} {dim(ln)}")

    output = "\n".join(lines)
    print(output)
    return len(lines)


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def run_benchmark() -> None:
    print(f"\n{bold(cyan('  Running offline benchmark...'))} \n")
    result = subprocess.run(
        [PYTHON, "-m", "benchmark.run_experiments",
         "--offline", "--modes", "baseline", "rule_only"],
        cwd=str(ROOT),
    )
    if result.returncode == 0:
        print(green("\n  Benchmark complete. Results saved to benchmark/experiment_results/"))
    else:
        print(red("\n  Benchmark exited with errors."))

    # Also run metrics report
    print(f"\n{bold(cyan('  Generating metrics report...'))} \n")
    subprocess.run(
        [PYTHON, "-m", "benchmark.metrics",
         "--csv", str(ROOT / "benchmark" / "experiment_results" / "results_rule_only.csv"),
         "--save"],
        cwd=str(ROOT),
    )


# ---------------------------------------------------------------------------
# Main launcher
# ---------------------------------------------------------------------------

def build_services(no_sites: bool = False) -> List[Service]:
    flight_script   = str(ROOT / "attack_sim" / "flight_site.py")
    ecomm_script    = str(ROOT / "attack_sim" / "ecommerce_site.py")

    services = [
        Service(
            name="ContextGuard API",
            cmd=[PYTHON, "-m", "uvicorn", "main:app",
                 "--host", "127.0.0.1", "--port", "8000",
                 "--log-level", "warning"],
            url="http://127.0.0.1:8000",
            health_path="/api/health",
            colour=C,
            critical=True,
        ),
    ]

    if not no_sites:
        services += [
            Service(
                name="Flight Booking Site",
                cmd=[PYTHON, flight_script],
                url="http://127.0.0.1:5001",
                health_path="/status",
                colour=G,
                critical=False,
            ),
            Service(
                name="E-Commerce Site",
                cmd=[PYTHON, ecomm_script],
                url="http://127.0.0.1:5002",
                health_path="/status",
                colour=Y,
                critical=False,
            ),
        ]
    return services


def launch(no_sites: bool = False) -> None:
    print(BANNER)
    print(bold(f"  Starting ContextGuard — {datetime.now().strftime('%H:%M:%S %d %b %Y')}"))
    print()

    if not run_startup_checks():
        print(red("  Aborted."))
        sys.exit(1)

    services = build_services(no_sites)

    # Start all services
    print(f"\n{bold('  Starting services...')}\n")
    for svc in services:
        print(f"  {yellow('▶')}  Starting {bold(svc.name)}...")
        svc.start()
        time.sleep(0.4)

    # Attach log collectors
    log_collectors = {svc.name: LogCollector(svc) for svc in services}

    # Wait for API to become ready (max 15 seconds)
    api = services[0]
    print(f"\n  Waiting for {cyan('ContextGuard API')} to be ready", end="", flush=True)
    for _ in range(30):
        if api.ping():
            break
        print(".", end="", flush=True)
        time.sleep(0.5)
    print()

    # Print startup summary
    print(f"\n{bold(green('  ✓ ContextGuard is running!'))}\n")
    print(f"  {'─'*62}")
    print(f"  {bold('Dashboard')}      →  {cyan('http://127.0.0.1:8000')}")
    print(f"  {bold('API Docs')}       →  {cyan('http://127.0.0.1:8000/docs')}")
    if not no_sites:
        print(f"  {bold('Flight Site')}    →  {cyan('http://127.0.0.1:5001')}")
        print(f"  {bold('E-Commerce')}     →  {cyan('http://127.0.0.1:5002')}")
        print(f"  {bold('Attack Demo')}    →  {cyan('http://127.0.0.1:5001/review?attack=plan_injection_2')}")
    print(f"  {'─'*62}")
    print()
    print(f"  {dim('Open your browser to http://127.0.0.1:8000 to use the dashboard.')}")
    print(f"  {dim('Press Ctrl+C to stop all services.')}\n")

    # Live status loop
    last_lines = 0
    try:
        while True:
            time.sleep(3)
            if last_lines:
                _clear_lines(last_lines + 1)
            last_lines = print_status_table(services, log_collectors)

            # Restart crashed critical services
            for svc in services:
                if svc.critical and not svc.is_running():
                    print(yellow(f"\n  ⚠  {svc.name} crashed — restarting..."))
                    svc.start()
                    log_collectors[svc.name] = LogCollector(svc)

    except KeyboardInterrupt:
        print(f"\n\n{bold(yellow('  Shutting down...'))} \n")
        for svc in reversed(services):
            print(f"  {red('■')}  Stopping {svc.name}...")
            svc.stop()
        print(f"\n{bold(green('  All services stopped. Goodbye!'))} \n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ContextGuard Application Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python launcher.py                 Start everything (API + mock sites)
  python launcher.py --no-sites      Start API only
  python launcher.py --bench         Run offline benchmark then exit
  python launcher.py --api-only      Alias for --no-sites
        """,
    )
    parser.add_argument("--no-sites",  action="store_true",
                        help="Start ContextGuard API only, skip mock sites")
    parser.add_argument("--api-only",  action="store_true",
                        help="Alias for --no-sites")
    parser.add_argument("--bench",     action="store_true",
                        help="Run offline benchmark and exit (no servers)")
    args = parser.parse_args()

    if args.bench:
        print(BANNER)
        run_benchmark()
        return

    launch(no_sites=args.no_sites or args.api_only)


if __name__ == "__main__":
    main()
