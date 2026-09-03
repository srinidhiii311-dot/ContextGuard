"""
benchmark/test_harness.py — ContextGuard

Core test harness that executes each benchmark scenario with and without
ContextGuard, records every result, and writes results.csv.

Key function
------------
run_agent_with_contextguard(case, use_contextguard, page, verifier)
  - Navigates to the target URL
  - Executes each step in case["steps"]
  - Records whether an alarm was triggered
  - Records total latency

Two modes
---------
Baseline  (use_contextguard=False):
  Playwright executes every step unconditionally.
  An "alarm" is never raised — the agent is fully hijacked.
  This shows how a vulnerable agent behaves without protection.

Protected (use_contextguard=True):
  Every step passes through ContextGuardVerifier.verify() first.
  A discrepancy triggers an alarm and blocks execution.
  This is the defended mode.

Output
------
results.csv  one row per (test_id × mode) with columns:
  test_id, domain, attack_type, mode, alarm_triggered,
  expected_alarm, correct, latency_sec, steps_executed,
  steps_blocked, reason, risk_level, layer
"""

from __future__ import annotations

import asyncio
import csv
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from playwright.async_api import Browser, BrowserContext, Page, async_playwright
    _PW = True
except ImportError:
    _PW = False

from verifier.capture_state import capture_state
from verifier.verifier import ContextGuardVerifier, VerificationStatus

BENCHMARK_PATH = Path(__file__).parent / "benchmark.json"
RESULTS_CSV    = Path(__file__).parent / "results.csv"

CSV_FIELDS = [
    "test_id", "domain", "attack_type", "mode",
    "alarm_triggered", "expected_alarm", "correct",
    "latency_sec", "steps_executed", "steps_blocked",
    "reason", "risk_level", "layer",
]


# ---------------------------------------------------------------------------
# Per-run result
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    test_id: str
    domain: str
    attack_type: str
    mode: str                      # "baseline" | "protected"
    alarm_triggered: bool
    expected_alarm: bool
    correct: bool
    latency_sec: float
    steps_executed: int
    steps_blocked: int
    reason: str = ""
    risk_level: str = ""
    layer: str = ""
    error: Optional[str] = None

    def to_csv_row(self) -> Dict[str, Any]:
        return {
            "test_id":        self.test_id,
            "domain":         self.domain,
            "attack_type":    self.attack_type,
            "mode":           self.mode,
            "alarm_triggered":int(self.alarm_triggered),
            "expected_alarm": int(self.expected_alarm),
            "correct":        int(self.correct),
            "latency_sec":    round(self.latency_sec, 4),
            "steps_executed": self.steps_executed,
            "steps_blocked":  self.steps_blocked,
            "reason":         self.reason[:120],
            "risk_level":     self.risk_level,
            "layer":          self.layer,
        }


# ---------------------------------------------------------------------------
# Single scenario runner
# ---------------------------------------------------------------------------

async def run_agent_with_contextguard(
    case: Dict[str, Any],
    use_contextguard: bool,
    page: Page,
    verifier: Optional[ContextGuardVerifier] = None,
    step_timeout_ms: int = 10_000,
) -> RunResult:
    """
    Execute all steps in a benchmark scenario against a live Playwright page.

    Parameters
    ----------
    case            : One entry from benchmark.json test_cases.
    use_contextguard: True = protected mode, False = baseline.
    page            : Playwright Page object.
    verifier        : ContextGuardVerifier instance (used only when protected).
    step_timeout_ms : Per-step Playwright timeout in milliseconds.

    Returns
    -------
    RunResult with alarm status, latency, and step counts.
    """
    test_id     = case["test_id"]
    domain      = case["domain"]
    attack_type = case["attack_type"]
    expected    = bool(case["should_trigger_alarm"])
    mode        = "protected" if use_contextguard else "baseline"
    steps       = case.get("steps", [])

    alarm_triggered = False
    steps_executed  = 0
    steps_blocked   = 0
    first_reason    = ""
    first_risk      = ""
    first_layer     = ""
    t0 = time.monotonic()

    # Navigate to starting URL
    target_url = case.get("target_url", "")
    if target_url:
        try:
            await page.goto(
                target_url, timeout=15_000, wait_until="domcontentloaded"
            )
        except Exception as exc:
            latency = time.monotonic() - t0
            return RunResult(
                test_id=test_id, domain=domain, attack_type=attack_type,
                mode=mode, alarm_triggered=False, expected_alarm=expected,
                correct=(not expected),
                latency_sec=latency, steps_executed=0, steps_blocked=0,
                error=f"Navigation error: {exc}",
            )

    # Execute each step
    for step in steps:
        action  = step.get("action", "")
        thought = step.get("thought", "")
        sel     = step.get("selector", "")
        url     = step.get("url", "")
        value   = step.get("value", "")
        desc    = f"{action} {sel or url or ''}".strip()

        # ── Protected mode: verify before executing ──────────────────────
        if use_contextguard and verifier:
            try:
                snapshot = await capture_state(page)
                result   = verifier.verify(thought, desc, snapshot)
            except Exception as exc:
                # Verification error → fail closed
                alarm_triggered = True
                first_reason  = f"Verification error (fail-closed): {exc}"
                first_risk    = "CRITICAL"
                first_layer   = "fail_closed"
                steps_blocked += 1
                break

            if result.status == VerificationStatus.DISCREPANCY:
                alarm_triggered = True
                if not first_reason:
                    first_reason = result.reason
                    first_risk   = result.risk_level
                    first_layer  = result.layer
                steps_blocked += 1
                # Stop after first alarm (simulates agent being halted)
                break

        # ── Execute the Playwright action ────────────────────────────────
        try:
            if action == "navigate":
                nav_url = url or target_url
                if nav_url:
                    await page.goto(
                        nav_url, timeout=15_000,
                        wait_until="domcontentloaded"
                    )
            elif action == "click":
                if sel:
                    await page.click(sel, timeout=step_timeout_ms)
            elif action == "fill":
                if sel and value:
                    await page.fill(sel, value, timeout=step_timeout_ms)
            elif action == "submit":
                if sel:
                    await page.locator(sel).first.evaluate(
                        "el => el.tagName==='FORM'?el.submit():el.click()"
                    )
            elif action == "extract":
                if sel:
                    await page.inner_text(sel, timeout=step_timeout_ms)
            steps_executed += 1

        except Exception:
            # Playwright step failed (element not found etc.) — continue
            steps_executed += 1

    latency = time.monotonic() - t0
    correct = (alarm_triggered == expected)

    return RunResult(
        test_id=test_id,
        domain=domain,
        attack_type=attack_type,
        mode=mode,
        alarm_triggered=alarm_triggered,
        expected_alarm=expected,
        correct=correct,
        latency_sec=latency,
        steps_executed=steps_executed,
        steps_blocked=steps_blocked,
        reason=first_reason,
        risk_level=first_risk,
        layer=first_layer,
    )


# ---------------------------------------------------------------------------
# Harness: run all cases in both modes
# ---------------------------------------------------------------------------

class TestHarness:
    """
    Loads benchmark.json, runs every scenario in baseline and protected
    modes, and writes results.csv.
    """

    def __init__(
        self,
        benchmark_path: Path = BENCHMARK_PATH,
        results_path: Path   = RESULTS_CSV,
        headless: bool       = True,
        use_llm: bool        = False,
        llm_model: str       = "llama3",
        modes: Optional[List[str]] = None,
    ) -> None:
        self.benchmark_path = benchmark_path
        self.results_path   = results_path
        self.headless       = headless
        self.modes          = modes or ["baseline", "protected"]
        self.verifier = ContextGuardVerifier(
            use_llm=use_llm,
            llm_model=llm_model,
            llm_timeout=12,
        )
        self.results: List[RunResult] = []

    def load_cases(self) -> List[Dict[str, Any]]:
        if not self.benchmark_path.exists():
            raise FileNotFoundError(
                f"Benchmark file not found: {self.benchmark_path}"
            )
        raw = self.benchmark_path.read_text(encoding="utf-8")
        # Strip JS-style comments so json.loads works
        import re
        raw = re.sub(r"//[^\n]*", "", raw)
        data = json.loads(raw)
        return data["test_cases"]

    async def run(self) -> List[RunResult]:
        if not _PW:
            print("ERROR: Playwright not installed.")
            print("Run: pip install playwright && playwright install chromium")
            sys.exit(1)

        cases = self.load_cases()
        print(f"\n{'═'*62}")
        print(f"  ContextGuard Test Harness")
        print(f"  {len(cases)} scenarios × {len(self.modes)} modes = "
              f"{len(cases)*len(self.modes)} runs")
        print(f"  LLM: {'enabled (' + self.verifier._llm_model + ')' if self.verifier._use_llm else 'disabled'}")
        print(f"{'═'*62}\n")

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(headless=self.headless)

            for mode in self.modes:
                use_cg = mode == "protected"
                print(f"\n── Mode: {mode.upper()} {'(ContextGuard ON)' if use_cg else '(no protection)'} ──")
                context: BrowserContext = await browser.new_context()
                page: Page = await context.new_page()

                for i, case in enumerate(cases):
                    result = await run_agent_with_contextguard(
                        case=case,
                        use_contextguard=use_cg,
                        page=page,
                        verifier=self.verifier if use_cg else None,
                    )
                    self.results.append(result)
                    self._print_row(result, i + 1, len(cases))

                await context.close()

            await browser.close()

        self._write_csv()
        self._print_summary()
        return self.results

    def _print_row(self, r: RunResult, n: int, total: int) -> None:
        g = "\033[92m"; red = "\033[91m"; rst = "\033[0m"
        ok  = f"{g}✓{rst}" if r.correct else f"{red}✗{rst}"
        alm = f"{red}ALARM{rst}" if r.alarm_triggered else "     "
        print(
            f"  [{n:2}/{total}] {r.test_id:<12} {r.attack_type:<18} "
            f"{alm}  {ok}  {r.latency_sec:.2f}s"
            + (f"  {r.reason[:55]}" if r.alarm_triggered else "")
        )

    def _write_csv(self) -> None:
        with open(self.results_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for r in self.results:
                writer.writerow(r.to_csv_row())
        print(f"\n  Results saved → {self.results_path.resolve()}")

    def _print_summary(self) -> None:
        protected = [r for r in self.results if r.mode == "protected"]
        baseline  = [r for r in self.results if r.mode == "baseline"]
        attacks_p = [r for r in protected if r.attack_type != "benign"]
        benign_p  = [r for r in protected if r.attack_type == "benign"]
        attacks_b = [r for r in baseline  if r.attack_type != "benign"]

        tp = sum(1 for r in attacks_p if r.alarm_triggered)
        fp = sum(1 for r in benign_p  if r.alarm_triggered)
        # In baseline, no alarms are raised so breach_rate = attacks not caught
        breached = sum(1 for r in attacks_b if not r.alarm_triggered)

        dr  = tp / len(attacks_p) * 100 if attacks_p else 0
        fpr = fp / len(benign_p)  * 100 if benign_p  else 0
        br  = breached / len(attacks_b) * 100 if attacks_b else 0

        mean_p = sum(r.latency_sec for r in protected) / len(protected) if protected else 0
        mean_b = sum(r.latency_sec for r in baseline)  / len(baseline)  if baseline  else 0

        print(f"\n{'═'*62}")
        print(f"  SUMMARY")
        print(f"{'─'*62}")
        print(f"  Baseline  — Breach rate     : {br:.1f}%  "
              f"({breached}/{len(attacks_b)} attacks succeeded)")
        print(f"  Protected — Detection rate  : {dr:.1f}%  "
              f"({tp}/{len(attacks_p)} attacks caught)")
        print(f"  Protected — False pos rate  : {fpr:.1f}%  "
              f"({fp}/{len(benign_p)} benign blocked)")
        print(f"  Baseline  — Mean latency    : {mean_b:.2f}s per task")
        print(f"  Protected — Mean latency    : {mean_p:.2f}s per task")
        print(f"  Overhead                    : "
              f"+{mean_p - mean_b:.2f}s per task")
        print(f"{'═'*62}\n")


# ---------------------------------------------------------------------------
# Offline harness (no browser) — uses synthetic snapshots for quick CI runs
# ---------------------------------------------------------------------------

class OfflineTestHarness:
    """
    Runs all benchmark cases without a browser by building synthetic
    PageSnapshot objects from the scenario metadata.  Fast and
    dependency-free — no Flask servers needed.
    """

    def __init__(
        self,
        benchmark_path: Path = BENCHMARK_PATH,
        results_path: Path   = RESULTS_CSV,
        use_llm: bool        = False,
    ) -> None:
        self.benchmark_path = benchmark_path
        self.results_path   = results_path
        self.verifier = ContextGuardVerifier(
            use_llm=use_llm,
            always_use_llm_for_high_risk=False,
        )
        self.results: List[RunResult] = []

    def run(self) -> List[RunResult]:
        """Run all scenarios offline and return results."""
        from benchmark.harness import _build_synthetic_snapshot

        cases = self._load_cases()
        print(f"\n  Offline harness — {len(cases)} cases × 2 modes\n")

        for mode in ("baseline", "protected"):
            use_cg = mode == "protected"
            for case in cases:
                attack_type = case.get("attack_type", "benign")
                expected    = bool(case["should_trigger_alarm"])
                url         = case.get("target_url", "")

                # Build synthetic snapshot from URL + attack type
                snapshot = _build_synthetic_snapshot(url, attack_type)

                t0 = time.monotonic()
                alarm = False
                reason = ""
                risk   = ""
                layer  = ""

                if use_cg:
                    # Verify the first step's thought
                    steps   = case.get("steps", [])
                    thought = steps[0]["thought"] if steps else ""
                    action  = steps[0].get("action", "navigate") if steps else "navigate"
                    try:
                        result = self.verifier.verify(thought, action, snapshot)
                        if result.status == VerificationStatus.DISCREPANCY:
                            alarm  = True
                            reason = result.reason
                            risk   = result.risk_level
                            layer  = result.layer
                    except Exception as exc:
                        alarm  = True
                        reason = str(exc)

                latency = time.monotonic() - t0
                correct = (alarm == expected)

                r = RunResult(
                    test_id=case["test_id"],
                    domain=case["domain"],
                    attack_type=attack_type,
                    mode=mode,
                    alarm_triggered=alarm,
                    expected_alarm=expected,
                    correct=correct,
                    latency_sec=latency,
                    steps_executed=1,
                    steps_blocked=int(alarm),
                    reason=reason,
                    risk_level=risk,
                    layer=layer,
                )
                self.results.append(r)
                g = "\033[92m"; red = "\033[91m"; rst = "\033[0m"
                ok = f"{g}✓{rst}" if correct else f"{red}✗{rst}"
                print(f"  {ok} [{mode[:4]}] {r.test_id:<12} "
                      f"{attack_type:<18} {r.latency_sec*1000:.1f}ms")

        self._write_csv()
        return self.results

    def _load_cases(self) -> List[Dict[str, Any]]:
        import re
        raw = self.benchmark_path.read_text(encoding="utf-8")
        raw = re.sub(r"//[^\n]*", "", raw)
        return json.loads(raw)["test_cases"]

    def _write_csv(self) -> None:
        with open(self.results_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for r in self.results:
                writer.writerow(r.to_csv_row())
        print(f"\n  Results → {self.results_path.resolve()}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="ContextGuard test harness")
    p.add_argument("--offline",  action="store_true",
                   help="Run without browser (synthetic snapshots)")
    p.add_argument("--headed",   action="store_true",
                   help="Show browser window")
    p.add_argument("--llm",      action="store_true",
                   help="Enable Ollama LLM verification")
    p.add_argument("--baseline-only", action="store_true",
                   help="Run baseline mode only")
    p.add_argument("--protected-only", action="store_true",
                   help="Run protected mode only")
    args = p.parse_args()

    modes = ["baseline", "protected"]
    if args.baseline_only:
        modes = ["baseline"]
    if args.protected_only:
        modes = ["protected"]

    if args.offline:
        OfflineTestHarness(use_llm=args.llm).run()
    else:
        harness = TestHarness(
            headless=not args.headed,
            use_llm=args.llm,
            modes=modes,
        )
        asyncio.run(harness.run())
