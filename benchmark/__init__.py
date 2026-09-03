"""
ContextGuard benchmark package.

Usage
-----
# Full browser benchmark:
from benchmark.harness import BenchmarkHarness
import asyncio
summary = asyncio.run(BenchmarkHarness().run())

# Offline (no browser):
from benchmark.harness import OfflineHarness
summary = OfflineHarness().run()
"""

from benchmark.harness import BenchmarkHarness, OfflineHarness, ScenarioResult

__all__ = ["BenchmarkHarness", "OfflineHarness", "ScenarioResult"]
