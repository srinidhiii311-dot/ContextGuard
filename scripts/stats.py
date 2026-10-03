"""
scripts/stats.py — Statistical Confidence Interval Helpers for Dissertation Evaluation

Provides exact two-sided Wilson score confidence interval calculations for binomial
proportions (recall, false positive rate, detection/enforcement rate).
"""

from __future__ import annotations

from math import sqrt
from typing import Tuple


def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """
    Compute two-sided Wilson score confidence interval for binomial proportion p = k / n.
    
    Parameters
    ----------
    k : int
        Number of successes / positive observations.
    n : int
        Total number of trials.
    z : float
        z-score corresponding to desired confidence level (default 1.96 for 95% CI).

    Returns
    -------
    Tuple[float, float]
        (lower_bound, upper_bound) clamped to [0.0, 1.0].
    """
    if n <= 0:
        return 0.0, 0.0
    p = k / n
    d = 1.0 + (z * z) / n
    c = p + (z * z) / (2.0 * n)
    m = z * sqrt((p * (1.0 - p)) / n + (z * z) / (4.0 * n * n))
    low = max(0.0, (c - m) / d)
    high = min(1.0, (c + m) / d)
    return low, high


def format_ci(k: int, n: int, z: float = 1.96, precision: int = 1) -> str:
    """
    Format proportion and its 95% Wilson confidence interval as a percentage string.
    Example: 25/25 -> "100.0% [86.7%, 100.0%]"
             0/30  -> "0.0% [0.0%, 11.4%]"
             0/100 -> "0.0% [0.0%, 3.7%]"
    """
    if n <= 0:
        return "N/A"
    p = (k / n) * 100.0
    low, high = wilson(k, n, z)
    return f"{p:.{precision}f}% [{low * 100.0:.{precision}f}%, {high * 100.0:.{precision}f}%]"


def format_rate_with_ci(k: int, n: int, z: float = 1.96, precision: int = 1) -> str:
    """Alias for format_ci."""
    return format_ci(k, n, z=z, precision=precision)
