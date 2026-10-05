"""Common signal type so every new monitor plugs into risk_engine the same way."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List


@dataclass
class Signal:
    name: str
    score: int                 # 0-100 contribution proposed by this monitor
    severity: str = "none"     # none | low | medium | high
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "score": self.score,
                "severity": self.severity, "evidence": list(self.evidence)}


def combine(base_score: int, signals: Iterable[Signal],
            extra_signal_bonus: int = 10, min_extra: int = 20) -> int:
    """Raise-only fusion: max(base, strongest signal) + a small bonus for every
    additional signal that is itself >= min_extra. Never returns below base_score.
    The constants are tunable and MUST be justified by the ablation table."""
    sigs = sorted((s for s in signals if s.score > 0), key=lambda s: -s.score)
    if not sigs:
        return base_score
    top = max(base_score, sigs[0].score)
    extras = sum(1 for s in sigs[1:] if s.score >= min_extra)
    return min(100, top + extra_signal_bonus * extras)
