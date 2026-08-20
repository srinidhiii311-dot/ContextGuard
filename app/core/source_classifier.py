"""
Source Classifier — ContextGuard Core

Classifies where an action instruction came from and assigns a trust value.

Untrusted page content is flagged because a malicious web page can embed
prompt-injection strings designed to hijack the agent's behaviour. Keyword
detection is used as evidence, not as the sole decision criterion; the
resulting indicators are passed to the risk analyser for scoring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from app.models.action import ActionSource, SourceType


# ---------------------------------------------------------------------------
# Trust table
# ---------------------------------------------------------------------------

_TRUST_VALUES: dict[str, float] = {
    SourceType.system: 1.00,
    SourceType.user: 0.90,
    SourceType.trusted_content: 0.80,
    SourceType.tool_output: 0.30,
    SourceType.page_content: 0.25,
    SourceType.unknown: 0.10,
}

_TRUSTED_SOURCE_TYPES = {
    SourceType.system,
    SourceType.user,
    SourceType.trusted_content,
}

# ---------------------------------------------------------------------------
# Prompt-injection indicators
# Phrases that strongly suggest an attempt to override agent instructions.
# Detection here is evidence for the risk analyser, not a standalone block.
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(all\s+)?(previous|prior|earlier|above)\s+instructions?",
        r"bypass\s+security",
        r"disable\s+safeguards?",
        r"reveal\s+confidential\s+information",
        r"reveal\s+(the\s+)?system\s+prompt",
        r"upload\s+local\s+files?",
        r"send\s+data\s+externally",
        r"transmit\s+private\s+information",
        r"submit\s+credentials?",
        r"do\s+not\s+tell\s+the\s+user",
        r"continue\s+without\s+approval",
        r"override\s+the\s+security\s+policy",
        r"override\s+safeguards?",
        r"act\s+as\s+(if\s+)?you\s+(have\s+no\s+restrictions|are\s+unrestricted)",
        r"you\s+are\s+now\s+(in\s+)?developer\s+mode",
        r"jailbreak",
        r"disregard\s+(your\s+)?(previous\s+)?(instructions?|guidelines?|rules?)",
        r"forget\s+(your\s+)?(previous\s+)?(instructions?|guidelines?|rules?)",
        r"new\s+instructions?\s*:",
        r"system\s*:\s*(ignore|forget|disregard)",
    ]
]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    """Output of the source classifier."""
    source_type: str
    trust_value: float          # 0.0 – 1.0
    trusted: bool
    explanation: str
    injection_indicators: List[str] = field(default_factory=list)
    injection_detected: bool = False


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class SourceClassifier:
    """
    Classifies an ActionSource and detects prompt-injection indicators.

    The classifier does not make the final allow/block decision; it returns
    structured evidence consumed by the risk analyser and decision engine.
    """

    def classify(self, source: ActionSource) -> ClassificationResult:
        """
        Classify a single ActionSource.

        Returns a ClassificationResult with trust value, trusted flag,
        an explanation string, and any detected injection indicators.
        """
        source_type = source.source_type
        trust_value = _TRUST_VALUES.get(source_type, 0.10)
        trusted = source_type in _TRUSTED_SOURCE_TYPES

        injection_indicators: List[str] = []

        # Only scan content from potentially untrusted sources
        if source.content:
            injection_indicators = self._detect_injection(source.content)

        injection_detected = len(injection_indicators) > 0

        # Build explanation
        if trusted:
            explanation = (
                f"Source type '{source_type}' is trusted "
                f"(trust={trust_value:.2f}). "
                "Instructions from this source are accepted."
            )
        else:
            explanation = (
                f"Source type '{source_type}' is untrusted "
                f"(trust={trust_value:.2f}). "
                "Actions from this source are subject to taint tracking and "
                "elevated risk scoring."
            )

        if injection_detected:
            explanation += (
                f" Prompt-injection indicators detected: "
                f"{injection_indicators}. "
                "This action will be scored with a prompt-injection penalty."
            )

        return ClassificationResult(
            source_type=str(source_type),
            trust_value=trust_value,
            trusted=trusted,
            explanation=explanation,
            injection_indicators=injection_indicators,
            injection_detected=injection_detected,
        )

    def _detect_injection(self, content: str) -> List[str]:
        """
        Scan content for prompt-injection pattern matches.

        Returns a list of matched phrases as evidence strings.
        Keyword detection alone does not block; it raises the risk score.
        """
        matches: List[str] = []
        for pattern in _INJECTION_PATTERNS:
            m = pattern.search(content)
            if m:
                matches.append(m.group(0))
        return matches

    def is_trusted(self, source_type: str) -> bool:
        """Quick helper: is the given source type trusted?"""
        return source_type in _TRUSTED_SOURCE_TYPES

    def get_trust_value(self, source_type: str) -> float:
        """Return the numeric trust value for a source type."""
        return _TRUST_VALUES.get(source_type, 0.10)


# Module-level singleton for convenience
classifier = SourceClassifier()
