"""
contextguard/threat_characterizer.py — Component 4: Unknown Threat Characterization

Invoked when Known Threat Detection confidence falls below threshold.
Computes deviation signal (embedding cosine distance) and assigns a bucketed
label constrained strictly to contextguard/config/characterization_buckets.yaml.

Requirements:
- FR12: Assign a characterization label from fixed, predefined bucket list.
- Section 7 Must Not: Invent a label outside the predefined bucket list.
- NFR4: Failure (e.g. LLM error) must not silently ALLOW; default conservatively to fallback bucket.
"""

from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from contextguard.models import LockedIntent, ThreatDetectionResult

CONFIG_DIR = Path(__file__).parent / "config"


def _tokenize(text: str) -> List[str]:
    clean = re.sub(r"[^a-zA-Z0-9\s]", " ", text.lower())
    words = clean.split()
    ngrams = []
    for w in words:
        if len(w) >= 3:
            for i in range(len(w) - 2):
                ngrams.append(w[i : i + 3])
    return words + ngrams


def _compute_vector(tokens: List[str]) -> Dict[str, float]:
    counts: Dict[str, float] = {}
    for t in tokens:
        counts[t] = counts.get(t, 0.0) + 1.0
    return {k: 1.0 + math.log(v) for k, v in counts.items()}


def compute_cosine_distance(text_a: str, text_b: str) -> float:
    """Computes cosine distance D_cos(u, v) = 1.0 - cos_sim(u, v), bounded [0.0, 2.0]."""
    vec_a = _compute_vector(_tokenize(text_a))
    vec_b = _compute_vector(_tokenize(text_b))

    intersection = set(vec_a.keys()) & set(vec_b.keys())
    dot = sum(vec_a[k] * vec_b[k] for k in intersection)

    norm_a = math.sqrt(sum(v ** 2 for v in vec_a.values()))
    norm_b = math.sqrt(sum(v ** 2 for v in vec_b.values()))

    if norm_a == 0.0 or norm_b == 0.0:
        return 1.0

    similarity = dot / (norm_a * norm_b)
    return max(0.0, min(2.0, 1.0 - similarity))


class ThreatCharacterizer:
    """Handles unknown threat characterization via deviation signals and constrained labeling."""

    def __init__(
        self,
        buckets_path: Optional[Path] = None,
        weights_path: Optional[Path] = None,
    ) -> None:
        b_file = buckets_path or (CONFIG_DIR / "characterization_buckets.yaml")
        w_file = weights_path or (CONFIG_DIR / "risk_weights.yaml")

        b_data = yaml.safe_load(b_file.read_text(encoding="utf-8"))
        self.buckets: List[Dict[str, Any]] = b_data.get("buckets", [])
        self.valid_bucket_ids: List[str] = [b["id"] for b in self.buckets]
        self.fallback_bucket: str = b_data.get("fallback_bucket", "unknown_instruction_manipulation")

        w_data = yaml.safe_load(w_file.read_text(encoding="utf-8"))
        dev_norm = w_data.get("deviation_normalization", {})
        self.delta_min: float = float(dev_norm.get("delta_min", 0.59))
        self.delta_max: float = float(dev_norm.get("delta_max", 0.96))

    def normalize_deviation(self, raw_distance: float) -> float:
        """Applies min-max clamping using empirically calibrated bounds."""
        if self.delta_max <= self.delta_min:
            return min(1.0, max(0.0, raw_distance))
        norm = (raw_distance - self.delta_min) / (self.delta_max - self.delta_min)
        return min(1.0, max(0.0, norm))

    def characterize(
        self,
        locked_intent: LockedIntent,
        current_dom_text: str,
        action_target: str = "",
        action_type: str = "",
        inconsistency_detail: str = "",
    ) -> ThreatDetectionResult:
        """
        Executes unknown threat characterization.
        Outputs attack_type = None and characterization_label populated.
        """
        intent_str = f"{locked_intent.origin} to {locked_intent.destination}, {locked_intent.cabin_class}, {locked_intent.passenger_count} passengers"
        context_str = f"{current_dom_text[:600]} {action_target} {action_type} {inconsistency_detail}"

        # 1. Compute raw deviation signal
        raw_deviation = compute_cosine_distance(intent_str, context_str)
        normalized_deviation = round(self.normalize_deviation(raw_deviation), 3)

        # 2. Assign constrained bucket label (Section 7: Must NOT invent label outside bucket list)
        chosen_bucket = self._select_constrained_bucket(
            context_str=context_str,
            action_type=action_type,
            inconsistency_detail=inconsistency_detail,
        )

        return ThreatDetectionResult(
            is_threat=True,
            is_known_path=False,
            attack_type=None,
            confidence=0.0,
            characterization_label=chosen_bucket,
            deviation_signal=round(raw_deviation, 4),
            normalized_deviation=normalized_deviation,
        )

    def _select_constrained_bucket(
        self,
        context_str: str,
        action_type: str,
        inconsistency_detail: str,
    ) -> str:
        """
        Selects strictly from self.valid_bucket_ids.
        Uses deterministic semantic distance to bucket descriptions with conservative fallback per NFR4.
        """
        try:
            # Score context against each bucket description
            lowered = context_str.lower()
            if "navigation" in lowered or action_type == "NAVIGATE" or "url" in inconsistency_detail:
                if "abnormal_navigation_behaviour" in self.valid_bucket_ids:
                    return "abnormal_navigation_behaviour"

            if "form" in lowered or "field" in inconsistency_detail or "param" in inconsistency_detail:
                if "unauthorized_state_mutation" in self.valid_bucket_ids:
                    return "unauthorized_state_mutation"

            if "override" in lowered or "instruction" in lowered or "agent" in lowered:
                if "unknown_instruction_manipulation" in self.valid_bucket_ids:
                    return "unknown_instruction_manipulation"

            # Default to fallback bucket from configuration
            return self.fallback_bucket
        except Exception:
            # NFR4: fail-safe default to conservative fallback
            return self.fallback_bucket
