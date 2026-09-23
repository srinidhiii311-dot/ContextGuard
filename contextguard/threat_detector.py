"""
contextguard/threat_detector.py — Component 3: Known Threat Detection

Classifies inconsistencies and page context against the known attack taxonomy
defined in contextguard/config/attack_taxonomy.yaml.

Requirements:
- FR11: Classify detected inconsistencies against defined taxonomy with confidence.
- FR13: Configurable confidence threshold (recorded with run).
- Section 7: Must NOT assign a known attack type below the confidence threshold.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from contextguard.models import ConsistencyReport, InconsistencyItem, ThreatDetectionResult

CONFIG_DIR = Path(__file__).parent / "config"


class ThreatDetector:
    """Classifies inconsistencies against the known attack taxonomy."""

    def __init__(self, config_path: Optional[Path] = None) -> None:
        cfg_file = config_path or (CONFIG_DIR / "attack_taxonomy.yaml")
        if not cfg_file.exists():
            raise FileNotFoundError(f"Missing attack taxonomy config: {cfg_file}")
        
        data = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
        self.confidence_threshold: float = float(data.get("classification_confidence_threshold", 0.70))
        self.known_attacks: Dict[str, Dict[str, Any]] = data.get("known_attacks", {})

    def detect(
        self,
        consistency_report: ConsistencyReport,
        dom_text: str,
        justification_text: Optional[str] = None,
        action_target: str = "",
        action_type: str = "",
    ) -> ThreatDetectionResult:
        """
        Runs known attack classification.
        Always called when consistency_report.is_consistent == False.
        """
        if consistency_report.is_consistent and not consistency_report.marker_presence:
            return ThreatDetectionResult(
                is_threat=False,
                is_known_path=True,
                attack_type=None,
                confidence=0.0,
            )

        combined_text = f"{dom_text} {justification_text or ''} {action_target}".lower()

        best_attack_type: Optional[str] = None
        best_confidence: float = 0.0

        # Check against each attack class in attack_taxonomy.yaml
        for attack_name, attack_data in self.known_attacks.items():
            pattern_hints = attack_data.get("pattern_hints", [])
            base_severity = float(attack_data.get("severity_weight", 0.75))

            matched_hints = [p for p in pattern_hints if p.lower() in combined_text]
            if not matched_hints:
                continue

            # Confidence heuristics:
            # - Frequency of matching patterns
            # - Presence of explicit marker found during verification
            # - Action type / target alignment
            match_ratio = min(1.0, len(matched_hints) / 2.0) # 2+ hints = full match ratio
            
            confidence = 0.60 + (0.30 * match_ratio)
            
            # Boost if marker_hit from consistency checker directly matches
            if consistency_report.marker_hit and any(consistency_report.marker_hit.lower() in h.lower() for h in pattern_hints):
                confidence = max(confidence, 0.90)

            # Specific attack alignment bonuses
            if attack_name == "NAVIGATION_MANIPULATION" and (action_type == "NAVIGATE" or "http" in action_target):
                confidence = min(1.0, confidence + 0.10)
            elif attack_name == "DOM_MANIPULATION" and any(item.check_type == "FIELD_MISMATCH" for item in consistency_report.inconsistencies):
                confidence = min(1.0, confidence + 0.05)

            if confidence > best_confidence:
                best_confidence = confidence
                best_attack_type = attack_name

        # If inconsistencies exist (e.g. parameter mismatch) but no specific pattern hint matched:
        if best_confidence == 0.0 and not consistency_report.is_consistent:
            # Check if it is a pure navigation violation
            if any(item.check_type == "NAVIGATION_BOUNDARY" for item in consistency_report.inconsistencies):
                best_attack_type = "NAVIGATION_MANIPULATION"
                best_confidence = 0.75
            elif any(item.check_type == "FIELD_MISMATCH" for item in consistency_report.inconsistencies):
                # Parameter mismatch without known text hints (low confidence known or candidate for unknown)
                best_attack_type = "CONTEXT_MANIPULATION"
                best_confidence = 0.50  # Below 0.70 threshold -> will trigger Unknown path
            elif any(item.check_type == "PROCESS_INTEGRITY" for item in consistency_report.inconsistencies):
                # Plan/process integrity violation without taxonomy keywords -> Component 4 unknown path
                best_attack_type = None
                best_confidence = 0.40  # Below 0.70 threshold -> triggers Component 4

        # FR12 & Section 7 Must Not: Do NOT assign a known attack type below confidence threshold
        if best_confidence < self.confidence_threshold:
            return ThreatDetectionResult(
                is_threat=True,
                is_known_path=True,
                attack_type=None,       # Suppressed per FR12
                confidence=best_confidence,
            )

        return ThreatDetectionResult(
            is_threat=True,
            is_known_path=True,
            attack_type=best_attack_type,
            confidence=round(best_confidence, 3),
        )
