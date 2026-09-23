"""
contextguard/ml/feature_extractor.py — Feature Extraction for ML Risk Model

Extracts an 18-dimensional feature vector from:
- State Difference (S_{t-1} -> S_t)
- Intended Agent Action
- Trusted Task Context
- Workflow Progression

NO attack labels or scenario keys are used as features!
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import numpy as np

from contextguard.state_difference import StateDifference
from contextguard.task_context import TrustedTaskContext


FEATURE_NAMES = [
    "url_changed",
    "domain_changed",
    "is_external_domain",
    "text_len_ratio",
    "jaccard_similarity",
    "transition_semantic_dist",
    "task_semantic_dist",
    "new_forms_count",
    "new_inputs_count",
    "new_buttons_count",
    "sensitive_field_detected",
    "action_type_code",
    "action_sensitivity",
    "action_entity_mismatch",
    "workflow_step",
    "workflow_position_expected",
    "workflow_order_anomaly",
    "cumulative_anomalies",
]

_ACTION_MAP = {
    "NONE": 0,
    "WAIT": 0,
    "CLICK": 1,
    "TYPE": 2,
    "SELECT": 3,
    "SUBMIT": 4,
    "NAVIGATE": 5,
}

_WORKFLOW_PAGES = {
    "search": 1,
    "results": 2,
    "passenger": 3,
    "review": 4,
    "confirmed": 5,
}


class FeatureExtractor:
    """Transforms raw browser transition & action data into numerical model features."""

    def extract_features(
        self,
        diff: StateDifference,
        action: Optional[Dict[str, Any]],
        task_context: TrustedTaskContext,
        current_page_name: str = "search",
        cumulative_anomalies: int = 0,
    ) -> Dict[str, float]:
        """
        Computes the feature dictionary from observable evidence.
        """
        act_type = str(action.get("type", "NONE")).upper() if action else "NONE"
        act_code = float(_ACTION_MAP.get(act_type, 1))

        act_target = str(action.get("selector", action.get("target", ""))).lower() if action else ""
        act_val = action.get("value", "") if action else ""

        # Action sensitivity
        act_sens = 0.1
        if any(term in act_target for term in ("pay", "checkout", "cvv", "ssn", "password", "commit")) or ("card" in act_target and "flight" not in act_target):
            act_sens = 0.95
        elif act_type == "NAVIGATE" or "http" in act_target or "href" in act_target:
            act_sens = 0.85
        elif act_type in ("SUBMIT", "CLICK") and ("confirm" in act_target or "book" in act_target):
            act_sens = 0.80
        elif act_type in ("SELECT", "TYPE"):
            act_sens = 0.35

        # Entity mismatch
        mismatch_flag = 0.0
        if act_val:
            if "cabin" in act_target or "class" in act_target:
                if task_context.check_entity_mismatch("cabin_class", act_val):
                    mismatch_flag = 1.0
            elif "passenger" in act_target or "count" in act_target or "pcount" in act_target:
                if task_context.check_entity_mismatch("passengers", act_val):
                    mismatch_flag = 1.0
            elif "origin" in act_target or "from" in act_target:
                if task_context.check_entity_mismatch("origin", act_val):
                    mismatch_flag = 1.0
            elif "dest" in act_target or "to" in act_target:
                if task_context.check_entity_mismatch("destination", act_val):
                    mismatch_flag = 1.0

        # Workflow position
        curr_page_num = float(_WORKFLOW_PAGES.get(current_page_name.lower(), 1))
        expected_page_num = float(min(5, diff.step_number + 1))
        # Anomaly if premature high-sensitivity commit when not on review page (4), or external domain
        is_premature_commit = (act_sens >= 0.75 and curr_page_num < 4)
        workflow_anomaly = 1.0 if (is_premature_commit or diff.is_external_domain) else 0.0

        feat_dict: Dict[str, float] = {
            "url_changed": float(diff.url_changed),
            "domain_changed": float(diff.domain_changed),
            "is_external_domain": float(diff.is_external_domain),
            "text_len_ratio": float(max(-2.0, min(2.0, diff.text_len_ratio))),
            "jaccard_similarity": float(max(0.0, min(1.0, diff.jaccard_similarity))),
            "transition_semantic_dist": float(max(0.0, min(2.0, diff.transition_semantic_dist))),
            "task_semantic_dist": float(max(0.0, min(2.0, diff.task_semantic_dist))),
            "new_forms_count": float(diff.new_forms_count),
            "new_inputs_count": float(diff.new_inputs_count),
            "new_buttons_count": float(diff.new_buttons_count),
            "sensitive_field_detected": float(diff.sensitive_field_detected),
            "action_type_code": act_code,
            "action_sensitivity": act_sens,
            "action_entity_mismatch": mismatch_flag,
            "workflow_step": float(diff.step_number),
            "workflow_position_expected": expected_page_num,
            "workflow_order_anomaly": workflow_anomaly,
            "cumulative_anomalies": float(cumulative_anomalies),
        }
        return feat_dict

    def to_array(self, feat_dict: Dict[str, float]) -> np.ndarray:
        return np.array([feat_dict[name] for name in FEATURE_NAMES], dtype=np.float32)


feature_extractor = FeatureExtractor()
