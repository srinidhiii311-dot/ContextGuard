"""
contextguard/state_difference.py — State Difference & Transition Analysis Engine

Analyzes the transition from Previous State (S_{t-1}) -> Current State (S_t).
Measures DOM structural deltas, URL/domain changes, token overlaps,
semantic cosine distances, and sensitive field emergence.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from backend.database.db import ContextGuardRuntimeDAO
from contextguard.state_collector import BrowserState
from contextguard.task_context import TrustedTaskContext


def _tokenize(text: str) -> List[str]:
    clean = re.sub(r"[^a-zA-Z0-9\s]", " ", text.lower())
    words = clean.split()
    ngrams: List[str] = []
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


def compute_semantic_distance(text_a: str, text_b: str) -> float:
    """Computes cosine distance bounded in [0.0, 2.0]."""
    if not text_a or not text_b:
        return 1.0
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


def compute_jaccard_similarity(text_a: str, text_b: str) -> float:
    set_a = set(re.sub(r"[^a-zA-Z0-9\s]", " ", text_a.lower()).split())
    set_b = set(re.sub(r"[^a-zA-Z0-9\s]", " ", text_b.lower()).split())
    if not set_a and not set_b:
        return 1.0
    union = set_a | set_b
    if not union:
        return 1.0
    return len(set_a & set_b) / len(union)


@dataclass
class StateDifference:
    transition_id:          str
    session_id:             str
    step_number:            int
    url_changed:            bool
    domain_changed:         bool
    is_external_domain:     bool
    text_len_ratio:         float
    jaccard_similarity:     float
    transition_semantic_dist: float
    task_semantic_dist:     float
    new_forms_count:        int
    new_inputs_count:       int
    new_buttons_count:      int
    sensitive_field_detected: bool
    summary_diff:           Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transition_id":          self.transition_id,
            "session_id":             self.session_id,
            "step_number":            self.step_number,
            "url_changed":            self.url_changed,
            "domain_changed":         self.domain_changed,
            "is_external_domain":     self.is_external_domain,
            "text_len_ratio":         round(self.text_len_ratio, 3),
            "jaccard_similarity":     round(self.jaccard_similarity, 3),
            "transition_semantic_dist": round(self.transition_semantic_dist, 3),
            "task_semantic_dist":     round(self.task_semantic_dist, 3),
            "new_forms_count":        self.new_forms_count,
            "new_inputs_count":       self.new_inputs_count,
            "new_buttons_count":      self.new_buttons_count,
            "sensitive_field_detected": self.sensitive_field_detected,
            "summary_diff":           self.summary_diff,
        }


class StateDifferenceEngine:
    """Computes objective differences between previous and current browser states."""

    def __init__(self, base_domain: str = "127.0.0.1:8000") -> None:
        self.base_domain = base_domain

    def analyze_transition(
        self,
        session_id: str,
        step_number: int,
        prev_state: Optional[BrowserState],
        curr_state: BrowserState,
        task_context: TrustedTaskContext,
        agent_action_id: Optional[str] = None,
    ) -> StateDifference:
        """
        Extracts structural, lexical, and semantic differences between states.
        """
        # 1. URL & Domain changes
        url_changed = False
        domain_changed = False
        is_external = False

        curr_netloc = urlparse(curr_state.url).netloc or "localhost"
        if self.base_domain not in curr_netloc and "localhost" not in curr_netloc:
            is_external = True

        if prev_state:
            prev_netloc = urlparse(prev_state.url).netloc or "localhost"
            url_changed = prev_state.url != curr_state.url
            domain_changed = prev_netloc != curr_netloc

        # 2. Text differences
        prev_text = prev_state.visible_text if prev_state else ""
        curr_text = curr_state.visible_text

        prev_len = max(1, len(prev_text))
        curr_len = len(curr_text)
        text_len_ratio = (curr_len - prev_len) / prev_len if prev_state else 0.0

        jaccard_sim = compute_jaccard_similarity(prev_text, curr_text) if prev_state else 1.0
        transition_sem_dist = compute_semantic_distance(prev_text, curr_text) if prev_state else 0.0

        # Semantic distance from task intent
        task_text = f"Flight booking from {task_context.origin} to {task_context.destination} cabin {task_context.cabin_class} passengers {task_context.passengers} {task_context.raw_instruction}"
        task_sem_dist = compute_semantic_distance(task_text, curr_text)

        # 3. DOM element deltas
        prev_inputs: List[Dict[str, Any]] = prev_state.inputs if prev_state else []
        curr_inputs: List[Dict[str, Any]] = curr_state.inputs

        prev_forms: List[Dict[str, Any]] = prev_state.forms if prev_state else []
        curr_forms: List[Dict[str, Any]] = curr_state.forms

        prev_buttons: List[str] = prev_state.buttons if prev_state else []
        curr_buttons: List[str] = curr_state.buttons

        new_inputs_count = max(0, len(curr_inputs) - len(prev_inputs))
        new_forms_count = max(0, len(curr_forms) - len(prev_forms))
        new_buttons_count = max(0, len(curr_buttons) - len(prev_buttons))

        # 4. Sensitive field detection
        sensitive_field_detected = False
        for inp in curr_inputs:
            name_low = str(inp.get("name", "")).lower()
            id_low = str(inp.get("id", "")).lower()
            type_low = str(inp.get("type", "")).lower()
            placeholder = str(inp.get("placeholder", "")).lower()

            comb = f"{name_low} {id_low} {type_low} {placeholder}"
            if any(s in comb for s in ("card", "cvv", "credit", "ssn", "password", "bank", "routing")):
                sensitive_field_detected = True
                break

        summary_diff = {
            "url_changed": url_changed,
            "domain_changed": domain_changed,
            "is_external_domain": is_external,
            "text_len_ratio": round(text_len_ratio, 3),
            "jaccard_similarity": round(jaccard_sim, 3),
            "transition_semantic_dist": round(transition_sem_dist, 3),
            "task_semantic_dist": round(task_sem_dist, 3),
            "new_inputs": new_inputs_count,
            "new_forms": new_forms_count,
            "sensitive_fields": sensitive_field_detected,
        }

        # Persist to database
        trans_id = ContextGuardRuntimeDAO.record_state_transition(
            session_id=session_id,
            step_number=step_number,
            prev_state_id=prev_state.state_id if prev_state else None,
            curr_state_id=curr_state.state_id,
            url_changed=url_changed,
            domain_changed=domain_changed,
            dom_diff=summary_diff,
            semantic_distance=transition_sem_dist,
            agent_action_id=agent_action_id,
        )

        return StateDifference(
            transition_id=trans_id,
            session_id=session_id,
            step_number=step_number,
            url_changed=url_changed,
            domain_changed=domain_changed,
            is_external_domain=is_external,
            text_len_ratio=text_len_ratio,
            jaccard_similarity=jaccard_sim,
            transition_semantic_dist=transition_sem_dist,
            task_semantic_dist=task_sem_dist,
            new_forms_count=new_forms_count,
            new_inputs_count=new_inputs_count,
            new_buttons_count=new_buttons_count,
            sensitive_field_detected=sensitive_field_detected,
            summary_diff=summary_diff,
        )
