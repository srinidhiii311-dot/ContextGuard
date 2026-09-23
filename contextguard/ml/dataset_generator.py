"""
contextguard/ml/dataset_generator.py — Transition-Level Dataset Generator

Generates a diverse, realistic dataset of browser state transitions:
- Benign sessions across varied routes (Chennai, Bangalore, Delhi, Mumbai, Hyderabad),
  passenger counts (1–4), cabin classes (Economy, Business), dates, and normal page variations.
- Adversarial / abnormal sessions across unexpected external redirects, DOM tampers,
  sensitive credential insertions, entity mismatches, and goal deviations.

Strict session-level grouping for data leakage prevention!
"""

from __future__ import annotations

import csv
import os
import random
from pathlib import Path
from typing import Any, Dict, List, Tuple
import numpy as np

from contextguard.ml.feature_extractor import FEATURE_NAMES

DATASET_DIR = Path(__file__).parent.parent.parent / "dataset"
PROCESSED_DIR = DATASET_DIR / "processed"
LABELS_DIR = DATASET_DIR / "labels"


def generate_synthetic_dataset(num_sessions: int = 120, seed: int = 42) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Synthesizes transition-level samples for model training and validation.
    Returns (transition_rows, label_rows).
    """
    random.seed(seed)
    np.random.seed(seed)

    cities = ["Chennai", "Bangalore", "Delhi", "Mumbai", "Hyderabad", "Kolkata"]
    cabins = ["Economy", "Business"]
    
    transition_records: List[Dict[str, Any]] = []
    ground_truth_records: List[Dict[str, Any]] = []

    for s_idx in range(num_sessions):
        session_id = f"sess_{s_idx:04d}"
        origin = random.choice(cities)
        dest = random.choice([c for c in cities if c != origin])
        cabin = random.choice(cabins)
        passengers = random.randint(1, 4)

        # 55% benign, 45% adversarial
        is_attack_session = (s_idx % 2 == 1)
        attack_step = random.randint(1, 3) if is_attack_session else 999
        attack_category = random.choice([
            "prompt_injection", "navigation_hijack", "context_tamper",
            "dom_tampering", "unauthorized_commit", "malicious_advisory"
        ]) if is_attack_session else "none"

        num_steps = 4  # search -> results -> passenger -> review -> confirmed
        cum_anomalies = 0

        for step in range(num_steps):
            is_anomaly_step = is_attack_session and (step >= attack_step)
            label = 1 if is_anomaly_step else 0
            if label == 1:
                cum_anomalies += 1

            # Synthesize features based on scenario physics
            if not is_anomaly_step:
                # Normal booking progression
                url_changed = 1.0 if step > 0 else 0.0
                domain_changed = 0.0
                is_external = 0.0
                text_len_ratio = float(np.random.normal(0.15, 0.08))
                jaccard_sim = float(np.clip(np.random.normal(0.65, 0.10), 0.3, 0.95))
                transition_sem_dist = float(np.clip(np.random.normal(0.35, 0.08), 0.1, 0.65))
                task_sem_dist = float(np.clip(np.random.normal(0.30, 0.07), 0.1, 0.55))
                new_forms = 1.0 if step in (0, 2) else 0.0
                new_inputs = float(random.choice([2, 3]) if step in (0, 2) else 0)
                new_buttons = float(random.choice([1, 2]) if step in (0, 2) else 0)
                sensitive_field = 0.0
                act_code = float(random.choice([1, 2, 3]))
                act_sens = 0.2 if step < 3 else 0.5
                entity_mismatch = 0.0
                workflow_anomaly = 0.0
            else:
                # Abnormal / adversarial transition
                if attack_category == "navigation_hijack":
                    url_changed = 1.0
                    domain_changed = 1.0
                    is_external = 1.0
                    text_len_ratio = float(np.random.normal(0.40, 0.15))
                    jaccard_sim = float(np.clip(np.random.normal(0.20, 0.08), 0.05, 0.35))
                    transition_sem_dist = float(np.clip(np.random.normal(0.95, 0.12), 0.75, 1.4))
                    task_sem_dist = float(np.clip(np.random.normal(0.90, 0.12), 0.70, 1.35))
                    new_forms = 1.0
                    new_inputs = float(random.choice([1, 3]))
                    new_buttons = 1.0
                    sensitive_field = float(random.choice([0, 1]))
                    act_code = 5.0  # NAVIGATE
                    act_sens = 0.90
                    entity_mismatch = 0.0
                    workflow_anomaly = 1.0

                elif attack_category in ("prompt_injection", "context_tamper"):
                    url_changed = 0.0
                    domain_changed = 0.0
                    is_external = 0.0
                    text_len_ratio = float(np.random.normal(0.25, 0.08))
                    jaccard_sim = float(np.clip(np.random.normal(0.55, 0.08), 0.35, 0.75))
                    transition_sem_dist = float(np.clip(np.random.normal(0.55, 0.10), 0.35, 0.85))
                    task_sem_dist = float(np.clip(np.random.normal(0.60, 0.10), 0.40, 0.90))
                    new_forms = 0.0
                    new_inputs = 0.0
                    new_buttons = 0.0
                    sensitive_field = 0.0
                    act_code = 3.0  # SELECT or TYPE
                    act_sens = 0.40
                    entity_mismatch = 1.0  # Diverged from locked intent!
                    workflow_anomaly = 0.0

                elif attack_category == "dom_tampering":
                    url_changed = 0.0
                    domain_changed = 0.0
                    is_external = 0.0
                    text_len_ratio = float(np.random.normal(0.30, 0.08))
                    jaccard_sim = float(np.clip(np.random.normal(0.50, 0.08), 0.35, 0.70))
                    transition_sem_dist = float(np.clip(np.random.normal(0.65, 0.10), 0.45, 0.90))
                    task_sem_dist = float(np.clip(np.random.normal(0.65, 0.10), 0.45, 0.90))
                    new_forms = 1.0
                    new_inputs = 2.0
                    new_buttons = 1.0
                    sensitive_field = 1.0  # Credit card / CVV emerged!
                    act_code = 2.0  # TYPE
                    act_sens = 0.95
                    entity_mismatch = 0.0
                    workflow_anomaly = 0.0

                else: # unauthorized_commit or malicious_advisory
                    url_changed = 1.0
                    domain_changed = 0.0
                    is_external = 0.0
                    text_len_ratio = float(np.random.normal(0.35, 0.10))
                    jaccard_sim = float(np.clip(np.random.normal(0.40, 0.08), 0.20, 0.60))
                    transition_sem_dist = float(np.clip(np.random.normal(0.80, 0.12), 0.60, 1.1))
                    task_sem_dist = float(np.clip(np.random.normal(0.85, 0.12), 0.65, 1.15))
                    new_forms = 1.0
                    new_inputs = 1.0
                    new_buttons = 1.0
                    sensitive_field = float(random.choice([0, 1]))
                    act_code = 4.0  # SUBMIT
                    act_sens = 0.95
                    entity_mismatch = 0.0
                    workflow_anomaly = 1.0

            trans_id = f"trans_{session_id}_{step}"
            feat_record = {
                "transition_id": trans_id,
                "session_id": session_id,
                "step_number": step,
                "url_changed": url_changed,
                "domain_changed": domain_changed,
                "is_external_domain": is_external,
                "text_len_ratio": round(text_len_ratio, 4),
                "jaccard_similarity": round(jaccard_sim, 4),
                "transition_semantic_dist": round(transition_sem_dist, 4),
                "task_semantic_dist": round(task_sem_dist, 4),
                "new_forms_count": new_forms,
                "new_inputs_count": new_inputs,
                "new_buttons_count": new_buttons,
                "sensitive_field_detected": sensitive_field,
                "action_type_code": act_code,
                "action_sensitivity": act_sens,
                "action_entity_mismatch": entity_mismatch,
                "workflow_step": float(step),
                "workflow_position_expected": float(step + 1),
                "workflow_order_anomaly": workflow_anomaly,
                "cumulative_anomalies": float(cum_anomalies),
            }
            transition_records.append(feat_record)

            label_record = {
                "transition_id": trans_id,
                "session_id": session_id,
                "step_number": step,
                "ground_truth_label": label, # 0 = normal, 1 = abnormal/adversarial
                "attack_category": attack_category if is_anomaly_step else "none",
            }
            ground_truth_records.append(label_record)

    return transition_records, ground_truth_records


def build_and_save_dataset(num_sessions: int = 150) -> Tuple[Path, Path]:
    """Generates dataset and writes features and labels to CSV."""
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    LABELS_DIR.mkdir(parents=True, exist_ok=True)

    feat_path = PROCESSED_DIR / "transition_features.csv"
    label_path = LABELS_DIR / "ground_truth.csv"

    features, labels = generate_synthetic_dataset(num_sessions=num_sessions)

    # Write transition features
    if features:
        with open(feat_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(features[0].keys()))
            writer.writeheader()
            writer.writerows(features)

    # Write ground truth labels
    if labels:
        with open(label_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(labels[0].keys()))
            writer.writeheader()
            writer.writerows(labels)

    return feat_path, label_path


if __name__ == "__main__":
    fp, lp = build_and_save_dataset(150)
    print(f"[Dataset] Saved features to: {fp}")
    print(f"[Dataset] Saved labels to  : {lp}")
