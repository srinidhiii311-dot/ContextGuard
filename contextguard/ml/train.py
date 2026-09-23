"""
contextguard/ml/train.py — ML Risk Model Training Pipeline

Trains an interpretable RandomForestClassifier on transition-level features.
Enforces session-level train/validation/test split to prevent data leakage.
Evaluates accuracy, precision, recall, F1, FPR, FNR, and feature importances.
Saves model to contextguard/models/risk_model.joblib.
"""

from __future__ import annotations

import csv
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score

from contextguard.ml.dataset_generator import build_and_save_dataset
from contextguard.ml.feature_extractor import FEATURE_NAMES

MODEL_DIR = Path(__file__).parent.parent / "models"
MODEL_PATH = MODEL_DIR / "risk_model.joblib"


def load_dataset() -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """Loads features, labels, and session IDs."""
    dataset_dir = Path(__file__).parent.parent.parent / "dataset"
    feat_path = dataset_dir / "processed" / "transition_features.csv"
    label_path = dataset_dir / "labels" / "ground_truth.csv"

    if not feat_path.exists() or not label_path.exists():
        print("[Train] Generating dataset first...")
        build_and_save_dataset(150)

    # Read labels
    labels_dict: Dict[str, int] = {}
    with open(label_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            labels_dict[r["transition_id"]] = int(r["ground_truth_label"])

    X_list: List[List[float]] = []
    y_list: List[int] = []
    session_ids: List[str] = []

    with open(feat_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            tid = r["transition_id"]
            if tid in labels_dict:
                row = [float(r[col]) for col in FEATURE_NAMES]
                X_list.append(row)
                y_list.append(labels_dict[tid])
                session_ids.append(r["session_id"])

    return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.int32), session_ids


def train_model() -> Dict[str, Any]:
    """Runs end-to-end training and evaluation."""
    X, y, sessions = load_dataset()
    unique_sessions = list(dict.fromkeys(sessions))
    np.random.seed(42)
    np.random.shuffle(unique_sessions)

    n_sessions = len(unique_sessions)
    n_train = int(n_sessions * 0.70)
    n_val = int(n_sessions * 0.15)

    train_sess = set(unique_sessions[:n_train])
    val_sess = set(unique_sessions[n_train : n_train + n_val])
    test_sess = set(unique_sessions[n_train + n_val :])

    train_mask = np.array([s in train_sess for s in sessions])
    test_mask = np.array([s in test_sess for s in sessions])

    X_train, y_train = X[train_mask], y[train_mask]
    X_test, y_test = X[test_mask], y[test_mask]

    print(f"[Train] Training on {len(X_train)} samples ({len(train_sess)} sessions)")
    print(f"[Train] Testing on  {len(X_test)} samples ({len(test_sess)} sessions)")

    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=7,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
    )
    clf.fit(X_train, y_train)

    # Evaluate on unseen held-out test sessions
    y_pred = clf.predict(X_test)
    y_probs = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_probs) if len(np.unique(y_test)) > 1 else 1.0

    # False positive / negative rates
    neg_mask = (y_test == 0)
    pos_mask = (y_test == 1)
    fpr = float(np.mean(y_pred[neg_mask] == 1)) if np.any(neg_mask) else 0.0
    fnr = float(np.mean(y_pred[pos_mask] == 0)) if np.any(pos_mask) else 0.0

    # Feature importances
    importances = dict(zip(FEATURE_NAMES, [round(float(imp), 4) for imp in clf.feature_importances_]))
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    metrics = {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(auc), 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "feature_importances": sorted_importances,
    }

    # Save model artifact
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "metrics": metrics,
    }
    joblib.dump(bundle, MODEL_PATH)
    print(f"[Train] Model saved to {MODEL_PATH}")
    print(f"[Train] Test Metrics: Accuracy={acc:.3f}, Precision={prec:.3f}, Recall={rec:.3f}, F1={f1:.3f}, FPR={fpr:.3f}, FNR={fnr:.3f}")
    print("[Train] Top Features:")
    for k, v in list(sorted_importances.items())[:5]:
        print(f"   - {k}: {v}")

    return metrics


if __name__ == "__main__":
    train_model()
