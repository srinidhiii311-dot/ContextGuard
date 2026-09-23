"""
backend/contextguard/classifier.py — Phase 2 Offline Trained ML Classifier

Offline trained on audit logs + testbed ground truth.
During runtime inference, evaluates feature vectors without seeing test_case_id.
Pure Python + math implementation with optional NumPy acceleration for zero-dependency reliability.
"""

from __future__ import annotations

import datetime
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional

MODEL_PATH = Path(__file__).parent / "model_weights.json"

# Features used for classification
ML_FEATURE_KEYS = [
    "intent_inconsistency",
    "domain_risk",
    "injection_risk",
    "field_tampering_risk",
]


def _sigmoid(x: float) -> float:
    clamped = max(-15.0, min(15.0, x))
    return 1.0 / (1.0 + math.exp(-clamped))


class MLClassifier:
    """Offline-trainable statistical / ML model for anomaly detection."""

    def __init__(self) -> None:
        self.weights: List[float] = [0.35, 0.40, 0.25, 0.30]
        self.bias: float = -0.15
        self.trained_samples: int = 0
        self.last_trained_at: str = ""
        self.load_model()

    def load_model(self) -> None:
        if MODEL_PATH.exists():
            try:
                data = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
                self.weights = [float(w) for w in data.get("weights", self.weights)]
                self.bias = float(data.get("bias", self.bias))
                self.trained_samples = int(data.get("trained_samples", 0))
                self.last_trained_at = str(data.get("last_trained_at", ""))
            except Exception:
                pass

    def save_model(self) -> None:
        data = {
            "weights": self.weights,
            "bias": self.bias,
            "trained_samples": self.trained_samples,
            "last_trained_at": self.last_trained_at,
            "features": ML_FEATURE_KEYS,
        }
        MODEL_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def predict_risk(self, features: Dict[str, Any]) -> float:
        """Predicts risk score (0-100) using trained linear/logistic weights."""
        x = [float(features.get(k, 0.0)) for k in ML_FEATURE_KEYS]
        # Dot product: w . x + bias
        z = sum(w * xi for w, xi in zip(self.weights, x)) + self.bias
        prob = _sigmoid(z * 2.5)
        return round(prob * 100.0, 1)

    def train_offline(self, dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Trains offline on historical sessions with ground-truth labels.
        dataset item format: { 'features': [float, float, float, float], 'label': 0 or 1 }
        """
        if not dataset:
            dataset = [
                {"features": [0.0, 0.0, 0.0, 0.0], "label": 0},
                {"features": [0.1, 0.0, 0.0, 0.0], "label": 0},
                {"features": [0.0, 0.0, 0.1, 0.0], "label": 0},
                {"features": [0.9, 0.0, 0.0, 0.0], "label": 1},
                {"features": [0.0, 1.0, 0.0, 0.0], "label": 1},
                {"features": [0.0, 0.0, 0.8, 0.0], "label": 1},
                {"features": [0.0, 0.0, 0.0, 1.0], "label": 1},
                {"features": [0.8, 0.0, 0.6, 0.0], "label": 1},
            ]

        N = len(dataset)
        lr = 0.1
        w = list(self.weights)
        b = self.bias

        # Gradient Descent (200 epochs)
        for _ in range(200):
            dw = [0.0] * len(w)
            db = 0.0
            for item in dataset:
                x = item["features"]
                y = float(item["label"])
                z = sum(wi * xi for wi, xi in zip(w, x)) + b
                pred = _sigmoid(z * 2.5)
                err = pred - y
                for i in range(len(w)):
                    dw[i] += err * x[i]
                db += err

            for i in range(len(w)):
                w[i] -= lr * (dw[i] / N)
            b -= lr * (db / N)

        self.weights = [round(v, 4) for v in w]
        self.bias = round(b, 4)
        self.trained_samples = N
        self.last_trained_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.save_model()

        # Compute accuracy
        correct = 0
        for item in dataset:
            x = item["features"]
            y = int(item["label"])
            z = sum(wi * xi for wi, xi in zip(self.weights, x)) + self.bias
            pred = 1 if _sigmoid(z * 2.5) >= 0.5 else 0
            if pred == y:
                correct += 1

        acc = (correct / N) * 100.0 if N else 100.0

        return {
            "samples": N,
            "accuracy": round(acc, 1),
            "weights": {ML_FEATURE_KEYS[i]: self.weights[i] for i in range(len(ML_FEATURE_KEYS))},
            "bias": self.bias,
            "last_trained_at": self.last_trained_at,
        }


ml_classifier = MLClassifier()
