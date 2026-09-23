"""
contextguard/ml/risk_model.py — Runtime ML Risk Model & Predictor

Consumes extracted transition features and outputs:
- Continuous Risk Score: 0 to 100
- Model Confidence: 0.0 to 1.0 (calibrated prediction certainty)
- Top Contributing Features for audit explainability

Uses the trained RandomForest model from contextguard/models/risk_model.joblib.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from contextguard.ml.feature_extractor import FEATURE_NAMES, feature_extractor

MODEL_PATH = Path(__file__).parent.parent / "models" / "risk_model.joblib"


class MLRiskModel:
    """Runtime risk prediction engine."""

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = model_path or MODEL_PATH
        self.model: Optional[Any] = None
        self.feature_names: List[str] = FEATURE_NAMES
        self.metrics: Dict[str, Any] = {}
        self._load_model()

    def _load_model(self) -> None:
        if self.model_path.exists():
            try:
                import joblib
                bundle = joblib.load(self.model_path)
                self.model = bundle["model"]
                self.feature_names = bundle.get("feature_names", FEATURE_NAMES)
                self.metrics = bundle.get("metrics", {})
            except Exception as e:
                print(f"[MLRiskModel] Warning loading model ({e}), using analytical estimator.")
                self.model = None

    def predict(
        self,
        features: Dict[str, float],
    ) -> Tuple[int, float, Dict[str, float]]:
        """
        Calculates risk score (0-100), confidence (0-1), and feature contributions.
        Returns: (risk_score, confidence, top_contributions)
        """
        x_vec = np.array([[features.get(f, 0.0) for f in self.feature_names]], dtype=np.float32)

        if self.model is not None:
            try:
                # Predict class probabilities
                probs = self.model.predict_proba(x_vec)[0]
                # Class 1 probability (abnormal/adversarial)
                p_anomaly = float(probs[1]) if len(probs) > 1 else float(probs[0])

                risk_score = int(round(p_anomaly * 100))
                # Confidence: distance from decision threshold 0.5 scaled to [0.5, 1.0]
                confidence = float(round(0.5 + abs(p_anomaly - 0.5), 3))

                # Identify top contributing features based on feature values * importances
                contributions: Dict[str, float] = {}
                importances = getattr(self.model, "feature_importances_", None)
                if importances is not None:
                    for i, name in enumerate(self.feature_names):
                        val = float(x_vec[0][i])
                        imp = float(importances[i])
                        if val > 0:
                            contributions[name] = round(val * imp * 100, 2)

                top_contrib = dict(sorted(contributions.items(), key=lambda x: x[1], reverse=True)[:4])

                return risk_score, confidence, top_contrib

            except Exception:
                pass

        # Robust analytical fallback if model not loaded
        p_est = 0.05
        contribs = {}
        if features.get("is_external_domain", 0.0) > 0:
            p_est += 0.40
            contribs["is_external_domain"] = 40.0
        if features.get("sensitive_field_detected", 0.0) > 0:
            p_est += 0.35
            contribs["sensitive_field_detected"] = 35.0
        if features.get("action_entity_mismatch", 0.0) > 0:
            p_est += 0.30
            contribs["action_entity_mismatch"] = 30.0
        if features.get("task_semantic_dist", 0.0) > 0.70:
            p_est += 0.20
            contribs["task_semantic_dist"] = 20.0
        if features.get("action_sensitivity", 0.0) > 0.80:
            p_est += 0.15
            contribs["action_sensitivity"] = 15.0

        p_est = min(0.98, max(0.02, p_est))
        risk_score = int(round(p_est * 100))
        confidence = float(round(0.5 + abs(p_est - 0.5), 3))
        return risk_score, confidence, contribs


# Global singleton predictor
risk_predictor = MLRiskModel()
