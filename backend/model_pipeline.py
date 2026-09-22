from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import shap
import torch
import torch.nn as nn


class AttackForecasterTransformer(nn.Module):
    def __init__(self, feature_dim: int, seq_len: int, num_classes: int):
        super().__init__()
        self.embedding = nn.Linear(feature_dim, 64)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=64,
            nhead=4,
            dim_feedforward=128,
            batch_first=True,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=2)
        self.fc = nn.Sequential(
            nn.Linear(64 * seq_len, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.embedding(x)
        x = self.transformer(x)
        x = x.reshape(x.size(0), -1)
        return self.fc(x)


@dataclass
class InferenceResult:
    current_label: str
    current_confidence: float
    current_probabilities: dict[str, float]
    next_label: str
    next_confidence: float
    next_probabilities: dict[str, float]
    risk_score: int
    shap_triggers: list[dict[str, Any]]


class ModelPipeline:
    def __init__(self, model_dir: str | Path):
        self.model_dir = Path(model_dir)
        self.feature_scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.xgboost_model = None
        self.shap_explainer = None
        self.transformer_model = None
        self.class_names: list[str] = []
        self.loaded = False

    def load(self) -> None:
        required = [
            "feature_scaler.pkl",
            "label_encoder.pkl",
            "feature_names.pkl",
            "xgboost_model.pkl",
            "transformer_forecaster.pt",
        ]
        missing = [name for name in required if not (self.model_dir / name).exists()]
        if missing:
            raise FileNotFoundError("Missing trained artifacts: " + ", ".join(missing))

        self.feature_scaler = joblib.load(self.model_dir / "feature_scaler.pkl")
        self.label_encoder = joblib.load(self.model_dir / "label_encoder.pkl")
        self.feature_names = list(joblib.load(self.model_dir / "feature_names.pkl"))
        self.xgboost_model = joblib.load(self.model_dir / "xgboost_model.pkl")

        from constants import FEATURE_NAMES, LABELS
        if self.feature_names != FEATURE_NAMES:
            raise ValueError(
                f"Feature contract mismatch. Artifact: {self.feature_names}; expected: {FEATURE_NAMES}"
            )
        if list(self.label_encoder.classes_) != LABELS:
            raise ValueError(
                f"Label contract mismatch. Artifact: {list(self.label_encoder.classes_)}; expected: {LABELS}"
            )
        if int(getattr(self.feature_scaler, "n_features_in_", 0)) != len(FEATURE_NAMES):
            raise ValueError("Scaler feature count does not match the live feature contract.")
        xgb_features = int(getattr(self.xgboost_model, "n_features_in_", len(FEATURE_NAMES)))
        if xgb_features != len(FEATURE_NAMES):
            raise ValueError(
                f"XGBoost expects {xgb_features} features, live contract provides {len(FEATURE_NAMES)}."
            )

        self.class_names = [str(x) for x in self.label_encoder.classes_]
        self.transformer_model = AttackForecasterTransformer(
            feature_dim=len(FEATURE_NAMES),
            seq_len=5,
            num_classes=len(self.class_names),
        )
        state = torch.load(
            self.model_dir / "transformer_forecaster.pt",
            map_location=torch.device("cpu"),
        )
        self.transformer_model.load_state_dict(state)
        self.transformer_model.eval()
        self.shap_explainer = shap.TreeExplainer(self.xgboost_model)
        self.loaded = True

    def predict(self, raw_window: list[list[float]] | np.ndarray) -> InferenceResult:
        if not self.loaded:
            raise RuntimeError("Model pipeline is not loaded")
        raw = np.asarray(raw_window, dtype=np.float32)
        if raw.shape != (5, 42):
            raise ValueError(f"Expected window shape (5, 42), got {raw.shape}")

        scaled = self.feature_scaler.transform(raw)
        latest = scaled[-1].reshape(1, -1)

        current_probs = np.asarray(self.xgboost_model.predict_proba(latest)[0], dtype=np.float32)
        current_idx = int(np.argmax(current_probs))
        current_conf = float(current_probs[current_idx])

        tensor = torch.tensor(scaled, dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            next_probs = torch.softmax(self.transformer_model(tensor), dim=1).numpy()[0]
        next_idx = int(np.argmax(next_probs))
        next_conf = float(next_probs[next_idx])

        current_label = str(self.label_encoder.inverse_transform([current_idx])[0])
        next_label = str(self.label_encoder.inverse_transform([next_idx])[0])

        return InferenceResult(
            current_label=current_label,
            current_confidence=current_conf,
            current_probabilities={self.class_names[i]: float(p) for i, p in enumerate(current_probs)},
            next_label=next_label,
            next_confidence=next_conf,
            next_probabilities={self.class_names[i]: float(p) for i, p in enumerate(next_probs)},
            risk_score=self._risk(current_label, current_conf, next_conf),
            shap_triggers=self._shap(latest, raw[-1], current_idx),
        )

    @staticmethod
    def _risk(current_label: str, current_conf: float, next_conf: float) -> int:
        if current_label == "Normal":
            return min(35, int(10 + current_conf * 15 + next_conf * 10))
        base = 70.0 * current_conf + next_conf * 20.0
        return min(100, max(0, int(base)))

    def _shap(self, latest_scaled: np.ndarray, latest_raw: np.ndarray, class_idx: int) -> list[dict[str, Any]]:
        try:
            explanation = self.shap_explainer(latest_scaled, check_additivity=False)
            values = np.asarray(explanation.values)
            if values.ndim == 3:
                importance = np.abs(values[0, :, class_idx])
            elif values.ndim == 2:
                importance = np.abs(values[0])
            else:
                importance = np.abs(values)
            indices = np.argsort(importance)[::-1][:5]
            from constants import FEATURE_NAMES
            return [
                {
                    "feature": FEATURE_NAMES[int(i)],
                    "value": round(float(latest_raw[int(i)]), 4),
                    "importance_score": round(float(importance[int(i)]), 6),
                }
                for i in indices
            ]
        except Exception:
            return []

    def status(self) -> dict[str, Any]:
        return {
            "loaded": self.loaded,
            "classes": self.class_names,
            "features": list(self.feature_names or []),
            "xgboost": type(self.xgboost_model).__name__ if self.xgboost_model is not None else None,
            "transformer": type(self.transformer_model).__name__ if self.transformer_model is not None else None,
            "shap": self.shap_explainer is not None,
        }
