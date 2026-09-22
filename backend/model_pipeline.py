from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import torch
import torch.nn as nn


FEATURE_NAMES = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "ACK Flag Cnt",
]


class AttackForecasterTransformer(nn.Module):
    def __init__(self, feature_dim: int, seq_len: int, num_classes: int):
        super().__init__()
        self.input_projection = nn.Linear(feature_dim, 64)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=64,
            nhead=4,
            dim_feedforward=128,
            batch_first=True,
        )
        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer,
            num_layers=2,
        )
        self.fc_out = nn.Sequential(
            nn.Linear(64 * seq_len, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.input_projection(x)
        x = self.transformer_encoder(x)
        x = x.reshape(x.size(0), -1)
        return self.fc_out(x)


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
        self.xgboost_model = None
        self.shap_explainer = None
        self.transformer_model = None
        self.class_names: list[str] = []
        self.loaded = False

    def load(self) -> None:
        required = [
            "feature_scaler.pkl",
            "label_encoder.pkl",
            "xgboost_model.pkl",
            "shap_explainer.pkl",
            "transformer_forecaster.pt",
        ]
        missing = [name for name in required if not (self.model_dir / name).exists()]
        if missing:
            raise FileNotFoundError(
                "Missing trained artifacts: " + ", ".join(missing)
            )

        self.feature_scaler = joblib.load(self.model_dir / "feature_scaler.pkl")
        self.label_encoder = joblib.load(self.model_dir / "label_encoder.pkl")
        self.xgboost_model = joblib.load(self.model_dir / "xgboost_model.pkl")
        self.shap_explainer = joblib.load(self.model_dir / "shap_explainer.pkl")

        self.class_names = [str(x) for x in self.label_encoder.classes_]

        if self.class_names != ["Benign", "FTP-BruteForce", "SSH-Bruteforce"]:
            raise ValueError(
                f"Unexpected label encoder classes: {self.class_names}"
            )

        self.transformer_model = AttackForecasterTransformer(
            feature_dim=16,
            seq_len=5,
            num_classes=len(self.class_names),
        )

        state = torch.load(
            self.model_dir / "transformer_forecaster.pt",
            map_location=torch.device("cpu"),
        )
        self.transformer_model.load_state_dict(state)
        self.transformer_model.eval()
        self.loaded = True

    def _label(self, index: int) -> str:
        return str(self.label_encoder.inverse_transform([index])[0])

    def _risk(self, current_label: str, current_conf: float, next_conf: float) -> int:
        base_risk = 10 if current_label == "Benign" else 70
        threat_multiplier = 1.0 if current_label == "Benign" else 1.3
        return min(
            100,
            int(
                base_risk * current_conf * threat_multiplier
                + next_conf * 15
            ),
        )

    def _shap(self, xgb_input: np.ndarray, raw_window: np.ndarray, class_idx: int) -> list[dict[str, Any]]:
        try:
            values = self.shap_explainer(xgb_input).values
            if values.ndim == 3:
                importance = np.abs(values[0, :, class_idx])
            else:
                importance = np.abs(values[0])

            importance = importance.reshape(5, 16).mean(axis=0)
            indices = np.argsort(importance)[::-1][:3]
            return [
                {
                    "feature": FEATURE_NAMES[int(i)],
                    "value": round(float(raw_window[-1, int(i)]), 4),
                    "importance_score": round(float(importance[int(i)]), 6),
                }
                for i in indices
            ]
        except Exception:
            return []

    def predict(self, raw_window: list[list[float]] | np.ndarray) -> InferenceResult:
        if not self.loaded:
            raise RuntimeError("Model pipeline is not loaded")

        raw = np.asarray(raw_window, dtype=np.float32)
        if raw.shape != (5, 16):
            raise ValueError(f"Expected raw window shape (5, 16), got {raw.shape}")

        scaled = self.feature_scaler.transform(raw)
        xgb_input = scaled.reshape(1, -1)

        current_idx = int(self.xgboost_model.predict(xgb_input)[0])
        current_probs = np.asarray(
            self.xgboost_model.predict_proba(xgb_input)[0],
            dtype=np.float32,
        )
        current_conf = float(np.max(current_probs))

        tensor = torch.tensor(scaled, dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            logits = self.transformer_model(tensor)
            next_probs = torch.softmax(logits, dim=1).numpy()[0]

        next_idx = int(np.argmax(next_probs))
        next_conf = float(next_probs[next_idx])

        current_label = self._label(current_idx)
        next_label = self._label(next_idx)

        return InferenceResult(
            current_label=current_label,
            current_confidence=current_conf,
            current_probabilities={
                self._label(i): float(p)
                for i, p in enumerate(current_probs)
            },
            next_label=next_label,
            next_confidence=next_conf,
            next_probabilities={
                self._label(i): float(p)
                for i, p in enumerate(next_probs)
            },
            risk_score=self._risk(current_label, current_conf, next_conf),
            shap_triggers=self._shap(xgb_input, raw, current_idx),
        )
