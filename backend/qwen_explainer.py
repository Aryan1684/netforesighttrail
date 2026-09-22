from __future__ import annotations

import os

import httpx


class QwenExplainer:
    def __init__(self):
        self.url = os.getenv(
            "NETFORESIGHT_QWEN_URL",
            "http://127.0.0.1:11434/api/chat",
        )
        self.model = os.getenv(
            "NETFORESIGHT_QWEN_MODEL",
            "qwen2.5:3b",
        )
        self.timeout = float(os.getenv("NETFORESIGHT_QWEN_TIMEOUT", "60"))

    def config(self) -> dict:
        return {
            "url": self.url,
            "model": self.model,
            "timeout": self.timeout,
        }

    async def explain(self, payload: dict) -> str:
        prompt = (
            "You are the local explanation layer for the NetForeSight SOC dashboard. "
            "Use only the supplied model outputs. Do not invent attacks, evidence, or facts. "
            "Return a concise analyst-facing explanation with four sections: "
            "Threat Summary, Temporal Forecast, Feature Attribution, Mitigation Steps. "
            "This is a defensive monitoring system.\n\n"
            + str(payload)
        )

        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a concise SOC analyst assistant.",
                },
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.2},
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.url, json=body)
                response.raise_for_status()
                data = response.json()
                return str(data.get("message", {}).get("content", "")).strip()
        except Exception:
            return self._fallback(payload)

    def _fallback(self, payload: dict) -> str:
        detection = payload.get("current_detection", {})
        forecast = payload.get("next_stage_forecast", {})
        risk = payload.get("risk_assessment", {})
        triggers = payload.get("top_shap_triggers", [])

        trigger_text = ", ".join(
            f"{x.get('feature')} ({x.get('importance_score')})"
            for x in triggers
        ) or "No SHAP attribution available."

        return (
            f"Threat Summary: Detected {detection.get('predicted_attack', 'Unknown')} "
            f"with {detection.get('confidence', 0):.1f}% confidence; "
            f"risk score {risk.get('score', 0)}.\n"
            f"Temporal Forecast: {forecast.get('predicted_next_attack', 'Unknown')} "
            f"with {forecast.get('probability', 0):.1f}% probability.\n"
            f"Feature Attribution: {trigger_text}.\n"
            "Mitigation Steps: Validate the alert against surrounding traffic and "
            "review affected connections before taking containment action."
        )
