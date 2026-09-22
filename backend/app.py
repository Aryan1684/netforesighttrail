from __future__ import annotations

import asyncio
import json
import os
import threading
from collections import deque
from datetime import datetime
from pathlib import Path

import psutil
import pyshark
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from flow_engine import FlowEngine
from mitre_mapper import map_label, path_priority
from model_pipeline import ModelPipeline
from qwen_explainer import QwenExplainer


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models"

app = FastAPI(title="NetForeSight Integration")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

flow_engine = FlowEngine(
    idle_timeout=float(os.getenv("NETFORESIGHT_FLOW_IDLE_TIMEOUT", "5")),
    active_timeout=float(os.getenv("NETFORESIGHT_FLOW_ACTIVE_TIMEOUT", "30")),
)
models = ModelPipeline(MODEL_DIR)
qwen = QwenExplainer()
sequence_history = deque(maxlen=100)
latest_update: dict = {}
clients: set[WebSocket] = set()


def load_models_once() -> None:
    models.load()


def snapshot_fallback() -> dict:
    counters = psutil.net_io_counters()
    connections = psutil.net_connections(kind="inet")
    active = sum(
        1 for c in connections
        if c.status in {"ESTABLISHED", "SYN_SENT", "SYN_RECV"}
    )
    return {
        "packets": counters.packets_sent + counters.packets_recv,
        "bytes": counters.bytes_sent + counters.bytes_recv,
        "active_flows": active,
        "protocols": {},
    }


def make_update(inference: dict | None) -> dict:
    stats = flow_engine.stats()
    fallback = snapshot_fallback()

    base = {
        "type": "network_update",
        "time": datetime.now().strftime("%H:%M:%S"),
        "source": "pyshark_live_capture",
        "flows": stats["active_flows"],
        "packets": stats["packets"],
        "bytes": stats["bytes"],
        "protocols": stats["protocols"],
        "sequence_ready": stats["sequence_ready"],
        "models_loaded": models.loaded,
    }

    if not inference:
        base.update(
            {
                "event": "Collecting flow history",
                "risk": 0,
                "status": "MONITORING",
                "next_attack": "Analyzing",
                "confidence": 0,
                "mitre": None,
                "path_priority": None,
                "explanation": "Waiting for five completed flow records before model inference.",
            }
        )
        return base

    result = inference
    mitre = map_label(result.current_label)
    priority = path_priority(
        result.current_label,
        result.next_label,
        result.current_confidence,
        result.next_confidence,
        result.risk_score,
    )

    payload = {
        "current_detection": {
            "predicted_attack": result.current_label,
            "confidence": result.current_confidence * 100,
            "probabilities": {
                k: v * 100 for k, v in result.current_probabilities.items()
            },
        },
        "next_stage_forecast": {
            "predicted_next_attack": result.next_label,
            "probability": result.next_confidence * 100,
            "probabilities": {
                k: v * 100 for k, v in result.next_probabilities.items()
            },
        },
        "risk_assessment": {
            "score": result.risk_score,
            "severity": (
                "CRITICAL" if result.risk_score > 75
                else "ELEVATED" if result.risk_score > 45
                else "LOW"
            ),
        },
        "top_shap_triggers": result.shap_triggers,
    }

    explanation = sequence_history[-1].get("explanation", "") if sequence_history else ""
    base.update(
        {
            "event": f"Detected: {result.current_label}",
            "risk": result.risk_score,
            "status": payload["risk_assessment"]["severity"],
            "next_attack": result.next_label,
            "confidence": round(result.current_confidence * 100, 2),
            "current_stage": result.current_label,
            "prediction": payload["next_stage_forecast"],
            "detection": payload["current_detection"],
            "mitre": mitre,
            "path_priority": priority,
            "top_triggers": result.shap_triggers,
            "explanation": explanation or "Generating local analyst explanation.",
        }
    )
    return base


async def broadcast(data: dict) -> None:
    dead = []
    for ws in list(clients):
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


def capture_worker() -> None:
    interface = os.getenv("NETFORESIGHT_INTERFACE", "5")
    tshark_path = os.getenv(
        "NETFORESIGHT_TSHARK_PATH",
        r"C:\Program Files\Wireshark\tshark.exe",
    )

    capture = None
    try:
        capture = pyshark.LiveCapture(
            interface=interface,
            tshark_path=tshark_path,
        )
        for packet in capture.sniff_continuously():
            for vector in flow_engine.ingest(packet):
                sequence_history.append({"window": vector})
    except Exception as exc:
        sequence_history.append({"capture_error": str(exc)})
    finally:
        if capture is not None:
            try:
                capture.close()
            except Exception:
                pass


async def inference_loop() -> None:
    global latest_update

    previous_packets = 0
    previous_bytes = 0
    last_qwen = ""

    while True:
        await asyncio.sleep(1)

        window = flow_engine.sequence_window()
        inference = None
        if window is not None and models.loaded:
            try:
                inference = models.predict(window)
            except Exception as exc:
                latest_update = {
                    "type": "error",
                    "message": f"Model inference failed: {exc}",
                }
                await broadcast(latest_update)
                continue

        update = make_update(inference)

        current_packets = flow_engine.total_packets
        current_bytes = flow_engine.total_bytes
        update["incoming_packets"] = max(0, current_packets - previous_packets)
        update["outgoing_packets"] = 0
        update["bytes_per_second"] = max(0, current_bytes - previous_bytes)
        update["active_connections"] = flow_engine.active_flows

        previous_packets = current_packets
        previous_bytes = current_bytes

        if inference is not None:
            analyst_payload = {
                "current_detection": update["detection"],
                "next_stage_forecast": update["prediction"],
                "risk_assessment": {"score": update["risk"]},
                "top_shap_triggers": update["top_triggers"],
            }
            explanation = await qwen.explain(analyst_payload)
            last_qwen = explanation
            update["explanation"] = last_qwen
        elif last_qwen:
            update["explanation"] = last_qwen

        latest_update = update
        await broadcast(update)


@app.get("/")
async def root():
    return {
        "service": "NetForeSight Integration",
        "status": "online",
        "models_loaded": models.loaded,
        "websocket": "/ws/alerts",
    }


@app.get("/api/health")
async def health():
    fallback = snapshot_fallback()
    return {
        "status": "online",
        "models_loaded": models.loaded,
        "class_names": models.class_names,
        "traffic": flow_engine.stats(),
        "fallback": fallback,
    }


@app.get("/api/alerts")
async def alerts():
    return latest_update or make_update(None)


@app.websocket("/ws/alerts")
async def alerts_ws(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    if latest_update:
        await websocket.send_json(latest_update)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.discard(websocket)
    except Exception:
        clients.discard(websocket)


@app.on_event("startup")
async def startup():
    try:
        load_models_once()
        print("[+] All trained NetForeSight artifacts loaded.")
    except Exception as exc:
        print(f"[-] Model load failed: {exc}")
    threading.Thread(target=capture_worker, daemon=True).start()
    asyncio.create_task(inference_loop())
