from __future__ import annotations
import asyncio, os, socket, subprocess, threading
from datetime import datetime
from pathlib import Path
import psutil, pyshark
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from flow_engine import FlowEngine
from mitre_mapper import map_label, priority
from model_pipeline import ModelPipeline
from qwen_explainer import QwenExplainer

ROOT=Path(__file__).resolve().parents[1]
MODEL_DIR=ROOT/"models"
TSHARK_PATH=os.getenv("NETFORESIGHT_TSHARK_PATH",r"C:Program FilesWireshark	shark.exe")
INTERFACE=os.getenv("NETFORESIGHT_INTERFACE","")
flow_engine=FlowEngine(idle_timeout=float(os.getenv("NETFORESIGHT_FLOW_IDLE_TIMEOUT","5")),active_timeout=float(os.getenv("NETFORESIGHT_FLOW_ACTIVE_TIMEOUT","30")),sequence_length=5)
models=ModelPipeline(MODEL_DIR)
qwen=QwenExplainer()
app=FastAPI(title="NetForeSight",version="4.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_credentials=False,allow_methods=["*"],allow_headers=["*"])
clients:set[WebSocket]=set()
capture_interface=None
capture_error=None
latest_update={"type":"network_update","time":datetime.now().strftime("%H:%M:%S"),"event":"Starting live monitoring","risk":0,"status":"STARTING","next_attack":"Analyzing","confidence":0,"flows":0,"packets":0,"sequence_ready":False,"source":"starting"}

def local_ips():
    result=set()
    for addresses in psutil.net_if_addrs().values():
        for addr in addresses:
            if getattr(addr,"family",None) in {socket.AF_INET,socket.AF_INET6}: result.add(str(addr.address).split("%")[0])
    return result

def detect_interface():
    if INTERFACE:return INTERFACE
    try:
        output=subprocess.check_output([TSHARK_PATH,"-D"],text=True,timeout=10)
        for line in output.splitlines():
            if "Wi-Fi" in line or "WiFi" in line:
                n=line.split(".",1)[0].strip()
                if n.isdigit():return n
        for line in output.splitlines():
            n=line.split(".",1)[0].strip()
            if n.isdigit() and "Loopback" not in line:return n
    except Exception:
        pass
    return "5"

def severity(risk):
    return "CRITICAL" if risk>=76 else "ELEVATED" if risk>=46 else "MONITORING"

def build_payload(result=None,previous_completed=0,previous_packets=0):
    stats=flow_engine.stats()
    data={"type":"network_update","time":datetime.now().strftime("%H:%M:%S"),"event":"Collecting completed flows","risk":0,"status":"MONITORING","next_attack":"Analyzing","confidence":0,"flows":max(0,stats["completed_flows"]-previous_completed),"packets":max(0,stats["packets"]-previous_packets),"packets_per_second":stats["packets_per_second"],"bytes_per_second":stats["bytes_per_second"],"incoming_packets":stats["incoming_packets"],"outgoing_packets":stats["outgoing_packets"],"active_connections":stats["active_flows"],"completed_flows":stats["completed_flows"],"flows_per_sec":stats["completed_flows"]/max(1,stats["packets"]/max(stats["packets_per_second"],1e-6)) if stats["packets_per_second"] else 0,"protocols":stats["protocols"],"source":"pyshark_live_capture","sequence_ready":stats["sequence_ready"],"models":models.status(),"capture_interface":capture_interface}
    if capture_error:
        data["capture_error"]=capture_error
        data["status"]="ERROR"
    if result is None:
        data["event"]="Collecting five completed flows" if not stats["sequence_ready"] else "Analyzing live traffic"
        return data
    data.update({"event":f"Detected: {result.current_label}","risk":result.risk_score,"status":severity(result.risk_score),"next_attack":result.next_label,"current_stage":result.current_label,"confidence":round(result.current_confidence*100,2),"forecast_confidence":round(result.next_confidence*100,2),"prediction":{"predicted_next_attack":result.next_label,"probability":round(result.next_confidence*100,2),"probabilities":{k:round(v*100,2) for k,v in result.next_probabilities.items()}},"detection":{"predicted_attack":result.current_label,"confidence":round(result.current_confidence*100,2),"probabilities":{k:round(v*100,2) for k,v in result.current_probabilities.items()}},"mitre":map_label(result.current_label),"path_priority":priority(result.current_confidence,result.next_confidence,result.risk_score),"top_triggers":result.shap_triggers,"explanation":"Generating analyst explanation..."})
    return data

def capture_worker():
    global capture_interface,capture_error
    loop=asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    interface=detect_interface()
    capture_interface=interface
    capture_error=None
    if not Path(TSHARK_PATH).exists():
        capture_error=f"TShark not found: {TSHARK_PATH}"
        loop.close()
        return
    capture=None
    try:
        capture=pyshark.LiveCapture(interface=interface,tshark_path=TSHARK_PATH)
        local=local_ips()
        for packet in capture.sniff_continuously():
            try:
                flow_engine.ingest(packet,local)
            except Exception:
                continue
    except Exception as exc:
        capture_error=f"Live capture unavailable: {exc}"
    finally:
        try:
            if capture is not None:
                capture.close()
        except Exception:
            pass
        loop.close()

async def broadcast(payload):
    dead=[]
    for ws in list(clients):
        try:await ws.send_json(payload)
        except Exception:dead.append(ws)
    for ws in dead:clients.discard(ws)

async def inference_loop():
    global latest_update
    previous_completed=previous_packets=0
    last_explanation_key=""
    while True:
        await asyncio.sleep(1)
        stats=flow_engine.stats()
        window=flow_engine.sequence_window()
        result=None
        if window is not None and models.loaded:
            try:result=models.predict(window)
            except Exception as exc:
                latest_update={"type":"error","time":datetime.now().strftime("%H:%M:%S"),"event":"Model inference failed","message":str(exc),"capture_interface":capture_interface}
                await broadcast(latest_update);continue
        payload=build_payload(result,previous_completed,previous_packets)
        previous_completed,previous_packets=stats["completed_flows"],stats["packets"]
        if result is not None:
            key=f"{result.current_label}|{result.next_label}|{result.risk_score}|{result.shap_triggers}"
            if key!=last_explanation_key:
                payload["explanation"]=await qwen.explain({"current_detection":payload["detection"],"next_stage_forecast":payload["prediction"],"risk_assessment":{"score":payload["risk"]},"top_shap_triggers":payload["top_triggers"],"mitre":payload["mitre"]})
                last_explanation_key=key
        latest_update=payload
        await broadcast(payload)

@app.get("/")
async def root():return {"service":"NetForeSight","status":"online","models_loaded":models.loaded,"websocket":"/ws/alerts"}

@app.get("/api/health")
async def health():return {"status":"online" if models.loaded else "degraded","models":models.status(),"qwen":qwen.config(),"capture":{**flow_engine.stats(),"interface":capture_interface,"error":capture_error,"tshark":TSHARK_PATH}}

@app.get("/api/capture/stats")
async def capture_stats():return flow_engine.stats()

@app.get("/api/models/status")
async def model_status():return models.status()

@app.get("/api/alerts")
async def alerts():return latest_update

@app.get("/api/predict/forecast")
async def forecast():
    window=flow_engine.sequence_window()
    if window is None:return {"ready":False,"message":"Five completed flows are required before forecasting."}
    if not models.loaded:return {"ready":False,"message":"Trained model artifacts are not loaded."}
    result=models.predict(window)
    return {"ready":True,"predicted_next_stage":result.next_label,"confidence":result.next_confidence,"class_probabilities":result.next_probabilities}

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket:WebSocket):
    await websocket.accept();clients.add(websocket);await websocket.send_json(latest_update)
    try:
        while True:await websocket.receive_text()
    except (WebSocketDisconnect,Exception):clients.discard(websocket)

@app.on_event("startup")
async def startup_event():
    try:models.load();print("[+] Trained ML artifacts loaded.")
    except Exception as exc:print(f"[-] Model load failed: {exc}")
    threading.Thread(target=capture_worker,daemon=True).start()
    asyncio.create_task(inference_loop())

if __name__=="__main__":
    import uvicorn
    uvicorn.run("app:app",host="127.0.0.1",port=8000)
