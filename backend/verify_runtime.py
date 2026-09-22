from pathlib import Path
import json
import os
import subprocess
import sys
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
TSHARK=os.getenv("NETFORESIGHT_TSHARK_PATH",r"C:\Program Files\Wireshark\tshark.exe")
sys.path.insert(0,str(ROOT/"backend"))

def main():
    print("[1/5] TShark")
    if not Path(TSHARK).exists(): raise SystemExit(f"TShark not found: {TSHARK}")
    print(subprocess.check_output([TSHARK,"--version"],text=True,timeout=15).splitlines()[0])
    print("[2/5] Model artifacts")
    required=["feature_scaler.pkl","label_encoder.pkl","feature_names.pkl","xgboost_model.pkl","transformer_forecaster.pt"]
    missing=[x for x in required if not (ROOT/"models"/x).exists()]
    if missing: raise SystemExit("Missing: "+", ".join(missing))
    print("[3/5] Model contract and load")
    from model_pipeline import ModelPipeline
    p=ModelPipeline(ROOT/"models");p.load()
    print("features:",len(p.feature_names),"classes:",p.class_names,"xgb:",type(p.xgboost_model).__name__)
    print("[4/5] TShark interfaces")
    print(subprocess.check_output([TSHARK,"-D"],text=True,timeout=15))
    print("[5/5] Ollama/Qwen")
    body=json.dumps({"model":os.getenv("NETFORESIGHT_QWEN_MODEL","qwen2.5:3b"),"messages":[{"role":"user","content":"Reply with OK only."}],"stream":False}).encode()
    req=urllib.request.Request("http://127.0.0.1:11434/api/chat",data=body,headers={"Content-Type":"application/json"})
    result=json.loads(urllib.request.urlopen(req,timeout=60).read().decode())
    print("Qwen:",result.get("message",{}).get("content","").strip())
    print("ALL RUNTIME CHECKS PASSED")

if __name__=="__main__": main()
