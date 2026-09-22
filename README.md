# NetForeSight Integration

## Workflow
TShark live packets -> bidirectional flow aggregation -> 40 UNSW-NB15-compatible features -> five completed-flow sequence -> StandardScaler -> XGBoost current detection + Transformer next-state forecast -> SHAP -> MITRE mapping -> local Qwen explanation -> FastAPI/WebSocket -> dashboard.

## Fixed issues
- No packet-level zero-placeholder inference.
- Real bidirectional flow state is maintained.
- Inference waits for five completed flows instead of zero-padding.
- XGBoost uses the latest scaled flow, matching the training script.
- Transformer uses the exact five-by-40 sequence contract.
- SHAP is constructed from the loaded XGBoost model at runtime.
- MITRE mapping and path priority are returned with every prediction.
- Qwen uses the local Ollama API and has a deterministic fallback.
- TShark Wi-Fi interface is auto-detected unless NETFORESIGHT_INTERFACE is set.
- Runtime health and model status endpoints are included.

## Setup
Run setup.cmd.

Then verify with:
.venv\Scripts\activate
python backend\verify_runtime.py

Start with backend\run.cmd.

Serve the frontend:
cd frontend
python -m http.server 5500

Open http://127.0.0.1:5500

## Model compatibility note
The source repository did not persist the categorical encoders used for proto, service, and state. This integration reconstructs deterministic UNSW vocabularies for those fields. Exact reproduction of those three encoders requires the original training dataset or saved encoders. The runtime refuses incompatible feature dimensions rather than silently accepting the wrong shape.

Qwen is explanation-only. It does not generate the prediction.
