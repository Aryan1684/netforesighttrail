# NetForeSight Integration

Live TShark packets -> bidirectional flow aggregation -> exact 16 CIC-style features -> 5-flow sequence -> trained XGBoost detection + trained Transformer forecast -> SHAP attribution -> MITRE mapping -> optional local Qwen explanation -> FastAPI -> WebSocket -> existing dashboard.

No training is performed here.

Trained artifacts are downloaded by setup.cmd from the source model repository:
- feature_scaler.pkl
- label_encoder.pkl
- xgboost_model.pkl
- shap_explainer.pkl
- transformer_forecaster.pt

Qwen is an optional local explanation layer. Install Ollama, then run:
ollama pull qwen2.5:3b-instruct
ollama list

Windows:
1. Run setup.cmd.
2. Install/start Ollama and pull Qwen.
3. Run run.cmd.
4. Open http://127.0.0.1:5500

The backend expects TShark at C:\Program Files\Wireshark\tshark.exe and Wi-Fi interface 5. Change NETFORESIGHT_INTERFACE if tshark -D shows another interface.

The trained models require five completed flow records before inference. This is deliberate because the trained input shape is (5, 16).
