@echo off
setlocal
cd /d "%~dp0"
python --version || exit /b 1
if not exist .venv python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r backend\requirements.txt || exit /b 1
if not exist _sources git clone https://github.com/TheWizardKingg/NetForesight.git _sources
if not exist models mkdir models
copy /Y _sources\feature_scaler.pkl models\feature_scaler.pkl
copy /Y _sources\label_encoder.pkl models\label_encoder.pkl
copy /Y _sources\xgboost_model.pkl models\xgboost_model.pkl
copy /Y _sources\shap_explainer.pkl models\shap_explainer.pkl
copy /Y _sources\transformer_forecaster.pt models\transformer_forecaster.pt
if not exist _mvp git clone https://github.com/Aryan1684/netforesightMVP.git _mvp
if not exist frontend mkdir frontend
copy /Y _mvp\frontend\index.html frontend\index.html
copy /Y _mvp\frontend\style.css frontend\style.css
copy /Y _mvp\frontend\script.js frontend\script.js
copy /Y _mvp\frontend\logo.svg frontend\logo.svg
echo Setup complete. Install/start Ollama, pull Qwen, then run run.cmd.
endlocal
