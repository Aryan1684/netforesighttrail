@echo off
setlocal
cd /d "%~dp0"
if not exist .venv python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r backend\requirements.txt || exit /b 1
if not exist models mkdir models
echo Downloading trained artifacts...
curl.exe -L --fail -o models\feature_scaler.pkl https://raw.githubusercontent.com/TheWizardKingg/NetForesight/main/backend/feature_scaler.pkl || exit /b 1
curl.exe -L --fail -o models\label_encoder.pkl https://raw.githubusercontent.com/TheWizardKingg/NetForesight/main/backend/label_encoder.pkl || exit /b 1
curl.exe -L --fail -o models\feature_names.pkl https://raw.githubusercontent.com/TheWizardKingg/NetForesight/main/backend/feature_names.pkl || exit /b 1
curl.exe -L --fail -o models\xgboost_model.pkl https://raw.githubusercontent.com/TheWizardKingg/NetForesight/main/backend/xgboost_model.pkl || exit /b 1
curl.exe -L --fail -o models\transformer_forecaster.pt https://raw.githubusercontent.com/TheWizardKingg/NetForesight/main/backend/transformer_forecaster.pt || exit /b 1
echo Setup complete.
endlocal
