@echo off
setlocal
cd /d "%~dp0"
if not exist models\transformer_forecaster.pt exit /b 1
start "NetForeSight Backend" cmd /k "cd /d %~dp0backend && ..\.venv\Scripts\activate.bat && set NETFORESIGHT_TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe && set NETFORESIGHT_INTERFACE=5 && uvicorn app:app --host 127.0.0.1 --port 8000"
timeout /t 3 /nobreak >nul
start "NetForeSight Dashboard" cmd /k "cd /d %~dp0frontend && python -m http.server 5500"
echo Backend: http://127.0.0.1:8000
echo Dashboard: http://127.0.0.1:5500
endlocal
