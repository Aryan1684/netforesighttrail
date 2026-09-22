@echo off
setlocal
cd /d "%~dp0"
call .venv\Scripts\activate.bat
set NETFORESIGHT_TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
cd backend
uvicorn app:app --host 127.0.0.1 --port 8000
endlocal
