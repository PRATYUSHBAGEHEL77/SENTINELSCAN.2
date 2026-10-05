@echo off
setlocal
cd /d %~dp0
if not exist .venv python -m venv .venv
call .venv\Scripts\activate
python -m pip install -r requirements.txt
start "Assessment Lab :8100" cmd /k "python assessment_lab\vulnerable_app.py"
start "SentinelScan :8000" cmd /k "python backend\server.py"
timeout /t 2 >nul
start http://127.0.0.1:8000/
