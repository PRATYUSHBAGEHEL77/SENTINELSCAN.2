@echo off
setlocal
cd /d %~dp0
if not exist .venv python -m venv .venv
call .venv\Scripts\activate
python tools\self_scan.py
pause
