@echo off
title Launch Janus System
cd /d "%~dp0"
echo ========================================================
echo Launching Full Janus Stack for Presentation / Demo
echo ========================================================
start "Janus Backend (Port 8000)" cmd /k "cd /d %~dp0 && python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload"
timeout /t 2 /nobreak >nul
start "Janus Frontend (Port 5173)" cmd /k "cd /d %~dp0frontend && npm run dev"
echo.
echo Both servers are starting up in separate terminal windows:
echo - Backend API & Docs: http://localhost:8000/docs
echo - Frontend Dashboard: http://localhost:5173
echo.
