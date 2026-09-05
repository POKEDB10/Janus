@echo off
title Janus Frontend (Port 5173)
cd /d "%~dp0frontend"
echo ========================================================
echo Starting Janus React Frontend on http://localhost:5173
echo ========================================================
npm run dev
pause
