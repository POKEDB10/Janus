@echo off
title Janus Backend (Port 8000)
cd /d "%~dp0"
echo ========================================================
echo Starting Janus FastAPI Backend on http://localhost:8000
echo API Docs (Dark Mode): http://localhost:8000/docs
echo ========================================================
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
pause
