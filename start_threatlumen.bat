@echo off
title ThreatLumen Nexus - Initialization Protocol

echo ==================================================
echo   THREATLUMEN NEXUS // BOOT SEQUENCE INITIATED
echo ==================================================

:: Set the project root to the directory this script is in
cd /d "%~dp0"

echo [1/3] Launching Secure Backend Node...
start "ThreatLumen Backend [FastAPI]" cmd /k "cd backend && python -m uvicorn main:app --port 8000 --reload"

echo [2/3] Initializing Frontend Interface...
:: Using call npm to ensure it runs correctly in the batch context
start "ThreatLumen Frontend [Vite]" cmd /k "cd frontend && npm run dev"

echo [3/3] Establishing Neural Link (Opening Browser)...
:: Wait 3 seconds for services to spin up
timeout /t 3 /nobreak >nul
start http://localhost:5173

echo.
echo [SUCCESS] System is live.
echo You may minimize this window, but do not close the server windows.
timeout /t 5
exit
