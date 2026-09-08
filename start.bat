@echo off
chcp 65001 >nul 2>&1
title AI Agent Security Platform
color 0B
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONPATH=%~dp0

echo.
echo  ============================================================
echo   AI Web Agent Security Testing Platform
echo   ContextGuard -- Runtime Safety Gateway
echo  ============================================================
echo.

if not exist "venv\Scripts\python.exe" (
    echo  [ERROR] Virtual environment not found.
    echo.
    echo  Run these commands first:
    echo    python -m venv venv
    echo    venv\Scripts\activate
    echo    pip install -r requirements.txt
    echo    playwright install chromium
    echo.
    pause
    exit /b 1
)

echo  Starting platform...
echo  Dashboard: http://127.0.0.1:8000/dashboard
echo  Booking:   http://127.0.0.1:8000/
echo.
echo  Press Ctrl+C to stop.
echo.

"venv\Scripts\python.exe" launcher.py

echo.
echo  Platform stopped.
pause
