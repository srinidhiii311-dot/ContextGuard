@echo off
chcp 65001 >nul 2>&1
title ContextGuard -- Runtime Safety Gateway
color 0B

echo.
echo  ============================================================
echo   ContextGuard -- Runtime Safety Gateway for Web Agents
echo  ============================================================
echo.

:: Move to the folder this .bat file lives in
cd /d "%~dp0"

:: Set UTF-8 encoding to prevent UnicodeEncodeError
set PYTHONIOENCODING=utf-8
set PYTHONPATH=%~dp0

:: Check venv exists
if not exist "venv\Scripts\python.exe" (
    echo  [ERROR] Virtual environment not found.
    echo.
    echo  Run these commands first:
    echo.
    echo    python -m venv venv
    echo    venv\Scripts\activate
    echo    pip install -r requirements.txt
    echo    playwright install chromium
    echo.
    pause
    exit /b 1
)

echo  Starting all services...
echo  Open your browser to: http://127.0.0.1:8000
echo.
echo  Press Ctrl+C in this window to stop everything.
echo.

"venv\Scripts\python.exe" launcher.py

echo.
echo  ContextGuard has stopped.
pause
