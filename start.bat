@echo off
title ContextGuard — Runtime Safety Gateway
color 0B

echo.
echo  ========================================================
echo   ContextGuard — Runtime Safety Gateway for Web Agents
echo  ========================================================
echo.

:: Move to the folder this .bat file lives in
cd /d "%~dp0"

:: Check venv exists
if not exist "venv\Scripts\python.exe" (
    echo  [ERROR] Virtual environment not found.
    echo.
    echo  Please set up the environment first:
    echo.
    echo    python -m venv venv
    echo    venv\Scripts\activate
    echo    pip install -r requirements.txt
    echo    playwright install chromium
    echo.
    pause
    exit /b 1
)

:: Check Flask is installed (quick dependency check)
"venv\Scripts\python.exe" -c "import flask" 2>nul
if errorlevel 1 (
    echo  [WARNING] Some packages may be missing. Installing now...
    echo.
    "venv\Scripts\pip.exe" install -r requirements.txt --quiet
    echo.
)

echo  Starting all services...
echo  Open your browser to: http://127.0.0.1:8000
echo.
echo  Press Ctrl+C in this window to stop everything.
echo.

:: Run the launcher
"venv\Scripts\python.exe" launcher.py

echo.
echo  ContextGuard has stopped.
pause
