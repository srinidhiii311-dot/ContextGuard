@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONPATH=%~dp0

if exist "venv\Scripts\python.exe" (
    set PY="venv\Scripts\python.exe"
) else (
    set PY=python
)

echo.
echo  =============================================================
echo   ContextGuard -- Adversarial Injection Demo (Slow Motion)
echo   Attack Scenario: TC-2 Prompt Injection (Cabin Override)
echo   Isolated ContextGuard Verification + Pre-Action Gate
echo  =============================================================
echo.
%PY% run_agent_session.py --scenario prompt_injection --instruction "Book an economy flight from Chennai to Bangalore for 2 passengers" --origin Chennai --destination Bangalore --passengers 2 --cabin-class Economy --speed 1.5 --slowmo 300
echo.
pause
