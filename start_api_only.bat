@echo off
chcp 65001 >nul 2>&1
title ContextGuard -- API Only
color 0B
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONPATH=%~dp0
echo.
echo  ContextGuard -- API + Dashboard only
echo  =====================================
echo.
"venv\Scripts\python.exe" launcher.py --api-only
echo.
pause
