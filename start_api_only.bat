@echo off
title ContextGuard — API Only
color 0B
cd /d "%~dp0"
echo.
echo  ContextGuard — API + Dashboard only (no mock sites)
echo  =====================================================
echo.
"venv\Scripts\python.exe" launcher.py --api-only
echo.
pause
