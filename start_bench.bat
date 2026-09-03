@echo off
chcp 65001 >nul 2>&1
title ContextGuard -- Benchmark
color 0B
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONPATH=%~dp0
echo.
echo  ContextGuard -- Running Offline Benchmark
echo  ==========================================
echo.
"venv\Scripts\python.exe" launcher.py --bench
echo.
pause
