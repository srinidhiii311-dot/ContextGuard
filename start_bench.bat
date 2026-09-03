@echo off
title ContextGuard — Benchmark
color 0B
cd /d "%~dp0"
echo.
echo  ContextGuard — Running Offline Benchmark
echo  =========================================
echo.
"venv\Scripts\python.exe" launcher.py --bench
echo.
pause
