@echo off
title AURA-CRYPT Server ^& Mobile Tunnel
cd /d "%~dp0"
echo Starting Image Encryption Server...
".\.venv\Scripts\python.exe" run_server.py
pause
