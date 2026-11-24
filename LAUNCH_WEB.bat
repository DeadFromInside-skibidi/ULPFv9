@echo off
title ULPF Web UI
cd /d "%~dp0"
set "PY=python"
if exist "python311\python.exe" set "PY=python311\python.exe"
echo.
echo  ======================================================
echo   ULPF v10.0 - Institutional Enterprise Web Interface
echo  ======================================================
echo.
echo  [*] Opening Web UI: http://127.0.0.1:8000/
start "" /b cmd /c "timeout /t 3 /nobreak >nul & start "" http://127.0.0.1:8000/"
"%PY%" -m ulpf.main serve --port 8000
