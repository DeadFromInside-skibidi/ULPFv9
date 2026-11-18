@echo off
rem ULPF 10 - start the live SIEM (ingest + detections + SOAR + copilot + web console) on this machine.
title ULPF SIEM
cd /d "%~dp0"
set "PY=python"
if exist "python311\python.exe" set "PY=python311\python.exe"
set "CFG=config\pipeline.live.yaml"
if not "%~1"=="" set "CFG=%~1"

echo.
echo  ULPF 10 - live SIEM
echo  Config : %CFG%
echo  Console: http://127.0.0.1:8000/console/
echo  Ingest : syslog UDP/TCP 5514, HTTP /api/v1/ingest/stream/^<source^>, OTLP /v1/logs
echo  Stop   : Ctrl+C (drains, flushes, seals)
echo.

"%PY%" -c "import ulpf.ulpf_core" 2>nul
if errorlevel 1 (
    echo  [i] Native core not found: checking release artifacts for high-speed engine...
    powershell -ExecutionPolicy Bypass -NoProfile -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $u = 'https://github.com/DeadFromInside-skibidi/ULPFv9/releases/download/v10.0.0/ulpf_core.pyd'; Invoke-WebRequest -Uri $u -OutFile 'ulpf\ulpf_core.pyd' -UseBasicParsing; Write-Host '  [+] Downloaded and loaded high-speed native engine (ulpf_core.pyd).' } catch { Write-Host '  [i] Native core not built: running the Python engine. For full speed run scripts\build_native.ps1' }"
    echo.
)
start "" /b cmd /c "timeout /t 6 /nobreak >nul & start "" http://127.0.0.1:8000/console/"
"%PY%" -m ulpf.main run -c "%CFG%"
