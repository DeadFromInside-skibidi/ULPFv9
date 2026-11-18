@echo off
title ULPF Desktop GUI
cd /d "%~dp0"
echo.
echo  ==========================================
echo   ULPF 10 - Universal Log Pre-processing
echo  ==========================================
echo.

if exist "dist\ULPF\ULPF.exe" (
    echo  [*] Launching standalone ULPF.exe...
    start "" "dist\ULPF\ULPF.exe"
    timeout /t 2 /nobreak >nul
    echo  [+] ULPF.exe launched. Check your taskbar.
) else if exist "python311\pythonw.exe" (
    echo  [*] Launching via embedded python311...
    start "" "python311\pythonw.exe" -m ulpf.gui.qt_app
    timeout /t 2 /nobreak >nul
    echo  [+] GUI launched via Python 3.11.
) else (
    echo  [*] Embedded python not found. Falling back to system python...
    echo  [*] Automatically checking and installing requirements...
    python -m pip install -r requirements.txt
    echo  [*] Launching via system python...
    start "" pythonw -m ulpf.gui.qt_app
)

echo.
echo  GUI is launching - look for the ULPF window on your screen.
echo.
pause
