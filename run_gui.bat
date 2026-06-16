@echo off
cd /d "%~dp0"
where pythonw.exe >nul 2>nul
if errorlevel 1 (
    echo pythonw.exe not found. Falling back to one combined desktop window.
    python -m securemail.gui.app --mode all
    exit /b
)

start "SecureMail Client" pythonw.exe -m securemail.gui.app --mode client
start "SecureMail Monitor" pythonw.exe -m securemail.gui.app --mode monitor
