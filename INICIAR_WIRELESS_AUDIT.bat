@echo off
setlocal
cd /d "%~dp0"
where pythonw.exe >nul 2>nul
if %errorlevel%==0 (
    start "Wireless Audit Pro" pythonw.exe "%~dp0WirelessAuditPro.py"
) else (
    python.exe "%~dp0WirelessAuditPro.py"
)
endlocal
