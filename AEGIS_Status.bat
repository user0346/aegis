@echo off
setlocal enabledelayedexpansion

set "PIDFILE=%USERPROFILE%\.aegis\service.pid"
set "LOGFILE=%USERPROFILE%\.aegis\service-bg.log"

echo === AEGIS Background-Status ===
echo.

if not exist "%PIDFILE%" (
    echo Status:  NICHT LAEUFT
    goto :tail
)

set "RUNPID="
for /f "usebackq tokens=*" %%i in ("%PIDFILE%") do set "RUNPID=%%i"
if not defined RUNPID (
    echo Status:  PID-File leer
    goto :tail
)

tasklist /FI "PID eq !RUNPID!" 2>nul | findstr /C:"!RUNPID!" >nul
if errorlevel 1 (
    echo Status:  PID-File vorhanden ^(!RUNPID!^) aber Prozess tot - stale.
) else (
    echo Status:  LAEUFT, PID !RUNPID!
    echo IPC:     \\.\pipe\aegis-v2-bus
    echo Log:     %LOGFILE%
)

:tail
echo.
echo === Letzte 15 Log-Zeilen ===
if exist "%LOGFILE%" (
    powershell -NoProfile -Command "Get-Content -Tail 15 '%LOGFILE%'"
) else (
    echo ^(noch keine Logs^)
)
goto :eof
