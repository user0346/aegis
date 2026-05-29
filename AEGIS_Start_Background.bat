@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "PIDFILE=%USERPROFILE%\.aegis\service.pid"

if exist "%PIDFILE%" (
    set "RUNPID="
    for /f "usebackq tokens=*" %%i in ("%PIDFILE%") do set "RUNPID=%%i"
    if defined RUNPID (
        tasklist /FI "PID eq !RUNPID!" 2>nul | findstr /C:"!RUNPID!" >nul
        if not errorlevel 1 (
            echo AEGIS laeuft bereits mit PID !RUNPID!
            goto :eof
        )
    )
    del /f /q "%PIDFILE%" >nul 2>&1
)

where pythonw.exe >nul 2>&1
if errorlevel 1 (
    echo FEHLER: pythonw.exe nicht im PATH.
    goto :eof
)

echo Starte AEGIS-Service im Hintergrund...
start "" /B pythonw.exe "%SCRIPT_DIR%bin\aegis_core_background.pyw"

timeout /t 2 /nobreak >nul
if exist "%PIDFILE%" (
    set "RUNPID="
    for /f "usebackq tokens=*" %%i in ("%PIDFILE%") do set "RUNPID=%%i"
    echo Service laeuft mit PID !RUNPID!
    echo Log: %USERPROFILE%\.aegis\service-bg.log
) else (
    echo WARNUNG: PID-File nicht erstellt. Pruefe Log.
)
goto :eof
