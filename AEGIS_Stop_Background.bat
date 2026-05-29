@echo off
setlocal enabledelayedexpansion

set "PIDFILE=%USERPROFILE%\.aegis\service.pid"
set "STOPFILE=%USERPROFILE%\.aegis\.stop"

if not exist "%PIDFILE%" (
    echo AEGIS scheint nicht zu laufen ^(kein PID-File^).
    goto :eof
)

> "%STOPFILE%" echo stop
echo Stop-Sentinel gesetzt, warte auf sauberen Shutdown...

set /a "count=0"
:wait_loop
if not exist "%PIDFILE%" goto stopped
if !count! GEQ 8 goto force_kill
timeout /t 1 /nobreak >nul
set /a "count=count+1"
goto wait_loop

:force_kill
echo Sauberer Stop hat zu lange gedauert. Force-Kill...
set "PID="
for /f "usebackq tokens=*" %%i in ("%PIDFILE%") do set "PID=%%i"
if defined PID (
    taskkill /F /PID !PID! >nul 2>&1
)
if exist "%PIDFILE%" del /f /q "%PIDFILE%" >nul 2>&1
if exist "%STOPFILE%" del /f /q "%STOPFILE%" >nul 2>&1
echo Force-Stop ausgefuehrt.
goto :eof

:stopped
echo AEGIS sauber gestoppt.
if exist "%STOPFILE%" del /f /q "%STOPFILE%" >nul 2>&1
goto :eof
