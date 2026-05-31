@echo off
title AEGIS Guard
setlocal enabledelayedexpansion
set "PY=py"
set "PYW=pyw"
set "ROOT=%~dp0"
set "PIDFILE=%USERPROFILE%\.aegis\service.pid"
:menu
cls
echo ================ AEGIS GUARD ================
echo   [1] Start        (service + UI)
echo   [2] Open UI
echo   [3] Stop
echo   [4] Status
echo   --------------------------------------------
echo   [5] First-time setup  (browser host + autostart + baseline)
echo   [6] Autostart ON      [7] Autostart OFF
echo   [8] Re-pin integrity  (after an update)
echo   [0] Exit
echo ============================================
set /p c="Choice: "
if "%c%"=="1" ( start "" /B "%PYW%" "%ROOT%bin\aegis_core_background.pyw" & timeout /t 2 /nobreak >nul & start "" /B "%PYW%" "%ROOT%bin\aegis_shell.py" & echo Started. & pause & goto menu )
if "%c%"=="2" ( start "" /B "%PYW%" "%ROOT%bin\aegis_shell.py" & goto menu )
if "%c%"=="3" ( if exist "%PIDFILE%" ( for /f %%i in (%PIDFILE%) do taskkill /PID %%i /F >nul 2>&1 ) & powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*aegis*' -and $_.Name -like 'python*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1 & echo Stopped ^(service + UI^). & pause & goto menu )
if "%c%"=="4" ( "%PY%" -c "import os;p=os.path.expanduser('~/.aegis/service.pid');print('RUNNING (PID '+open(p).read().strip()+')' if os.path.exists(p) else 'NOT active')" & pause & goto menu )
if "%c%"=="5" ( echo [1/3] Browser host... & "%PY%" "%ROOT%aegis2\setup\install_native_host.py" & echo [2/3] Autostart... & "%PY%" "%ROOT%aegis2\setup\install_autostart.py" & echo [3/3] Integrity baseline... & "%PY%" "%ROOT%aegis2\setup\repin_integrity.py" & echo Setup complete. & pause & goto menu )
if "%c%"=="6" ( "%PY%" "%ROOT%aegis2\setup\install_autostart.py" & echo Autostart ON. & pause & goto menu )
if "%c%"=="7" ( "%PY%" "%ROOT%aegis2\setup\install_autostart.py" --uninstall & echo Autostart OFF. & pause & goto menu )
if "%c%"=="8" ( "%PY%" "%ROOT%aegis2\setup\repin_integrity.py" & pause & goto menu )
if "%c%"=="0" goto ende
echo Invalid choice: %c%
pause
goto menu
:ende
endlocal
exit /b 0
