@echo off
title AEGIS Guard - Steuerung
setlocal enabledelayedexpansion
set "PY=py"
set "PYW=pyw"
set "ROOT=%~dp0"
set "PIDFILE=%USERPROFILE%\.aegis\service.pid"
:menu
cls
echo ============== AEGIS GUARD ==============
echo   [1] Starten (Service + Oberflaeche)
echo   [2] Oberflaeche oeffnen
echo   [3] Stoppen
echo   [4] Status
echo   [5] Integritaet neu pinnen (nach Update)
echo   [6] Autostart EIN / [7] Autostart AUS
echo   [0] Schliessen
echo ========================================
set /p c="Auswahl: "
if "%c%"=="1" ( start "" /B "%PYW%" "%ROOT%bin\aegis_core_background.pyw" & timeout /t 2 /nobreak >nul & start "" /B "%PYW%" "%ROOT%bin\aegis_shell.py" & echo gestartet. & pause & goto menu )
if "%c%"=="2" ( start "" /B "%PYW%" "%ROOT%bin\aegis_shell.py" & goto menu )
if "%c%"=="3" ( if exist "%PIDFILE%" ( for /f %%i in (%PIDFILE%) do taskkill /PID %%i /F >nul 2>&1 ) & powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*aegis*' -and $_.Name -like 'python*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1 & echo gestoppt ^(Service + Oberflaeche^). & pause & goto menu )
if "%c%"=="4" ( "%PY%" -c "import os;p=os.path.expanduser('~/.aegis/service.pid');print('LAEUFT (PID '+open(p).read().strip()+')' if os.path.exists(p) else 'NICHT aktiv')" & pause & goto menu )
if "%c%"=="5" ( "%PY%" "%ROOT%aegis2\setup\repin_integrity.py" & pause & goto menu )
if "%c%"=="6" ( "%PY%" "%ROOT%aegis2\setup\install_autostart.py" & echo Autostart EIN. & pause & goto menu )
if "%c%"=="7" ( "%PY%" "%ROOT%aegis2\setup\install_autostart.py" --uninstall & echo Autostart AUS. & pause & goto menu )
if "%c%"=="0" goto ende
echo Ungueltige Auswahl: %c%
pause
goto menu
:ende
endlocal
exit /b 0
