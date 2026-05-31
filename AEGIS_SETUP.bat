@echo off
title AEGIS Guard - Einrichtung
setlocal
set "PY=py"
set "PYW=pyw"
set "ROOT=%~dp0"
echo ==================================================
echo     AEGIS GUARD  -  Einrichtung (alles in einem)
echo ==================================================
echo.
echo [1/4] Browser-Host registrieren (Brave/Chrome/Edge)...
"%PY%" "%ROOT%aegis2\setup\install_native_host.py"
echo.
echo [2/4] Autostart beim Login einrichten...
"%PY%" "%ROOT%aegis2\setup\install_autostart.py"
echo.
echo [3/4] Integritaets-Baseline setzen...
"%PY%" "%ROOT%aegis2\setup\repin_integrity.py"
echo.
echo [4/4] AEGIS starten (Service + Oberflaeche)...
start "" /B "%PYW%" "%ROOT%bin\aegis_core_background.pyw"
timeout /t 2 /nobreak >nul
start "" /B "%PYW%" "%ROOT%bin\aegis_shell.py"
echo.
echo ==================================================
echo     FERTIG. AEGIS laeuft und startet kuenftig
echo     automatisch beim Login (Tray-Icon unten rechts).
echo     Browser-Erweiterung separat laden (siehe INSTALL).
echo ==================================================
echo.
pause
