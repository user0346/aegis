@echo off
setlocal enableextensions
title AEGIS - Installation
cd /d "%~dp0"

echo.
echo   ===============================================
echo      AEGIS - Installation
echo   ===============================================
echo.
echo   Installiert AEGIS direkt aus dem Quellcode. Funktioniert auch dort,
echo   wo Windows Smart App Control die unsignierte .exe blockiert.
echo.

REM ---------- 0) Selbstplatzierung: egal wohin entpackt -> fester Install-Ort ----------
REM   AEGIS legt sich selbst nach %LOCALAPPDATA%\Programs\AEGIS, damit der Nutzer den
REM   Download-Ordner danach loeschen kann. Opt-out: eine Datei ".portable" im Ordner.
REM   /XD current schuetzt eine evtl. vorhandene Frozen-Installation (...\AEGIS\current).
set "TARGET=%LOCALAPPDATA%\Programs\AEGIS"
if exist "%~dp0.portable" goto :findpy
if /I "%~dp0"=="%TARGET%\" goto :findpy
echo   [0/3] Platziere AEGIS nach %TARGET% ...
robocopy "%~dp0." "%TARGET%" /MIR /XD .git __pycache__ .venv venv env node_modules current /XF .portable .setup_done /NFL /NDL /NJH /NJS /NP /R:1 /W:1 >nul
if errorlevel 8 (
  echo   [!] Verschieben fehlgeschlagen — fahre an diesem Ort fort.
) else (
  cd /d "%TARGET%"
  echo   [*] AEGIS liegt jetzt unter %TARGET% ^(dieser Download-Ordner kann danach weg^).
)

:findpy
REM ---------- 1) Python finden (py-Launcher bevorzugt, kein Store-Stub) ----------
set "PY="
set "PYW="
py -3 --version >nul 2>nul && ( set "PY=py -3" & set "PYW=pyw -3" )
if not defined PY python --version >nul 2>nul && ( set "PY=python" & set "PYW=pythonw" )
if not defined PY (
  echo   [X] Python wurde nicht gefunden.
  echo.
  echo       Bitte zuerst Python 3.11 oder neuer installieren:
  echo           https://www.python.org/downloads/
  echo       WICHTIG: im Setup das Haekchen "Add python.exe to PATH" setzen.
  echo.
  echo       Danach diese Datei einfach erneut doppelklicken.
  echo.
  start "" "https://www.python.org/downloads/"
  pause
  exit /b 1
)
echo   [1/3] Python gefunden:
%PY% --version

REM ---------- 2) Kern-Abhaengigkeiten ----------
echo.
echo   [2/3] Installiere benoetigte Pakete ^(beim ersten Mal ein paar Minuten^)...
%PY% -m pip install --disable-pip-version-check -r requirements_v2.txt
if errorlevel 1 (
  echo.
  echo   [X] Die Pakete liessen sich nicht installieren.
  echo       Pruefe die Internetverbindung und starte diese Datei erneut.
  echo.
  pause
  exit /b 1
)

REM ---------- 3) Einrichten + Starten ----------
echo.
echo   [3/3] Richte AEGIS ein ^(Autostart, Verknuepfung, Integritaets-Basis^)...
%PY% "bin\aegis_app.py" --setup

echo.
echo   Starte AEGIS...
start "" %PYW% "bin\aegis_app.py"

echo.
echo   Fertig! Das AEGIS-Fenster sollte sich gleich oeffnen, und AEGIS
echo   startet ab jetzt automatisch mit Windows.
echo.
echo   Optional (Sprachsteuerung):  %PY% -m pip install -r requirements_v2_voice.txt
echo.
echo   Dieses Fenster kannst du schliessen.
timeout /t 8 >nul
exit /b 0
