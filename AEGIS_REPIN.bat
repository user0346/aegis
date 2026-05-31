@echo off
title AEGIS - Integritaets-Baseline neu setzen
set "PY=py"
echo Setzt die Integritaets-Pruefsumme nach einem Update neu + holt AEGIS aus dem Safe-Mode.
echo.
"%PY%" "%~dp0aegis2\setup\repin_integrity.py"
echo.
pause
