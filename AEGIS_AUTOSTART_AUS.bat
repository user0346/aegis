@echo off
title AEGIS - Autostart entfernen
set "PY=py"
"%PY%" "%~dp0aegis2\setup\install_autostart.py" --uninstall
echo.
pause
