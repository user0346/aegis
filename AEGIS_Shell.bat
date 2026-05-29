@echo off
REM ==================================================================
REM  AEGIS UI-Shell starten — connected sich an Background-Service
REM ==================================================================
setlocal

set SCRIPT_DIR=%~dp0

REM Pruefe ob Service laeuft
if not exist "%USERPROFILE%\.aegis\service.pid" (
    echo HINWEIS: Background-Service laeuft nicht.
    echo          UI startet trotzdem ^(zeigt DISCONNECTED^).
    echo          Service starten mit AEGIS_Start_Background.bat
    echo.
)

start "" /B pythonw.exe "%SCRIPT_DIR%bin\aegis_shell.py"
endlocal
