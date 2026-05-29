"""Subprocess-Helfer: startet Kindprozesse OHNE sichtbares Konsolenfenster.

Unter pythonw (kein Konsolen-Host) genuegt creationflags=CREATE_NO_WINDOW
NICHT immer — PowerShell/cmd flackern dann gelegentlich kurz auf. Erst die
Kombination mit STARTUPINFO(STARTF_USESHOWWINDOW + wShowWindow=SW_HIDE)
unterdrueckt das Fenster deterministisch.

Alle Module, die PowerShell/cmd aufrufen, nutzen run_hidden() statt
subprocess.run(), damit der Hintergrund-Service (pythonw) nie Fenster aufpoppt.
Das war die Ursache der 2s-PowerShell-Popups des UsbWatcher (v2.0.7).
"""
from __future__ import annotations

import subprocess
import sys

CREATE_NO_WINDOW = 0x08000000
_SW_HIDE = 0  # win32 SW_HIDE


def hidden_startupinfo():
    """STARTUPINFO mit verstecktem Fenster (nur win32, sonst None)."""
    if sys.platform != "win32":
        return None
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = _SW_HIDE
    return si


def run_hidden(args, **kwargs):
    """Wie subprocess.run, aber ohne aufpoppendes Fenster.

    win32: setzt CREATE_NO_WINDOW (mergt mit evtl. uebergebenen creationflags)
    plus STARTUPINFO(SW_HIDE). Auf anderen Plattformen unveraendert.
    """
    if sys.platform == "win32":
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_NO_WINDOW
        if not kwargs.get("startupinfo"):
            kwargs["startupinfo"] = hidden_startupinfo()
    return subprocess.run(args, **kwargs)
