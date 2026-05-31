"""Zentrale, frozen-aware Start-Logik fuer AEGIS.

EINE Stelle entscheidet, WIE eine AEGIS-Rolle (Core, Watchdog, Shell, Restart,
Repin, Setup) gestartet wird — unabhaengig davon, ob die App als gefrorene
PyInstaller-Binary (AEGIS.exe) oder aus dem Quellcode (py/pyw) laeuft. So gibt
es keine zweite Stelle, die im .exe-Fall stillschweigend bricht.

  Gefroren:   [<...>\\AEGIS.exe, "--core"]
  Quellcode:  [pythonw.exe, "<...>\\bin\\aegis_app.py", "--core"]

Damit ein Endnutzer NUR die .exe doppelklickt: Die UI startet bei Bedarf den
Core selbst (s. bin/aegis_app.py), und alle In-App-Buttons (Neustart, Autostart,
Repin, Setup) laufen ueber genau diese Funktionen.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Repo-Root (…/AEGIS_V2) — nur im Quellcode-Modus relevant; gefroren ignoriert.
ROOT = Path(__file__).resolve().parents[2]
_ENTRY = ROOT / "bin" / "aegis_app.py"

NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0   # CREATE_NO_WINDOW
DETACHED  = 0x00000008 if sys.platform == "win32" else 0   # DETACHED_PROCESS

VALID_MODES = ("core", "watchdog", "shell", "restart", "repin", "setup", "stop")


def is_frozen() -> bool:
    """True, wenn als PyInstaller-Binary (AEGIS.exe) gestartet."""
    return bool(getattr(sys, "frozen", False))


def app_path() -> str:
    """Pfad der laufenden App (gefroren: AEGIS.exe, sonst der Interpreter)."""
    return sys.executable


def _pythonw() -> str:
    cand = Path(sys.executable).with_name("pythonw.exe")
    return str(cand) if cand.exists() else sys.executable


def argv_for(mode: str) -> list[str]:
    """Argv, um AEGIS im gegebenen Modus zu starten — gefroren ODER aus Quellcode."""
    if mode not in VALID_MODES:
        raise ValueError(f"unbekannter Modus: {mode!r}")
    if is_frozen():
        return [sys.executable, "--" + mode]
    return [_pythonw(), str(_ENTRY), "--" + mode]


def spawn(mode: str, *, detached: bool = True):
    """Startet eine AEGIS-Rolle fensterlos im Hintergrund. Returns Popen oder None."""
    flags = NO_WINDOW | (DETACHED if detached else 0)
    try:
        return subprocess.Popen(argv_for(mode), creationflags=flags, close_fds=True)
    except Exception:  # noqa: BLE001
        return None


def run_blocking(mode: str, *, timeout: float | None = 90) -> int:
    """Startet eine Rolle und wartet (fuer kurze Setup-Aktionen). Returns rc."""
    try:
        r = subprocess.run(argv_for(mode), capture_output=True,
                           timeout=timeout, creationflags=NO_WINDOW)
        return r.returncode
    except Exception:  # noqa: BLE001
        return 1


def proc_names() -> set[str]:
    """Akzeptable Prozessnamen fuer 'ist das ein AEGIS-Prozess?'-Pruefungen.

    Quellcode: python(w).exe. Gefroren: zusaetzlich der Name der App-Binary
    (z.B. aegis.exe), damit Restart/Kill die gefrorenen Prozesse findet."""
    names = {"python.exe", "pythonw.exe"}
    if is_frozen():
        names.add(Path(sys.executable).name.lower())
    return names
