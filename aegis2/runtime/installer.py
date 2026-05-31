"""Selbst-Installation / Relocation der gefrorenen AEGIS.exe.

Wird beim Start aufgerufen (bin/aegis_app.py). Laeuft die App aus einem 'losen'
Ort (Downloads/Desktop/Temp — wo Endnutzer eine ZIP einfach entpacken), kopiert
sie sich an einen FESTEN, user-eigenen Pfad und startet von dort neu; der
Download-Rest wird nach dem Beenden per fensterlosem Helfer geloescht.

2026-Best-Practice (VS Code / Chrome / Velopack): fester Pfad
  %LOCALAPPDATA%\\Programs\\AEGIS\\current
— NIE versioniert. Ein wechselnder Pfad bricht Verknuepfungen, Taskleisten-Pins,
Autostart, Firewall-Regeln und Defender-Ausnahmen bei jedem Update. Updates
ersetzen daher NUR den Inhalt dieses festen Ordners (robocopy /MIR).

Alles laeuft rein im User-Modus: kein Admin, kein UAC, kein Fremd-Installer.
Wer portabel bleiben will, legt eine Datei `.portable` neben die AEGIS.exe.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_CREATE_NO_WINDOW = 0x08000000
_DETACHED = 0x00000008
SETUP_MARKER = ".setup_done"     # liegt im Install-Ordner, sobald Erst-Setup lief


def canonical_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "Programs" / "AEGIS" / "current"


def _norm(p: Path) -> str:
    try:
        return os.path.normcase(os.path.normpath(os.path.realpath(str(p))))
    except Exception:  # noqa: BLE001
        return os.path.normcase(os.path.normpath(str(p)))


def is_canonical() -> bool:
    """True, wenn die laufende .exe bereits am festen Install-Pfad liegt."""
    if not getattr(sys, "frozen", False):
        return False
    return _norm(Path(sys.executable).resolve().parent) == _norm(canonical_dir())


def _is_loose_location(d: Path) -> bool:
    """True, wenn d unter Downloads/Desktop/Temp liegt (typischer 'einfach entpackt'-Ort)."""
    nd = _norm(d)
    home = os.environ.get("USERPROFILE") or str(Path.home())
    cands = [
        Path(home) / "Downloads", Path(home) / "Desktop",
        Path(home) / "OneDrive" / "Desktop", Path(home) / "OneDrive" / "Downloads",
    ]
    for var in ("TEMP", "TMP"):
        v = os.environ.get(var)
        if v:
            cands.append(Path(v))
    for c in cands:
        nc = _norm(c)
        if nd == nc or nd.startswith(nc + os.sep):
            return True
    return ("\\downloads\\" in nd or nd.endswith("\\downloads")
            or "\\desktop\\" in nd or "\\temp\\" in nd)


def _spawn_cleanup_helper(src: Path) -> None:
    """Loescht den urspruenglichen (Download-)Ordner, NACHDEM wir uns beendet haben.
    Der Helfer liegt in %TEMP% (ausserhalb von src) und loescht sich selbst.
    SICHERHEIT: Pfad als single-quoted PowerShell-Literal -LiteralPath -> kein $-,
    Backtick- oder Wildcard-Interpretieren; eingebettete ' werden verdoppelt."""
    pid = os.getpid()
    lit = str(src).replace("'", "''")
    ps = (
        "$ErrorActionPreference='SilentlyContinue'\r\n"
        f"try{{ Wait-Process -Id {pid} -Timeout 90 }} catch {{}}\r\n"
        "Start-Sleep -Seconds 1\r\n"
        f"Remove-Item -LiteralPath '{lit}' -Recurse -Force\r\n"
        "Remove-Item -LiteralPath $PSCommandPath -Force\r\n"
    )
    try:
        fd, path = tempfile.mkstemp(suffix=".ps1", prefix="aegis_relocate_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(ps)
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", path],
            creationflags=_CREATE_NO_WINDOW | _DETACHED, close_fds=True)
    except Exception:  # noqa: BLE001
        pass


def maybe_self_install() -> bool:
    """Relocate aus einem losen Ort an den festen Pfad. Returns True, wenn relocated
    und die installierte Kopie gestartet wurde -> der Aufrufer soll sich beenden."""
    if not getattr(sys, "frozen", False):
        return False
    src = Path(sys.executable).resolve().parent          # ...\AEGIS (onedir-Ordner)
    canonical = canonical_dir()
    if _norm(src) == _norm(canonical):
        return False                                     # laeuft schon am festen Ort
    if (src / ".portable").exists():
        return False                                     # bewusst portabel
    if not _is_loose_location(src):
        return False                                     # bewusster Ort -> nicht verschieben

    inst_exe = canonical / "AEGIS.exe"
    try:
        canonical.parent.mkdir(parents=True, exist_ok=True)
        if not inst_exe.exists():
            staging = canonical.parent / "current.new"
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
            shutil.copytree(src, staging)                # ganzes Bundle inkl. _internal
            if canonical.exists():
                old = canonical.parent / "current.old"
                if old.exists():
                    shutil.rmtree(old, ignore_errors=True)
                os.replace(str(canonical), str(old))     # gleiches Volume -> atomar
                shutil.rmtree(old, ignore_errors=True)
            os.replace(str(staging), str(canonical))
    except Exception:  # noqa: BLE001
        return False                                     # Kopieren fehlgeschlagen -> portabel weiterlaufen
    if not inst_exe.exists():
        return False

    try:
        subprocess.Popen([str(inst_exe)], cwd=str(canonical),
                         creationflags=_CREATE_NO_WINDOW)
    except Exception:  # noqa: BLE001
        return False
    _spawn_cleanup_helper(src)
    return True


def run_first_time_setup_if_needed() -> None:
    """Beim ALLERERSTEN Start am festen Pfad: Autostart + Verknuepfungen + Baseline
    einrichten (zeigen dann auf den festen Pfad). Marker verhindert Wiederholung."""
    if not is_canonical():
        return
    marker = canonical_dir() / SETUP_MARKER
    if marker.exists():
        return
    try:
        from aegis2.runtime.setup_all import main as setup_main
        setup_main()
    except Exception:  # noqa: BLE001
        pass
    try:
        marker.write_text("ok", encoding="utf-8")
    except OSError:
        pass
