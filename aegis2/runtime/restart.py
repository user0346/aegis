"""AEGIS sauberer Neustart / Stop — importierbare, frozen-aware Variante.

Beendet alle AEGIS-Prozesse (Service + Watchdog + Oberflaeche), ausser sich
selbst, und startet — sofern kein reiner Stop — Core und UI frisch.

Frozen-aware: Im gefrorenen Betrieb heissen die Prozesse AEGIS.exe (nicht
python.exe); Kill-Matching und Respawn laufen daher ueber den zentralen
Launcher (proc_names()/spawn()).

Aufgerufen von:
  - bin/aegis_app.py --restart / --stop        (Quellcode ODER AEGIS.exe)
  - aegis2/service/orchestrator._cmd_system_restart  (In-App-Button)
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from aegis2.shared import launcher

NO_WINDOW = launcher.NO_WINDOW
AEGISDIR = Path.home() / ".aegis"

# Install-Root fuer die cmdline-Validierung: gefroren der Exe-Ordner, sonst Repo-Root.
if launcher.is_frozen():
    ROOT = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parents[2]


def _looks_like_aegis(name: str, cmdline: str) -> bool:
    """True, wenn (name, cmdline) zu einem AEGIS-Prozess passen — frozen ODER Quellcode."""
    if name.lower() not in launcher.proc_names():
        return False
    cl = cmdline.lower()
    if "aegis" not in cl:
        return False
    # Zusatz-Anker, damit nicht irgendein fremder Prozess mit 'aegis' im Pfad getroffen wird.
    anchors = (str(ROOT).lower(), "aegis_core_background", "aegis_watchdog",
               "aegis_app", "--core", "--watchdog", "--shell", "--restart")
    return any(a in cl for a in anchors)


def _pid_is_aegis_process(pid: int) -> bool:
    """Validiert vor dem Kill, dass <pid> wirklich ein AEGIS-Prozess ist.

    SICHERHEIT: service.pid / watchdog.pid liegen unter ~/.aegis. Ein ungeprueftes
    taskkill aus einer gespooften PID-Datei wuerde sonst einen fremden Prozess
    beenden. Ohne psutil -> fail-closed (nicht killen)."""
    try:
        import psutil
    except Exception:  # noqa: BLE001
        return False
    try:
        if not psutil.pid_exists(pid):
            return False
        proc = psutil.Process(pid)
        return _looks_like_aegis(proc.name() or "", " ".join(proc.cmdline() or []))
    except Exception:  # noqa: BLE001
        return False


def _kill_aegis() -> int:
    """Beendet alle AEGIS-Prozesse (ausser uns selbst). Returns Anzahl."""
    me = os.getpid()
    killed = 0
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                nm = proc.info.get("name") or ""
                cl = " ".join(proc.info.get("cmdline") or [])
                if proc.info["pid"] != me and _looks_like_aegis(nm, cl):
                    proc.kill()
                    killed += 1
            except Exception:  # noqa: BLE001
                pass
        return killed
    except Exception:  # noqa: BLE001
        pass
    # Fallback: taskkill ueber WMIC, falls psutil fehlt
    try:
        out = subprocess.run(
            ["wmic", "process", "get", "processid,commandline,name", "/format:list"],
            capture_output=True, text=True, creationflags=NO_WINDOW).stdout or ""
        name = cmd = ""
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("CommandLine="):
                cmd = line[len("CommandLine="):]
            elif line.startswith("Name="):
                name = line[len("Name="):]
            elif line.startswith("ProcessId="):
                pid = line[len("ProcessId="):]
                if pid.isdigit() and int(pid) != me and _looks_like_aegis(name, cmd):
                    subprocess.run(["taskkill", "/F", "/PID", pid],
                                   capture_output=True, creationflags=NO_WINDOW)
                    killed += 1
                name = cmd = ""
    except Exception:  # noqa: BLE001
        pass
    return killed


def main(stop_only: bool = False) -> int:
    AEGISDIR.mkdir(exist_ok=True)

    # 1) Respawn-Sperre setzen, damit Watchdog/Core nicht sofort neu starten
    try:
        (AEGISDIR / ".stop").write_text("stop", encoding="utf-8")
    except OSError:
        pass
    time.sleep(2)

    # PID-Files gezielt killen — aber NUR nach Validierung der PID (s.o.).
    for pf in ("service.pid", "watchdog.pid"):
        p = AEGISDIR / pf
        if p.exists():
            try:
                pid = int(p.read_text(encoding="utf-8").strip())
                if _pid_is_aegis_process(pid):
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                   capture_output=True, creationflags=NO_WINDOW)
            except Exception:  # noqa: BLE001
                pass
            try:
                p.unlink()
            except OSError:
                pass

    # zwei Kill-Runden (faengt Respawn-Reste)
    for _ in range(2):
        _kill_aegis()
        time.sleep(1)

    if stop_only:
        # .stop bleibt liegen -> kein Auto-Respawn. Naechster regulaerer Start raeumt ihn weg.
        return 0

    # 2) Sperre entfernen
    try:
        (AEGISDIR / ".stop").unlink()
    except OSError:
        pass
    time.sleep(1)

    # 2b) Integritaets-Baseline neu setzen (nach Code-Aenderungen) -> kein TAMPER/Safe-Mode.
    #     Im gefrorenen Betrieb ist die Baseline an die Binary gebunden (s. self_protect),
    #     der Repin ist dort ein No-Op, schadet aber nicht.
    launcher.run_blocking("repin", timeout=60)

    # 3) frisch starten (frozen-aware ueber den Launcher)
    launcher.spawn("core")
    time.sleep(2)
    launcher.spawn("shell")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(stop_only=(len(sys.argv) > 1 and sys.argv[1].lower() == "stop")))
