"""AEGIS sauberer Neustart / Stop — robust in Python statt fragiler Batch-Logik.

Aufruf:
  python aegis_restart.py          -> alle AEGIS-Prozesse beenden + frisch starten
  python aegis_restart.py stop     -> nur beenden (kein Neustart)

Killt JEDEN python/pythonw-Prozess, dessen Kommandozeile 'aegis' enthaelt
(also Dienst + Watchdog + Oberflaeche), ausser sich selbst. Kein cmd-Klammer-
Problem, kein Auto-Schliessen.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
AEGISDIR = Path.home() / ".aegis"
ROOT = Path(__file__).resolve().parents[1]          # ...\AEGIS_V2
STOP_ONLY = len(sys.argv) > 1 and sys.argv[1].lower() == "stop"

# Erwartete Interpreter-Namen fuer AEGIS-Hintergrundprozesse.
_EXPECTED_PROC_NAMES = {"pythonw.exe", "python.exe"}


def _pythonw() -> str:
    cand = Path(sys.executable).with_name("pythonw.exe")
    return str(cand) if cand.exists() else "pythonw"


def _pid_is_aegis_process(pid: int) -> bool:
    """Validiert, dass <pid> wirklich ein AEGIS-Prozess ist, bevor wir killen.

    SICHERHEIT: service.pid / watchdog.pid liegen unter ~/.aegis (world-writable).
    Da dieses Skript ELEVATED laufen kann, wuerde ein ungeprueftes
    'taskkill /F /PID' aus einer gespooften PID-Datei einen beliebigen fremden
    (auch System-)Prozess beenden. Wir verifizieren daher per psutil: Prozess
    existiert, Name ist python(w).exe, und die Kommandozeile referenziert das
    AEGIS-Install-Tree. Schlaegt die Pruefung fehl oder fehlt psutil -> NICHT
    killen (fail-closed).
    """
    try:
        import psutil
    except Exception:  # noqa: BLE001
        return False
    try:
        if not psutil.pid_exists(pid):
            return False
        proc = psutil.Process(pid)
        if (proc.name() or "").lower() not in _EXPECTED_PROC_NAMES:
            return False
        cmdline = " ".join(proc.cmdline() or []).lower()
        if "aegis" not in cmdline:
            return False
        root = str(ROOT).lower()
        if root not in cmdline and "aegis_core_background" not in cmdline \
                and "aegis_watchdog" not in cmdline:
            return False
        return True
    except Exception:  # noqa: BLE001
        return False


def _kill_aegis() -> int:
    """Beendet alle AEGIS-python(w)-Prozesse (ausser uns selbst). Returns Anzahl."""
    me = os.getpid()
    killed = 0
    # bevorzugt psutil (sauber)
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                nm = (proc.info.get("name") or "").lower()
                if nm not in ("python.exe", "pythonw.exe"):
                    continue
                cl = " ".join(proc.info.get("cmdline") or []).lower()
                if "aegis" in cl and proc.info["pid"] != me:
                    proc.kill()
                    killed += 1
            except Exception:  # noqa: BLE001
                pass
        return killed
    except Exception:  # noqa: BLE001
        pass
    # Fallback: WMIC (falls psutil fehlt)
    try:
        out = subprocess.run(
            ["wmic", "process", "where",
             "name='pythonw.exe' or name='python.exe'",
             "get", "processid,commandline", "/format:list"],
            capture_output=True, text=True, creationflags=NO_WINDOW).stdout or ""
        cmd = ""
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("CommandLine="):
                cmd = line[len("CommandLine="):]
            elif line.startswith("ProcessId="):
                pid = line[len("ProcessId="):]
                if pid.isdigit() and int(pid) != me and "aegis" in cmd.lower():
                    subprocess.run(["taskkill", "/F", "/PID", pid],
                                   capture_output=True, creationflags=NO_WINDOW)
                    killed += 1
                cmd = ""
    except Exception:  # noqa: BLE001
        pass
    return killed


def main() -> int:
    AEGISDIR.mkdir(exist_ok=True)
    print("=" * 50)
    print(" AEGIS - " + ("Beenden" if STOP_ONLY else "Sauberer Neustart"))
    print("=" * 50)

    # 1) Respawn-Sperre setzen, damit Watchdog/Core nicht sofort neu starten
    print("\n[1/3] Beende alle alten AEGIS-Prozesse ...")
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
                # sonst: gespoofte/fremde PID -> ueberspringen (fail-closed).
                # Der psutil-cmdline-Sweep unten faengt echte AEGIS-Reste sowieso.
            except Exception:  # noqa: BLE001
                pass
            try:
                p.unlink()
            except OSError:
                pass

    # zwei Kill-Runden (faengt Respawn-Reste)
    total = 0
    for _ in range(2):
        total += _kill_aegis()
        time.sleep(1)
    print(f"      {total} Prozess(e) beendet.")

    if STOP_ONLY:
        # .stop bleibt liegen -> kein Auto-Respawn. Naechster regulaerer Start raeumt ihn weg.
        print("\nAEGIS vollstaendig beendet. (Ollama laeuft bewusst separat weiter.)")
        return 0

    # 2) Sperre entfernen
    print("[2/3] Respawn-Sperre entfernen ...")
    try:
        (AEGISDIR / ".stop").unlink()
    except OSError:
        pass
    time.sleep(1)

    # 2b) Integritaets-Baseline neu setzen (nach Code-Aenderungen) -> kein TAMPER/Safe-Mode.
    #     Bewusst NUR im Dev-Neustart (AEGIS_LOKAL) — der Endnutzer-Launcher macht das nicht.
    print("      Integritaets-Baseline aktualisieren (Repin) ...")
    try:
        rp = ROOT / "aegis2" / "setup" / "repin_integrity.py"
        if rp.exists():
            subprocess.run([sys.executable, str(rp)], capture_output=True,
                           timeout=60, creationflags=NO_WINDOW)
    except Exception:  # noqa: BLE001
        pass

    # 3) frisch starten
    print("[3/3] AEGIS frisch starten (neueste Version) ...")
    pyw = _pythonw()
    core = ROOT / "bin" / "aegis_core_background.pyw"
    shell = ROOT / "bin" / "aegis_shell.py"
    try:
        subprocess.Popen([pyw, str(core)], creationflags=NO_WINDOW)
        time.sleep(2)
        subprocess.Popen([pyw, str(shell)], creationflags=NO_WINDOW)
    except Exception as e:  # noqa: BLE001
        print("   FEHLER beim Start:", e)
        return 1
    print("\nFERTIG. Die Oberflaeche oeffnet sich gleich frisch.")
    print("(Falls noch ein altes AEGIS-Fenster offen ist: schliessen.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
