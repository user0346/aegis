"""AEGIS Watchdog — Respawn-Schutz (Tamper-Stufe 1).

Laeuft als eigener pythonw-Prozess. Prueft im Sekundentakt, ob der
Service-Core lebt. Wird der Core gekillt (Task-Manager, kill), startet der
Watchdog ihn binnen Sekunden neu. Der Core ueberwacht umgekehrt den Watchdog —
beide stoppen dauerhaft nur durch GLEICHZEITIGES Beenden.

Legitimer Stop: ~/.aegis/.stop anlegen -> Watchdog respawnt NICHT mehr und
beendet sich selbst. (Im spaeteren System-Dienst liegt .stop im
SYSTEM-geschuetzten Pfad, sodass Dritte ihn nicht ausloesen koennen.)
"""
import os
import sys
import time
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

AEGIS_DIR = Path.home() / ".aegis"
WD_PID    = AEGIS_DIR / "watchdog.pid"
SVC_PID   = AEGIS_DIR / "service.pid"
STOP_FILE = AEGIS_DIR / ".stop"
LAUNCHER  = ROOT / "bin" / "aegis_core_background.pyw"
CHECK_SEC = 3
# Fail-safe: crasht der Core wiederholt, NICHT endlos respawnen (kein Lahmlegen).
MAX_RESPAWNS = 5        # max Neustarts ...
RESPAWN_WINDOW = 120    # ... in diesem Zeitfenster (Sekunden), sonst aufgeben


def _pid_alive(pid_file: Path) -> bool:
    try:
        if not pid_file.exists():
            return False
        pid = int(pid_file.read_text(encoding="utf-8").strip() or "0")
        if pid <= 0:
            return False
        try:
            import psutil
            return psutil.pid_exists(pid)
        except Exception:  # noqa: BLE001
            os.kill(pid, 0)   # Fallback: wirft, wenn Prozess weg
            return True
    except Exception:  # noqa: BLE001
        return False


def _pythonw() -> str:
    cand = Path(sys.executable).parent / "pythonw.exe"
    return str(cand if cand.exists() else sys.executable)


def _spawn_core() -> None:
    try:
        subprocess.Popen([_pythonw(), str(LAUNCHER)],
                         creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
                         close_fds=True)
    except Exception:  # noqa: BLE001
        pass


def main() -> int:
    AEGIS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        WD_PID.write_text(str(os.getpid()), encoding="utf-8")
    except OSError:
        pass
    respawns: list = []
    try:
        while True:
            if STOP_FILE.exists():
                break                       # legitimer Stop -> kein Respawn
            if not _pid_alive(SVC_PID):
                now = time.time()
                respawns[:] = [t for t in respawns if now - t < RESPAWN_WINDOW]
                if len(respawns) >= MAX_RESPAWNS:
                    # Fail-safe: Core crasht wiederholt -> aufgeben statt PC lahmlegen.
                    # Sentinel setzen, damit der User in Ruhe eingreifen kann.
                    try:
                        STOP_FILE.write_text("crashloop", encoding="utf-8")
                    except OSError:
                        pass
                    break
                respawns.append(now)
                _spawn_core()
                time.sleep(5)               # dem Core Zeit zum Hochfahren geben
            time.sleep(CHECK_SEC)
    finally:
        try:
            WD_PID.unlink(missing_ok=True)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
