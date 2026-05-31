"""AEGIS Watchdog — Respawn-Schutz (Tamper-Stufe 1) — importierbare Variante.

Prueft im Sekundentakt, ob der Service-Core lebt. Wird der Core gekillt
(Task-Manager, kill), startet der Watchdog ihn binnen Sekunden neu. Der Core
ueberwacht umgekehrt den Watchdog — beide stoppen dauerhaft nur durch
GLEICHZEITIGES Beenden.

Legitimer Stop: ~/.aegis/.stop anlegen -> Watchdog respawnt NICHT mehr und
beendet sich selbst.

Aufgerufen von bin/aegis_watchdog.pyw (Quellcode) bzw. AEGIS.exe --watchdog.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from aegis2.shared import launcher

AEGIS_DIR = Path.home() / ".aegis"
WD_PID    = AEGIS_DIR / "watchdog.pid"
SVC_PID   = AEGIS_DIR / "service.pid"
STOP_FILE = AEGIS_DIR / ".stop"
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
                launcher.spawn("core")      # frozen-aware (AEGIS.exe --core bzw. pyw)
                time.sleep(5)               # dem Core Zeit zum Hochfahren geben
            time.sleep(CHECK_SEC)
    finally:
        try:
            WD_PID.unlink(missing_ok=True)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
