"""AEGIS Service-Core — Background-Modus (kein Konsolen-Fenster).

Wird mit pythonw.exe gestartet → unsichtbar im Tray-/Background-Layer.
Schreibt PID nach ~/.aegis/service.pid damit der Stop-Helper ihn findet.

Stoppt sauber wenn ~/.aegis/.stop angelegt wird oder per taskkill /F /PID.
"""
import os
import sys
import time
import logging
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PID_FILE = Path.home() / ".aegis" / "service.pid"
STOP_FILE = Path.home() / ".aegis" / ".stop"
LOG_PATH = Path.home() / ".aegis" / "service-bg.log"


def main() -> int:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_PATH), filemode="a",
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        level=logging.INFO,
    )
    log = logging.getLogger("aegis.bg")
    log.info("Background-Launcher start, PID=%d", os.getpid())

    # PID-File schreiben
    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    # Stop-Sentinel löschen, falls noch da
    try:
        if STOP_FILE.exists():
            STOP_FILE.unlink()
    except OSError:
        pass

    try:
        from aegis2.shared.events import EventBus, Event, Severity, Category
        from aegis2.service.ipc_server import IpcServer
        from aegis2.service.orchestrator import Orchestrator

        bus = EventBus()
        orch = Orchestrator(bus)
        ipc = IpcServer(on_command=orch.handle_command)

        def _on_event(ev: Event) -> None:
            ipc.broadcast({"t": "event", "ev": {
                "ts": ev.ts, "severity": ev.severity, "category": ev.category,
                "source": ev.source, "message": ev.message, "metadata": ev.metadata,
            }})
        bus.subscribe(_on_event)

        ipc.start()
        log.info("IPC running, token persisted")
        token_path = Path.home() / ".aegis" / "ipc_token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(ipc.token, encoding="utf-8")

        orch.start_all()
        bus.emit(Event(Severity.INFO, Category.SYSTEM,
                       "AEGIS Background-Service bereit", "background-launcher"))
        log.info("Started %d modules", len(orch.modules))

        # Polling-Loop: stoppt wenn .stop-Sentinel auftaucht
        while True:
            if STOP_FILE.exists():
                log.info("Stop-Sentinel gefunden -> shutdown")
                break
            time.sleep(2.0)

        orch.stop_all()
        ipc.stop()
        log.info("Stopped cleanly")
    except Exception:  # noqa: BLE001
        log.exception("Background loop crashed")
        return 1
    finally:
        try:
            PID_FILE.unlink(missing_ok=True)
            STOP_FILE.unlink(missing_ok=True)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
