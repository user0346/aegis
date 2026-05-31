"""AEGIS Service-Core (Hintergrund) — importierbare Variante.

Enthaelt die komplette Core-Schleife (EventBus + Orchestrator + IPC-Pipe-
Server). Aufgerufen von:
  - bin/aegis_core_background.pyw   (Quellcode, pythonw — Rueckwaerts-Kompat.)
  - bin/aegis_app.py --core         (Quellcode ODER gefrorene AEGIS.exe)

Schreibt PID nach ~/.aegis/service.pid; stoppt sauber, sobald ~/.aegis/.stop
auftaucht oder der Prozess per taskkill beendet wird.
"""
from __future__ import annotations

import logging
import os
import threading as _th
import time
from pathlib import Path

from aegis2.shared import launcher

PID_FILE = Path.home() / ".aegis" / "service.pid"
STOP_FILE = Path.home() / ".aegis" / ".stop"
LOG_PATH = Path.home() / ".aegis" / "service-bg.log"
WD_PID = Path.home() / ".aegis" / "watchdog.pid"


def _wd_alive() -> bool:
    try:
        pid = int(WD_PID.read_text(encoding="utf-8").strip() or "0")
        if pid <= 0:
            return False
        try:
            import psutil
            return psutil.pid_exists(pid)
        except Exception:  # noqa: BLE001
            os.kill(pid, 0)
            return True
    except Exception:  # noqa: BLE001
        return False


_LAST_WD_SPAWN = 0.0


def _ensure_watchdog() -> None:
    """Startet den Respawn-Watchdog, falls er nicht laeuft (Tamper-Schutz).
    Frozen-aware ueber den zentralen Launcher (AEGIS.exe --watchdog bzw. pyw).

    Debounce: nach einem Spawn ~12s lang nicht erneut spawnen. Der (gefrorene)
    Watchdog braucht einen Moment zum Hochfahren, bis er seine PID schreibt —
    ohne Debounce wuerde die 2s-Pruefschleife einen ZWEITEN Watchdog starten."""
    global _LAST_WD_SPAWN
    if _wd_alive():
        return
    if time.time() - _LAST_WD_SPAWN < 12.0:
        return
    _LAST_WD_SPAWN = time.time()
    launcher.spawn("watchdog")


def main() -> int:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_PATH), filemode="a",
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        level=logging.INFO,
    )
    log = logging.getLogger("aegis.bg")
    log.info("Core-Launcher start, PID=%d, frozen=%s", os.getpid(), launcher.is_frozen())

    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
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
        token_path = Path.home() / ".aegis" / "ipc_token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        # Evtl. kaputte ACL eines Vorlaufs nicht uebernehmen: erst loeschen (geht ueber
        # das Ordner-Recht), dann frisch schreiben -> erbt saubere, lesbare Rechte.
        try:
            token_path.unlink()
        except Exception:  # noqa: BLE001
            pass
        token_path.write_text(ipc.token, encoding="utf-8")
        # Token nur fuer den aktuellen User lesbar (defense-in-depth). WICHTIG: in EINEM
        # icacls-Aufruf (Vererbung entfernen UND Grant zusammen) — getrennte Aufrufe koennen
        # die Datei UNLESBAR machen, wenn der zweite fehlschlaegt (-> UI koppelt sich ab).
        # Bei Fehler: /reset, damit die Datei garantiert lesbar bleibt.
        try:
            import sys as _sys
            if _sys.platform == "win32":
                import getpass, subprocess as _sp
                _usr = getpass.getuser()
                r = _sp.run(["icacls", str(token_path), "/inheritance:r",
                             "/grant:r", f"{_usr}:F"],
                            capture_output=True, text=True, timeout=5)
                if r.returncode != 0:
                    log.warning("IPC-Token-ACL-Haertung fehlgeschlagen (rc=%s) — /reset, "
                                "Datei bleibt lesbar.", r.returncode)
                    _sp.run(["icacls", str(token_path), "/reset"],
                            capture_output=True, timeout=5)
        except Exception:  # noqa: BLE001
            log.warning("IPC-Token-ACL-Haertung uebersprungen.")
        log.info("IPC running, token persisted (%s)", token_path)

        orch.start_all()
        bus.emit(Event(Severity.INFO, Category.SYSTEM,
                       "AEGIS Background-Service bereit", "core-launcher"))
        log.info("Started %d modules", len(orch.modules))

        # Lokale KI (Ollama) automatisch hochfahren, falls installiert aber gestoppt
        def _ollama_autostart():
            try:
                from aegis2.voice.ollama_setup import is_installed, ensure_running
                if is_installed():
                    ensure_running(timeout=20)
                    log.info("Ollama auto-start ok")
            except Exception:  # noqa: BLE001
                pass
        _th.Thread(target=_ollama_autostart, daemon=True).start()

        # cosign fuer Update-Verifikation bereitstellen (self-bootstrapping, Hintergrund)
        def _cosign_ensure():
            try:
                from aegis2.shared.github_updater import ensure_cosign
                ensure_cosign()
            except Exception:  # noqa: BLE001
                pass
        _th.Thread(target=_cosign_ensure, daemon=True).start()

        # Respawn-Watchdog starten + in der Loop am Leben halten (gegenseitig)
        _ensure_watchdog()
        log.info("Watchdog gestartet (Respawn-Schutz aktiv)")

        # Polling-Loop: stoppt wenn .stop-Sentinel auftaucht
        while True:
            if STOP_FILE.exists():
                log.info("Stop-Sentinel gefunden -> shutdown")
                break
            _ensure_watchdog()
            time.sleep(2.0)

        orch.stop_all()
        ipc.stop()
        log.info("Stopped cleanly")
    except Exception:  # noqa: BLE001
        log.exception("Core loop crashed")
        return 1
    finally:
        try:
            PID_FILE.unlink(missing_ok=True)
            # STOP_FILE bleibt bestehen, damit der Watchdog NICHT respawnt;
            # wird beim naechsten regulaeren Start geloescht (Race-Schutz).
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
