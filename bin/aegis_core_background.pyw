"""AEGIS Service-Core — Background-Modus (kein Konsolen-Fenster).

Wird mit pythonw.exe gestartet → unsichtbar im Tray-/Background-Layer.
Schreibt PID nach ~/.aegis/service.pid damit der Stop-Helper ihn findet.

Stoppt sauber wenn ~/.aegis/.stop angelegt wird oder per taskkill /F /PID.
"""
import os
import sys
import time
import logging
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PID_FILE = Path.home() / ".aegis" / "service.pid"
STOP_FILE = Path.home() / ".aegis" / ".stop"
LOG_PATH = Path.home() / ".aegis" / "service-bg.log"
WATCHDOG = ROOT / "bin" / "aegis_watchdog.pyw"
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


def _ensure_watchdog() -> None:
    """Startet den Respawn-Watchdog, falls er nicht laeuft (Tamper-Schutz)."""
    if _wd_alive() or not WATCHDOG.exists():
        return
    try:
        cand = Path(sys.executable).parent / "pythonw.exe"
        pyw = str(cand if cand.exists() else sys.executable)
        subprocess.Popen([pyw, str(WATCHDOG)],
                         creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
                         close_fds=True)
    except Exception:  # noqa: BLE001
        pass


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
        token_path = Path.home() / ".aegis" / "ipc_token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(ipc.token, encoding="utf-8")
        # Token-Datei nur fuer den aktuellen User lesbar (defense-in-depth, wie in core.py).
        try:
            import os as _os, sys as _sys
            _os.chmod(token_path, 0o600)
            if _sys.platform == "win32":
                import getpass, subprocess as _sp
                _usr = getpass.getuser()
                _sp.run(["icacls", str(token_path), "/inheritance:r"],
                        capture_output=True, timeout=5)
                r = _sp.run(["icacls", str(token_path), "/grant:r", f"{_usr}:F"],
                            capture_output=True, text=True, timeout=5)
                if r.returncode != 0:
                    log.warning("IPC-Token-ACL-Haertung fehlgeschlagen (icacls rc=%s).",
                                r.returncode)
        except Exception:  # noqa: BLE001
            log.warning("IPC-Token-ACL-Haertung uebersprungen.")
        log.info("IPC running, token persisted (%s)", token_path)

        orch.start_all()
        bus.emit(Event(Severity.INFO, Category.SYSTEM,
                       "AEGIS Background-Service bereit", "background-launcher"))
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
        import threading as _th
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
        log.exception("Background loop crashed")
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
    sys.exit(main())
