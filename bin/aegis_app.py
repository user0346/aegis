"""AEGIS — Einzel-Binary-Entry (Multi-Call-Launcher).

EINE ausfuehrbare Datei, mehrere Rollen — gesteuert per Flag. Genau dieses
Skript wird von PyInstaller zu AEGIS.exe eingefroren; die gefrorene Binary ruft
sich selbst mit denselben Flags erneut auf (sys.executable --core, ...).

  (kein Flag / --shell)  UI-Shell starten  (stellt zugleich sicher, dass der
                         Hintergrund-Service laeuft -> Endnutzer doppelklickt NUR die App)
  --core                 Hintergrund-Service (Pipe-Server + Monitoring)
  --watchdog             Respawn-Watchdog (Tamper-Schutz)
  --restart              sauberer Neustart aller AEGIS-Prozesse
  --stop                 alles beenden (kein Respawn)
  --repin                Integritaets-Baseline neu setzen
  --setup                Ersteinrichtung (Autostart + Baseline)

Aus dem Quellcode existieren weiterhin die bin/*.pyw-Shims (Rueckwaerts-Kompat.).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Quellcode-Modus: Repo-Root auf den Importpfad. Gefroren erledigt das PyInstaller.
if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _service_alive() -> bool:
    pid_file = Path.home() / ".aegis" / "service.pid"
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
            os.kill(pid, 0)   # wirft, wenn Prozess weg
            return True
    except Exception:  # noqa: BLE001
        return False


def _ensure_core_running() -> None:
    """Startet den Core, falls kein lebender Service da ist (fuer den UI-Start)."""
    if _service_alive():
        return
    from aegis2.shared import launcher
    # frischer Start: evtl. liegengebliebenes Stop-Sentinel entfernen, sonst
    # beendet sich der frische Core sofort wieder.
    try:
        (Path.home() / ".aegis" / ".stop").unlink()
    except Exception:  # noqa: BLE001
        pass
    launcher.spawn("core")


def _mode_from_argv() -> str:
    for a in sys.argv[1:]:
        if a.startswith("-"):
            return a.lstrip("-").lower()
    return "shell"


def main() -> int:
    mode = _mode_from_argv()

    if mode == "core":
        from aegis2.runtime.service import main as m
        return m()
    if mode in ("watchdog", "wd"):
        from aegis2.runtime.watchdog import main as m
        return m()
    if mode == "restart":
        from aegis2.runtime.restart import main as m
        return m()
    if mode == "stop":
        from aegis2.runtime.restart import main as m
        return m(stop_only=True)
    if mode == "repin":
        from aegis2.setup import repin_integrity
        try:
            repin_integrity.main()
        except Exception:  # noqa: BLE001
            pass
        return 0
    if mode == "setup":
        from aegis2.runtime.setup_all import main as m
        return m()

    # default: UI-Shell (und sicherstellen, dass der Hintergrund-Schutz laeuft)
    _ensure_core_running()
    from aegis2.ui.app import run
    return run()


if __name__ == "__main__":
    sys.exit(main())
