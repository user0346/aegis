"""Service-Core entrypoint (no UI).

Boots the Orchestrator + IPC Server, runs until SIGTERM/SCM-stop.
Designed to be invocable in TWO modes:
  1. As a Windows Service (via service.py wrapper).
  2. As a foreground process (for debugging — `python bin/aegis_core.py --foreground`).
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

# Make sibling packages importable when run as script
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis2.shared.events import EventBus, Event, Severity, Category  # noqa: E402
from aegis2.service.ipc_server import IpcServer  # noqa: E402
from aegis2.service.orchestrator import Orchestrator  # noqa: E402


LOG_PATH = Path.home() / ".aegis" / "service.log"


def setup_logging() -> logging.Logger:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_PATH), filemode="a",
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        level=logging.INFO,
    )
    return logging.getLogger("aegis2.service")


def main(foreground: bool = False) -> int:
    log = setup_logging()
    log.info("AEGIS V2 service-core starting (foreground=%s)", foreground)

    bus = EventBus()
    orch = Orchestrator(bus)
    ipc = IpcServer(on_command=orch.handle_command)

    # Bridge bus events to IPC broadcast (subscribed clients only)
    def _on_event(ev: Event) -> None:
        ipc.broadcast({"t": "event", "ev": {
            "ts": ev.ts, "severity": ev.severity, "category": ev.category,
            "source": ev.source, "message": ev.message, "metadata": ev.metadata,
        }})
        # Safety: bei CRITICAL/THREAT auto-demote Autonomy
        if ev.severity in ("CRITICAL", "THREAT"):
            try:
                from aegis2.cognition.autonomy import get_autonomy
                get_autonomy().on_critical_threat(ev.message)
            except Exception:  # noqa: BLE001
                pass
    bus.subscribe(_on_event)

    ipc.start()
    log.info("IPC started, token=%s", ipc.token)
    # Persist token so UI can find it
    token_path = Path.home() / ".aegis" / "ipc_token"
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(ipc.token, encoding="utf-8")

    orch.start_all()
    log.info("Orchestrator started with %d modules", len(orch.modules))
    bus.emit(Event(Severity.INFO, Category.SYSTEM, "AEGIS Service ready", "core"))

    # Run loop
    stop_flag = {"stop": False}

    def _on_signal(*_):
        log.info("SIGTERM/SIGINT received")
        stop_flag["stop"] = True

    if foreground:
        signal.signal(signal.SIGINT, _on_signal)
        signal.signal(signal.SIGTERM, _on_signal)

    try:
        while not stop_flag["stop"]:
            time.sleep(1.0)
    finally:
        log.info("Shutting down")
        orch.stop_all()
        ipc.stop()
        log.info("Stopped")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--foreground", action="store_true",
                    help="Run as foreground process instead of service")
    args = ap.parse_args()
    sys.exit(main(foreground=args.foreground))
