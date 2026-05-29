"""Module base class — daemon thread + stop event + structured emit."""
from __future__ import annotations

import threading
from typing import Optional

from ..events import EventBus, Event, Severity, Category


class Module:
    name: str = "Module"

    def __init__(self, bus: EventBus):
        self.bus = bus
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._running = False

    # ---- lifecycle ----
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._safe_run, name=self.name, daemon=True)
        self._thread.start()
        self.emit(Severity.INFO, Category.SYSTEM, f"{self.name} gestartet")

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self.emit(Severity.INFO, Category.SYSTEM, f"{self.name} gestoppt")

    def is_running(self) -> bool:
        return self._running

    # ---- emit helper ----
    def emit(self, severity: str, category: str, message: str, metadata: Optional[dict] = None) -> None:
        self.bus.emit(Event(severity=severity, category=category, message=message,
                            source=self.name, metadata=metadata or {}))

    # ---- subclass interface ----
    def run(self) -> None:
        raise NotImplementedError

    def _safe_run(self) -> None:
        try:
            self.run()
        except Exception as e:  # noqa: BLE001
            self.emit(Severity.CRITICAL, Category.SYSTEM,
                      f"{self.name} crashed: {type(e).__name__}: {str(e)[:200]}")
