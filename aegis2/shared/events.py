"""Event-Bus + Event type.

The Event-Bus runs INSIDE the service-core process. UI subscribers are remote
(over IPC). The Bus knows nothing about Qt — it's pure Python threading.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional


# ---- Severity / Category constants ----
class Severity:
    INFO = "INFO"
    WARN = "WARN"
    THREAT = "THREAT"
    CRITICAL = "CRITICAL"
    QUARANTINE = "QUARANTINE"


class Category:
    FILE = "FILE"
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    URL = "URL"
    DNS = "DNS"
    SYSTEM = "SYSTEM"
    QUARANTINE = "QUARANTINE"
    VOICE = "VOICE"
    TAMPER = "TAMPER"          # NEU in V2


@dataclass
class Event:
    severity: str
    category: str
    message: str
    source: str = ""
    metadata: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, s: str) -> "Event":
        d = json.loads(s)
        return cls(**d)


class EventBus:
    """Thread-safe pub/sub. Listeners run inline; exceptions are isolated."""

    def __init__(self):
        self._listeners: list[Callable[[Event], None]] = []
        self._lock = threading.Lock()

    def subscribe(self, cb: Callable[[Event], None]) -> None:
        with self._lock:
            self._listeners.append(cb)

    def unsubscribe(self, cb: Callable[[Event], None]) -> None:
        with self._lock:
            try:
                self._listeners.remove(cb)
            except ValueError:
                pass

    def emit(self, ev: Event) -> None:
        with self._lock:
            cbs = list(self._listeners)
        for cb in cbs:
            try:
                cb(ev)
            except Exception:  # noqa: BLE001
                # listener-isolation: one bad listener can't break the bus
                pass
