"""ProcessWatcher — pollt psutil für neue Prozesse, klassifiziert per Heuristik."""
from __future__ import annotations

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

from ..events import EventBus, Event, Severity, Category
from .. import threat_intel as ti
from .base import Module
import os


class ProcessWatcher(Module):
    name = "ProcessWatcher"

    def __init__(self, bus: EventBus, interval: float = 1.5):
        super().__init__(bus)
        self.interval = interval
        self._seen_pids: set[int] = set()
        self._own_pid = os.getpid()
        self._aegis_pids: set[int] = set()
        self.db = None

    def run(self) -> None:
        if not psutil:
            self.emit(Severity.WARN, Category.SYSTEM,
                      "psutil fehlt — ProcessWatcher inaktiv")
            return
        try:
            from ..db import get_db
            self.db = get_db()
        except Exception:
            self.db = None
        try:
            self._seen_pids = set(p.pid for p in psutil.process_iter())
        except psutil.Error:
            self._seen_pids = set()

        while not self._stop.is_set():
            try:
                current = {p.pid: p for p in psutil.process_iter(
                    ["pid", "name", "exe", "cmdline", "ppid"])}
                new_pids = set(current.keys()) - self._seen_pids
                for pid in new_pids:
                    proc = current.get(pid)
                    if not proc:
                        continue
                    try:
                        info = proc.info
                        name = info.get("name") or ""
                        exe = info.get("exe") or ""
                        cmdline_list = info.get("cmdline") or []
                        cmdline = " ".join(cmdline_list)
                        ppid = info.get("ppid") or 0
                        if ppid == self._own_pid or ppid in self._aegis_pids:
                            self._aegis_pids.add(pid)
                            continue
                        classification = ti.classify_process(name, cmdline, exe)
                        metadata = {
                            "pid": pid, "ppid": ppid, "name": name, "exe": exe,
                            "cmdline": cmdline[:300],
                            "verdict": classification["verdict"],
                            "reasons": classification["reasons"],
                            "score": classification["score"],
                        }
                        if classification["verdict"] == "malicious":
                            self.emit(Severity.THREAT, Category.PROCESS,
                                      f"MALICIOUS process pattern: {name} (PID {pid})",
                                      metadata)
                        elif classification["verdict"] == "suspicious":
                            self.emit(Severity.WARN, Category.PROCESS,
                                      f"Suspicious process: {name} (PID {pid})", metadata)
                        else:
                            _bl = self.db.baseline_observe("proc", name) if self.db else {"status": "new"}
                            if _bl.get("status") != "known":
                                self.emit(Severity.INFO, Category.PROCESS,
                                          f"Neuer Prozess: {name} (PID {pid})", metadata)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                self._seen_pids = set(current.keys())
            except psutil.Error as e:
                self.emit(Severity.WARN, Category.SYSTEM,
                          f"ProcessWatcher Fehler: {e}")
            self._stop.wait(self.interval)
