"""ProcessWatcher — pollt psutil für neue Prozesse, klassifiziert per Heuristik."""
from __future__ import annotations

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

from ..events import EventBus, Event, Severity, Category
from .. import threat_intel as ti
from .. import adaptive
from .base import Module
import os


class ProcessWatcher(Module):
    name = "ProcessWatcher"

    def __init__(self, bus: EventBus, interval: float = 1.0):
        super().__init__(bus)
        self.interval = interval
        self._seen_pids: set[int] = set()
        self._own_pid = os.getpid()
        self._aegis_pids: set[int] = set()
        self.db = None

    # ---- Active Response ----
    _NEVER_KILL = {
        "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe",
        "runtimebroker.exe", "taskhostw.exe", "ctfmon.exe", "conhost.exe",
        "searchhost.exe", "fontdrvhost.exe", "spoolsv.exe",
        "python.exe", "pythonw.exe",   # AEGIS selbst
    }
    _DROP_ZONES = ("/appdata/local/temp/", "/appdata/roaming/", "/windows/temp/",
                   "/programdata/", "/users/public/", "/$recycle.bin/", "/temp/", "/tmp/")

    def _maybe_neutralize(self, proc, pid, name, exe, classification) -> None:
        """Stoppt MALICIOUS-Prozesse die aus einer untrusted Drop-Zone laufen.
        Whitelist- und Pfad-geschuetzt; per Setting 'enable_active_response' abschaltbar."""
        try:
            if self.db is not None and not bool(self.db.get_setting("enable_active_response", True)):
                return
        except Exception:
            pass
        if (name or "").lower() in self._NEVER_KILL:
            return
        el = (exe or "").lower().replace(chr(92), "/")
        if not el:
            return
        if el.startswith(("c:/windows/", "c:/program files/", "c:/program files (x86)/")):
            return   # signierte System-/Programmpfade nie anfassen
        if not any(z in el for z in self._DROP_ZONES):
            return   # nur Drop-Zonen
        self._neutralize(proc, pid, name, exe)

    def _neutralize(self, proc, pid, name, exe) -> None:
        frozen = killed = False
        try:
            proc.suspend(); frozen = True          # sofort einfrieren -> stoppt weitere Syscalls
        except Exception:
            pass
        try:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except Exception:
                pass
            killed = True
        except Exception:
            pass
        act = "beendet" if killed else ("eingefroren" if frozen else "FEHLGESCHLAGEN (Rechte?)")
        self.emit(Severity.CRITICAL, Category.PROCESS,
                  f"NEUTRALISIERT: {name} (PID {pid}) aus Drop-Zone {act}",
                  {"pid": pid, "name": name, "exe": exe,
                   "action": "terminate" if killed else ("suspend" if frozen else "failed")})
        try:
            ident = (name or "").lower()
            adaptive.learn_from_decision(self.db, "proc", ident,
                                         "malicious", category="PROCESS", base_score=70)
            # Re-Infektion: kehrt derselbe Prozess trotz Neutralisierung wieder?
            n = adaptive.check_reinfection(self.db, "proc", ident)
            if n >= adaptive.REINFECT_THRESHOLD:
                self.emit(Severity.CRITICAL, Category.PROCESS,
                          f"RE-INFEKTION: {name} kehrt trotz Neutralisierung zum {n}. Mal "
                          f"zurueck — Persistenz-Malware, setzt sich selbst neu auf",
                          {"name": name, "exe": exe, "reinfection_count": n,
                           "status": "WIEDERHOLT BLOCKIERT"})
        except Exception:
            pass

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
                        _rs = "; ".join(classification.get("reasons") or [])[:140]
                        _why = (f" — {_rs}" if _rs and _rs != "Keine Auffaelligkeiten" else "")
                        if classification["verdict"] == "malicious":
                            self.emit(Severity.THREAT, Category.PROCESS,
                                      f"MALICIOUS process pattern: {name} (PID {pid}){_why}",
                                      metadata)
                            self._maybe_neutralize(proc, pid, name, exe, classification)
                        elif classification["verdict"] == "suspicious":
                            self.emit(Severity.WARN, Category.PROCESS,
                                      f"Suspicious process: {name} (PID {pid}){_why}", metadata)
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
