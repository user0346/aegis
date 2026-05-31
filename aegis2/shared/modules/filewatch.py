"""FileWatcher — beobachtet Downloads/Desktop/Documents via watchdog.

Neue EXEs werden gehasht, klassifiziert und (bei first-seen oder
suspicious-Verdict) in den QuarantineManager geschoben.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    Observer = None
    FileSystemEventHandler = object  # type: ignore

from ..db import Database
from ..events import EventBus, Event, Severity, Category
from .. import threat_intel as ti
from .base import Module
from .quarantine import QuarantineManager


def _expand_watch_folders() -> list[Path]:
    """Standard-Watch-Ordner inkl. der haeufigsten Malware-Drop-Zonen
    (%TEMP%, %LOCALAPPDATA%\\Temp, %APPDATA%\\Roaming, C:\\Windows\\Temp)."""
    home = Path.home()
    cands = [home / "Downloads", home / "Desktop", home / "Documents"]
    for ev in ("TEMP", "TMP"):
        v = os.environ.get(ev)
        if v:
            cands.append(Path(v))
    la = os.environ.get("LOCALAPPDATA")
    if la:
        cands.append(Path(la) / "Temp")
    # %APPDATA%\\Roaming und C:\\Windows\\Temp werden NICHT live ueberwacht
    # (zu viele Schreibvorgaenge -> Dauerlast). Der On-Demand-Full-Scan deckt sie ab.
    out, seen = [], set()
    for pth in cands:
        try:
            r = pth.resolve()
        except Exception:
            r = pth
        if r in seen:
            continue
        seen.add(r)
        out.append(pth)
    return out


WATCH_FOLDERS_DEFAULT = _expand_watch_folders()

# Potenziell ausfuehrbare Endungen — in Temp/AppData wird NUR darauf reagiert.
_EXEC_EXTS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".ps1", ".psm1",
              ".vbs", ".vbe", ".js", ".jse", ".jar", ".msi", ".msp", ".pif",
              ".hta", ".wsf", ".wsh", ".cpl", ".sys", ".lnk", ".reg", ".scf"}


# VT-Key wird EINMAL entschluesselt (DPAPI) und gecacht — nicht pro Datei.
_VT_KEY_CACHE: dict = {"loaded": False, "key": None}


def _vt_callback():
    """Liefert vt_lookup_cb(sha)->dict wenn ein VT-Key gesetzt ist, sonst None.
    Key bleibt lokal/DPAPI; Lookup ist ein read-only GET via threat_intel."""
    if not _VT_KEY_CACHE["loaded"]:
        try:
            from ...cognition.secrets_store import get_secret
            _VT_KEY_CACHE["key"] = get_secret("vt_api_key")
        except Exception:  # noqa: BLE001
            _VT_KEY_CACHE["key"] = None
        _VT_KEY_CACHE["loaded"] = True
    key = _VT_KEY_CACHE["key"]
    if not key:
        return None
    from ..threat_intel import vt_lookup_hash
    return lambda h: vt_lookup_hash(h, key)


class _FsEventHandler(FileSystemEventHandler):  # type: ignore
    def __init__(self, callback):
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self.callback("created", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.callback("moved", event.dest_path)


class FileWatcher(Module):
    name = "FileWatcher"

    def __init__(self, bus: EventBus, db: Database, quarantine: QuarantineManager,
                 folders: Optional[list[Path]] = None,
                 auto_quarantine_executables: bool = True):
        super().__init__(bus)
        self.db = db
        self.quarantine = quarantine
        self.folders = folders or WATCH_FOLDERS_DEFAULT
        self.auto_quarantine = auto_quarantine_executables
        self._observer = None
        # Self-Exclude: eigenen Projekt-Baum NIE anfassen (sonst quarantaeniert
        # AEGIS seinen eigenen Code, da das Projekt unter Desktop liegen kann).
        try:
            _proj = Path(__file__).resolve().parents[3]
        except Exception:
            _proj = None
        self._exclude_roots = [r for r in [_proj] if r]
        for _x in (db.get_setting('watch_exclude_paths', '') or '').split(';'):
            _x = _x.strip()
            if _x:
                try:
                    self._exclude_roots.append(Path(_x).resolve())
                except Exception:
                    pass

    def run(self) -> None:
        if not HAS_WATCHDOG:
            self.emit(Severity.WARN, Category.SYSTEM,
                      "watchdog nicht installiert — FileWatcher inaktiv")
            return
        if not self.folders:
            return
        self._observer = Observer()
        handler = _FsEventHandler(self._on_event)
        for folder in self.folders:
            if folder.exists():
                # Temp NICHT rekursiv (zu viele Events) — Dropper landen top-level.
                _fl = str(folder).lower()
                _rec = not (("\\temp" in _fl) or ("\\tmp" in _fl))
                self._observer.schedule(handler, str(folder), recursive=_rec)
                self.emit(Severity.INFO, Category.FILE,
                          f"Beobachte Ordner: {folder}" + ("" if _rec else " (flach)"))
            else:
                self.emit(Severity.WARN, Category.SYSTEM,
                          f"Watch-Ordner existiert nicht: {folder}")
        self._observer.start()
        while not self._stop.is_set():
            self._stop.wait(1.0)
        self._observer.stop()
        self._observer.join(timeout=3.0)

    def _on_event(self, action: str, path: str) -> None:
        try:
            p = Path(path)
            try:
                rp = p.resolve()
                for ex in self._exclude_roots:
                    if ex == rp or ex in rp.parents:
                        return   # eigener Projekt-Baum -> ignorieren
            except Exception:
                pass
            if p.name.lower().startswith("powershell_transcript"):
                return
            # Performance: in Temp/AppData-Baeumen nur ausfuehrbare Dateien
            # durch die teure Scan-/Hash-Pipeline schicken (sonst Browser-Cache-Flut).
            _pl = str(p).lower()
            if (("\\temp\\" in _pl) or ("\\tmp\\" in _pl) or ("\\appdata\\" in _pl)) \
               and p.suffix.lower() not in _EXEC_EXTS:
                return
            time.sleep(0.25)        # FS-settle (verkuerzt: Race-Window kleiner)
            if not p.exists() or p.is_dir():
                return

            # ---- L0/L1: Layered Scanner mit sofortigem Pre-Exec-Block ----
            try:
                from ..scanner import scan_file
                scan = scan_file(p, vt_lookup_cb=_vt_callback())
                if scan.verdict == "block":
                    self.emit(Severity.THREAT, Category.FILE,
                              f"PRE-EXEC-BLOCK ({scan.layer}): {p.name}",
                              {"path": str(p), "sha256": scan.sha256,
                               "layer": scan.layer, "reasons": scan.reasons,
                               "confidence": scan.confidence})
                    # Sofort in Quarantine — BEVOR Windows die Datei evtl. öffnet
                    self.quarantine.quarantine(p, f"scanner:{scan.layer}",
                                               scan.sha256)
                    return
                if scan.verdict == "warn":
                    self.emit(Severity.WARN, Category.FILE,
                              f"SCAN-WARN ({scan.layer}): {p.name}",
                              {"path": str(p), "sha256": scan.sha256,
                               "layer": scan.layer, "reasons": scan.reasons})
            except Exception as e:  # noqa: BLE001
                self.emit(Severity.WARN, Category.SYSTEM,
                          f"Scanner-Fehler: {type(e).__name__}: {e}")
            try:
                size = p.stat().st_size
            except OSError:
                return
            if size == 0:
                return

            sha = ti.file_sha256(p)
            if not sha:
                return
            is_new = self.db.upsert_file(sha, str(p), size, "", "unknown")
            classification = ti.classify_file(p, sha)
            is_exec = classification["is_executable"]
            verdict = classification["verdict"]

            prior = self.db.get_decision("file_hash", sha)
            if prior == "allow":
                self.emit(Severity.INFO, Category.FILE,
                          f"Bekannte File (allow): {p.name}",
                          {"sha256": sha, "path": str(p)})
                return
            if prior == "deny":
                self.emit(Severity.THREAT, Category.FILE,
                          f"BLOCKED FILE re-appeared: {p.name}",
                          {"sha256": sha, "path": str(p)})
                self.quarantine.quarantine(p, "previously denied", sha)
                return

            if is_exec:
                metadata = {
                    "sha256": sha, "path": str(p), "size": size,
                    "verdict": verdict, "reasons": classification["reasons"],
                    "score": classification["score"], "is_new": is_new,
                }
                if verdict == "malicious":
                    self.emit(Severity.THREAT, Category.FILE,
                              f"MALICIOUS heuristic: {p.name}", metadata)
                    if self.auto_quarantine:
                        self.quarantine.quarantine(p, "heuristic verdict: malicious", sha)
                elif verdict == "suspicious":
                    self.emit(Severity.WARN, Category.FILE,
                              f"SUSPICIOUS file: {p.name}", metadata)
                    if self.auto_quarantine:
                        self.quarantine.quarantine(p, "heuristic verdict: suspicious", sha)
                elif verdict == "unknown" and is_new:
                    self.emit(Severity.QUARANTINE, Category.FILE,
                              f"NEW EXE first-seen: {p.name} -> Vault", metadata)
                    if self.auto_quarantine:
                        self.quarantine.quarantine(p, "first-seen executable", sha)
            else:
                if is_new:
                    self.emit(Severity.INFO, Category.FILE,
                              f"Neue Datei: {p.name}",
                              {"sha256": sha, "path": str(p),
                               "size": size, "is_executable": False})
        except Exception as e:
            self.emit(Severity.WARN, Category.SYSTEM,
                      f"FileWatcher-Handler-Fehler: {e}")
