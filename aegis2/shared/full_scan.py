"""Full-System-Scanner — durchsucht ALLE bekannten Persistence-Locations.

Quellen 2026 (May-CISA-KEV + ANY.RUN persistence research):
  - HKLM/HKCU\\...\\Run + RunOnce (klassischer Autostart)
  - HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Tasks
  - HKLM\\...\\Services (Service-Persistence)
  - Startup-Ordner (User + AllUsers)
  - %TEMP%, %APPDATA%\\Local\\Temp (haeufigste Drop-Zone)
  - Browser-Extension-Ordner (Chrome, Edge, Brave, Opera, Firefox)
  - %APPDATA%\\Roaming (legit aber haeufig fuer Persistence missbraucht)
  - WMI-Subscriptions (Advanced-Persistence)
  - Scheduled-Tasks (schtasks /Query)

Live-Progress via Callback. Cancellable.
"""
from __future__ import annotations

import csv
import os
import subprocess
import sys
import threading
import time
# winreg lazy imported below
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .scanner import scan_file, ScanResult
from . import adaptive
from .proc import run_hidden


# ============================================================
#  Locations Registry
# ============================================================

REGISTRY_RUN_KEYS = [
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
    (r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices", "HKLM"),
    (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM"),
]

STARTUP_FOLDERS = [
    Path(os.environ.get("APPDATA", ""))
        / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    Path(os.environ.get("PROGRAMDATA", ""))
        / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
]

TEMP_FOLDERS = [
    Path(os.environ.get("TEMP", "")),
    Path(os.environ.get("TMP", "")),
    Path(os.environ.get("LOCALAPPDATA", "")) / "Temp" if os.environ.get("LOCALAPPDATA") else None,
    Path("C:/Windows/Temp"),
]

BROWSER_EXTENSION_DIRS = {
    "Chrome":   Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/User Data/Default/Extensions",
    "Edge":     Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Edge/User Data/Default/Extensions",
    "Brave":    Path(os.environ.get("LOCALAPPDATA", "")) / "BraveSoftware/Brave-Browser/User Data/Default/Extensions",
    "Opera":    Path(os.environ.get("APPDATA", ""))     / "Opera Software/Opera Stable/Extensions",
    "Firefox":  Path(os.environ.get("APPDATA", ""))     / "Mozilla/Firefox/Profiles",
}


# ============================================================
#  Result Types
# ============================================================

@dataclass
class FullScanItem:
    location_kind: str         # "registry_run" | "startup_folder" | "temp" | "browser_ext" | "scheduled_task" | "service"
    location_path: str
    name: str
    value: str = ""
    verdict: str = "unknown"   # block | warn | clean | unknown
    layer: str = ""
    reasons: list = field(default_factory=list)
    sha256: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kind": self.location_kind,
            "path": self.location_path,
            "name": self.name,
            "value": self.value,
            "verdict": self.verdict,
            "layer": self.layer,
            "reasons": self.reasons,
            "sha256": self.sha256,
            "extra": self.extra,
        }


@dataclass
class FullScanReport:
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    items_total: int = 0
    items_block: int = 0
    items_warn: int = 0
    items_unknown: int = 0
    locations_scanned: int = 0
    items: list = field(default_factory=list)
    cancelled: bool = False
    error: Optional[str] = None

    def summary(self) -> dict:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": (self.finished_at or time.time()) - self.started_at,
            "items_total": self.items_total,
            "items_block": self.items_block,
            "items_warn": self.items_warn,
            "items_unknown": self.items_unknown,
            "locations_scanned": self.locations_scanned,
            "cancelled": self.cancelled,
            "error": self.error,
            "items_preview": [i.to_dict() for i in self.items[:50]],
        }


# ============================================================
#  Scanner
# ============================================================

class FullSystemScanner:
    """Owner instanziiert einen Scanner pro Run. Cancellable + Progress-Callback."""

    def __init__(self,
                 on_progress: Optional[Callable[[dict], None]] = None,
                 on_item: Optional[Callable[[FullScanItem], None]] = None):
        self.on_progress = on_progress or (lambda _: None)
        self.on_item = on_item or (lambda _: None)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.report = FullScanReport()
        self._thread: Optional[threading.Thread] = None
        self._current_loc = ""

    # ---- Control ----
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="FullScan")
        self._thread.start()

    def cancel(self) -> None:
        self._stop.set()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ---- Main runner ----
    def _run(self) -> None:
        self._emit_progress("start")
        # Reputation einmalig in den Speicher laden -> schnelle Lookups, keine DB pro Datei
        self._db = None
        self._rep_cache = {}
        self._learn_queue = []
        try:
            from .db import get_db
            self._db = get_db()
            for _r in self._db.reputation_all():
                self._rep_cache[(_r["kind"], _r["ident"])] = (_r["mal_hits"], _r["ben_hits"])
        except Exception:
            pass
        # VT-Key EINMAL pro Scan-Lauf entschluesseln (DPAPI) -> nicht pro Datei.
        # Vorhanden -> read-only GET-Callback an scan_file; sonst None (laeuft wie bisher).
        self._vt_cb = None
        try:
            from ..cognition.secrets_store import get_secret
            _vk = get_secret("vt_api_key")
            if _vk:
                from .threat_intel import vt_lookup_hash
                self._vt_cb = lambda h: vt_lookup_hash(h, _vk)
        except Exception:
            self._vt_cb = None
        steps = [
            ("registry", self._scan_registry_runs),
            ("processes", self._scan_processes),
            ("startup", self._scan_startup_folders),
            ("tasks", self._scan_scheduled_tasks),
            ("services", self._scan_services),
            ("temp", self._scan_temp_folders),
            ("browser", self._scan_browser_extensions),
            ("wmi", self._scan_wmi_subscriptions),
        ]
        errs = []
        for nm, fn in steps:
            if self._stop.is_set():
                self._mark_cancelled(); return
            try:
                fn()
            except Exception as e:  # noqa: BLE001 — eine kaputte Location darf den Scan nicht stoppen
                errs.append(f"{nm}: {type(e).__name__}: {str(e)[:90]}")
            self._emit_progress(nm)
        # Gelernte Funde EINMAL gebatcht schreiben (kein per-Datei-DB-Lock im Scan)
        if self._db is not None and self._learn_queue:
            for _k, _i in self._learn_queue:
                try:
                    self._db.reputation_update(_k, _i, malicious=True, weight=0.4)
                except Exception:
                    pass
        self.report.error = ("; ".join(errs)) if errs else None
        self.report.finished_at = time.time()
        self._emit_progress("done")

    def _mark_cancelled(self) -> None:
        self.report.cancelled = True
        self.report.finished_at = time.time()
        self._emit_progress("cancelled")

    def _emit_progress(self, phase: str) -> None:
        try:
            self.on_progress({
                "phase": phase,
                "location": self._current_loc,
                "items_total": self.report.items_total,
                "items_block": self.report.items_block,
                "items_warn": self.report.items_warn,
                "locations_scanned": self.report.locations_scanned,
            })
        except Exception:  # noqa: BLE001
            pass

    def _record(self, item: FullScanItem) -> None:
        with self._lock:
            self.report.items.append(item)
            self.report.items_total += 1
            if item.verdict == "block":  self.report.items_block += 1
            elif item.verdict == "warn": self.report.items_warn += 1
            elif item.verdict == "unknown": self.report.items_unknown += 1
        try:
            self.on_item(item)
        except Exception:  # noqa: BLE001
            pass

    # ---- Scan sections ----
    def _scan_processes(self) -> None:
        """Laufende Prozesse heuristisch pruefen — schnell (exe nur bei Verdacht)."""
        try:
            import psutil
        except ImportError:
            return
        from . import threat_intel as ti
        self._current_loc = "Laufende Prozesse"
        self._emit_progress("processes")
        checked = 0
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):   # KEIN exe (auf Win langsam)
            if self._stop.is_set():
                return
            if checked >= 400:
                break
            try:
                info = proc.info
                name = info.get("name") or ""
                if not name:
                    continue
                cmd = " ".join(info.get("cmdline") or [])
                checked += 1
                if checked % 40 == 0:
                    self._current_loc = "Prozesse (%d)" % checked
                    self._emit_progress("processes")           # Zwischen-Fortschritt
                cls = ti.classify_process(name, cmd, "")       # exe erst bei Verdacht
                v = cls.get("verdict", "unknown")
                _mb = getattr(self, "_rep_cache", {}).get(("proc", name.lower()))
                _rep = adaptive.reputation_score_from(_mb[0], _mb[1]) if _mb else 0.0
                if v not in ("malicious", "suspicious") and _rep < 18:
                    continue
                exe = ""
                try:
                    exe = proc.exe()                           # exe nur fuer Kandidaten
                except Exception:
                    pass
                if exe:
                    cls = ti.classify_process(name, cmd, exe)  # genauer nachklassifizieren
                    v = cls.get("verdict", v)
                item = FullScanItem(
                    location_kind="process", location_path=exe or name,
                    name=name, value=(exe or cmd[:160]))
                trusted = adaptive.is_trusted_path(exe)
                # signierter System-/Programm-Interpreter (z.B. powershell.exe) -> nie block
                item.verdict = "warn" if trusted else ("block" if (v == "malicious" or _rep >= 30) else "warn")
                item.layer = "process-heuristic"
                item.reasons = cls.get("reasons", [])[:5]
                if _rep >= 18:
                    item.reasons = (item.reasons or []) + ["Gelernt: Ruf %.0f" % _rep]
                item.extra = {"pid": info.get("pid"), "score": cls.get("score", 0)}
                self._record(item)
                # nur aus echter Heuristik lernen, NIE bei System-Pfaden (kein FP-Aufbau)
                if v == "malicious" and not trusted:
                    self._learn_queue.append(("proc", name.lower()))
            except Exception:
                continue
        self._current_loc = "Prozesse (%d geprueft)" % checked
        self.report.locations_scanned += 1

    def _scan_registry_runs(self) -> None:
        if sys.platform != "win32":
            return
        try:
            import winreg
        except ImportError:
            return
        for key_str, hive_name in REGISTRY_RUN_KEYS:
            if self._stop.is_set(): return
            self._current_loc = key_str
            self._emit_progress("registry")
            hive_root, subkey = self._split_reg_path(key_str)
            try:
                with winreg.OpenKey(hive_root, subkey) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _t = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        item = FullScanItem(
                            location_kind="registry_run",
                            location_path=key_str, name=name, value=str(value))
                        self._classify_command(item, str(value))
                        self._record(item)
            except OSError:
                pass
            self.report.locations_scanned += 1

    def _scan_startup_folders(self) -> None:
        for folder in STARTUP_FOLDERS:
            if self._stop.is_set(): return
            if not folder or not folder.exists(): continue
            self._current_loc = str(folder)
            self._emit_progress("startup")
            try:
                for entry in folder.iterdir():
                    if self._stop.is_set(): return
                    if entry.is_file():
                        item = FullScanItem(
                            location_kind="startup_folder",
                            location_path=str(folder),
                            name=entry.name, value=str(entry))
                        # If .lnk → just record. If exe/script → scan.
                        if entry.suffix.lower() in (".exe", ".bat", ".cmd",
                                                    ".ps1", ".vbs", ".js"):
                            self._scan_executable(item, entry)
                        else:
                            item.verdict = "unknown"
                            item.layer = "startup-noscan"
                        self._record(item)
            except OSError:
                pass
            self.report.locations_scanned += 1

    # schtasks /V /FO CSV gibt je nach Windows-UI-Sprache LOKALISIERTE Kopfzeilen
    # aus. Wir mappen ueber die Header-NAMEN (nicht ueber feste Spaltenindizes,
    # denn die Spaltenanzahl/-reihenfolge ist nicht garantiert). DE-Header von
    # einem echten deutschen Windows verifiziert (schtasks /Query /FO CSV /V):
    #   "Aufgabenname" / "Auszuführende Aufgabe" / "Als Benutzer ausführen".
    # Hinweis: Die deutsche Run-As-Spalte heisst "Als Benutzer ausführen"
    # (Index ~14), NICHT "Letztes Ergebnis" (Index 6) — der alte Positions-Code
    # las faelschlich das Ergebnis-Feld als Benutzer.
    _SCHTASKS_TASKNAME_HDRS = ("taskname", "aufgabenname")
    _SCHTASKS_RUN_HDRS = ("task to run", "auszuführende aufgabe",
                          "auszufuehrende aufgabe")
    _SCHTASKS_RUNAS_HDRS = ("run as user", "als benutzer ausführen",
                            "als benutzer ausfuehren", "ausführen als benutzer",
                            "ausfuehren als benutzer")

    @staticmethod
    def _pick_field(row: dict, candidates: tuple) -> str:
        """Holt einen Wert aus einer DictReader-Zeile per Header-Name
        (case-insensitive, sprach-tolerant). Leerer String wenn nichts passt."""
        # Normalisierte Sicht auf die Zeile (Header koennen fuehrende/folgende
        # Leerzeichen oder abweichende Gross-/Kleinschreibung haben).
        norm = {(k or "").strip().lower(): v for k, v in row.items() if k is not None}
        for cand in candidates:
            if cand in norm and norm[cand] is not None:
                return str(norm[cand]).strip()
        return ""

    def _scan_scheduled_tasks(self) -> None:
        if sys.platform != "win32":
            return
        self._current_loc = "Scheduled Tasks"
        self._emit_progress("schtasks")
        try:
            r = run_hidden(
                ["schtasks", "/Query", "/FO", "CSV", "/V"],
                capture_output=True, text=True, timeout=25,
                encoding="utf-8", errors="replace"
            )
            stdout = r.stdout or ""
        except Exception:  # noqa: BLE001
            return
        # csv.DictReader parst Quoting/eingebettete Kommata korrekt und schluesselt
        # nach der ersten Kopfzeile. schtasks haengt pro Sektion erneut eine
        # Kopfzeile an -> solche "Header-als-Daten"-Zeilen filtern wir unten raus.
        try:
            reader = csv.DictReader(stdout.splitlines())
        except Exception:  # noqa: BLE001
            return
        for row in reader:
            if self._stop.is_set(): return
            if not row:
                continue
            taskname = self._pick_field(row, self._SCHTASKS_TASKNAME_HDRS)
            # Wiederholte Kopfzeilen (pro Sektion) oder Leerzeilen ueberspringen.
            if not taskname or taskname.lower() in (
                    "aufgabenname", "taskname", "hostname"):
                continue
            task_to_run = self._pick_field(row, self._SCHTASKS_RUN_HDRS)
            run_as = self._pick_field(row, self._SCHTASKS_RUNAS_HDRS)
            if not task_to_run or task_to_run.lower() in ("n/a", "n. v."):
                continue
            # Microsoft-/System-Tasks ueberspringen
            if taskname.lower().startswith("\\microsoft"): continue
            item = FullScanItem(
                location_kind="scheduled_task",
                location_path="schtasks",
                name=taskname, value=task_to_run,
                extra={"run_as": run_as})
            self._classify_command(item, task_to_run)
            self._record(item)
        self.report.locations_scanned += 1

    def _scan_services(self) -> None:
        if sys.platform != "win32":
            return
        self._current_loc = "Services"
        self._emit_progress("services")
        try:
            r = run_hidden(
                ["powershell", "-NoProfile", "-Command",
                 "Get-CimInstance Win32_Service | Select-Object Name,PathName,StartMode,State | "
                 "ConvertTo-Csv -NoTypeInformation"],
                capture_output=True, text=True, timeout=25,
                encoding="utf-8", errors="replace"
            )
            lines = (r.stdout or "").splitlines()
        except Exception:  # noqa: BLE001
            return
        for line in lines[1:]:
            if self._stop.is_set(): return
            parts = self._csv_split(line)
            if len(parts) < 4: continue
            name, pathname, startmode, state = (p.strip('"') for p in parts[:4])
            if not pathname or pathname.startswith(("C:\\Windows\\System32\\svchost",
                                                    "C:\\Windows\\system32\\svchost",
                                                    "C:\\Windows\\System32\\drivers")):
                continue
            try:
                item = FullScanItem(
                    location_kind="service",
                    location_path="services",
                    name=name, value=pathname,
                    extra={"start_mode": startmode, "state": state})
                self._classify_command(item, pathname)
                self._record(item)
            except Exception:  # noqa: BLE001 — geschuetzter Service-Pfad (WinError 5) ueberspringen
                continue
        self.report.locations_scanned += 1

    def _scan_temp_folders(self) -> None:
        scanned_count = 0
        max_per_folder = 80   # cap damit nicht hunderte Files
        for folder in TEMP_FOLDERS:
            if self._stop.is_set(): return
            if not folder or not folder.exists(): continue
            self._current_loc = str(folder)
            self._emit_progress("temp")
            try:
                # Nur ausfuehrbare + recent files
                items_in_folder = 0
                for entry in folder.rglob("*"):
                    if self._stop.is_set(): return
                    if items_in_folder >= max_per_folder: break
                    if not entry.is_file(): continue
                    if entry.suffix.lower() not in (
                            ".exe", ".scr", ".bat", ".cmd", ".com",
                            ".ps1", ".vbs", ".vbe", ".js", ".hta", ".pif", ".msi"):
                        continue
                    try:
                        st = entry.stat()
                        # nur die letzten 30 Tage
                        if time.time() - st.st_mtime > 30 * 86400: continue
                        # grosse Files (Installer) sind kein Drop-Vektor -> Hash sparen
                        if st.st_size > 80 * 1024 * 1024: continue
                    except OSError:
                        continue
                    item = FullScanItem(
                        location_kind="temp",
                        location_path=str(folder),
                        name=entry.name, value=str(entry))
                    self._scan_executable(item, entry)
                    self._record(item)
                    items_in_folder += 1
                    scanned_count += 1
            except (OSError, PermissionError):
                pass
            self.report.locations_scanned += 1
        self._current_loc = f"temp ({scanned_count} files)"

    def _scan_browser_extensions(self) -> None:
        for browser, base in BROWSER_EXTENSION_DIRS.items():
            if self._stop.is_set(): return
            if not base or not base.exists(): continue
            self._current_loc = f"{browser} extensions"
            self._emit_progress("browser")
            try:
                for ext in base.iterdir():
                    if self._stop.is_set(): return
                    if not ext.is_dir(): continue
                    # Look up manifest.json or extension.json
                    info_files = list(ext.rglob("manifest.json"))
                    name = "(unknown)"
                    perms = []
                    if info_files:
                        try:
                            import json as _json
                            data = _json.loads(info_files[0].read_text(encoding="utf-8", errors="replace"))
                            name = data.get("name", ext.name)
                            if isinstance(name, str) and name.startswith("__MSG_"):
                                name = self._resolve_i18n_name(info_files[0].parent, data, ext.name)
                            perms = data.get("permissions", [])
                        except Exception:  # noqa: BLE001
                            pass
                    risky = any(p in perms for p in
                                ["webRequest", "webRequestBlocking",
                                 "<all_urls>", "cookies", "tabs",
                                 "history", "management"])
                    item = FullScanItem(
                        location_kind="browser_ext",
                        location_path=str(ext.parent),
                        name=name, value=ext.name,
                        extra={"browser": browser,
                               "permissions": perms[:10],
                               "risky": risky})
                    if risky:
                        item.verdict = "warn"
                        item.layer = "browser-perm"
                        item.reasons.append("Erhöhte Browser-Permissions")
                    else:
                        item.verdict = "unknown"
                    self._record(item)
            except (OSError, PermissionError):
                pass
            self.report.locations_scanned += 1

    @staticmethod
    def _resolve_i18n_name(ext_dir, manifest, fallback):
        """Loest __MSG_key__ aus _locales/<locale>/messages.json auf."""
        import json as _json, re
        m = re.match(r"__MSG_(.+?)__", manifest.get("name", ""))
        if not m:
            return fallback
        key = m.group(1)
        default_locale = manifest.get("default_locale", "en")
        for loc in (default_locale, "en", "en_US", "de"):
            mp = ext_dir / "_locales" / loc / "messages.json"
            if mp.exists():
                try:
                    msgs = _json.loads(mp.read_text(encoding="utf-8", errors="replace"))
                    val = msgs.get(key) or msgs.get(key.lower())
                    if isinstance(val, dict) and val.get("message"):
                        return val["message"]
                except Exception:
                    pass
        return fallback

    def _scan_wmi_subscriptions(self) -> None:
        """Advanced-Persistence via WMI-EventConsumer."""
        if sys.platform != "win32":
            return
        self._current_loc = "WMI Subscriptions"
        self._emit_progress("wmi")
        try:
            r = run_hidden(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WmiObject -Namespace root/subscription -Class __EventConsumer | "
                 "Select-Object Name,CommandLineTemplate,CreatorSID | ConvertTo-Csv -NoTypeInformation"],
                capture_output=True, text=True, timeout=15,
                encoding="utf-8", errors="replace"
            )
            lines = (r.stdout or "").splitlines()
        except Exception:  # noqa: BLE001
            return
        for line in lines[1:]:
            if self._stop.is_set(): return
            parts = self._csv_split(line)
            if len(parts) < 1: continue
            name = parts[0].strip('"')
            cmd = parts[1].strip('"') if len(parts) > 1 else ""
            if not name: continue
            item = FullScanItem(
                location_kind="wmi_subscription",
                location_path="root/subscription",
                name=name, value=cmd)
            item.layer = "wmi"
            # Windows-Standard-Consumer sind benigne (auf jedem System vorhanden)
            _bn = name.strip().lower()
            _BENIGN_WMI = ("scm event log consumer", "bvtconsumer",
                           "bvtfilter", "ntdsconnection")
            if _bn in _BENIGN_WMI:
                item.verdict = "clean"
                item.reasons = ["Windows-Standard WMI-Consumer (benigne)"]
            else:
                item.verdict = "warn"
                item.reasons = ["WMI Event Consumer (advanced persistence vector)"]
            self._record(item)
        self.report.locations_scanned += 1

    # ---- Helpers ----
    def _classify_command(self, item: FullScanItem, command: str) -> None:
        """Extract path from command + scan if executable."""
        path_str = self._extract_path(command)
        if not path_str:
            item.verdict = "unknown"
            item.layer = "cmd-noscan"
            return
        path_str = os.path.expandvars(path_str)   # %windir% etc. aufloesen
        p = Path(path_str)
        if p.exists() and p.is_file():
            self._scan_executable(item, p)
        else:
            item.verdict = "unknown"
            item.layer = "path-missing"
            item.reasons = [f"Referenced path not found: {path_str}"]

    def _scan_executable(self, item: FullScanItem, path: Path) -> None:
        try:
            result = scan_file(path, vt_lookup_cb=getattr(self, "_vt_cb", None),
                               skip_layers={"L6"})
            item.verdict = result.verdict
            item.layer = result.layer
            item.reasons = result.reasons
            item.sha256 = result.sha256
            item.extra["confidence"] = result.confidence
            self._apply_adaptive(item, "file", result.sha256 or path.name.lower())
        except Exception as e:  # noqa: BLE001
            item.verdict = "unknown"
            item.layer = "scan-error"
            item.reasons = [f"Scan-Fehler: {e}"]

    def _apply_adaptive(self, item, kind: str, ident: str) -> None:
        """Gelernte Reputation anwenden (boeses NIE vergessen/skippen) + aus Funden lernen.
        Nutzt den In-Memory-Cache -> keine DB-Last pro Datei."""
        if not ident:
            return
        try:
            mb = getattr(self, "_rep_cache", {}).get((kind, ident))
            if mb:
                rep = adaptive.reputation_score_from(mb[0], mb[1])
                if rep >= 30 and item.verdict != "block":
                    item.verdict = "block"; item.layer = "adaptive-reputation"
                    item.reasons = (item.reasons or []) + ["Gelernt: stark belastet (Ruf %.0f)" % rep]
                elif rep >= 18 and item.verdict in ("clean", "unknown"):
                    item.verdict = "warn"; item.layer = "adaptive-reputation"
                    item.reasons = (item.reasons or []) + ["Gelernt: auffaellig (Ruf %.0f)" % rep]
            # Nur aus HARTER Heuristik lernen — nicht aus "warn" (reine Vorsicht)
            # und nicht aus dem adaptiven Block selbst (sonst FP-Selbstverstaerkung).
            if item.verdict == "block" and item.layer != "adaptive-reputation":
                getattr(self, "_learn_queue", []).append((kind, ident))
        except Exception:
            pass

    @staticmethod
    def _split_reg_path(p: str) -> tuple:
        import winreg
        hive_name, rest = p.split("\\", 1)
        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU":  winreg.HKEY_USERS,
        }
        return hive_map.get(hive_name, winreg.HKEY_LOCAL_MACHINE), rest

    @staticmethod
    def _argv_split(command: str) -> list:
        """Zerlegt eine Windows-Kommandozeile in Argumente — wie es Windows
        selbst tut. Bevorzugt CommandLineToArgvW (Win32, exakt korrekt fuer
        Quoting/Backslash-Regeln), faellt auf shlex(posix=False) zurueck."""
        if not command:
            return []
        c = command.strip()
        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes import wintypes
                argc = ctypes.c_int(0)
                # CommandLineToArgvW interpretiert ein leeres argv[0] eigen ->
                # nur mit nicht-leerem String aufrufen (oben bereits geprueft).
                CommandLineToArgvW = ctypes.windll.shell32.CommandLineToArgvW
                CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
                CommandLineToArgvW.argtypes = [wintypes.LPCWSTR,
                                               ctypes.POINTER(ctypes.c_int)]
                argv = CommandLineToArgvW(c, ctypes.byref(argc))
                if argv:
                    try:
                        return [argv[i] for i in range(argc.value)]
                    finally:
                        ctypes.windll.kernel32.LocalFree(argv)
            except Exception:  # noqa: BLE001 — Fallback unten
                pass
        try:
            import shlex
            return shlex.split(c, posix=False)
        except Exception:  # noqa: BLE001
            return c.split()

    @staticmethod
    def _extract_path(command: str) -> str:
        """Extrahiert den Image-Pfad (Programm) aus einer Kommandozeile.

        Robust gegen:
          - zitierte Pfade:  "C:\\Program Files\\X\\run.exe" -x   -> ganzer Pfad
          - UNzitierte Pfade MIT Leerzeichen: Windows startet die laengste
            existierende Datei, d.h.  C:\\Program Files\\Evil\\run.exe -x  meint
            das Programm, NICHT C:\\Program. Wir probieren wachsende Praefixe
            der Token (mit/ohne .exe) und nehmen den laengsten existierenden
            Treffer. Faellt nichts trifft, nutzen wir argv[0] (1. Token)."""
        if not command:
            return ""
        c = command.strip()
        # Zitierter Pfad: Windows nimmt exakt den Inhalt der ersten Anfuehrung.
        if c.startswith('"'):
            end = c.find('"', 1)
            return c[1:end] if end > 0 else c[1:]

        args = FullSystemScanner._argv_split(c)
        # argv[0] ist die Windows-Standard-Interpretation (1. Argument). Fuer
        # UNzitierte Pfade mit Leerzeichen ist das aber nur das erste Token
        # (z.B. "C:\\Program") -> wir verfeinern unten per Existenz-Probe.
        first = args[0] if args else ""

        # Unzitierter Pfad mit Leerzeichen: Windows startet die laengste
        # tatsaechlich existierende Datei. Wir testen wachsende Praefixe an
        # Wortgrenzen auf Existenz (laengster Treffer gewinnt) und bilden so die
        # Aufloesung nach. Greift nur, wenn argv[0] selbst nicht existiert.
        try:
            tokens = c.split(" ")
            best = ""
            prefix = ""
            for tok in tokens:
                prefix = tok if not prefix else prefix + " " + tok
                cand = os.path.expandvars(prefix.strip('"'))
                # Mit und ohne implizite .exe-Endung probieren; den konkret
                # existierenden Pfad zurueckgeben (inkl. .exe falls so getroffen).
                for probe in (cand, cand + ".exe"):
                    try:
                        if os.path.isfile(probe):
                            best = probe
                    except OSError:
                        pass
            if best:
                return best
        except Exception:  # noqa: BLE001
            pass
        # Nichts existiert (oder kein Leerzeichen-Pfad) -> argv[0] als Fallback.
        return first

    @staticmethod
    def _csv_split(line: str) -> list:
        """Eine einzelne CSV-Zeile in Felder zerlegen — via stdlib csv
        (korrektes Quoting, eingebettete Kommata/Anfuehrungszeichen)."""
        try:
            for fields in csv.reader([line]):
                return list(fields)
        except Exception:  # noqa: BLE001 — defensiver Fallback
            pass
        # Fallback: simpler quote-bewusster Split.
        out, cur, in_q = [], "", False
        for ch in line:
            if ch == '"': in_q = not in_q
            elif ch == "," and not in_q:
                out.append(cur); cur = ""
                continue
            cur += ch
        out.append(cur)
        return out
