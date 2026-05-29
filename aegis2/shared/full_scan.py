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
        steps = [
            ("registry", self._scan_registry_runs),
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
            lines = (r.stdout or "").splitlines()
        except Exception:  # noqa: BLE001
            return
        for line in lines[1:]:
            if self._stop.is_set(): return
            parts = self._csv_split(line)
            if len(parts) < 9: continue
            taskname = parts[1].strip('"')
            run_as = parts[6].strip('"') if len(parts) > 6 else ""
            task_to_run = parts[8].strip('"') if len(parts) > 8 else ""
            if not task_to_run or task_to_run.lower() == "n/a": continue
            # Skip Microsoft / system tasks
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
            # WMI-Subscriptions sind selten legitim ausser von AV → warn
            item.verdict = "warn"
            item.layer = "wmi"
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
        p = Path(path_str)
        if p.exists() and p.is_file():
            self._scan_executable(item, p)
        else:
            item.verdict = "unknown"
            item.layer = "path-missing"
            item.reasons = [f"Referenced path not found: {path_str}"]

    def _scan_executable(self, item: FullScanItem, path: Path) -> None:
        try:
            result = scan_file(path)
            item.verdict = result.verdict
            item.layer = result.layer
            item.reasons = result.reasons
            item.sha256 = result.sha256
            item.extra["confidence"] = result.confidence
        except Exception as e:  # noqa: BLE001
            item.verdict = "unknown"
            item.layer = "scan-error"
            item.reasons = [f"Scan-Fehler: {e}"]

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
    def _extract_path(command: str) -> str:
        """Extract path from a command-line (handles quoted)."""
        if not command:
            return ""
        c = command.strip()
        if c.startswith('"'):
            end = c.find('"', 1)
            return c[1:end] if end > 0 else ""
        # First whitespace-delimited token
        return c.split()[0] if c else ""

    @staticmethod
    def _csv_split(line: str) -> list:
        """Simple CSV-split with quote handling."""
        out, cur, in_q = [], "", False
        for ch in line:
            if ch == '"': in_q = not in_q
            elif ch == "," and not in_q:
                out.append(cur); cur = ""
                continue
            cur += ch
        out.append(cur)
        return out
