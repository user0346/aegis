"""USB-Device-Watcher (Phase 5b).

Pollt 5-Sekunden-Intervall die Liste angeschlossener USB-Devices via WMI
(Win32_PnPEntity wo PNPDeviceID mit 'USB\' beginnt).

Was wird gemeldet:
  * Neue Removable-Disk angeschlossen           -> WARN  (BadUSB-Risiko)
  * Neues HID-Keyboard angeschlossen            -> WARN  (Rubber-Ducky-Risiko)
  * Neues HID-Mouse angeschlossen               -> INFO
  * Neuer Netzwerk-Adapter via USB              -> WARN  (Routing-Hijack)
  * Composite-Device mit Storage+HID            -> CRITICAL (BadUSB-typisch)
  * VID/PID auf benutzer-definierter Blocklist  -> CRITICAL
  * Device disconnected                          -> INFO

Heuristik fuer BadUSB:
Composite-Devices die GLEICHZEITIG storage + HID-keyboard interfaces
zeigen sind ein klassisches Rubber-Ducky-Pattern. Echte USB-Sticks
haben nur Mass-Storage; echte Tastaturen haben nur HID.

Defensive Properties:
  - Read-only; AEGIS schaltet KEINE Devices ab (Risiko: User-Maus crashen)
  - Nur Events + UI-Notification + Sir-Speaker bei CRITICAL
  - Erste 2 Minuten nach Service-Start: nur Baseline aufbauen, keine Events
"""
from __future__ import annotations

import json
import logging
import subprocess
import time
from typing import Optional

from ..db import Database
from ..events import EventBus, Severity, Category
from ..proc import run_hidden
from .base import Module


log = logging.getLogger("aegis2.usb_watch")


POLL_INTERVAL_S = 5
BASELINE_S = 120     # 2 min nach Start: nur lernen, keine Events

# Windows: PowerShell-Fenster komplett unterdrücken
CREATE_NO_WINDOW = 0x08000000


# PNP-Class -> friendly
PNP_CLASS_FRIENDLY = {
    "HIDClass":         "HID device",
    "Keyboard":         "USB-Keyboard",
    "Mouse":            "USB-Mouse",
    "DiskDrive":        "Removable disk",
    "USB":              "USB controller/hub",
    "USBDevice":        "USB device",
    "Net":              "USB network adapter",
    "Bluetooth":        "USB-Bluetooth",
    "Image":            "USB camera/scanner",
    "MEDIA":            "USB audio",
}


PS_SCRIPT = r"""
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$ErrorActionPreference = 'SilentlyContinue'
$d = Get-CimInstance -ClassName Win32_PnPEntity |
     Where-Object { $_.PNPDeviceID -like 'USB\*' -or $_.PNPClass -eq 'USB' }
$out = @()
foreach ($x in $d) {
    $out += [PSCustomObject]@{
        DeviceID    = $x.PNPDeviceID
        Name        = $x.Name
        Class       = $x.PNPClass
        Manufacturer= $x.Manufacturer
        Status      = $x.Status
    }
}
$out | ConvertTo-Json -Depth 3 -Compress
"""


def _parse_vid_pid(pnp_id: str) -> tuple[str, str]:
    r"""USB\VID_046D&PID_C534... -> ('046D', 'C534')."""
    vid = pid = ""
    if not pnp_id:
        return vid, pid
    parts = pnp_id.upper().split("\\")
    for p in parts:
        if "VID_" in p and "PID_" in p:
            for fragment in p.split("&"):
                if fragment.startswith("VID_"):
                    vid = fragment[4:8] if len(fragment) >= 8 else fragment[4:]
                elif fragment.startswith("PID_"):
                    pid = fragment[4:8] if len(fragment) >= 8 else fragment[4:]
    return vid, pid


class UsbWatcher(Module):
    name = "UsbWatcher"

    def __init__(self, bus: EventBus, db: Database, interval_s: int = POLL_INTERVAL_S):
        super().__init__(bus)
        self.db = db
        self.interval_s = max(2, int(interval_s))
        # Aktuell bekannte Devices: pnp_id -> dict
        self._known: dict[str, dict] = {}
        self._baseline_ready = False
        self._t_started = 0.0
        # Composite-tracking: per VID+PID welche Klassen wir gesehen haben
        self._composite_classes: dict[str, set[str]] = {}

    # ------------------------------------------------------------------
    def run(self) -> None:
        self._t_started = time.time()
        while not self._stop.is_set():
            try:
                self._poll_once()
            except Exception as e:  # noqa: BLE001
                log.warning("usb-watch poll error: %s", e)
            if self._stop.wait(self.interval_s):
                break

    # ------------------------------------------------------------------
    def _poll_once(self) -> None:
        rows = self._enumerate()
        if rows is None:
            return    # WMI failure — silent skip
        now = time.time()
        baseline = (now - self._t_started) < BASELINE_S
        current_ids = {r["DeviceID"] for r in rows if r.get("DeviceID")}

        # Neue Devices
        new_devs = []
        for r in rows:
            dev_id = r.get("DeviceID") or ""
            if not dev_id:
                continue
            if dev_id not in self._known:
                r["vid"], r["pid"] = _parse_vid_pid(dev_id)
                self._known[dev_id] = r
                if baseline:
                    continue   # Baseline: lernen, nicht emitten
                new_devs.append(r)

        # Entfernte Devices
        removed = []
        for dev_id in list(self._known.keys()):
            if dev_id not in current_ids:
                removed.append(self._known.pop(dev_id))

        if not self._baseline_ready and not baseline:
            self._baseline_ready = True
            self.emit(Severity.INFO, Category.SYSTEM,
                      f"USB-Baseline gelernt: {len(self._known)} Devices")

        # Events emittieren
        for r in new_devs:
            self._emit_new(r)
        for r in removed:
            self._emit_removed(r)

    # ------------------------------------------------------------------
    def _enumerate(self) -> Optional[list[dict]]:
        try:
            r = run_hidden(
                ["powershell.exe", "-NoProfile", "-NonInteractive",
                 "-WindowStyle", "Hidden",
                 "-ExecutionPolicy", "Bypass", "-Command", PS_SCRIPT],
                capture_output=True, timeout=20,
                encoding="utf-8", errors="replace",
                creationflags=CREATE_NO_WINDOW,
            )
            if r.returncode != 0 or not r.stdout:
                return None
            data = json.loads(r.stdout)
            if isinstance(data, dict):
                return [data]
            return data or []
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return None
        except Exception as e:  # noqa: BLE001
            log.warning("usb-watch enumerate failed: %s", e)
            return None

    # ------------------------------------------------------------------
    def _blocklist(self) -> set[str]:
        """User-defined VID:PID blocklist via DB-Settings (comma-separated)."""
        s = (self.db.get_setting("usb_vid_pid_blocklist", "") or "").upper()
        return set(t.strip() for t in s.split(",") if ":" in t)

    def _emit_new(self, r: dict) -> None:
        dev_id = r.get("DeviceID", "") or ""
        name = r.get("Name", "") or "(unknown)"
        cls = r.get("Class", "") or ""
        mfr = r.get("Manufacturer", "") or ""
        vid, pid = _parse_vid_pid(dev_id)
        friendly = PNP_CLASS_FRIENDLY.get(cls, cls or "USB device")
        key = f"{vid}:{pid}".upper()
        meta = {"name": name, "class": cls, "vid": vid, "pid": pid,
                "manufacturer": mfr, "device_id": dev_id[:200]}

        # 1) Blocklist check (highest priority)
        if key in self._blocklist():
            self.emit(Severity.CRITICAL, Category.SYSTEM,
                      f"USB-BLOCKLIST: {friendly} {key} ({name})", meta)
            return

        # 2) Composite tracking: gleicher VID+PID, mehrere Klassen
        if vid and pid:
            seen = self._composite_classes.setdefault(key, set())
            seen.add(cls)
            has_storage = bool(seen.intersection({"DiskDrive", "USB"}))
            has_kbd     = "Keyboard" in seen
            if has_storage and has_kbd:
                self.emit(Severity.CRITICAL, Category.SYSTEM,
                          f"BadUSB-Verdacht: Device {key} hat Storage+Keyboard "
                          f"(Composite — typisches Rubber-Ducky-Pattern). {name}",
                          meta)
                return

        # 3) Per-class severity
        if cls == "DiskDrive":
            self.emit(Severity.WARN, Category.FILE,
                      f"Removable storage angeschlossen: {name}", meta)
        elif cls == "Keyboard":
            self.emit(Severity.WARN, Category.SYSTEM,
                      f"USB-Keyboard angeschlossen: {name} (vid={vid} pid={pid})", meta)
        elif cls == "Net":
            self.emit(Severity.WARN, Category.NETWORK,
                      f"USB-Netzwerk-Adapter angeschlossen: {name}", meta)
        elif cls == "Mouse":
            self.emit(Severity.INFO, Category.SYSTEM,
                      f"USB-Mouse: {name}", meta)
        else:
            self.emit(Severity.INFO, Category.SYSTEM,
                      f"USB-Device: {friendly} ({name})", meta)
    def _emit_removed(self, r: dict) -> None:
        name = r.get("Name", "") or "(unknown)"
        cls  = r.get("Class", "") or ""
        if cls in ("Keyboard", "DiskDrive", "Net"):
            self.emit(Severity.INFO, Category.SYSTEM,
                      f"USB entfernt: {name} ({cls})", {})
