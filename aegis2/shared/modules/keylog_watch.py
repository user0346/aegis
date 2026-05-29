"""Keylogger-Detection (Phase 5c).

Detection ist HEURISTISCH — keine 100%-Garantie. Echte Detection braucht
Kernel-Driver (ETW kbd-class) den AEGIS bewusst NICHT installiert
(siehe BOOT_STRATEGY.md).

Stattdessen: pruefe ungewoehnliche Process-Verhalten die mit Keylog-
Aktivitaet korrelieren:

  1. PROCESSES MIT HIDDEN WINDOWS UND PERSISTENT
     - Prozess hat Window (HWND existiert)
     - Window-Style enthaelt WS_DISABLED oder Position off-screen
     - Process laeuft >5 Min
     -> WARN

  2. RAW-INPUT-REGISTRATION
     - Prozesse die RegisterRawInputDevices(RIDEV_INPUTSINK | KEYBOARD)
       aufgerufen haben sind potenzielle Global-Key-Capture
     - Read via NtQuerySystemInformation oder einfacher: ETW-Logging
       activate, dann pattern-match
     - Schwer ohne Driver; daher: schlanke Heuristik via Process-Name-DB

  3. PROCESSES MIT auffaelligen MODULES
     - DLLs die typische Keyhook-APIs nutzen: User32 + GetAsyncKeyState
     - Mehrfaches polling-Intervall ueber 1 Min

  4. PROCESSES IN AUTOSTART, die NICHT Microsoft-signed sind, UND
     auf User-Input reagieren ohne sichtbares Fenster

Was wir realistisch detecten:
  - Bekannte Keylogger via Signaturen-DB (signatures.py)
  - Heuristik: Hidden+Persistent+InputRelevant -> WARN
  - Process-Name auf einer User-eingebbaren Blocklist -> CRITICAL

Limitations sind explizit dokumentiert. False-Positive-Rate wird
aktiv getrackt via Calibration-Loop (learner.py).

Lauf-Intervall: 60s
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import os
import time
from typing import Optional

from ..db import Database
from ..events import EventBus, Severity, Category
from .base import Module


log = logging.getLogger("aegis2.keylog_watch")


POLL_INTERVAL_S = 60
BOOT_DELAY_S = 60
PROCESS_AGE_THRESHOLD_S = 300   # nur Prozesse aelter als 5 Min

# Sus-Process-Namen die ohne weiteren Check sofort WARN ausloesen.
# (Bekannte Keylogger; das ist eine kuratierte mini-DB, der vollstaendige
# Hash-Block ist in shared/signatures.py)
HEURISTIC_NAME_PATTERNS = (
    "keylogger", "keylog", "kbdcapture", "keystroke", "keytrap",
    "klg", "logkeys",
)

# Whitelist: bekannt-benigne Prozesse die typisch Global-Hooks nutzen
WHITELIST_PROCESSES = {
    # Microsoft
    "explorer.exe", "dwm.exe", "RuntimeBroker.exe", "ApplicationFrameHost.exe",
    "TextInputHost.exe", "ctfmon.exe",
    # Common AVs
    "MsMpEng.exe", "SecurityHealthService.exe", "SecurityHealthSystray.exe",
    # AEGIS itself
    "pythonw.exe", "python.exe",
    # Common system tray apps
    "OneDrive.exe", "Teams.exe", "MicrosoftEdgeUpdate.exe",
}


# ============================================================
#  Win32 helpers
# ============================================================
user32   = ctypes.WinDLL("user32",   use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi    = ctypes.WinDLL("psapi",    use_last_error=True)


PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WS_VISIBLE  = 0x10000000

EnumWindows         = user32.EnumWindows
EnumWindowsProc     = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
IsWindowVisible     = user32.IsWindowVisible
GetWindowTextLengthW= user32.GetWindowTextLengthW
GetWindowLongW      = user32.GetWindowLongW
GetWindowRect       = user32.GetWindowRect

OpenProcess         = kernel32.OpenProcess
OpenProcess.restype = wt.HANDLE
OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

CloseHandle         = kernel32.CloseHandle
GetProcessImageFileNameW = psapi.GetProcessImageFileNameW
QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW


def _image_name(pid: int) -> Optional[str]:
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wt.DWORD(len(buf))
        if QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
    except Exception:  # noqa: BLE001
        return None
    finally:
        CloseHandle(h)
    return None


# ============================================================
#  Detector
# ============================================================

class KeylogWatcher(Module):
    name = "KeylogWatcher"

    def __init__(self, bus: EventBus, db: Database, interval_s: int = POLL_INTERVAL_S):
        super().__init__(bus)
        self.db = db
        self.interval_s = max(20, int(interval_s))
        # Already-reported pids per name (to avoid spam)
        self._reported: set[str] = set()
        self._baseline: set[str] = set()
        self._baseline_done = False
        self._t_started = 0.0

    # ------------------------------------------------------------------
    def run(self) -> None:
        self._t_started = time.time()
        self._stop.wait(BOOT_DELAY_S)
        while not self._stop.is_set():
            try:
                self._scan_once()
            except Exception as e:  # noqa: BLE001
                log.warning("keylog scan failed: %s", e)
            if self._stop.wait(self.interval_s):
                break

    # ------------------------------------------------------------------
    def _scan_once(self) -> None:
        # 1) Process-Name patterns (mini-signature)
        try:
            import psutil
        except ImportError:
            log.warning("psutil not available — skipping keylog scan")
            return

        user_blocklist = self._user_blocklist()
        procs = list(psutil.process_iter(["pid", "name", "create_time", "exe"]))
        if not self._baseline_done:
            for _p in procs:
                try:
                    _i = _p.info; _n = (_i.get("name") or "").lower()
                    if _n: self._baseline.add(_n + "@" + (_i.get("exe") or ""))
                except Exception:
                    pass
            self._baseline_done = True
            self.emit(Severity.INFO, Category.SYSTEM,
                      "Keylog-Baseline gelernt: %d Prozesse (werden nicht geflaggt)" % len(self._baseline))
            return
        for proc in procs:
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                pid = info.get("pid") or 0
                exe = info.get("exe") or ""
                ct = info.get("create_time") or 0
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if not name:
                continue
            if name in WHITELIST_PROCESSES or name.lower() in {w.lower() for w in WHITELIST_PROCESSES}:
                continue

            key = f"{name}@{exe}"
            if key in self._reported:
                continue

            # Heuristik 1: Sus-Namen
            if any(pat in name for pat in HEURISTIC_NAME_PATTERNS):
                self._reported.add(key)
                self.emit(Severity.CRITICAL, Category.PROCESS,
                          f"Keylogger-Verdacht: Process-Name match '{name}'",
                          {"pid": pid, "exe": exe, "match": "name-pattern"})
                continue

            # Heuristik 2: User-Blocklist
            if name in user_blocklist or os.path.basename(exe).lower() in user_blocklist:
                self._reported.add(key)
                self.emit(Severity.CRITICAL, Category.PROCESS,
                          f"User-Blocklist match: '{name}'",
                          {"pid": pid, "exe": exe, "match": "user-blocklist"})
                continue

            # Heuristik 3: NUR neue, untrusted, hidden, persistente Prozesse.
            age = time.time() - ct if ct else 0
            if age < PROCESS_AGE_THRESHOLD_S:
                continue
            if key in self._baseline:
                continue
            if self._is_trusted_path(exe):
                continue
            if not self._has_hidden_window(pid):
                continue
            if self._has_visible_window(pid):
                continue
            self._reported.add(key)
            self.emit(Severity.WARN, Category.PROCESS,
                      f"Hidden persistent process: {name} (age={int(age)}s)",
                      {"pid": pid, "exe": exe,
                       "match": "heuristic-hidden-persistent"})

    # ------------------------------------------------------------------
    def _user_blocklist(self) -> set[str]:
        s = (self.db.get_setting("keylog_blocklist_names", "") or "").lower()
        return set(t.strip() for t in s.split(",") if t.strip())

    @staticmethod
    def _is_trusted_path(exe: str) -> bool:
        e = (exe or "").lower().replace(chr(92), "/")
        if not e:
            return False
        for p in ("c:/windows/", "c:/program files/", "c:/program files (x86)/", "c:/programdata/"):
            if e.startswith(p):
                return True
        return ("/windowsapps/" in e) or ("/appdata/local/programs/" in e)

    # ------------------------------------------------------------------
    def _has_hidden_window(self, pid: int) -> bool:
        """True wenn der PID mindestens ein Top-Level-Window hat das NICHT
        visible ist (off-screen oder WS_VISIBLE-Flag fehlt)."""
        found = [False]

        @EnumWindowsProc
        def cb(hwnd, _lparam):
            p = wt.DWORD(0)
            GetWindowThreadProcessId(hwnd, ctypes.byref(p))
            if p.value != pid:
                return True
            # Window gehoert zu unserem PID
            if not IsWindowVisible(hwnd):
                found[0] = True
                return False
            # Check off-screen
            rect = wt.RECT()
            if GetWindowRect(hwnd, ctypes.byref(rect)):
                if rect.left < -10000 or rect.top < -10000:
                    found[0] = True
                    return False
            return True

        try:
            EnumWindows(cb, 0)
        except Exception:  # noqa: BLE001
            return False
        return found[0]

    def _has_visible_window(self, pid: int) -> bool:
        found = [False]

        @EnumWindowsProc
        def cb(hwnd, _lparam):
            p = wt.DWORD(0)
            GetWindowThreadProcessId(hwnd, ctypes.byref(p))
            if p.value != pid:
                return True
            if IsWindowVisible(hwnd):
                if GetWindowTextLengthW(hwnd) > 0:
                    found[0] = True
                    return False
            return True

        try:
            EnumWindows(cb, 0)
        except Exception:  # noqa: BLE001
            return False
        return found[0]
