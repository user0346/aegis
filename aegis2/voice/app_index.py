"""Index installierter Apps aus dem Windows-Start-Menue -> Start/Fokus per Name.

SICHERHEIT (2026-Best-Practice gegen Voice-Injection): Es werden NUR Verknuepfungen
(.lnk) aus den Start-Menue-Ordnern indexiert — also tatsaechlich installierte
Programme. Eine Sprach-/Texteingabe wird gegen die App-NAMEN gematcht und startet
hoechstens eine bekannte Verknuepfung; sie wird NIE als beliebiger Pfad/Command
ausgefuehrt. Damit kann auch eine eingeschleuste Eingabe kein fremdes .exe starten.

open_or_focus(): laeuft die App bereits, wird ihr Fenster in den Vordergrund geholt
(kein Doppelstart); sonst wird sie gestartet.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

_DIRS = [
    Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
    Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
]
_SKIP = ("uninstall", "deinstall", "readme", "lizenz", "license", "hilfe", "help",
         "website", "homepage", "support", "report", "changelog")


@lru_cache(maxsize=1)
def _index() -> dict:
    idx: dict = {}
    for d in _DIRS:
        try:
            if not d.exists():
                continue
            for lnk in d.rglob("*.lnk"):
                name = lnk.stem.strip().lower()
                if not name or any(s in name for s in _SKIP):
                    continue
                idx.setdefault(name, str(lnk))
        except Exception:  # noqa: BLE001
            continue
    return idx


def find_app(query: str) -> Optional[str]:
    """Findet den .lnk-Pfad zu einem App-Namen: exakt -> enthaelt -> Wort-Treffer."""
    q = (query or "").strip().lower()
    if not q:
        return None
    idx = _index()
    if q in idx:
        return idx[q]
    # Teilstring-/Wort-Treffer NUR ab aussagekraeftiger Laenge (>=4 Zeichen) —
    # sonst matcht "ey" faelschlich "k[ey]board"/"Editor" usw. (False-Positive).
    if len(q) < 4:
        return None
    for name, path in idx.items():
        if q in name:
            return path
    qwords = set(q.split())
    for name, path in idx.items():
        if qwords & set(name.replace("-", " ").replace("_", " ").split()):
            return path
    return None


def _target_exe(lnk_path: str) -> str:
    """Ziel-EXE einer .lnk-Verknuepfung (fuer Prozess-Abgleich)."""
    try:
        import win32com.client  # type: ignore
        sc = win32com.client.Dispatch("WScript.Shell").CreateShortCut(lnk_path)
        return sc.TargetPath or ""
    except Exception:  # noqa: BLE001
        return ""


def _running_pid(exe_path: str) -> Optional[int]:
    """PID eines laufenden Prozesses mit diesem EXE-Namen, sonst None."""
    if not exe_path:
        return None
    name = os.path.basename(exe_path).lower()
    try:
        import psutil  # type: ignore
        for p in psutil.process_iter(["name"]):
            try:
                if (p.info.get("name") or "").lower() == name:
                    return p.pid
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return None


def _focus_pid(pid: int) -> bool:
    """Holt das sichtbare Hauptfenster des Prozesses in den Vordergrund."""
    try:
        import win32gui  # type: ignore
        import win32process  # type: ignore
        import win32con  # type: ignore
        wins = []

        def _cb(hwnd, _):
            if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
                try:
                    _, wpid = win32process.GetWindowThreadProcessId(hwnd)
                    if wpid == pid:
                        wins.append(hwnd)
                except Exception:  # noqa: BLE001
                    pass
        win32gui.EnumWindows(_cb, None)
        if not wins:
            return False
        h = wins[0]
        win32gui.ShowWindow(h, win32con.SW_RESTORE)   # aus Minimiert holen
        try:
            # ALT-Trick umgeht die Windows-Foreground-Sperre
            import win32com.client  # type: ignore
            win32com.client.Dispatch("WScript.Shell").SendKeys("%")
        except Exception:  # noqa: BLE001
            pass
        try:
            win32gui.SetForegroundWindow(h)
        except Exception:  # noqa: BLE001
            pass
        return True
    except Exception:  # noqa: BLE001
        return False


def open_or_focus(query: str):
    """App finden; laeuft sie -> Fenster nach vorne; sonst starten.
    Returns (ok: bool, msg: str) oder None, wenn keine passende App gefunden wurde."""
    lnk = find_app(query)
    if not lnk:
        return None
    pid = _running_pid(_target_exe(lnk))
    if pid and _focus_pid(pid):
        return (True, "läuft bereits — in den Vordergrund geholt")
    try:
        os.startfile(lnk)  # noqa: S606  (nur indexierte .lnk, kein User-Pfad)
        return (True, "gestartet")
    except Exception as e:  # noqa: BLE001
        return (False, str(e))


def _pid_for(query: str):
    """PID der laufenden App zu `query` finden (über .lnk-Ziel-Exe, sonst Prozessname)."""
    pid = None
    try:
        lnk = find_app(query)
        if lnk:
            pid = _running_pid(_target_exe(lnk))
    except Exception:  # noqa: BLE001
        pid = None
    if not pid:
        try:
            pid = _running_pid(query if query.lower().endswith(".exe") else query + ".exe")
        except Exception:  # noqa: BLE001
            pid = None
    return pid


def _window_of_pid(pid: int):
    try:
        import win32gui      # type: ignore
        import win32process  # type: ignore
        wins = []

        def _cb(h, _):
            if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h):
                try:
                    _, wp = win32process.GetWindowThreadProcessId(h)
                    if wp == pid:
                        wins.append(h)
                except Exception:  # noqa: BLE001
                    pass
        win32gui.EnumWindows(_cb, None)
        return wins[0] if wins else None
    except Exception:  # noqa: BLE001
        return None


def focus_only(query: str):
    """Nur das BESTEHENDE Fenster nach vorne holen — startet NICHTS. (ok, msg)."""
    pid = _pid_for(query)
    if pid and _focus_pid(pid):
        return (True, "nach vorne geholt")
    return (False, "läuft gerade nicht")


def move_to_primary(query: str):
    """Das Fenster der App auf den Hauptmonitor verschieben (Größe bleibt, geklemmt). (ok, msg)."""
    pid = _pid_for(query)
    if not pid:
        return (False, "läuft gerade nicht")
    try:
        import win32gui  # type: ignore
        import win32con  # type: ignore
        import win32api  # type: ignore
        h = _window_of_pid(pid)
        if not h:
            return (False, "kein Fenster gefunden")
        mon = win32api.MonitorFromPoint((0, 0), win32con.MONITOR_DEFAULTTOPRIMARY)
        wl, wt, wr, wb = win32api.GetMonitorInfo(mon)["Work"]    # Arbeitsbereich Hauptmonitor
        win32gui.ShowWindow(h, win32con.SW_RESTORE)
        l, t, r, b = win32gui.GetWindowRect(h)
        w, ht = r - l, b - t
        nw, nh = min(w, wr - wl - 20), min(ht, wb - wt - 20)
        win32gui.SetWindowPos(h, 0, wl + 60, wt + 60, nw, nh, win32con.SWP_NOZORDER)
        try:
            win32gui.SetForegroundWindow(h)
        except Exception:  # noqa: BLE001
            pass
        return (True, "auf den Hauptmonitor verschoben")
    except Exception as e:  # noqa: BLE001
        return (False, str(e))
