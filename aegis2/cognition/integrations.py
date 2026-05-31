"""System-Integrationen — was AEGIS am PC tun darf.

Trennung in zwei Klassen:
  - READ-Operations (immer erlaubt im OBSERVE+ Level): system_info, browser_history,
    recent_files, installed_apps, running_processes.
  - WRITE-Operations (verlangen Consent-Token / Autonomy-Approval): open_url,
    launch_app, file_organize, notify, send_clipboard.

Jede WRITE-Funktion erwartet `consent_token` als ersten Parameter und
ruft consent.consume() bevor sie irgendwas tut.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Optional

from .consent import get_manager as _consent


# ============================================================
#  READ-Operations
# ============================================================

def system_info() -> dict:
    """Sicheres System-Snapshot. Keine PII."""
    out = {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "now": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        import psutil
        out["uptime_min"] = int((time.time() - psutil.boot_time()) / 60)
        out["memory_percent"] = psutil.virtual_memory().percent
        out["disk_c_free_gb"] = round(psutil.disk_usage("C:\\").free / 1024**3, 1) if sys.platform == "win32" else None
        try:
            bat = psutil.sensors_battery()
            if bat:
                out["battery_pct"] = bat.percent
                out["battery_plugged"] = bat.power_plugged
        except Exception:  # noqa: BLE001
            pass
    except ImportError:
        pass
    return out


def recent_files(limit: int = 20) -> list[dict]:
    """Liest %APPDATA%\\Microsoft\\Windows\\Recent — keine FS-Schreibrechte noetig."""
    if sys.platform != "win32":
        return []
    recent_dir = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
    if not recent_dir.exists():
        return []
    items = []
    try:
        files = sorted(recent_dir.glob("*.lnk"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        for f in files[:limit]:
            items.append({"name": f.stem, "mtime": f.stat().st_mtime})
    except OSError:
        pass
    return items


def installed_apps_quick() -> list[str]:
    """Naehrungs-Liste via Start-Menue Programs-Ordner."""
    if sys.platform != "win32":
        return []
    paths = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
        Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs",
    ]
    apps: set[str] = set()
    for base in paths:
        if not base.exists():
            continue
        try:
            for lnk in base.rglob("*.lnk"):
                apps.add(lnk.stem)
                if len(apps) > 400:
                    break
        except OSError:
            pass
    return sorted(apps)


def running_processes(limit: int = 50) -> list[dict]:
    try:
        import psutil
    except ImportError:
        return []
    out = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = p.info
            out.append({"pid": info.get("pid"),
                        "name": info.get("name"),
                        "cpu": info.get("cpu_percent"),
                        "mem": info.get("memory_percent")})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    out.sort(key=lambda x: x.get("mem") or 0, reverse=True)
    return out[:limit]


def browser_data_brief() -> dict:
    """Liefert nur Pfade + Vorhandensein, KEINE Inhalte ohne Consent.
    Dient als 'lookahead' damit das LLM weiss was theoretisch ginge.
    """
    home = Path.home()
    bases = {
        "chrome":  home / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default",
        "edge":    home / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default",
        "firefox": home / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles",
        "brave":   home / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default",
    }
    out = {}
    for name, p in bases.items():
        out[name] = {"present": p.exists()}
    return out


# ============================================================
#  WRITE-Operations — alle gated durch consent.consume()
# ============================================================

def _safe_consume(token: str, action: str) -> bool:
    try:
        return _consent().consume(token, action)
    except Exception:  # noqa: BLE001
        return False


def open_url(consent_token: str, url: str) -> dict:
    # Eigenes Action-Scope: open_url darf NICHT mit einem web_search-Token laufen.
    # web_search ist auto-erlaubt, open_url bewusst nicht — sonst Confused-Deputy-Bypass
    # (beliebige URL via auto-genehmigtem Such-Token oeffenbar).
    if not _safe_consume(consent_token, "open_url"):
        return {"ok": False, "error": "consent missing"}
    if not url or len(url) > 1000:
        return {"ok": False, "error": "invalid url"}
    # Sanity: nur http(s)
    if not url.lower().startswith(("http://", "https://")):
        return {"ok": False, "error": "only http(s) urls allowed"}
    try:
        webbrowser.open(url, new=2)
        return {"ok": True, "msg": f"opened: {url}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def web_search(consent_token: str, query: str, engine: str = "ddg") -> dict:
    if not _safe_consume(consent_token, "web_search"):
        return {"ok": False, "error": "consent missing"}
    if not query or len(query) > 500:
        return {"ok": False, "error": "invalid query"}
    q = urllib.parse.quote(query)
    url = ("https://duckduckgo.com/?q=" + q) if engine == "ddg" else ("https://www.google.com/search?q=" + q)
    try:
        webbrowser.open(url, new=2)
        return {"ok": True, "msg": f"search: {query}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def launch_app(consent_token: str, app: str) -> dict:
    """Startet eine App via 'cmd /c start' — Whitelist-Approach.

    Erlaubt: alphanumerisch + leerer-Spaces, max 64 chars, keine Pfade.
    Keine Shell-Metachars.
    """
    if not _safe_consume(consent_token, "launch_app"):
        return {"ok": False, "error": "consent missing"}
    app = (app or "").strip()
    if not app or len(app) > 64:
        return {"ok": False, "error": "invalid app name"}
    if any(c in app for c in '&|;`$<>"\\\n/'):
        return {"ok": False, "error": "shell metachar in app name"}
    if sys.platform != "win32":
        return {"ok": False, "error": "windows only"}
    try:
        subprocess.Popen(["cmd", "/c", "start", "", app], shell=False)
        return {"ok": True, "msg": f"launched: {app}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def notify(consent_token: str, title: str, message: str,
           duration_s: int = 5) -> dict:
    """Windows-Toast via PowerShell BurntToast oder ballloon."""
    if not _safe_consume(consent_token, "notification"):
        return {"ok": False, "error": "consent missing"}
    if not title or not message:
        return {"ok": False, "error": "title+message required"}
    title = title[:64]
    message = message[:256]
    try:
        # Simple-Tray-Fallback via msg.exe gibt's nicht mehr; nutze PowerShell SystemTray
        # Hier als Reliable-Fallback: schreibt in eine Sentinel-Datei die der UI-Shell pollen koennte.
        sentinel = Path.home() / ".aegis" / "notifications.jsonl"
        sentinel.parent.mkdir(parents=True, exist_ok=True)
        with open(sentinel, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": time.time(), "title": title, "message": message,
                "duration_s": duration_s,
            }) + "\n")
        return {"ok": True, "msg": "queued"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def file_organize_suggest(consent_token: str, folder: str) -> dict:
    """Analysiert Ordner, schlaegt Reorganisation vor. SCHREIBT NICHTS — nur Plan.
    Tatsaechliche Bewegung waere file_organize_execute (extra Consent).
    """
    if not _safe_consume(consent_token, "file_organize_suggest"):
        return {"ok": False, "error": "consent missing"}
    p = Path(folder)
    if not p.exists() or not p.is_dir():
        return {"ok": False, "error": "folder not found"}
    # Sanity: max recursion = 0, only direct children
    try:
        children = list(p.iterdir())
    except OSError:
        return {"ok": False, "error": "cannot read folder"}

    ext_groups = {
        "images": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"},
        "videos": {".mp4", ".mov", ".mkv", ".avi", ".webm"},
        "audio":  {".mp3", ".wav", ".flac", ".m4a", ".ogg"},
        "docs":   {".pdf", ".docx", ".doc", ".txt", ".md", ".odt", ".rtf"},
        "archives": {".zip", ".7z", ".rar", ".tar", ".gz"},
        "code":   {".py", ".js", ".ts", ".html", ".css", ".java", ".cpp", ".cs"},
        "exec":   {".exe", ".msi"},
    }
    plan: dict[str, list[str]] = {k: [] for k in ext_groups}
    plan["other"] = []
    for c in children:
        if c.is_dir():
            continue
        ext = c.suffix.lower()
        for group, exts in ext_groups.items():
            if ext in exts:
                plan[group].append(c.name)
                break
        else:
            plan["other"].append(c.name)
    plan = {k: v for k, v in plan.items() if v}    # leere weg
    return {"ok": True, "plan": plan,
            "summary": f"{sum(len(v) for v in plan.values())} Files in {len(plan)} Gruppen"}
