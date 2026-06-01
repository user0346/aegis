"""Browser-Control-Bruecke (Desktop-Seite) — schreibt Steuer-Befehle fuer die AEGIS-Browser-
Extension in eine datei-basierte Queue (vom Native-Host `setup/native_host.py` gepollt) und
liest deren Ergebnisse zurueck.

Die Extension fuehrt NUR eine Allow-List aus (Medien pausieren/fortsetzen, Tab oeffnen-oder-
fokussieren, offene Tabs / "was laeuft" lesen). KEINE Passwoerter, KEIN Auto-Submit, KEIN
beliebiger Code. Ist der Browser/die Extension nicht aktiv, lebt die Bruecke nicht -> die
Aufrufer fallen sauber zurueck (z. B. auf webbrowser.open / Media-Taste).
"""
from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

_DIR = Path.home() / ".aegis"
CMD_FILE = _DIR / "browser_cmd.jsonl"
RESULT_FILE = _DIR / "browser_result.jsonl"
HEARTBEAT_FILE = _DIR / "browser_bridge_alive"


def bridge_alive(max_age_s: float = 8.0) -> bool:
    """True, wenn der Native-Host (Browser mit AEGIS-Extension) zuletzt kuerzlich lebte."""
    try:
        ts = int(HEARTBEAT_FILE.read_text(encoding="utf-8").strip())
        return (time.time() - ts) <= max_age_s
    except Exception:  # noqa: BLE001
        return False


def send(cmd: str, **args) -> str:
    """Steuer-Befehl an die Extension schicken (fire-and-forget). Returns die Befehls-id."""
    cid = secrets.token_hex(6)
    payload = {"cmd": cmd, "id": cid}
    payload.update(args)
    try:
        _DIR.mkdir(parents=True, exist_ok=True)
        with open(CMD_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass
    return cid


def request(cmd: str, timeout: float = 2.5, **args):
    """Befehl schicken UND auf das Ergebnis warten (fuer Lese-Befehle list_tabs/now_playing).
    Returns das Ergebnis-dict oder None bei Timeout/keiner Bruecke."""
    if not bridge_alive():
        return None
    try:
        start = RESULT_FILE.stat().st_size if RESULT_FILE.exists() else 0
    except Exception:  # noqa: BLE001
        start = 0
    cid = send(cmd, **args)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if RESULT_FILE.exists():
                with open(RESULT_FILE, "rb") as f:
                    f.seek(start)
                    data = f.read()
                for line in data.split(b"\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line.decode("utf-8", "replace"))
                    except Exception:  # noqa: BLE001
                        continue
                    if isinstance(r, dict) and r.get("id") == cid:
                        return r
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.12)
    return None
