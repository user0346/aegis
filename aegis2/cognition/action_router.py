"""Action-Decision-Framework — User-Wahl pro Action-Type.

Inspiration: Claude Desktop "Vor dem Handeln fragen" / "Ohne Rückfrage handeln".
User wählt per Severity + Action-Type wie AEGIS reagieren soll.

Modi pro (severity, category)-Combo:
  ASK       — Pop-up + Approve/Deny via Consent-Queue (default für critical)
  AUTO      — direkt ausführen, nur Audit-Log (default für info/warn)
  SIR       — sprich es laut aus ("SIR, ..."), dann ASK
  SILENT    — nur Audit, kein UI-Event

Konfiguration persistent in DB-Settings unter key "action_routing".
Default-Map gleich unten.

Routing-Tabelle:
  category=TAMPER, sev=CRITICAL    → SIR   (immer laut, immer Approve nötig)
  category=NETWORK, sev=CRITICAL   → SIR   (Router/ARP-Spoof — laut)
  category=FILE, sev=THREAT        → ASK   (Quarantäne-Vorschlag)
  category=PROCESS, sev=WARN       → AUTO  (loggen, nichts tun)
  category=SYSTEM, sev=INFO        → SILENT
  ...
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional


MODE_ASK    = "ASK"
MODE_AUTO   = "AUTO"
MODE_SIR    = "SIR"
MODE_SILENT = "SILENT"

VALID_MODES = {MODE_ASK, MODE_AUTO, MODE_SIR, MODE_SILENT}

# Default Routing: (category, severity) → mode
DEFAULT_ROUTING = {
    ("TAMPER",   "CRITICAL"):     MODE_SIR,
    ("TAMPER",   "THREAT"):       MODE_ASK,
    ("TAMPER",   "WARN"):         MODE_AUTO,

    ("NETWORK",  "CRITICAL"):     MODE_SIR,
    ("NETWORK",  "THREAT"):       MODE_ASK,
    ("NETWORK",  "WARN"):         MODE_AUTO,

    ("FILE",     "CRITICAL"):     MODE_SIR,
    ("FILE",     "THREAT"):       MODE_ASK,
    ("FILE",     "QUARANTINE"):   MODE_ASK,
    ("FILE",     "WARN"):         MODE_AUTO,

    ("PROCESS",  "CRITICAL"):     MODE_ASK,
    ("PROCESS",  "THREAT"):       MODE_ASK,
    ("PROCESS",  "WARN"):         MODE_AUTO,

    ("URL",      "THREAT"):       MODE_ASK,
    ("URL",      "WARN"):         MODE_AUTO,

    ("DNS",      "CRITICAL"):     MODE_SIR,
    ("DNS",      "THREAT"):       MODE_ASK,
    ("DNS",      "WARN"):         MODE_AUTO,

    ("QUARANTINE", "QUARANTINE"): MODE_ASK,

    ("SYSTEM",   "CRITICAL"):     MODE_SIR,
    ("SYSTEM",   "THREAT"):       MODE_ASK,
    ("SYSTEM",   "WARN"):         MODE_AUTO,
    ("SYSTEM",   "INFO"):         MODE_SILENT,

    ("VOICE",    "INFO"):         MODE_SILENT,
}


def _load_routing(db) -> dict:
    """Liest aktuelle Konfig aus DB-Settings. Falls leer: DEFAULT."""
    cfg = db.get_setting("action_routing") if db else None
    if not isinstance(cfg, dict):
        # Convert default tuple keys to "cat|sev" strings for JSON
        return {f"{c}|{s}": m for (c, s), m in DEFAULT_ROUTING.items()}
    return cfg


def get_mode(db, category: str, severity: str) -> str:
    cfg = _load_routing(db)
    key = f"{category}|{severity}"
    if key in cfg and cfg[key] in VALID_MODES:
        return cfg[key]
    # Fallback: AUTO für WARN/INFO, ASK für höher
    if severity in ("CRITICAL", "THREAT"):
        return MODE_ASK
    return MODE_AUTO


def set_mode(db, category: str, severity: str, mode: str) -> bool:
    if mode not in VALID_MODES:
        return False
    cfg = _load_routing(db)
    cfg[f"{category}|{severity}"] = mode
    db.set_setting("action_routing", cfg)
    return True


def all_modes(db) -> dict:
    """Gibt komplette Routing-Tabelle zurück für UI."""
    cfg = _load_routing(db)
    # Sort by category for UI
    sorted_entries = sorted(cfg.items())
    return {"entries": [{"category": k.split("|")[0],
                         "severity": k.split("|")[1],
                         "mode": v} for k, v in sorted_entries]}


def reset_to_defaults(db) -> None:
    db.set_setting("action_routing",
                   {f"{c}|{s}": m for (c, s), m in DEFAULT_ROUTING.items()})


# ============================================================
#  Notification-Pipeline
# ============================================================

NOTIFY_SENTINEL = Path.home() / ".aegis" / "notifications.jsonl"


def route_event(db, event_dict: dict) -> dict:
    """Nimmt ein dict-event entgegen, entscheidet basierend auf Mode was
    geschehen soll. Returns metadata für UI/Service.

    UI-Shell pollt NOTIFY_SENTINEL für SIR-Notifications und Voice-Output.
    """
    cat = event_dict.get("category", "SYSTEM")
    sev = event_dict.get("severity", "INFO")
    mode = get_mode(db, cat, sev)

    result = {
        "category": cat, "severity": sev, "mode": mode,
        "should_ask": mode in (MODE_ASK, MODE_SIR),
        "should_speak": mode == MODE_SIR,
        "should_log": mode != MODE_SILENT,
    }

    if mode == MODE_SIR:
        # Sir-Mode: Sentinel-Datei schreiben damit UI/Voice-Pipeline es aufgreift
        try:
            NOTIFY_SENTINEL.parent.mkdir(parents=True, exist_ok=True)
            with open(NOTIFY_SENTINEL, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": time.time(),
                    "kind": "sir",
                    "category": cat,
                    "severity": sev,
                    "message": event_dict.get("message", ""),
                    "metadata": event_dict.get("metadata", {}),
                    "tts_text": f"Sir, {sev.lower()} Event in {cat.lower()}: "
                                + event_dict.get("message", "")[:200],
                }, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001
            pass

    return result
