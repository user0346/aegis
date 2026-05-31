"""Entwicklungs-/Lern-Statistik — macht MESSBAR sichtbar, dass AEGIS dazulernt.

Zwei Teile:
  1. _current(db): der aktuelle Lernstand (Programme normal, Wissens-Themen,
     geblockte Domains, verfeinerte Muster, erkannte Boesartige, Notizen,
     reflektierte Erkenntnisse) — aus dem vorhandenen learned_summary().
  2. Tages-Schnappschuesse (max. 1/Tag, in DB-Settings als JSON) -> daraus der
     Wochen-TREND ("+N seit ~1 Woche"). So SIEHT der Nutzer den Fortschritt,
     statt ihn glauben zu muessen.

Komplett defensiv: faellt eine Quelle aus, bleibt das Feld 0 statt zu crashen.
"""
from __future__ import annotations

import threading
import time

from .knowledge import learned_summary

_SNAP_KEY = "dev_snapshots_v1"
_MAX_SNAPS = 120

# Serialisiert das read-modify-write der Snapshots INNERHALB des Prozesses (mehrere
# Threads: periodischer Recorder + UI-Abfrage). Prozessuebergreifend ist es best-effort
# (Snapshots sind tagesweise + idempotent -> verlierbar ist hoechstens ein Intra-Tag-Delta).
_snap_lock = threading.Lock()


def _kb_count() -> int:
    try:
        from . import knowledge_base
        return int(knowledge_base.count() or 0)
    except Exception:  # noqa: BLE001
        return 0


def _notes_count() -> int:
    try:
        from . import user_memory
        return len([n for n in (user_memory.get_notes() or []) if str(n).strip()])
    except Exception:  # noqa: BLE001
        return 0


def _insights_count() -> int:
    try:
        import re as _re
        from .memory import find_learnings_file
        lf = find_learnings_file()
        if lf and lf.exists():
            return len(_re.findall(r"^###\s", lf.read_text(encoding="utf-8"), _re.M))
    except Exception:  # noqa: BLE001
        pass
    return 0


def _current(db) -> dict:
    """Aktueller Lernstand als flaches dict (alles Ganzzahlen)."""
    s = learned_summary(db)
    return {
        "programs_known": int(s.get("baseline_known", 0)),
        "knowledge_entries": _kb_count(),
        "domains_blocked": int(s.get("domains_blocked", 0)),
        "patterns": int(s.get("patterns_learned", 0)),
        "malicious_known": int(s.get("rep_bad", 0)),
        "quarantine_decided": int(s.get("quarantine_decided", 0)),
        "insights": _insights_count(),
        "notes": _notes_count(),
    }


def _ts(date_str) -> float:
    try:
        return time.mktime(time.strptime(str(date_str), "%Y-%m-%d"))
    except Exception:  # noqa: BLE001
        return 0.0


def _load_snaps(db) -> list:
    try:
        v = db.get_setting(_SNAP_KEY, [])     # DB dekodiert das JSON automatisch -> Liste
        return v if isinstance(v, list) else []
    except Exception:  # noqa: BLE001
        return []


def _save_snaps(db, snaps: list) -> None:
    try:
        db.set_setting(_SNAP_KEY, list(snaps[-_MAX_SNAPS:]))   # DB kodiert JSON automatisch
    except Exception:  # noqa: BLE001
        pass


def record_snapshot(db) -> None:
    """Hoechstens 1 Schnappschuss pro Tag (idempotent). Basis fuer den Trend.
    Heutiger Eintrag wird ueberschrieben (Hoechststand des Tages)."""
    try:
        with _snap_lock:                          # read-modify-write nicht verschachteln
            today = time.strftime("%Y-%m-%d")
            snaps = _load_snaps(db)
            cur = _current(db)
            if snaps and snaps[-1].get("date") == today:
                snaps[-1] = {"date": today, **cur}
            else:
                snaps.append({"date": today, **cur})
            _save_snaps(db, snaps)
    except Exception:  # noqa: BLE001
        pass


def _baseline_snapshot(snaps: list, days: int = 7):
    """Schnappschuss von ~`days` Tagen her (sonst der aelteste vorhandene)."""
    if not snaps:
        return None
    cutoff = time.time() - days * 86400
    older = [s for s in snaps if 0 < _ts(s.get("date")) <= cutoff]
    return older[-1] if older else snaps[0]


def development_stats(db) -> dict:
    """Vollbild fuer UI + Sprachbefehl: aktueller Stand + Wochen-Delta + Meta."""
    record_snapshot(db)                       # heutigen Stand festhalten
    snaps = _load_snaps(db)
    cur = _current(db)
    base = _baseline_snapshot(snaps, 7)
    delta = {}
    if base:
        for k, v in cur.items():
            try:
                delta[k] = int(v) - int(base.get(k, v))
            except Exception:  # noqa: BLE001
                delta[k] = 0
    since = snaps[0]["date"] if snaps else time.strftime("%Y-%m-%d")
    # _ts kann 0.0 liefern (unparsebares Datum) -> sonst (now-0)/86400 ~ 20605 Tage.
    # Dann auf die Zahl der Snapshots zurueckfallen und hart auf 10 Jahre deckeln.
    t_since = _ts(since)
    if snaps and t_since > 0:
        days_tracked = int((time.time() - t_since) / 86400) + 1
    else:
        days_tracked = len(snaps) or 1
    days_tracked = max(1, min(days_tracked, 3650))
    return {
        "current": cur,
        "delta7": delta,
        "since": since,
        "days_tracked": days_tracked,
        "points": len(snaps),
    }
