"""Asynchrones Gedaechtnis — AEGIS merkt sich von selbst dauerhafte Fakten ueber den Nutzer.

Idee (Agenten-Recherche 2026, mem0 schlank ohne Vektor-DB): Nach jedem Chat-Turn laeuft im
HINTERGRUND ein billiger, JSON-erzwungener LLM-Call, der NUR explizit genannte, dauerhafte
Fakten (Name, Vorlieben, Beruf, Geraete, Gewohnheiten) extrahiert und ins lokale user_memory
legt. Der Nutzer wartet NIE darauf (eigener Worker-Thread, nach dem Senden der Antwort).
Diese Fakten fliessen ueber user_memory.context_string() in den naechsten System-Prompt ->
AEGIS "kennt" dich ueber Sessions hinweg.

Datenschutz: alles bleibt lokal (~/.aegis/user_memory.json), verlaesst den PC nie. Nur
EXPLIZIT Gesagtes wird gespeichert (keine Spekulation). Abschaltbar via Setting
'auto_memory_enabled' (Default an). 'vergiss alles' loescht weiterhin alles.
"""
from __future__ import annotations

import queue
import threading

_q: "queue.Queue[tuple[str, str]]" = queue.Queue(maxsize=64)
_started = False
_lock = threading.Lock()

# Strenges Schema -> Ollama erzwingt valides JSON (GBNF). Leeres facts = nichts Merkenswertes.
_SCHEMA = {
    "type": "object",
    "properties": {
        "facts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"],
            },
        }
    },
    "required": ["facts"],
}

_SYS = (
    "Du bist ein Gedaechtnis-Extraktor. Aus einem kurzen Gespraech ziehst du NUR DAUERHAFTE, "
    "EXPLIZIT vom Nutzer genannte Fakten ueber den NUTZER selbst (Name/Anrede, Vorlieben, "
    "Abneigungen, Beruf, Wohnort, Geraete, feste Gewohnheiten). REGELN: Nur was der Nutzer "
    "WIRKLICH gesagt hat — niemals raten oder aus AEGIS' Antwort ableiten. Keine fluechtigen "
    "Dinge (aktuelle Uhrzeit, einmalige Befehle, Smalltalk). 'key' = kurzes deutsches Schlagwort "
    "(z.B. 'Name', 'mag', 'Beruf'), 'value' = knapp. Nichts Merkenswertes -> leere Liste."
)


def _enabled() -> bool:
    try:
        from ..shared.db import get_db
        return bool(get_db().get_setting("auto_memory_enabled", True))
    except Exception:  # noqa: BLE001
        return True


def observe(user_text: str, answer: str) -> None:
    """Einen Chat-Turn zum Hintergrund-Merken anmelden. Blockt nie (best-effort, non-blocking)."""
    if not user_text or len(user_text.strip()) < 6:
        return
    if not _enabled():
        return
    _ensure_worker()
    try:
        _q.put_nowait((user_text.strip(), (answer or "").strip()))
    except queue.Full:  # Backlog voll -> diesen Turn einfach auslassen
        pass


def _ensure_worker() -> None:
    global _started
    with _lock:
        if _started:
            return
        _started = True
        threading.Thread(target=_worker, daemon=True, name="AutoMemory").start()


def _worker() -> None:
    while True:
        user_text, answer = _q.get()
        try:
            _extract(user_text, answer)
        except Exception:  # noqa: BLE001
            pass
        finally:
            _q.task_done()


def _extract(user_text: str, answer: str) -> None:
    from . import llm
    from ..shared import user_memory
    prompt = (f"Gespraech:\nNutzer: {user_text[:600]}\nAEGIS: {answer[:300]}\n\n"
              "Welche dauerhaften Fakten ueber den NUTZER wurden hier EXPLIZIT genannt?")
    data = llm.ask_json(prompt, system=_SYS, schema=_SCHEMA, num_predict=200, timeout=30)
    if not data or not isinstance(data, dict):
        return
    for f in (data.get("facts") or [])[:5]:
        if not isinstance(f, dict):
            continue
        k = str(f.get("key") or "").strip()[:40]
        v = str(f.get("value") or "").strip()[:160]
        # Muell-/Leer-Schutz: beide Teile sinnvoll, value nicht bloss "unbekannt"/"keine"
        if k and v and v.lower() not in ("unbekannt", "keine", "n/a", "-", "null", "none"):
            user_memory.remember(k, v)
