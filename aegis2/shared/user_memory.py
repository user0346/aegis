"""Persoenliches Gedaechtnis ueber Sessions hinweg — Anrede, Vorlieben, haeufige Befehle.

Liegt lokal in ~/.aegis/user_memory.json (verlaesst den PC nie). Wird der LLM-
Konversation als System-Kontext beigegeben, damit AEGIS den Nutzer "kennt" und
ihn z.B. mit der gewuenschten Anrede anspricht und haeufige Aktionen vorschlaegt.
"""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

_PATH = Path.home() / ".aegis" / "user_memory.json"
_LOCK = threading.Lock()


def _fresh() -> dict:
    return {"address": "", "wake_word": "", "facts": {}, "command_counts": {},
            "notes": [], "aliases": {}}


def _load() -> dict:
    try:
        d = json.loads(_PATH.read_text(encoding="utf-8"))
        if isinstance(d, dict):
            base = _fresh()
            base.update({k: d.get(k, base[k]) for k in base})
            return base
    except Exception:  # noqa: BLE001
        pass
    return _fresh()


def _save(d: dict) -> None:
    try:
        _PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(_PATH)
    except Exception:  # noqa: BLE001
        pass


def set_address(form: str) -> None:
    """Gewuenschte Anrede merken (z.B. 'SIR', 'Boss', Vorname)."""
    form = (form or "").strip()[:40]
    with _LOCK:
        d = _load()
        d["address"] = form
        _save(d)


def get_address() -> str:
    return (_load().get("address") or "").strip()


def set_wake_word(word: str) -> None:
    """Eigenes Weckwort/Name fuer AEGIS (z.B. 'Jarvis'). Leer = Standard 'AEGIS'."""
    word = (word or "").strip()[:24]
    with _LOCK:
        d = _load()
        d["wake_word"] = word
        _save(d)


def get_wake_word() -> str:
    return (_load().get("wake_word") or "").strip()


def remember(key: str, value: str) -> None:
    with _LOCK:
        d = _load()
        d["facts"][str(key).strip()[:60]] = str(value).strip()[:200]
        _save(d)


_NOTE_JUNK = {"dass", "das", "die", "der", "den", "es", "und", "mir", "ok", "ja", "nein"}


def add_note(text: str) -> bool:
    """Freier Fakt ('merk dir, dass ...'). Persistent, fliesst in den LLM-Kontext.
    Lehnt Bruchstuecke/Fuellwoerter/nackte URLs ab und kuerzt sauber an der Satz-/
    Wortgrenze (kein Muell im Gedaechtnis). Returns True, wenn etwas gespeichert wurde."""
    text = (text or "").strip()
    low = text.lower().rstrip(".!?")
    if len(text) < 8 or low in _NOTE_JUNK:
        return False
    if re.match(r"^https?://\S+$", text):          # nackte URL ohne Aussage -> kein Fakt
        return False
    if len(text) > 280:                            # an Satz-/Wortgrenze kuerzen, nicht im Wort
        cut = max(text.rfind(". ", 0, 280), text.rfind("! ", 0, 280), text.rfind("? ", 0, 280))
        text = (text[:cut + 1] if cut > 100 else text[:280].rsplit(" ", 1)[0] + " …")
    with _LOCK:
        d = _load()
        notes = d.get("notes") or []
        if text.lower() not in [n.lower() for n in notes]:
            notes.append(text)
            d["notes"] = notes[-30:]            # die letzten 30 behalten
            _save(d)
    return True


def get_notes() -> list:
    return list(_load().get("notes") or [])


def forget_notes() -> int:
    """Alle gemerkten Notizen loeschen ('vergiss alles'). Returns Anzahl."""
    with _LOCK:
        d = _load()
        n = len(d.get("notes") or [])
        d["notes"] = []
        _save(d)
        return n


def forget_note_matching(text: str) -> int:
    """Notizen loeschen, die den Suchtext enthalten (Teilstring ODER Wort-Ueberlappung).
    Returns Anzahl geloeschter Notizen — fuer gezieltes 'vergiss, dass ...'."""
    q = (text or "").strip().lower()
    if not q:
        return 0
    qwords = {w for w in re.findall(r"[a-zäöüß0-9]{3,}", q)}
    with _LOCK:
        d = _load()
        notes = d.get("notes") or []
        kept, removed = [], 0
        for n in notes:
            nl = n.lower()
            nwords = {w for w in re.findall(r"[a-zäöüß0-9]{3,}", nl)}
            if q in nl or (qwords and len(qwords & nwords) >= max(1, len(qwords) // 2)):
                removed += 1
            else:
                kept.append(n)
        if removed:
            d["notes"] = kept
            _save(d)
        return removed


def set_alias(name: str, target: str) -> None:
    """Benannter Shortcut: name (z.B. 'lofi music') -> target (URL/App/Suchbegriff).
    Spaeter spielt/oeffnet 'spiele <name>' oder der nackte Name das gespeicherte Ziel."""
    name = (name or "").strip().lower()[:60]
    target = (target or "").strip()[:500]
    if not name or not target:
        return
    with _LOCK:
        d = _load()
        al = d.get("aliases") or {}
        al[name] = target
        d["aliases"] = al
        _save(d)


def get_alias(name: str) -> str:
    """Target zu einem Shortcut-Namen ('' wenn keiner). Toleriert 'standard '-Prefix."""
    import re
    if not name:
        return ""
    key = name.strip().lower().rstrip("?!.")
    al = _load().get("aliases") or {}
    if key in al:
        return al[key]
    key2 = re.sub(r"^(?:standard|standart|meine?|mein|die|das|der)\s+", "", key)
    return al.get(key2, "")


def get_aliases() -> dict:
    return dict(_load().get("aliases") or {})


def note_command(intent: str) -> None:
    """Zaehlt ausgefuehrte Befehle -> Basis fuer 'was der Nutzer oft macht'."""
    if not intent or intent in ("query", "unknown", "close"):
        return
    with _LOCK:
        d = _load()
        d["command_counts"][intent] = int(d["command_counts"].get(intent, 0)) + 1
        _save(d)


def top_commands(n: int = 3) -> list:
    c = _load().get("command_counts", {})
    return sorted(c.keys(), key=lambda k: c.get(k, 0), reverse=True)[:n]


def context_string() -> str:
    """Kompakter Kontext fuer die LLM-Konversation (Anrede + Vorlieben + Gewohnheiten)."""
    d = _load()
    parts = []
    addr = (d.get("address") or "").strip()
    if addr:
        parts.append(f"Sprich den Nutzer konsequent mit «{addr}» an.")
    facts = d.get("facts") or {}
    if facts:
        f = "; ".join(f"{k}: {v}" for k, v in list(facts.items())[:8])
        parts.append(f"Bekannt ueber den Nutzer: {f}.")
    notes = d.get("notes") or []
    if notes:
        parts.append("Der Nutzer hat dir Folgendes zu merken gegeben: "
                     + "; ".join(notes[-12:]) + ".")
    tc = top_commands(3)
    if tc:
        parts.append(f"Der Nutzer macht oft: {', '.join(tc)}.")
    return " ".join(parts)
