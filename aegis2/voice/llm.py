"""Optionale lokale LLM-Konversation via Ollama — gratis, offline, kein Key.

Nur aktiv, wenn Ollama lokal laeuft (127.0.0.1:11434). Ist es nicht da, gibt
ask() einfach None zurueck und AEGIS bleibt bei Persona + Befehlen. Keine Cloud,
kein Schluessel, keine Daten verlassen den PC.
"""
from __future__ import annotations

import json
import re

try:
    import urllib.request as _u
except Exception:  # noqa: BLE001
    _u = None

OLLAMA = "http://127.0.0.1:11434"
SYSTEM = ("Du bist AEGIS, der lokale Sicherheits-Assistent auf dem PC des Nutzers — "
          "freundlich, direkt, kompetent. Sprich AUSSCHLIESSLICH Deutsch — niemals "
          "englische Woerter einmischen —, natuerlich und KONKRET. "
          "Antworte knapp, aber mit Substanz (2-4 Saetze) — lieber eine klare, "
          "informative Antwort als eine nichtssagende. Stelle nicht bei jeder Antwort "
          "eine Gegenfrage. Keine Regieanweisungen oder (Pause)-Hinweise, keine Emojis, "
          "keine Listen — nur gesprochener Text. Beziehe dich auf das bisherige Gespraech.\n"
          "DEINE FAEHIGKEITEN — nutze sie, wenn der Nutzer fragt, was du kannst, und "
          "antworte dann mit JA + Beispiel-Befehl statt pauschal abzulehnen: Du kannst "
          "installierte PROGRAMME/Apps per Name oeffnen oder nach vorn holen (z.B. "
          "'oeffne Discord', 'oeffne Steam') — auch .exe-Programme, solange sie "
          "installiert sind; nur beliebige fremde Datei-PFADE oeffnest du aus Sicherheit "
          "nicht. Du oeffnest Websites, suchst im Web sowie auf Spotify/YouTube, meldest "
          "den Sicherheits-Status, startest Scans, zeigst Bedrohungen und die Quarantaene "
          "und kannst lokale KI-Modelle laden ('ollama pull ...'). "
          "WICHTIG — DU PLAUDERST NUR: Die eigentlichen Aktionen (Scan, Oeffnen, "
          "Quarantaene) laufen ueber feste Befehle, NICHT ueber dieses Gespraech. "
          "Behaupte NIEMALS, du haettest einen Scan oder eine Aktion gestartet, "
          "durchgefuehrt oder abgeschlossen — das waere bei einem Sicherheits-Tool eine "
          "gefaehrliche Luege. Wenn der Nutzer eine Aktion will, nenne ihm den Befehl, "
          "z.B.: 'Sag einfach Scan, dann starte ich einen echten System-Scan.'")


def _clean(t: str) -> str:
    """Entfernt Stoerer: <think>-Bloecke (qwen3-Reasoning), (Regie-Hinweise),
    *Aktionen*, Mehrfach-Whitespace."""
    if not t:
        return t
    t = re.sub(r"(?is)<think>.*?</think>", "", t)   # qwen3 'denkt laut' -> komplett raus
    t = re.sub(r"(?is)<think>.*$", "", t)           # offener/abgeschnittener think-Block
    t = re.sub(r"\([^)]{0,40}\)", "", t)        # (Pause), (lacht)
    t = re.sub(r"\*[^*]{0,40}\*", "", t)         # *seufzt*
    t = re.sub(r"\s{2,}", " ", t).strip()
    return t


def available(timeout: float = 2.5) -> bool:
    if _u is None:
        return False
    try:
        with _u.urlopen(OLLAMA + "/api/tags", timeout=timeout) as r:
            return getattr(r, "status", 200) == 200
    except Exception:
        return False


def first_model() -> str | None:
    try:
        with _u.urlopen(OLLAMA + "/api/tags", timeout=1.5) as r:
            models = json.loads(r.read().decode("utf-8")).get("models", [])
            return models[0]["name"] if models else None
    except Exception:
        return None


def installed_models() -> list:
    """Namen aller lokal installierten Modelle (per HTTP, kein subprocess)."""
    try:
        with _u.urlopen(OLLAMA + "/api/tags", timeout=1.5) as r:
            return [m.get("name", "") for m in
                    json.loads(r.read().decode("utf-8")).get("models", []) if m.get("name")]
    except Exception:
        return []


# Praeferenz (bestes zuerst) fuer die Auto-Wahl, wenn der Nutzer nichts gesetzt hat.
_PREFERRED = ("qwen3:30b-a3b-instruct-2507", "qwen3:14b", "qwen3:8b", "qwen3:4b-instruct",
              "qwen3:4b", "qwen2.5:7b", "qwen2.5:3b", "llama3.1:8b", "llama3.2:3b")


def active_model() -> str | None:
    """Das zu nutzende Modell — verlaesslich statt zufaellig models[0]:
       1) vom Nutzer aktiviertes Modell (Setting 'llm_model'), falls installiert
       2) bestes installiertes nach Praeferenzliste
       3) Fallback: erstes verfuegbares."""
    inst = installed_models()
    if not inst:
        return None
    try:
        from ..shared.db import get_db
        chosen = (get_db().get_setting("llm_model", "") or "").strip()
        if chosen and chosen in inst:
            return chosen
    except Exception:  # noqa: BLE001
        pass
    for p in _PREFERRED:
        if p in inst:
            return p
    return inst[0]


def set_active_model(name: str) -> bool:
    """Aktives Modell als Setting speichern -> wirkt sofort beim naechsten ask()."""
    try:
        from ..shared.db import get_db
        get_db().set_setting("llm_model", (name or "").strip())
        return True
    except Exception:  # noqa: BLE001
        return False


def ask_json(prompt: str, system: str | None = None, timeout: int = 45,
             num_predict: int = 400, schema: dict | None = None) -> dict | None:
    """Wie ask(), erzwingt aber JSON-Output (Ollama format=json) und parst es.

    Fuer das Reasoning-Lernen: niedrige Temperatur = konsistente Verdikte.
    Returns dict | None (None wenn Ollama fehlt/Antwort unbrauchbar).
    """
    if _u is None or not prompt:
        return None
    m = active_model()
    if not m:
        return None
    body = json.dumps({
        "model": m, "prompt": prompt, "system": system or SYSTEM,
        "stream": False, "format": schema if schema else "json",
        "options": {"num_predict": num_predict, "temperature": 0.0 if schema else 0.2},
    }).encode("utf-8")
    try:
        req = _u.Request(OLLAMA + "/api/generate", data=body,
                         headers={"Content-Type": "application/json"})
        with _u.urlopen(req, timeout=timeout) as r:
            resp = (json.loads(r.read().decode("utf-8")).get("response") or "").strip()
        return json.loads(resp) if resp else None
    except Exception:
        return None


def _has_cjk(t: str) -> bool:
    """True, wenn der Text nennenswert chin./jap./kor. Schriftzeichen enthaelt —
    Qwen rutscht bei manchen (oft emotionalen) Eingaben ins Chinesische."""
    if not t:
        return False
    n = sum(1 for ch in t if "぀" <= ch <= "鿿"
            or "가" <= ch <= "힯" or "＀" <= ch <= "￯")
    return n >= 2


def ask(prompt: str, model: str | None = None, timeout: int = 120,
        system: str | None = None, num_predict: int = 480) -> str | None:
    if _u is None or not prompt:
        return None
    m = model or active_model()
    if not m:
        return None

    def _gen(sys_prompt: str):
        body = json.dumps({
            "model": m, "prompt": prompt, "system": sys_prompt, "stream": False,
            "keep_alive": "30m",   # Modell 30 Min im Speicher halten -> kein langsames
                                   # Neu-Laden bei Folgefragen (Hauptgrund fuer "dauert lange")
            "options": {"num_predict": num_predict, "temperature": 0.5},
        }).encode("utf-8")
        try:
            req = _u.Request(OLLAMA + "/api/generate", data=body,
                             headers={"Content-Type": "application/json"})
            with _u.urlopen(req, timeout=timeout) as r:
                return _clean(json.loads(r.read().decode("utf-8")).get("response") or "")
        except Exception:
            return None

    resp = _gen(system or SYSTEM)
    # CJK-Rueckfall-Schutz: fremde Schriftzeichen -> einmal hart auf Deutsch neu generieren
    if resp and _has_cjk(resp):
        hard = (system or SYSTEM) + ("\n\nABSOLUT KRITISCH: Antworte NUR auf Deutsch, "
               "AUSSCHLIESSLICH mit lateinischen Buchstaben. KEINE chinesischen, "
               "japanischen oder koreanischen Schriftzeichen.")
        resp2 = _gen(hard)
        if resp2 and not _has_cjk(resp2):
            return resp2
        return "Alles klar. Womit kann ich dir helfen?"     # bleibt fremd -> sauberer Fallback
    return resp or None
