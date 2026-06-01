"""Optionale lokale LLM-Konversation via Ollama — gratis, offline, kein Key.

Nur aktiv, wenn Ollama lokal laeuft (127.0.0.1:11434). Ist es nicht da, gibt
ask() einfach None zurueck und AEGIS bleibt bei Persona + Befehlen. Keine Cloud,
kein Schluessel, keine Daten verlassen den PC.
"""
from __future__ import annotations

import json
import re
import threading

try:
    import urllib.request as _u
except Exception:  # noqa: BLE001
    _u = None

OLLAMA = "http://127.0.0.1:11434"
SYSTEM = ("Du bist AEGIS, der lokale Sicherheits-Assistent auf dem PC des Nutzers — "
          "freundlich, direkt, trocken-kompetent. Du DUZT den Nutzer immer (niemals 'Sie') und "
          "sprichst reines, natuerliches Deutsch — KEINE englischen Woerter einmischen (kein "
          "'however', 'actually', 'sure', 'okay so'); Eigennamen wie Windows oder Ollama bleiben. "
          "Beispielton: 'Klar, schau ich dir an.'\n"
          "SO ANTWORTEST DU (deine Antwort wird VORGELESEN): kurze, gesprochene Saetze. "
          "KEINE Listen, Aufzaehlungen, Sternchen, Markdown, Emojis oder Regieanweisungen. "
          "Standardmaessig 1-3 Saetze — geh nur ins Detail, wenn ausdruecklich gefragt; "
          "lieber eine klare, konkrete Antwort als Gefasel. Zahlen, Daten und Abkuerzungen "
          "sprichst du aus (z.B. 'fuenfzehnhundert Euro', 'A-P-I', '1. Mai' als 'erster Mai'). "
          "Keine Floskeln wie 'Als KI-Modell'. Weisst du etwas nicht, sag es in EINEM Satz "
          "und schlage den naechsten Schritt vor. Ist die Anfrage mehrdeutig, stell GENAU EINE "
          "kurze Rueckfrage, sonst antworte direkt. Beziehe dich auf das bisherige Gespraech.\n"
          "DEINE FAEHIGKEITEN — nenne sie mit JA + Beispiel, wenn gefragt wird, was du kannst: "
          "installierte Programme/Apps per Name oeffnen ('oeffne Discord', 'oeffne Steam'), "
          "Websites oeffnen, im Web sowie auf Spotify/YouTube suchen, den Sicherheits-Status "
          "melden, Scans starten, Bedrohungen und die Quarantaene zeigen, lokale KI-Modelle "
          "laden ('ollama pull ...'). Nur fremde Datei-PFADE oeffnest du aus Sicherheit nicht.\n"
          "WICHTIG — DU PLAUDERST NUR: Die echten Aktionen (Scan, Oeffnen, Quarantaene) laufen "
          "ueber feste Befehle, NICHT ueber dieses Gespraech. Behaupte NIEMALS, du haettest "
          "einen Scan oder eine Aktion gestartet, durchgefuehrt oder abgeschlossen — bei einem "
          "Sicherheits-Tool waere das eine gefaehrliche Luege. Will der Nutzer eine Aktion, "
          "nenne ihm den Befehl, z.B.: 'Sag einfach Scan, dann starte ich einen echten System-Scan.'")


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


# ============================================================
#  Multi-Backend: Default = Ollama nativ (unveraendert). Setzt der Nutzer
#  'llm_provider' = "openai_compatible", geht ask() ueber die OpenAI-kompatible
#  /v1/chat/completions-API -> deckt LM Studio, llama.cpp, vLLM, Jan, LocalAI,
#  KoboldCpp, GPT4All UND Cloud ab. Nur base_url/model/api_key noetig.
# ============================================================
def _provider() -> str:
    try:
        from ..shared.db import get_db
        db = get_db()
        p = (db.get_setting("llm_provider", "ollama") or "ollama").strip().lower()
    except Exception:  # noqa: BLE001
        return "ollama"
    # SELBSTHEILUNG: "Fremd-Backend" gewaehlt, aber KEINE Adresse hinterlegt -> das ist nie
    # erreichbar und wuerde den Assistenten stumm schalten ("brauche lokale KI"). Statt-
    # dessen automatisch das lokale Ollama nehmen, das ja laeuft. Der Nutzer muss nichts tun.
    if p == "openai_compatible":
        try:
            if not (db.get_setting("llm_base_url", "") or "").strip():
                return "ollama"
        except Exception:  # noqa: BLE001
            return "ollama"
    return p


def _oai_cfg() -> dict:
    """base_url (mit /v1), model, api_key aus den Settings."""
    try:
        from ..shared.db import get_db
        db = get_db()
        base = (db.get_setting("llm_base_url", "") or "").strip().rstrip("/")
        if base and not base.endswith("/v1"):
            base += "/v1"
        key = ""
        try:
            from ..cognition.secrets_store import get_secret
            key = (get_secret("llm_api_key") or "").strip()   # Cloud-Key verschluesselt
        except Exception:  # noqa: BLE001
            key = ""
        return {"base": base,
                "model": (db.get_setting("llm_model", "") or "").strip(),
                "key": key}
    except Exception:  # noqa: BLE001
        return {"base": "", "model": "", "key": ""}


def _ask_openai_compatible(prompt: str, system: str, timeout: int, num_predict: int) -> str | None:
    cfg = _oai_cfg()
    if _u is None or not cfg["base"] or not cfg["model"]:
        return None
    body = json.dumps({
        "model": cfg["model"],
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": prompt}],
        "temperature": 0.5, "max_tokens": num_predict, "stream": False,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json",
               "Authorization": "Bearer " + (cfg["key"] or "not-needed")}
    try:
        req = _u.Request(cfg["base"] + "/chat/completions", data=body, headers=headers)
        with _u.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode("utf-8"))
        choices = d.get("choices") or [{}]
        txt = ((choices[0].get("message") or {}).get("content") or "").strip()
        return _clean(txt) or None
    except Exception:  # noqa: BLE001
        return None


def available(timeout: float = 2.5) -> bool:
    if _u is None:
        return False
    if _provider() == "openai_compatible":
        cfg = _oai_cfg()
        if not cfg["base"] or not cfg["model"]:
            return False
        try:
            with _u.urlopen(cfg["base"] + "/models", timeout=timeout) as r:
                return getattr(r, "status", 200) == 200
        except Exception:  # noqa: BLE001
            return True   # /models evtl. auth-gated -> konfiguriert = nutzbar (ask() zeigt echte Fehler)
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
# 2026-Recherche: Gemma 3 = bestes DEUTSCH (Polish), Qwen3 = bester Reasoning/Agent-
# Allrounder (Apache-2.0). Beide gemischt; der Nutzer kann jedes Modell/Backend selbst
# waehlen (Settings -> KI-Modell/Backend). Siehe docs/ROADMAP.md.
# Reihenfolge = SCHNELL **und** gut fuer einen Sprachassistenten. Nicht-denkende Instruct-
# Modelle zuerst (gemma3 = bestes Deutsch; qwen2.5 = flott + klug). qwen3-"Denk"-Modelle ans
# ENDE: ihre <think>-Bloecke kosten zig Sekunden (qwen3:14b ~36 s vs. qwen2.5:7b ~1 s). Wird
# ein qwen3-Denkmodell doch genutzt, schaltet ask() per /no_think das Denken ab.
_PREFERRED = ("gemma3:27b", "gemma3:12b", "qwen3:30b-a3b-instruct-2507", "gemma3:4b",
              "qwen2.5:7b", "qwen3:4b-instruct", "qwen2.5:3b", "llama3.1:8b",
              "llama3.2:3b", "gemma3:1b", "qwen3:14b", "qwen3:8b", "qwen3:4b")


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


def prewarm() -> None:
    """Laedt das aktive Modell beim App-Start im HINTERGRUND in den RAM (keep_alive), damit
    die ERSTE echte Frage nicht ~20 s kalt laedt, sondern sofort kommt (Jarvis-Gefuehl).
    Best-effort, blockiert nie, schweigt bei Fehler/keinem Ollama."""
    if _u is None or _provider() != "ollama":
        return

    def _w():
        try:
            m = active_model()
            if not m:
                return
            body = json.dumps({"model": m, "keep_alive": -1}).encode("utf-8")     # leerer
            req = _u.Request(OLLAMA + "/api/generate", data=body,                  # prompt = nur laden
                             headers={"Content-Type": "application/json"})
            _u.urlopen(req, timeout=180).read()
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=_w, daemon=True, name="LLMPrewarm").start()


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
    # Multi-Backend: OpenAI-kompatibles Ziel (LM Studio/llama.cpp/vLLM/Cloud) statt Ollama.
    if _provider() == "openai_compatible":
        r = _ask_openai_compatible(prompt, system or SYSTEM, timeout, num_predict)
        if r is not None:
            return r
        # Fremd-Backend nicht erreichbar (Adresse falsch / Server aus) -> NICHT verstummen,
        # sondern lokal auf Ollama weiterversuchen (Selbstheilung; faellt hier unten durch).
    m = model or active_model()
    if not m:
        return None
    # qwen3-"Denk"-Modelle: /no_think schaltet den langsamen <think>-Block ab (Instruct-
    # Varianten denken ohnehin nicht). Bringt qwen3 von ~30 s auf wenige Sekunden.
    _ml = (m or "").lower()
    eff_prompt = ("/no_think\n" + prompt) if ("qwen3" in _ml and "instruct" not in _ml) else prompt

    def _gen(sys_prompt: str):
        body = json.dumps({
            "model": m, "prompt": eff_prompt, "system": sys_prompt, "stream": False,
            "keep_alive": -1,      # Modell DAUERHAFT geladen halten -> nie langsames Neu-Laden
                                   # (Jarvis-Gefuehl; haelt VRAM/RAM, ok fuer Dauer-Assistenten)
            "options": {"num_predict": num_predict, "temperature": 0.6,
                        "top_p": 0.9, "num_ctx": 4096},
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
