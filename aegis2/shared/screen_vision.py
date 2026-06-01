"""AEGIS sieht den Bildschirm — Screenshot + lokales Vision-Modell.

Auf «was ist das?» / «schau auf meinen Bildschirm» macht AEGIS einen Screenshot des
Primärmonitors und lässt ihn von einem lokalen, multimodalen Modell (Standard: gemma3:4b)
beschreiben/bewerten — komplett OFFLINE, kein Bild verlässt den PC, NUR auf Zuruf (kein
Dauer-Mitschnitt). Erkennt das Modell etwas Verdächtiges (Phishing, Fake-Warnung, dubioser
Download), wird das in der Antwort markiert, damit AEGIS warnen/handeln kann.

Best-effort: fehlt eine Lib oder Ollama, gibt analyze() None zurück und der Aufrufer meldet
das ehrlich. Voice/Steuerung darf nie brechen.
"""
from __future__ import annotations

import base64
import io
import json
import urllib.request
from typing import Optional

_OLLAMA = "http://127.0.0.1:11434"
_VISION_MODEL = "gemma3:4b"        # multimodal + lokal vorhanden; per Setting überschreibbar


def available() -> bool:
    """True, wenn Screen-Capture grundsätzlich möglich ist (Libs vorhanden)."""
    try:
        import mss  # noqa: F401
        import PIL  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def _capture():
    """Primärmonitor als PIL-Image (schnell via mss), auf max. 1280px skaliert. None bei Fehler."""
    try:
        import mss
        from PIL import Image
        with mss.mss() as sct:
            mons = sct.monitors
            mon = mons[1] if len(mons) > 1 else mons[0]      # [1] = Primär, [0] = ganzer Desktop
            shot = sct.grab(mon)
        img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        img.thumbnail((1280, 1280))                          # kleiner = schneller, reicht zum Erkennen
        return img
    except Exception:  # noqa: BLE001
        return None


def _to_b64(img) -> str:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _model() -> str:
    try:
        from .db import get_db
        m = (get_db().get_setting("vision_model", "") or "").strip()
        if m:
            return m
    except Exception:  # noqa: BLE001
        pass
    return _VISION_MODEL


def analyze(question: str = "", timeout: float = 90.0) -> Optional[str]:
    """Screenshot des Primärmonitors machen und vom Vision-Modell zur Frage des Nutzers
    beschreiben/bewerten lassen. Returns die Antwort (deutsch) oder None."""
    img = _capture()
    if img is None:
        return None
    b64 = _to_b64(img)
    q = (question or "").strip()
    prompt = (
        "Du siehst einen ECHTEN Screenshot vom Bildschirm des Nutzers. Beschreibe NUR, was du "
        "WIRKLICH und KLAR siehst — direkt, knapp, sachlich auf Deutsch (1–2 Sätze, ohne Vorrede). "
        "ERFINDE NICHTS: bist du dir nicht sicher, was es ist, sag das ehrlich («Ich erkenne nicht "
        "eindeutig, was das ist»). WARNE NUR bei einer EINDEUTIG erkennbaren Betrugsseite (echte "
        "Phishing-/Fake-Login-Seite, gefälschte Viren-/Windows-Warnung mit Telefonnummer, Tech-"
        "Support-Scam). Eine normale App, ein Editor, ein Diagramm, eine Sicherheits-/Dashboard-"
        "Oberfläche oder eine seriöse Webseite ist KEINE Gefahr — dann auf KEINEN Fall warnen. "
        "Nur bei echter, eindeutiger Gefahr beginne den betreffenden Satz mit «Achtung:».\n\n"
        "Frage des Nutzers: " + (q or "Was ist auf dem Bildschirm zu sehen?"))
    model = _model()
    ans = _ollama_vision(model, prompt, b64, timeout)
    # Konfiguriertes Modell (noch) nicht da (z.B. llama3.2-vision lädt noch)? -> auf gemma3:4b
    # zurückfallen, damit Vision SOFORT funktioniert und automatisch upgradet, sobald es da ist.
    if ans is None and model != _VISION_MODEL:
        ans = _ollama_vision(_VISION_MODEL, prompt, b64, timeout)
    return ans


def _ollama_vision(model: str, prompt: str, b64: str, timeout: float) -> Optional[str]:
    body = json.dumps({
        "model": model, "prompt": prompt, "images": [b64],
        "stream": False, "options": {"temperature": 0.2},
    }).encode("utf-8")
    try:
        req = urllib.request.Request(_OLLAMA + "/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode("utf-8"))
        return (d.get("response") or "").strip() or None
    except Exception:  # noqa: BLE001
        return None
