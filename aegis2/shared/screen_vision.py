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


def _capture(monitor: Optional[int] = None):
    """Bildschirm als PIL-Image (schnell via mss), auf max. 1280px skaliert. None bei Fehler.
    `monitor`: 1 = Primär, 2 = zweiter Bildschirm … (mss: [0] = ganzer Desktop, [1] = erster,
    [2] = zweiter). Ungültig/keiner -> Primärmonitor."""
    try:
        import mss
        from PIL import Image
        with mss.mss() as sct:
            mons = sct.monitors
            if monitor and 1 <= int(monitor) < len(mons):
                mon = mons[int(monitor)]                     # konkreter Bildschirm (1-basiert)
            else:
                mon = mons[1] if len(mons) > 1 else mons[0]  # [1] = Primär, [0] = ganzer Desktop
            shot = sct.grab(mon)
        img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        img.thumbnail((1280, 1280))                          # kleiner = schneller, reicht zum Erkennen
        return img
    except Exception:  # noqa: BLE001
        return None


def monitor_count() -> int:
    """Anzahl physischer Monitore (mss: len(monitors) - 1; [0] ist der virtuelle Gesamt-Desktop)."""
    try:
        import mss
        with mss.mss() as sct:
            return max(1, len(sct.monitors) - 1)
    except Exception:  # noqa: BLE001
        return 1


def _to_b64(img) -> str:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def capture_b64(monitor: Optional[int] = None) -> str:
    """Aktuellen Bildschirm als base64-PNG für die LIVE-Anzeige im UI (zeigt dem Nutzer, WAS
    AEGIS gerade sieht). `monitor`: 1=Primär, 2=zweiter … '' bei Fehler."""
    img = _capture(monitor)
    return _to_b64(img) if img is not None else ""


def _model() -> str:
    try:
        from .db import get_db
        m = (get_db().get_setting("vision_model", "") or "").strip()
        if m:
            return m
    except Exception:  # noqa: BLE001
        pass
    try:                                  # kein Setting -> bestes Vision-Modell fuer die Hardware
        from ..voice.ollama_setup import best_vision_model
        return best_vision_model()
    except Exception:  # noqa: BLE001
        return _VISION_MODEL


def analyze(question: str = "", timeout: float = 150.0, monitor: Optional[int] = None) -> Optional[str]:
    """Screenshot (Primär- oder gewähltem Monitor) machen und vom Vision-Modell zur Frage des
    Nutzers beschreiben/bewerten lassen. Returns die Antwort (deutsch) oder None."""
    img = _capture(monitor)
    if img is None:
        return None
    b64 = _to_b64(img)
    q = (question or "").strip()
    prompt = (
        "Du siehst einen ECHTEN Screenshot vom Bildschirm des Nutzers. Sage in 1–2 kurzen, sachlichen "
        "Sätzen auf Deutsch, welche App/Seite das ist und was darauf passiert — ohne Vorrede. Nenne "
        "ZUERST konkret, was du siehst (z. B. «Discord», «ein Spiel», «ein Browser mit …»). Bist du dir "
        "nicht sicher, sag es ehrlich («Ich erkenne nicht eindeutig, was das ist»).\n"
        "FEHLALARM VERMEIDEN — WICHTIGSTE REGEL: Du neigst dazu, Betrug oder Warnungen zu ERFINDEN, die "
        "gar nicht da sind. Das ist ein gefährlicher Fehlalarm. Im Zweifel IMMER entwarnen. Warne (Satz "
        "mit «Achtung:» beginnen) AUSSCHLIESSLICH, wenn du den Betrug an KONKRETEM, im Bild LESBAREM "
        "Text festmachen und ihn WÖRTLICH zitieren kannst (z. B. «Ihr Computer ist gesperrt, rufen Sie "
        "+49 …»). Kannst du keinen solchen Text zitieren: NICHT warnen. Erfinde NIEMALS eine "
        "Telefonnummer, eine Windows-/Viren-Warnung oder Microsoft-Branding, die du nicht wörtlich "
        "siehst.\n"
        "IMMER HARMLOS — hier NIEMALS warnen: Discord, WhatsApp, Teams, Chats, Spiele (Roblox, "
        "Minecraft, Fortnite …), Steam, YouTube, ein Browser mit normaler Seite, Editoren, Code, "
        "Datei-Explorer, Dashboards, ganz normale Programme.\n\n"
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
