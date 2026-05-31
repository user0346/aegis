"""Speech-to-Text — lokal (gratis, offline) bevorzugt, Cloud nur optional.

Reihenfolge (default prefer_local=True):
  1. faster-whisper  — LOKAL, offline, KEIN Key, kostenlos  (pip install faster-whisper)
  2. Anthropic / OpenAI  — Cloud, nur wenn Key gesetzt UND lokal nicht verfuegbar

So laesst sich Voice komplett kostenlos testen.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore

ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "")

_LOCAL_MODEL = None


def local_stt_available() -> bool:
    try:
        import faster_whisper  # noqa: F401
        return True
    except Exception:
        return False


def transcribe_wav(wav_bytes: bytes, language: str = "de",
                   prefer_local: bool = True) -> Optional[str]:
    """Transkribiert WAV-Bytes. Default: lokal+gratis zuerst."""
    if not wav_bytes:
        return None
    if prefer_local:
        t = _via_local(wav_bytes, language)
        if t:
            return t
    if requests is not None:
        if ANTHROPIC_KEY:
            t = _via_anthropic(wav_bytes, language)
            if t:
                return t
        if OPENAI_KEY:
            t = _via_openai(wav_bytes, language)
            if t:
                return t
    if not prefer_local:          # lokal als letzter Fallback
        return _via_local(wav_bytes, language)
    return None


def _via_local(wav_bytes: bytes, language: str) -> Optional[str]:
    """faster-whisper, lokal + offline. Modell wird einmalig gecacht."""
    global _LOCAL_MODEL
    try:
        from faster_whisper import WhisperModel
    except Exception:
        return None
    try:
        import tempfile
        if _LOCAL_MODEL is None:
            size = os.environ.get("AEGIS_WHISPER_MODEL", "base")  # tiny|base|small|medium
            _LOCAL_MODEL = WhisperModel(size, device="cpu", compute_type="int8")
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            f.write(wav_bytes)
            tmp = f.name
        try:
            # Erkennung Richtung AEGIS-Vokabular + Weckwort biasen (faster-whisper
            # initial_prompt) -> "Jarvis" & Befehle werden seltener verhört.
            _wake = ""
            try:
                from ..shared import user_memory as _um
                _wake = (_um.get_wake_word() or "").strip()
            except Exception:  # noqa: BLE001
                _wake = ""
            _hint = "AEGIS. " + ((_wake + ". ") if _wake else "")
            _hint += "Scan, Status, Quarantäne, Bedrohung, Sentinel, Discord, Spotify, lerne, merk dir."
            segments, _ = _LOCAL_MODEL.transcribe(tmp, language=language, vad_filter=True,
                                                  initial_prompt=_hint)
            text = (" ".join(s.text for s in segments)).strip()
            # Haeufige Fehlhoerer des Weckworts nachkorrigieren (z.B. "Jarvis").
            if _wake.lower() == "jarvis":
                import re as _re
                text = _re.sub(r"\b(jawas|jervis|charvis|harvis|jarwis|dscharwis|chavis|jarvi+s)\b",
                               "Jarvis", text, flags=_re.I)
            return text or None
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    except Exception:
        return None


def _via_anthropic(wav_bytes: bytes, language: str) -> Optional[str]:
    try:
        b64 = base64.b64encode(wav_bytes).decode("ascii")
        body = {
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 256,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "input_audio",
                     "source": {"type": "base64", "media_type": "audio/wav", "data": b64}},
                    {"type": "text",
                     "text": f"Transkribiere die Audiodatei ins {language}. Gib NUR den Transkript-Text zurueck."},
                ],
            }],
        }
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            data=json.dumps(body), timeout=15)
        if r.status_code != 200:
            return None
        for blk in r.json().get("content", []):
            if blk.get("type") == "text":
                return blk.get("text", "").strip()
    except Exception:
        return None
    return None


def _via_openai(wav_bytes: bytes, language: str) -> Optional[str]:
    try:
        files = {"file": ("audio.wav", wav_bytes, "audio/wav")}
        data = {"model": "whisper-1", "language": language}
        r = requests.post(
            "https://api.openai.com/v1/audio/transcriptions",
            headers={"Authorization": f"Bearer {OPENAI_KEY}"},
            files=files, data=data, timeout=20)
        if r.status_code != 200:
            return None
        return r.json().get("text", "").strip()
    except Exception:
        return None
