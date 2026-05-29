"""Cloud Speech-to-Text via Anthropic Messages API (multimodal audio).

Sends 16-kHz mono WAV bytes and returns transcript text. Falls back to
OpenAI Whisper API if anthropic key missing.
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


def transcribe_wav(wav_bytes: bytes, language: str = "de") -> Optional[str]:
    """Transcribe with whichever API key is available. Returns None on failure."""
    if requests is None or not wav_bytes:
        return None
    if ANTHROPIC_KEY:
        return _via_anthropic(wav_bytes, language)
    if OPENAI_KEY:
        return _via_openai(wav_bytes, language)
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
                     "text": f"Transkribiere die Audiodatei ins {language}. Gib NUR den Transkript-Text zurück, ohne Kommentare."},
                ],
            }],
        }
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            data=json.dumps(body), timeout=15,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        for blk in data.get("content", []):
            if blk.get("type") == "text":
                return blk.get("text", "").strip()
    except Exception:  # noqa: BLE001
        return None
    return None


def _via_openai(wav_bytes: bytes, language: str) -> Optional[str]:
    try:
        files = {"file": ("audio.wav", wav_bytes, "audio/wav")}
        data = {"model": "whisper-1", "language": language}
        r = requests.post(
            "https://api.openai.com/v1/audio/transcriptions",
            headers={"Authorization": f"Bearer {OPENAI_KEY}"},
            files=files, data=data, timeout=20,
        )
        if r.status_code != 200:
            return None
        return r.json().get("text", "").strip()
    except Exception:  # noqa: BLE001
        return None
