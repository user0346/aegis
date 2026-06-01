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


_LOCAL_DEVICE = None


def _add_cuda_dll_dirs() -> None:
    """nvidia cuBLAS/cuDNN/cudart/nvrtc-DLLs (pip-Pakete nvidia-*-cu12) fuer CTranslate2
    auffindbar machen — sonst 'cublas64_12.dll not found' und STT faellt auf CPU zurueck
    (langsam). PATH-Prepend + add_dll_directory (Windows). Best-effort, schadet nie."""
    try:
        import sysconfig
        sp = sysconfig.get_paths().get("purelib", "")
        dirs = [os.path.join(sp, "nvidia", s, "bin")
                for s in ("cublas", "cudnn", "cuda_runtime", "cuda_nvrtc")]
        dirs = [d for d in dirs if os.path.isdir(d)]
        if dirs:
            os.environ["PATH"] = os.pathsep.join(dirs) + os.pathsep + os.environ.get("PATH", "")
            for d in dirs:
                try:
                    os.add_dll_directory(d)
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        pass


def prewarm() -> None:
    """STT-Modell + GPU im HINTERGRUND vorwaermen, damit der ERSTE echte Sprachbefehl nicht
    den CUDA-Kaltstart (~20 s) abwarten muss. Best-effort, blockiert nie."""
    import threading

    def _w():
        try:
            m = _get_model()
            if m is None:
                return
            import numpy as _np
            seg, _ = m.transcribe(_np.zeros(16000, dtype=_np.float32), language="de")
            for _s in seg:
                break
        except Exception:  # noqa: BLE001
            pass
    threading.Thread(target=_w, daemon=True, name="STTPrewarm").start()


def _get_model():
    """Laedt faster-whisper EINMALIG, GPU bevorzugt. Default 'small' (deutlich genauer als
    'base'). Reihenfolge: cuda/float16 -> bei Fehler (keine CUDA-Libs/cuDNN) SAUBER cpu/int8.
    Die CUDA-Wahl wird mit einem Mini-Lauf VALIDIERT, damit ein fehlendes cuDNN nicht erst beim
    ersten echten Sprachbefehl crasht (STT darf NIE brechen). Env-Override:
    AEGIS_WHISPER_MODEL (tiny|base|small|medium), AEGIS_WHISPER_DEVICE (auto|cuda|cpu)."""
    global _LOCAL_MODEL, _LOCAL_DEVICE
    if _LOCAL_MODEL is not None:
        return _LOCAL_MODEL
    try:
        from faster_whisper import WhisperModel
    except Exception:  # noqa: BLE001
        return None
    # Deutsch-feinabgestimmtes large-v3-turbo (CT2) -> ~2,6% WER (vs. medium ~6-8%), int8 ~1,5GB.
    size = os.environ.get("AEGIS_WHISPER_MODEL", "jimmymeister/whisper-large-v3-turbo-german-ct2")
    pref = (os.environ.get("AEGIS_WHISPER_DEVICE", "auto") or "auto").strip().lower()
    plan = ([("cuda", "int8_float16")] if pref in ("auto", "cuda") else []) + [("cpu", "int8")]
    if any(d == "cuda" for d, _ in plan):
        _add_cuda_dll_dirs()        # nvidia-DLLs auffindbar machen (sonst CPU-Fallback)
    for dev, ct in plan:
        try:
            m = WhisperModel(size, device=dev, compute_type=ct)
            if dev == "cuda":          # CUDA wirklich initialisieren (sonst Crash erst spaeter)
                try:
                    import numpy as _np
                    seg, _ = m.transcribe(_np.zeros(8000, dtype=_np.float32), language="de")
                    next(iter(seg), None)
                except Exception:  # noqa: BLE001  -> CUDA nicht nutzbar -> naechster Plan (CPU)
                    continue
            _LOCAL_MODEL, _LOCAL_DEVICE = m, dev
            try:
                import logging
                logging.getLogger("aegis.voice.stt").info(
                    "faster-whisper '%s' auf %s geladen", size, dev)
            except Exception:  # noqa: BLE001
                pass
            return m
        except Exception:  # noqa: BLE001
            continue
    return None


def _via_local(wav_bytes: bytes, language: str) -> Optional[str]:
    """faster-whisper, lokal + offline. Modell GPU-bevorzugt (s. _get_model), einmalig gecacht."""
    m = _get_model()
    if m is None:
        return None
    try:
        import tempfile
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
            # Befehls-Vokabular als Bias (initial_prompt) -> seltener verhört ("scan" statt
            # "Nose", "fortsetzen" statt "froh setzen"). Deutsche Steuerwoerter + Eigennamen.
            _hint += ("Befehle: führe einen Scan aus, Status, scanne mein System, öffne, schließe, "
                      "beende, starte, zeig, Bedrohungen, Quarantäne, Sentinel, Netzwerk. "
                      "Musik: spiele, pausiere, stoppe, fortsetzen, weiter, nächster Titel, lauter, leiser. "
                      "Wissen: lerne, merk dir, vergiss, was ist, erkläre, suche. "
                      "Apps: Discord, Spotify, YouTube, Chrome, Brave, Steam.")
            segments, _ = m.transcribe(
                tmp, language=language, vad_filter=True, initial_prompt=_hint,
                beam_size=5, temperature=0.0, condition_on_previous_text=False,
                vad_parameters={"min_silence_duration_ms": 500})
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
