"""Audio recorder with VAD (voice-activity-detection).

Records 16-kHz mono until silence is detected (>=1.5s) OR 8s max. Returns WAV bytes for STT.

Backend-robust (Python 3.14-tauglich):
  1) sounddevice  — bevorzugt (hat Wheels inkl. PortAudio auch fuer 3.14), energie-basierte
     Stille-Erkennung (kein webrtcvad noetig).
  2) pyaudio + webrtcvad — Fallback (z.B. Python 3.13), falls sounddevice fehlt.
Fehlt beides oder kein Mikrofon -> sauber None (NIE ein nativer PortAudio-Crash).
"""
from __future__ import annotations

import collections
import io
import wave
from typing import Optional

try:
    import webrtcvad  # type: ignore
    import pyaudio  # type: ignore
    HAS_PYAUDIO = True
except ImportError:
    HAS_PYAUDIO = False


SAMPLE_RATE = 16000
FRAME_MS = 30
FRAME_SAMPLES = int(SAMPLE_RATE * (FRAME_MS / 1000.0))   # 480 Samples
FRAME_BYTES = FRAME_SAMPLES * 2                          # 16-bit
MAX_DURATION_S = 8
SILENCE_TAIL_S = 1.5
PADDING_S = 0.5


def _to_wav(frames: list[bytes]) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(SAMPLE_RATE)
        wf.writeframes(b"".join(frames))
    return buf.getvalue()


def record_until_silence(vad_aggressiveness: int = 2) -> Optional[bytes]:
    """Returns WAV-bytes (16-bit, mono, 16-kHz) oder None. Probiert sounddevice zuerst
    (3.14-tauglich), dann pyaudio+webrtcvad. NIE ein harter Crash bei fehlendem Mikro."""
    blob = _record_sounddevice()
    if blob is not None:
        return blob
    if HAS_PYAUDIO:
        return _record_pyaudio(vad_aggressiveness)
    return None


def _record_sounddevice() -> Optional[bytes]:
    """sounddevice-Aufnahme mit energie-basierter (RMS) Stille-Erkennung. Adaptive Schwelle
    aus den ersten Frames (Umgebungsgeraeusch) -> robust gegen leise/laute Raeume."""
    try:
        import sounddevice as sd
        import numpy as np
    except Exception:  # noqa: BLE001
        return None
    try:
        try:                                  # kein nutzbares Eingabegeraet? -> sauber raus
            sd.check_input_settings(samplerate=SAMPLE_RATE, channels=1, dtype="int16")
        except Exception:  # noqa: BLE001
            return None

        voiced: list[bytes] = []
        ring: collections.deque = collections.deque(maxlen=int(PADDING_S * 1000 / FRAME_MS))
        silence_frames = 0
        voiced_started = False
        max_frames = int(MAX_DURATION_S * 1000 / FRAME_MS)
        silence_threshold = int(SILENCE_TAIL_S * 1000 / FRAME_MS)
        ambient: list[float] = []
        thr: Optional[float] = None

        with sd.InputStream(samplerate=SAMPLE_RATE, channels=1, dtype="int16",
                            blocksize=FRAME_SAMPLES) as stream:
            for _ in range(max_frames):
                data, _of = stream.read(FRAME_SAMPLES)
                frame = np.asarray(data, dtype=np.int16).reshape(-1)
                rms = float(np.sqrt(np.mean(frame.astype(np.float32) ** 2))) if frame.size else 0.0
                if thr is None:                # erste ~9 Frames: Umgebung kalibrieren
                    ambient.append(rms)
                    if len(ambient) >= 9:
                        base = sorted(ambient)[len(ambient) // 2]
                        thr = max(base * 3.0, 350.0)
                    is_speech = False
                else:
                    is_speech = rms > thr
                fb = frame.tobytes()
                if not voiced_started:
                    ring.append(fb)
                    if is_speech:
                        voiced_started = True
                        voiced.extend(ring)
                else:
                    voiced.append(fb)
                    if is_speech:
                        silence_frames = 0
                    else:
                        silence_frames += 1
                        if silence_frames >= silence_threshold:
                            break
        return _to_wav(voiced) if voiced else None
    except Exception:  # noqa: BLE001
        return None


def _record_pyaudio(vad_aggressiveness: int = 2) -> Optional[bytes]:
    """Fallback: pyaudio + webrtcvad (z.B. Python 3.13)."""
    if not HAS_PYAUDIO:
        return None
    pa = None
    stream = None
    voiced: list[bytes] = []
    try:
        vad = webrtcvad.Vad(vad_aggressiveness)
        pa = pyaudio.PyAudio()
        try:
            if pa.get_device_count() <= 0:
                return None
            pa.get_default_input_device_info()
        except Exception:  # noqa: BLE001
            return None

        stream = pa.open(rate=SAMPLE_RATE, channels=1, format=pyaudio.paInt16,
                         input=True, frames_per_buffer=FRAME_SAMPLES)

        ring = collections.deque(maxlen=int(PADDING_S * 1000 / FRAME_MS))
        silence_frames = 0
        voiced_started = False
        max_frames = int(MAX_DURATION_S * 1000 / FRAME_MS)
        silence_threshold = int(SILENCE_TAIL_S * 1000 / FRAME_MS)

        for _ in range(max_frames):
            frame = stream.read(FRAME_SAMPLES, exception_on_overflow=False)
            is_speech = vad.is_speech(frame, SAMPLE_RATE)
            if not voiced_started:
                ring.append(frame)
                if is_speech:
                    voiced_started = True
                    voiced.extend(ring)
            else:
                voiced.append(frame)
                if is_speech:
                    silence_frames = 0
                else:
                    silence_frames += 1
                    if silence_frames >= silence_threshold:
                        break
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            if stream is not None:
                stream.stop_stream()
                stream.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            if pa is not None:
                pa.terminate()
        except Exception:  # noqa: BLE001
            pass

    return _to_wav(voiced) if voiced else None
