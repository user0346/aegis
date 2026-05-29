"""Audio recorder with VAD (voice-activity-detection).

Records 16-kHz mono until silence is detected (>=1.5s) OR 8s max.
Returns raw PCM bytes for upload to STT.
"""
from __future__ import annotations

import collections
import io
import wave
from typing import Optional

try:
    import webrtcvad  # type: ignore
    import pyaudio  # type: ignore
    HAS_AUDIO = True
except ImportError:
    HAS_AUDIO = False


SAMPLE_RATE = 16000
FRAME_MS = 30                  # webrtcvad supports 10/20/30 ms
FRAME_BYTES = int(SAMPLE_RATE * (FRAME_MS / 1000.0)) * 2  # 16-bit
MAX_DURATION_S = 8
SILENCE_TAIL_S = 1.5
PADDING_S = 0.5


def record_until_silence(vad_aggressiveness: int = 2) -> Optional[bytes]:
    """Returns a WAV-bytes blob (16-bit, mono, 16-kHz) or None on failure."""
    if not HAS_AUDIO:
        return None

    vad = webrtcvad.Vad(vad_aggressiveness)
    pa = pyaudio.PyAudio()
    stream = pa.open(rate=SAMPLE_RATE, channels=1, format=pyaudio.paInt16,
                     input=True, frames_per_buffer=FRAME_BYTES // 2)

    ring = collections.deque(maxlen=int(PADDING_S * 1000 / FRAME_MS))
    voiced: list[bytes] = []
    silence_frames = 0
    voiced_started = False
    max_frames = int(MAX_DURATION_S * 1000 / FRAME_MS)
    silence_threshold = int(SILENCE_TAIL_S * 1000 / FRAME_MS)

    try:
        for _ in range(max_frames):
            frame = stream.read(FRAME_BYTES // 2, exception_on_overflow=False)
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
    finally:
        try:
            stream.stop_stream()
            stream.close()
            pa.terminate()
        except Exception:  # noqa: BLE001
            pass

    if not voiced:
        return None

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(SAMPLE_RATE)
        wf.writeframes(b"".join(voiced))
    return buf.getvalue()
