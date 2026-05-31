"""Alarm-Sound — eigener, lokal generierter Warnton.

Kein heruntergeladenes Asset (Lizenz-/Herkunftsrisiko), kein Windows-Standard-
Klang: AEGIS erzeugt den Ton in reinem Python und spielt ihn via winsound
SND_MEMORY ab. Lokal, lizenzfrei, deterministisch.

WICHTIG: Muss im UI-/User-Prozess laufen — ein LocalSystem-Dienst sitzt in
Session 0 ohne Audio-Ausgabe. Der Dienst erkennt die Bedrohung, die UI alarmiert.

  play_alarm("critical")  -> dringlicher, schneller Doppelton (4 Zyklen)
  play_alarm("warn")      -> milderer Doppelton (2 Zyklen)

Throttle: max. 1 Wiedergabe pro _GAP Sekunden (gegen Sound-Spam bei Event-Flut).
"""
from __future__ import annotations

import io
import math
import struct
import sys
import threading
import time
import wave

_SR = 44100
_GAP = 6.0
_last_play = 0.0
_lock = threading.Lock()


def _tone_seq(level: str):
    if level == "critical":
        return [(988, 0.13), (1319, 0.13)] * 4   # hoch, schnell, 4 Zyklen
    return [(740, 0.16), (932, 0.16)] * 2          # milder, 2 Zyklen


def _gen_wav(level: str, amp: float = 0.5) -> bytes:
    frames = bytearray()
    fade = int(_SR * 0.005)   # 5ms Fade gegen Klick-Artefakte
    for freq, dur in _tone_seq(level):
        n = int(_SR * dur)
        for i in range(n):
            env = 1.0
            if i < fade:
                env = i / fade
            elif i > n - fade:
                env = (n - i) / fade
            val = amp * env * math.sin(2 * math.pi * freq * i / _SR)
            frames += struct.pack("<h", int(val * 32767))
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(_SR)
        w.writeframes(bytes(frames))
    return buf.getvalue()


def play_alarm(level: str = "critical") -> bool:
    """Spielt den Warnton asynchron. Throttled. Returns True, wenn abgespielt."""
    if sys.platform != "win32":
        return False
    global _last_play
    with _lock:
        now = time.time()
        if now - _last_play < _GAP:
            return False
        _last_play = now
    try:
        import winsound
        wav = _gen_wav(level)
        winsound.PlaySound(wav, winsound.SND_MEMORY | winsound.SND_ASYNC)
        return True
    except Exception:  # noqa: BLE001
        return False
