"""Porcupine wake-word listener.

Listens continuously for "AEGIS" using a custom Porcupine model.
Calls on_wake() callback when triggered. Designed to be low-CPU (<0.5%).

Config required (env or file ~/.aegis/voice.json):
  PV_ACCESS_KEY:    Picovoice access key (free tier OK for personal use)
  PV_KEYWORD_PATH:  path to .ppn custom keyword (or use "computer" built-in)
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Callable, Optional

try:
    import pvporcupine  # type: ignore
    import pyaudio  # type: ignore
    HAS_VOICE = True
except ImportError:
    HAS_VOICE = False


CONFIG_PATH = Path.home() / ".aegis" / "voice.json"


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
    return {
        "access_key": os.environ.get("PV_ACCESS_KEY", ""),
        "keyword_path": os.environ.get("PV_KEYWORD_PATH", ""),
        "builtin_keyword": "computer",      # fallback
        "sensitivity": 0.55,
    }


class WakeListener:
    def __init__(self, on_wake: Callable[[], None]):
        self.on_wake = on_wake
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> bool:
        if not HAS_VOICE:
            return False
        if self._running:
            return True
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="WakeListener", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def _loop(self) -> None:
        cfg = load_config()
        access = cfg.get("access_key", "")
        if not access:
            return
        kwargs = {"access_key": access, "sensitivities": [float(cfg.get("sensitivity", 0.55))]}
        if cfg.get("keyword_path"):
            kwargs["keyword_paths"] = [cfg["keyword_path"]]
        else:
            kwargs["keywords"] = [cfg.get("builtin_keyword", "computer")]

        try:
            porcupine = pvporcupine.create(**kwargs)
        except Exception:  # noqa: BLE001
            return

        pa = pyaudio.PyAudio()
        stream = pa.open(rate=porcupine.sample_rate, channels=1,
                         format=pyaudio.paInt16,
                         input=True,
                         frames_per_buffer=porcupine.frame_length)
        try:
            while not self._stop.is_set():
                pcm = stream.read(porcupine.frame_length, exception_on_overflow=False)
                # Convert bytes to int16 array
                import struct
                ints = struct.unpack_from("h" * porcupine.frame_length, pcm)
                idx = porcupine.process(ints)
                if idx >= 0:
                    try:
                        self.on_wake()
                    except Exception:  # noqa: BLE001
                        pass
        finally:
            try:
                stream.stop_stream()
                stream.close()
                pa.terminate()
                porcupine.delete()
            except Exception:  # noqa: BLE001
                pass
