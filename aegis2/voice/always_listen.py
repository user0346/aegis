"""Freihaendiges Weckwort — 'Hey Jarvis' ohne Knopf (openWakeWord, lokal & offline).

Laeuft NUR bei Setting 'wake_word_enabled' = True (Default AUS, bewusster Opt-in). Lauscht
mit openWakeWord (Apache-2.0-Code) auf das vortrainierte 'hey_jarvis'-Modell und ruft bei
Erkennung den uebergebenen on_wake()-Callback — der genau den Knopf-Sprachfluss ausloest
(aufnehmen -> STT -> Assistent -> sprechen). Sehr CPU-leicht.

Audio-Backend: sounddevice bevorzugt (hat Wheels inkl. PortAudio fuer Python 3.14),
pyaudio als Fallback (3.13). MIKRO-WICHTIG: das Mikro kann nicht doppelt offen sein —
darum schliesst der Lausch-Stream VOR on_wake (das die Aufnahme uebernimmt) und oeffnet
danach neu. Waehrend on_wake laeuft (Aufnahme + AEGIS spricht) wird NICHT gelauscht ->
kein Selbst-Trigger durch die eigene Stimme.

Verifiziert: openWakeWord laedt 'hey_jarvis' und scort Frames. Das echte Sprechen von
'Hey Jarvis' muss auf einem PC mit Mikrofon getestet werden.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

log = logging.getLogger("aegis.voice.wake")

SAMPLE_RATE = 16000
FRAME = 1280               # 80 ms @ 16 kHz = openWakeWord-Schrittweite
DEFAULT_THRESHOLD = 0.5
COOLDOWN_S = 2.0          # nach einem Treffer kurz nicht erneut ausloesen


def _have(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except Exception:  # noqa: BLE001
        return False


def available() -> bool:
    """True, wenn openWakeWord UND ein Audio-Backend (sounddevice ODER pyaudio) da sind."""
    return _have("openwakeword") and (_have("sounddevice") or _have("pyaudio"))


class AlwaysListen:
    """Hintergrund-Lauscher fuer das Weckwort. start()/stop(), thread-sicher, best-effort."""

    def __init__(self, on_wake: Callable[[], None],
                 on_state: Optional[Callable[[str], None]] = None):
        self.on_wake = on_wake
        self.on_state = on_state or (lambda _s: None)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._model = None

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> bool:
        if self.is_running():
            return True
        if not available():
            log.info("Weckwort: openwakeword/Audio-Backend fehlt -> inaktiv.")
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="AlwaysListen")
        self._thread.start()
        log.info("Weckwort-Lauscher gestartet ('hey jarvis').")
        return True

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=2.5)
        self._thread = None

    def _ensure_model(self) -> bool:
        if self._model is not None:
            return True
        try:
            import openwakeword
            from openwakeword.model import Model
            try:
                openwakeword.utils.download_models()       # einmalig; danach gecacht
            except Exception:  # noqa: BLE001
                pass
            self._model = Model(wakeword_models=["hey_jarvis"], inference_framework="onnx")
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("Weckwort-Modell laden fehlgeschlagen: %s", e)
            return False

    def _threshold(self) -> float:
        try:
            from ..shared.db import get_db
            v = get_db().get_setting("wake_word_threshold", DEFAULT_THRESHOLD)
            return float(v if v is not None else DEFAULT_THRESHOLD)
        except Exception:  # noqa: BLE001
            return DEFAULT_THRESHOLD

    def _loop(self) -> None:
        if not self._ensure_model():
            return
        try:
            import numpy as np
        except Exception:  # noqa: BLE001
            return
        use_sd = _have("sounddevice")
        thr = self._threshold()
        while not self._stop.is_set():
            try:
                woke = self._session_sd(thr, np) if use_sd else self._session_pa(thr, np)
            except Exception as e:  # noqa: BLE001
                log.warning("Weckwort-Schleife: %s", e)
                self._stop.wait(1.5)
                continue
            if woke is None:                       # kein Mikrofon -> beenden
                return
            if woke and not self._stop.is_set():   # Weckwort lief -> kurz aussetzen, Puffer leeren
                time.sleep(COOLDOWN_S)
                try:
                    self._model.reset()
                except Exception:  # noqa: BLE001
                    pass
        log.info("Weckwort-Lauscher beendet.")

    def _fire(self) -> bool:
        """Mikro ist frei -> Sprachfluss ausloesen. Returns True."""
        if self._stop.is_set():
            return False
        try:
            self.on_state("wake")
            self.on_wake()                          # aufnehmen -> STT -> Assistent -> sprechen
        except Exception as e:  # noqa: BLE001
            log.warning("on_wake-Fehler: %s", e)
        return True

    def _session_sd(self, thr, np):
        """Eine Lausch-Session via sounddevice. True=Weckwort erkannt, False=beendet, None=kein Mikro."""
        import sounddevice as sd
        try:
            sd.check_input_settings(samplerate=SAMPLE_RATE, channels=1, dtype="int16")
        except Exception:  # noqa: BLE001
            log.info("Weckwort: kein Eingabegeraet -> inaktiv.")
            return None
        detected = False
        with sd.InputStream(samplerate=SAMPLE_RATE, channels=1, dtype="int16",
                            blocksize=FRAME) as stream:
            while not self._stop.is_set():
                data, _of = stream.read(FRAME)
                audio = np.asarray(data, dtype=np.int16).reshape(-1)
                try:
                    scores = self._model.predict(audio)
                except Exception:  # noqa: BLE001
                    continue
                if float(scores.get("hey_jarvis", 0.0)) >= thr:
                    detected = True
                    break
        # with-Block verlassen -> Stream zu, Mikro frei
        if not detected:
            return False
        return self._fire()

    def _session_pa(self, thr, np):
        """Fallback-Session via pyaudio (Python 3.13). True/False/None wie _session_sd."""
        import pyaudio
        pa = None
        stream = None
        try:
            pa = pyaudio.PyAudio()
            try:
                if pa.get_device_count() <= 0:
                    return None
                pa.get_default_input_device_info()
            except Exception:  # noqa: BLE001
                log.info("Weckwort: kein Eingabegeraet -> inaktiv.")
                return None
            stream = pa.open(rate=SAMPLE_RATE, channels=1, format=pyaudio.paInt16,
                             input=True, frames_per_buffer=FRAME)
            detected = False
            while not self._stop.is_set():
                try:
                    data = stream.read(FRAME, exception_on_overflow=False)
                except Exception:  # noqa: BLE001
                    break
                audio = np.frombuffer(data, dtype=np.int16)
                try:
                    scores = self._model.predict(audio)
                except Exception:  # noqa: BLE001
                    continue
                if float(scores.get("hey_jarvis", 0.0)) >= thr:
                    detected = True
                    break
        finally:
            try:
                if stream is not None:
                    stream.stop_stream(); stream.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                if pa is not None:
                    pa.terminate()
            except Exception:  # noqa: BLE001
                pass
        if not detected:
            return False
        return self._fire()
