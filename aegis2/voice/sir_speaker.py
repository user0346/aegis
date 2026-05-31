"""Voice-Sir-Speaker — Edge-TTS Wrapper + Notifications-Poller.

Nutzt Windows-eingebautes System.Speech via PowerShell für TTS. Kein extra
pip-install nötig. Stimme: deutsch (Microsoft Katja oder Hedda Desktop).

Workflow:
  1. SirSpeaker.start() startet einen Thread der ~/.aegis/notifications.jsonl
     beobachtet. Neue Zeilen mit kind=="sir" werden ausgesprochen.
  2. SirSpeaker.speak(text) sofort sprechen lassen.
  3. Rate-Limit: max 1 Spruch / 3 Sekunden damit kein Spam-Audio.
  4. Voice-Activity-Lock: wenn Wake-Word gerade lauscht, kein TTS (Feedback-
     Loop vermeiden).

Manuelles Stoppen via SirSpeaker.stop().
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from ..shared.proc import run_hidden


log = logging.getLogger("aegis.voice.sir")

NOTIFY_SENTINEL = Path.home() / ".aegis" / "notifications.jsonl"
SEEK_FILE = Path.home() / ".aegis" / ".notifications.seek"
RATE_LIMIT_SEC = 3.0

# Default-Stimme. Override via SirSpeaker(voice=...).
DEFAULT_VOICE_DE = "Microsoft Katja Desktop"
FALLBACK_VOICE_DE = "Microsoft Hedda Desktop"


# Ein paar PowerShell-Escape-Sicherheiten:
def _ps_escape(s: str) -> str:
    # Single-quote-escape für PowerShell-Strings
    return s.replace("'", "''").replace("\r", "").replace("\n", " ").replace("`", "")


def _speak_via_powershell(text: str, voice: Optional[str] = None) -> bool:
    """Synchron sprechen. Returns True bei Erfolg."""
    if sys.platform != "win32" or not text:
        return False
    safe = _ps_escape(text)[:500]
    voice_pick = voice or DEFAULT_VOICE_DE
    script = (
        "Add-Type -AssemblyName System.Speech;"
        "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer;"
        f"try {{ $s.SelectVoice('{voice_pick}') }} catch {{ "
        f"  try {{ $s.SelectVoice('{FALLBACK_VOICE_DE}') }} catch {{}} }};"
        "$s.Rate = 0;"
        "$s.Volume = 90;"
        f"$s.Speak('{safe}')"
    )
    try:
        r = run_hidden(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=20,
            encoding="utf-8", errors="replace"
        )
        return r.returncode == 0
    except Exception as e:  # noqa: BLE001
        log.warning("TTS-PowerShell-Fehler: %s", e)
        return False


def list_voices() -> list[str]:
    """Zeigt verfügbare Stimmen — debug-helper."""
    if sys.platform != "win32":
        return []
    script = ("Add-Type -AssemblyName System.Speech;"
              "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer;"
              "$s.GetInstalledVoices() | "
              "ForEach-Object { $_.VoiceInfo.Name }")
    try:
        r = run_hidden(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=8,
            encoding="utf-8", errors="replace"
        )
        return [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
    except Exception:  # noqa: BLE001
        return []


# Entspannte neuronale Standard-Stimme (edge-tts, gratis, kein Key)
NEURAL_VOICE_DE = "de-DE-ConradNeural"
NEURAL_RATE = "-8%"   # etwas langsamer = ruhiger

# --- TTS-Serialisierung: neue Ausgabe WARTET, bis die vorherige fertig ist.
#     Der Stop-Button (stop_speaking) bricht laufende + wartende Ausgaben ab. ---
_tts_lock = threading.Lock()         # schuetzt _tts_alias
_tts_play_lock = threading.Lock()    # serialisiert Wiedergaben (warten statt ueberlappen)
_tts_alias = None
_tts_gen = 0                         # stop_speaking erhoeht -> wartende Ausgaben verwerfen


def stop_speaking() -> None:
    """Bricht die laufende Ausgabe ab UND verwirft wartende (fuer Stop-Button)."""
    global _tts_alias, _tts_gen
    with _tts_lock:
        a = _tts_alias
        _tts_alias = None
        _tts_gen += 1
    if a and sys.platform == "win32":
        try:
            from ctypes import windll
            windll.winmm.mciSendStringW("stop " + a, None, 0, None)
            windll.winmm.mciSendStringW("close " + a, None, 0, None)
        except Exception:  # noqa: BLE001
            pass


def _speak_via_edge(text: str, voice: str, rate: str = NEURAL_RATE) -> bool:
    """Microsoft Neural-TTS via edge-tts -> MP3 -> Windows-MCI-Abspielen.
    Kein API-Key, kein Extra-Player noetig. Returns True bei Erfolg."""
    if sys.platform != "win32" or not text:
        return False
    try:
        import edge_tts, asyncio, tempfile, os
        from ctypes import windll, create_unicode_buffer
    except Exception:
        return False
    tmp = os.path.join(tempfile.gettempdir(), "aegis_tts_%d.mp3" % (int(time.time() * 1000) % 1000000))
    try:
        async def _gen():
            await edge_tts.Communicate(text[:800], voice, rate=rate).save(tmp)
        asyncio.run(_gen())
        if not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
            return False
        alias = "aegistts%d" % (int(time.time() * 1000) % 100000)
        global _tts_alias
        with _tts_lock:
            _tts_alias = alias
        windll.winmm.mciSendStringW('open "%s" type mpegvideo alias %s' % (tmp, alias), None, 0, None)
        # WICHTIG: Asynchron abspielen (ohne "wait") und in einer BEGRENZTEN Schleife
        # pollen, bis die Wiedergabe stoppt. "play %s wait" blockiert sonst OHNE Timeout:
        # haengt das Audio-Geraet, blockiert der TTS-Thread fuer immer waehrend er
        # _tts_play_lock haelt -> ALLE spaeteren Sprachwarnungen wuerden blockiert.
        windll.winmm.mciSendStringW("play %s" % alias, None, 0, None)
        # Obergrenze ~60s; bei 50ms Poll-Intervall ergibt das die Iterations-Schranke.
        # So kann ein haengendes Geraet den Thread nicht dauerhaft festsetzen.
        poll_interval = 0.05
        max_iters = int(60.0 / poll_interval)
        buf = create_unicode_buffer(64)
        for _ in range(max_iters):
            # Stop-Button: stop_speaking() setzt _tts_alias auf None -> Wiedergabe beenden
            with _tts_lock:
                if _tts_alias != alias:
                    break
            buf.value = ""
            windll.winmm.mciSendStringW("status %s mode" % alias, buf, 64, None)
            mode = (buf.value or "").strip().lower()
            # "stopped"/leer -> fertig; nur bei "playing"/"seeking" weiter warten
            if mode and mode not in ("playing", "seeking"):
                break
            time.sleep(poll_interval)
        with _tts_lock:
            if _tts_alias == alias:
                _tts_alias = None
        windll.winmm.mciSendStringW("close %s" % alias, None, 0, None)
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("edge-tts-Fehler: %s", e)
        return False
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass


def speak_text(text: str, voice: Optional[str] = None) -> bool:
    """Zentrale Sprachausgabe: neuronale Stimme (edge-tts) bevorzugt, SAPI als Fallback.
    Stimme aus Setting 'tts_voice' (Default: ruhige Neural-Stimme)."""
    if not text:
        return False
    # Nutzer-Schalter: Sprachausgabe komplett deaktivierbar (Warnsound bleibt aktiv)
    try:
        from ..shared.db import get_db
        if not get_db().get_setting("tts_enabled", True):
            return False
    except Exception:  # noqa: BLE001
        pass
    # serialisieren: WARTEN, bis die vorherige Ausgabe fertig ist (kein Ueberlappen)
    my_gen = _tts_gen
    with _tts_play_lock:
        if my_gen != _tts_gen:        # waehrend des Wartens Stop geklickt -> verwerfen
            return False
        v = voice
        if v is None:
            try:
                from ..shared.db import get_db
                v = get_db().get_setting("tts_voice", NEURAL_VOICE_DE)
            except Exception:  # noqa: BLE001
                v = NEURAL_VOICE_DE
        if v in ("sapi", "system", ""):
            return _speak_via_powershell(text, None)
        if v and "Neural" in v:
            if _speak_via_edge(text, v):
                return True
            return _speak_via_powershell(text, None)
        return _speak_via_powershell(text, v)


class SirSpeaker:
    def __init__(self, voice: Optional[str] = None,
                 on_speak_start: Optional[Callable[[str], None]] = None,
                 on_speak_end: Optional[Callable[[str], None]] = None,
                 wake_lock_check: Optional[Callable[[], bool]] = None):
        self.voice = voice
        self.on_speak_start = on_speak_start or (lambda _t: None)
        self.on_speak_end = on_speak_end or (lambda _t: None)
        # wake_lock_check returns True if wake-word listener is currently
        # active (and we should suppress TTS to avoid feedback)
        self.wake_lock_check = wake_lock_check or (lambda: False)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._last_speak = 0.0
        self._thread: Optional[threading.Thread] = None
        self._seek = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        # Restore seek
        try:
            if SEEK_FILE.exists():
                # WICHTIG: utf-8 wie beim Schreiben (write_text(..., encoding="utf-8")).
                # Sonst kann ein Locale-Mismatch hier eine Exception werfen, der Seek
                # auf 0 zurueckfallen und ALLE alten Notifications neu gesprochen werden.
                self._seek = int(SEEK_FILE.read_text(encoding="utf-8").strip())
        except Exception:  # noqa: BLE001
            self._seek = 0
        # If sentinel doesn't exist, start from 0
        if not NOTIFY_SENTINEL.exists():
            self._seek = 0
        else:
            # Auf bestehende Größe seek'n damit alte Notifs nicht
            # bei Start nochmal gesprochen werden
            try:
                size = NOTIFY_SENTINEL.stat().st_size
                if self._seek > size:
                    self._seek = size
            except OSError:
                self._seek = 0
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="SirSpeaker")
        self._thread.start()
        log.info("SirSpeaker started, seek=%d", self._seek)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def speak(self, text: str, force: bool = False) -> bool:
        """Sofort sprechen. Respektiert wake-lock + rate-limit (außer force)."""
        if not text:
            return False
        if not force:
            if self.wake_lock_check():
                log.info("speak skipped (wake-lock)")
                return False
            with self._lock:
                if time.time() - self._last_speak < RATE_LIMIT_SEC:
                    return False
                self._last_speak = time.time()
        try:
            self.on_speak_start(text)
        except Exception:  # noqa: BLE001
            pass
        ok = speak_text(text, self.voice)
        try:
            self.on_speak_end(text)
        except Exception:  # noqa: BLE001
            pass
        return ok

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll_once()
            except Exception as e:  # noqa: BLE001
                log.warning("SirSpeaker poll error: %s", e)
            self._stop.wait(1.0)

    def _poll_once(self) -> None:
        if not NOTIFY_SENTINEL.exists():
            return
        try:
            with open(NOTIFY_SENTINEL, "rb") as f:
                f.seek(self._seek)
                new_data = f.read()
            if not new_data:
                return
            # WICHTIG: Nur bis zum LETZTEN vollstaendigen, mit "\n" abgeschlossenen
            # Record vorruecken. Eine angefangene letzte Zeile (Writer schreibt evtl.
            # noch) bleibt fuer den naechsten Poll gepuffert — sonst wuerde der Seek
            # ueber sie hinweg springen und der JSON-Record (inkl. gesprochener
            # kind=="sir" Sicherheitswarnungen) ginge dauerhaft verloren.
            nl = new_data.rfind(b"\n")
            if nl == -1:
                # noch keine komplette Zeile vorhanden -> Seek nicht vorruecken,
                # naechster Poll liest dieselben Bytes erneut (jetzt evtl. vollstaendig)
                return
            complete = new_data[:nl + 1]
            self._seek += len(complete)
            try:
                SEEK_FILE.write_text(str(self._seek), encoding="utf-8")
            except OSError:
                pass
        except OSError:
            return
        # Process new lines (nur die vollstaendigen, abgeschlossenen Records)
        for line in complete.split(b"\n"):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line.decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                continue
            if rec.get("kind") != "sir":
                continue
            text = rec.get("tts_text") or rec.get("message")
            if not text:
                continue
            self.speak(text)
