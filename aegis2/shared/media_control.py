"""App-genaue Mediensteuerung für Windows.

- Lautstärke EINER App (z. B. Spotify) über die Windows-Audio-Sessions (pycaw) — gezielt, NICHT
  der System-Sound. Genau das wollte der Nutzer: «dreh Spotify leiser» ≠ alles leiser.
- Wiedergabe-STATUS (läuft/pausiert) + Transport (play/pause/next/prev) über die Windows-
  Mediensteuerung SMTC (winrt) — funktioniert für JEDES Programm, das Mediensteuerung anmeldet
  (Spotify-Desktop, Browser-Player, …). Antwort auf «gibt es eine API, die das checkt?».

Alles best-effort: fehlt eine Lib oder läuft gerade nichts, geben die Funktionen None/False
zurück und der Aufrufer fällt sauber auf die globale Media-Taste zurück. STT/Voice darf nie brechen.
"""
from __future__ import annotations

from typing import Optional, Tuple


# ----------------------------------------------------------------- App-Lautstärke (pycaw)
def _sessions():
    from pycaw.pycaw import AudioUtilities
    return AudioUtilities.GetAllSessions()


def app_volume(app: str) -> Optional[float]:
    """Aktuelle Lautstärke (0..1) der ersten Audio-Session, deren Prozessname `app` enthält."""
    try:
        a = (app or "").lower()
        for s in _sessions():
            if s.Process and a in s.Process.name().lower():
                return float(s.SimpleAudioVolume.GetMasterVolume())
    except Exception:  # noqa: BLE001
        pass
    return None


def set_app_volume(app: str, level: float) -> bool:
    """Lautstärke (0..1) ALLER Sessions setzen, deren Prozessname `app` enthält."""
    try:
        a = (app or "").lower()
        level = max(0.0, min(1.0, float(level)))
        hit = False
        for s in _sessions():
            if s.Process and a in s.Process.name().lower():
                s.SimpleAudioVolume.SetMasterVolume(level, None)
                hit = True
        return hit
    except Exception:  # noqa: BLE001
        return False


def nudge_app_volume(app: str, delta: float) -> Optional[float]:
    """Lautstärke um `delta` (z. B. -0.15) ändern. Returns neue Lautstärke (0..1) oder None."""
    cur = app_volume(app)
    if cur is None:
        return None
    new = max(0.0, min(1.0, cur + delta))
    return new if set_app_volume(app, new) else None


def app_audio_running(app: str) -> bool:
    """True, wenn `app` aktuell eine Audio-Session hat (Spotify spielt/ist offen mit Ton)."""
    try:
        a = (app or "").lower()
        return any(s.Process and a in s.Process.name().lower() for s in _sessions())
    except Exception:  # noqa: BLE001
        return False


# ----------------------------------------------------------------- Status + Transport (SMTC)
def _run(coro):
    """winrt-IAsyncOperation in einem kurzlebigen Event-Loop ausführen (synchroner Aufrufer)."""
    import asyncio
    loop = None
    try:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(coro)
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            if loop is not None:
                loop.close()
        except Exception:  # noqa: BLE001
            pass


async def _manager():
    import winrt.windows.media.control as mc
    return await mc.GlobalSystemMediaTransportControlsSessionManager.request_async()


def _session_for(app: Optional[str]):
    """Die zu `app` passende SMTC-Session (per source_app_user_model_id) oder die aktuelle."""
    async def _go():
        mgr = await _manager()
        if mgr is None:
            return None
        if app:
            a = app.lower()
            try:
                for s in (mgr.get_sessions() or []):
                    sid = (s.source_app_user_model_id or "").lower()
                    if a in sid:
                        return s
            except Exception:  # noqa: BLE001
                pass
        return mgr.get_current_session()
    return _run(_go())


# playback_status: 0 Closed, 1 Opened, 2 Changing, 3 Stopped, 4 Playing, 5 Paused
_STATE = {4: "playing", 5: "paused", 3: "stopped"}


def playback_state(app: Optional[str] = None) -> Optional[str]:
    """'playing' / 'paused' / 'stopped' / None — für `app` oder die aktuelle Session."""
    s = _session_for(app)
    if s is None:
        return None
    try:
        return _STATE.get(int(s.get_playback_info().playback_status))
    except Exception:  # noqa: BLE001
        return None


def now_playing(app: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """(Titel, Interpret) der aktuellen/`app`-Session oder None."""
    s = _session_for(app)
    if s is None:
        return None

    async def _props():
        p = await s.try_get_media_properties_async()
        return ((getattr(p, "title", "") or "").strip(), (getattr(p, "artist", "") or "").strip())
    return _run(_props())


def _transport(app: Optional[str], method: str) -> bool:
    s = _session_for(app)
    if s is None:
        return False

    async def _go():
        return bool(await getattr(s, method)())
    return bool(_run(_go()))


def play(app: Optional[str] = None) -> bool:
    return _transport(app, "try_play_async")


def pause(app: Optional[str] = None) -> bool:
    return _transport(app, "try_pause_async")


def toggle(app: Optional[str] = None) -> bool:
    return _transport(app, "try_toggle_play_pause_async")


def next_track(app: Optional[str] = None) -> bool:
    return _transport(app, "try_skip_next_async")


def prev_track(app: Optional[str] = None) -> bool:
    return _transport(app, "try_skip_previous_async")
