"""QWebChannel-Bridge — exposes Python functions to JS in the embedded WebView.

JS calls:  await aegis.cmd('{"name":"stats"}')
Service push:  aegis.eventReceived.connect((json) => ...)
"""
from __future__ import annotations

import json
import logging
import secrets
import threading
from typing import Optional

from PyQt6.QtCore import QObject, QTimer, pyqtSignal, pyqtSlot

from .ipc_client import IpcClient


log = logging.getLogger("aegis.shell.bridge")


class AegisBridge(QObject):
    """Single QObject exposed to JS as `aegis`."""

    eventReceived = pyqtSignal(str)        # JSON-stringified event
    stateChanged = pyqtSignal(str)         # "connected" | "disconnected" | ...
    statsUpdated = pyqtSignal(str)         # JSON-stringified stats snapshot
    voiceState = pyqtSignal(str, str)      # (kind, payload) e.g. ("wake","detected")
    criticalAlert = pyqtSignal(str, str, str)  # (category, message, status) — Popup bei CRITICAL
    ollamaProgress = pyqtSignal(str, int)  # (stage, pct) — Ollama-Auto-Install (pct=100 fertig, -1 Fehler)
    fileSearchAsk = pyqtSignal(str, str)   # (query, kind) — Datei-Suche braucht Nutzer-Bestaetigung

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._last_state = "disconnected"
        self._ipc = IpcClient(on_frame=self._on_frame, on_state=self._on_state,
                              topics=["events", "stats"])
        self._pending: dict[str, list] = {}   # ref -> [resolve, reject]
        self._vc = None                        # VoiceController (lazy)
        self._last_stats = {}                  # fuer Voice-Lagemeldung
        self._ipc.start()
        # IpcClient often connects in milliseconds, BEFORE the WebChannel is
        # set up. Re-emit current state at 1s/3s/6s so the JS-side listener
        # (which subscribes after WebView load) always gets the actual state.
        for delay_ms in (1000, 3000, 6000):
            QTimer.singleShot(delay_ms,
                              lambda: self.stateChanged.emit(self._last_state))

    # ---- JS-callable slots ----
    @pyqtSlot(str, result=str)
    def cmd(self, json_str: str) -> str:
        """Synchronous command — returns a ref the JS side awaits via response signal.

        For Phase-1 simplicity we use fire-and-forget + emit `cmdResult` event.
        Phase-2 may switch to a promise-style via QWebChannel transaction map.
        """
        try:
            data = json.loads(json_str) if json_str else {}
        except Exception:  # noqa: BLE001
            return json.dumps({"ok": False, "error": "bad JSON"})
        ref = secrets.token_hex(8)
        frame = {"t": "cmd", "name": data.get("name", ""),
                 "args": data.get("args", {}), "ref": ref}
        ok = self._ipc.send(frame)
        log.debug("cmd name=%s send_ok=%s", data.get("name"), ok)
        return json.dumps({"ok": ok, "ref": ref})

    @pyqtSlot(result=str)
    def state(self) -> str:
        return "connected" if self._ipc._handle is not None else "disconnected"

    # ---- Voice (lokal/gratis: record -> STT -> Intent -> Action -> TTS) ----
    def _voice(self):
        if self._vc is None:
            from aegis2.voice.controller import VoiceController
            self._vc = VoiceController(
                ui_cmd=self._voice_ui_cmd,
                service_cmd=lambda f: self._ipc.send(
                    {"t": "cmd", "name": f.get("name", ""),
                     "args": f.get("args", {}), "ref": secrets.token_hex(6)}),
                status_cb=lambda: self._last_stats)
        return self._vc

    def _voice_ui_cmd(self, c):
        a = (c or {}).get("action")
        if a == "switch_tab":
            self.voiceState.emit("tab", c.get("tab", ""))
        elif a == "hide_window":
            self.voiceState.emit("hide", "")
        elif a == "confirm_file_search":
            self.fileSearchAsk.emit(c.get("query", "") or "", c.get("kind", "") or "")
        elif a == "assistant_notify":
            t = c.get("text", "") or ""
            if t:
                self.voiceState.emit("reply", t)   # proaktive Meldung -> AEGIS-Bubble im Chat

    def _voice_feedback(self, res):
        try:
            self.voiceState.emit("transcript", res.get("transcript", "") or "")
            self.voiceState.emit("reply", res.get("msg", "") or "")
            msg = res.get("msg", "")
            if msg:
                self.voiceState.emit("state", "speaking")
                try:
                    from aegis2.voice.sir_speaker import speak_text
                    speak_text(msg)
                except Exception:
                    pass
        finally:
            self.voiceState.emit("state", "idle")

    @pyqtSlot(str)
    def voiceText(self, text):
        text = (text or "").strip()
        if not text:
            return
        def _work():
            try:
                self.voiceState.emit("state", "thinking")
                self._voice_feedback(self._voice().handle_text(text))
            except Exception as e:  # noqa: BLE001
                self.voiceState.emit("state", "idle")
                self.voiceState.emit("reply", "Fehler: " + str(e))
        threading.Thread(target=_work, daemon=True).start()

    @pyqtSlot()
    def voiceListen(self):
        def _work():
            try:
                res = self._voice().listen_once(
                    on_stage=lambda st: self.voiceState.emit("state", st))
                self._voice_feedback(res)
            except Exception as e:  # noqa: BLE001
                self.voiceState.emit("state", "idle")
                self.voiceState.emit("reply", "Fehler: " + str(e))
        threading.Thread(target=_work, daemon=True).start()

    @pyqtSlot(str)
    def ttsPreview(self, voice):
        def _work():
            try:
                from aegis2.voice.sir_speaker import speak_text
                self.voiceState.emit("state", "speaking")
                speak_text("Hallo, ich bin AEGIS. So klingt diese Stimme.", voice or None)
            finally:
                self.voiceState.emit("state", "idle")
        threading.Thread(target=_work, daemon=True).start()

    # ---- Ollama-Auto-Install (lokale KI, kein manueller Download) ----
    @pyqtSlot(result=str)
    def ollamaStatus(self):
        try:
            from aegis2.voice.ollama_setup import status
            return json.dumps(status())
        except Exception as e:  # noqa: BLE001
            return json.dumps({"installed": False, "running": False, "error": str(e)})

    @pyqtSlot(result=str)
    def memoryGet(self):
        """Read-only: was AEGIS sich dauerhaft gemerkt hat (Anrede, Weckwort, Notizen,
        Shortcuts, haeufige Befehle, Anzahl Wissens-Eintraege). Laeuft im UI-Prozess,
        liest direkt das lokale Gedaechtnis — kein Pipe-/Service-Umweg."""
        try:
            from aegis2.shared import user_memory as _um, knowledge_base as _kb
            return json.dumps({
                "address": _um.get_address(),
                "wake_word": _um.get_wake_word(),
                "notes": _um.get_notes(),
                "aliases": _um.get_aliases(),
                "top_cmds": _um.top_commands(5),
                "knowledge_count": _kb.count(),
            })
        except Exception as e:  # noqa: BLE001
            return json.dumps({"error": str(e)})

    @pyqtSlot()
    def ollamaInstall(self):
        def _work():
            try:
                from aegis2.voice.ollama_setup import install
                r = install(progress=lambda s, p: self.ollamaProgress.emit(s, int(p)))
                self.ollamaProgress.emit(r.get("msg", ""), 100 if r.get("ok") else -1)
            except Exception as e:  # noqa: BLE001
                self.ollamaProgress.emit("Fehler: " + str(e), -1)
        threading.Thread(target=_work, daemon=True).start()

    @pyqtSlot()
    def stopSpeaking(self):
        """Stop-Button: bricht die laufende + wartende Sprachausgabe ab."""
        try:
            from aegis2.voice.sir_speaker import stop_speaking
            stop_speaking()
        except Exception:  # noqa: BLE001
            pass

    @pyqtSlot()
    def ollamaStart(self):
        """Startet den Ollama-Server (installiert aber gestoppt) — kein Re-Install."""
        def _work():
            try:
                from aegis2.voice.ollama_setup import ensure_running
                ensure_running(timeout=12)
            except Exception:  # noqa: BLE001
                pass
        threading.Thread(target=_work, daemon=True).start()

    @pyqtSlot(str, str)
    def runFileSearch(self, query, kind):
        """Wird NACH Nutzer-Bestaetigung (app.py-Dialog) aufgerufen: sucht + meldet."""
        def _work():
            try:
                self.voiceState.emit("reply", "Suche läuft …")
                from aegis2.voice import file_search
                hits = file_search.search(query, kind or "")
                summary = file_search.summarize(query, hits)
                self.voiceState.emit("reply", summary)
                try:
                    from aegis2.voice.sir_speaker import speak_text
                    speak_text(summary)
                except Exception:  # noqa: BLE001
                    pass
            except Exception as e:  # noqa: BLE001
                self.voiceState.emit("reply", "Datei-Suche fehlgeschlagen: " + str(e))
        threading.Thread(target=_work, daemon=True).start()

    # ---- internal ----
    def _on_frame(self, frame: dict) -> None:
        t = frame.get("t")
        if t == "event":
            ev = frame.get("ev", {})
            # CRITICAL -> Warnton im User-Prozess (Dienst hat in Session 0 kein Audio)
            if ev.get("severity") == "CRITICAL":
                try:
                    from aegis2.voice.alarm import play_alarm
                    play_alarm("critical")
                except Exception:  # noqa: BLE001
                    pass
                _md = ev.get("metadata", {}) or {}
                self.criticalAlert.emit(
                    ev.get("category", "") or "SYSTEM",
                    ev.get("message", "") or "Verdächtige Aktivität",
                    str(_md.get("status") or _md.get("action") or "BLOCKIERT"))
            self.eventReceived.emit(json.dumps(ev, ensure_ascii=False))
        elif t == "stats":
            self._last_stats = frame.get("data", {}) or {}
            self.statsUpdated.emit(json.dumps(frame.get("data", {}), ensure_ascii=False))
        elif t == "cmd_result":
            self.eventReceived.emit(json.dumps(frame, ensure_ascii=False))

    def _on_state(self, state: str) -> None:
        self._last_state = state
        self.stateChanged.emit(state)

    def push_voice(self, kind: str, payload: str) -> None:
        """Called from the voice subsystem (UI process) to surface wake/transcript."""
        self.voiceState.emit(kind, payload)

    def stop(self) -> None:
        self._ipc.stop()
