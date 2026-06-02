"""QWebChannel-Bridge — exposes Python functions to JS in the embedded WebView.

JS calls:  await aegis.cmd('{"name":"stats"}')
Service push:  aegis.eventReceived.connect((json) => ...)
"""
from __future__ import annotations

import json
import logging
import secrets
import threading
import time
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
    windowAction = pyqtSignal(str)         # ("minimize"|"restore") — natives Fenster-Steuern (GUI-Thread)
    bootProgress = pyqtSignal(str, int)    # (stage, pct) — Erststart-Modell-Lade-Overlay (pct=100 fertig, -1 Fehler)

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._last_state = "disconnected"
        self._ipc = IpcClient(on_frame=self._on_frame, on_state=self._on_state,
                              topics=["events", "stats"])
        self._pending: dict[str, list] = {}   # ref -> [resolve, reject]
        self._vc = None                        # VoiceController (lazy)
        self._wake = None                      # AlwaysListen (Weckwort, lazy + opt-in)
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
            try:                    # Voice/Desktop: Chat-Antwort Satz-fuer-Satz streamen + sprechen
                self._vc.router.speak_cb = self._speak_sentence
            except Exception:  # noqa: BLE001
                pass
        return self._vc

    def _speak_sentence(self, sentence):
        """Voice-Streaming: einen einzelnen, fertigen Satz sofort sprechen (Orb -> 'speaking').
        Wird vom Chat-Pfad pro Satz aufgerufen, waehrend der Rest noch generiert."""
        if not sentence:
            return
        self.voiceState.emit("state", "speaking")
        try:
            from aegis2.voice.sir_speaker import speak_text
            speak_text(sentence)
        except Exception:  # noqa: BLE001
            pass

    def _voice_ui_cmd(self, c):
        a = (c or {}).get("action")
        if a == "switch_tab":
            self.voiceState.emit("tab", c.get("tab", ""))
        elif a in ("hide_chat", "show_chat", "hide_vision"):
            self.voiceState.emit("ui", a)              # Chat-Panel / Vision-Thumbnail (panels.js)
        elif a == "show_vision":
            self.voiceState.emit("vision", c.get("img", "") or "")   # Screenshot ins Vision-Embed
        elif a == "hide_window":
            self.voiceState.emit("hide", "")
        elif a in ("minimize", "restore"):
            self.windowAction.emit(a)                  # nativ -> AegisWindow (GUI-Thread, queued)
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
            # Wurde die Antwort bereits Satz-fuer-Satz gestreamt-gesprochen (Voice-Chat),
            # NICHT noch einmal komplett vorlesen.
            if msg and not res.get("spoken"):
                self.voiceState.emit("state", "speaking")
                try:
                    from aegis2.voice.sir_speaker import speak_text
                    speak_text(msg)
                except Exception:
                    pass
        finally:
            self.voiceState.emit("state", "idle")

    # ---- Freihändige Gesprächs-Fortsetzung (Folge-Loop ohne erneutes Weckwort) ----
    _MAX_FOLLOWUPS = 6           # Sicherheitsnetz; natürliches Ende ist Stille
    _FOLLOWUP_SETTLE_S = 0.35    # kurz warten, bis das Lautsprecher-Echo abklingt
    # Nach diesen Intents ergibt freihändiges Weiterreden keinen Sinn / ist unerwünscht.
    # 'greet' bewusst NICHT drin: nach einer Begrüßung («Ja?» / Start-Gruß) SOLL AEGIS auf
    # die Antwort warten (genau der gewünschte Gesprächseinstieg ohne erneutes Weckwort).
    _STOP_INTENTS = frozenset({"restart", "tts_mute", "close", "close_app"})

    def _conversation_on(self) -> bool:
        try:
            from aegis2.shared.db import get_db
            return bool(get_db().get_setting("conversation_followup", True))
        except Exception:  # noqa: BLE001
            return True

    @staticmethod
    def _tts_on() -> bool:
        try:
            from aegis2.shared.db import get_db
            return bool(get_db().get_setting("tts_enabled", True))
        except Exception:  # noqa: BLE001
            return True

    def _is_followup_worthy(self, res) -> bool:
        return bool(res and res.get("ok")
                    and res.get("intent") not in self._STOP_INTENTS)

    def _voice_converse(self, res) -> None:
        """Spricht die erste Antwort und führt — falls Gesprächsmodus an — danach einen
        freihändigen Folge-Loop: kurzes Lausch-Fenster OHNE erneutes «Hey Jarvis», bei
        Sprache weiter, bei Stille (oder Stop/«sei ruhig») sauber raus. speak_text blockiert
        bis fertig -> beim Re-Öffnen des Mikros ist der Lautsprecher still (kein Selbst-Trigger)."""
        self._voice_feedback(res)
        if not self._conversation_on():
            return
        turns = 0
        while turns < self._MAX_FOLLOWUPS:
            # Beenden, wenn Sprachausgabe inzwischen aus ist («sei ruhig») oder die letzte
            # Antwort kein Weiterreden nahelegt (Neustart, App geschlossen, …).
            if not self._tts_on() or not self._is_followup_worthy(res):
                break
            turns += 1
            time.sleep(self._FOLLOWUP_SETTLE_S)
            try:
                res = self._voice().listen_once(
                    on_stage=lambda st: self.voiceState.emit("state", st), follow_up=True)
            except Exception as e:  # noqa: BLE001
                log.warning("Folge-Lauschen: %s", e)
                break
            # Nichts gesagt -> Gespräch still beenden (kein Fehlertext vorlesen).
            if res.get("follow_up_end") or (not res.get("ok") and res.get("stage") == "record"):
                break
            self._voice_feedback(res)
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
                self._voice_converse(res)
            except Exception as e:  # noqa: BLE001
                self.voiceState.emit("state", "idle")
                self.voiceState.emit("reply", "Fehler: " + str(e))
        threading.Thread(target=_work, daemon=True).start()

    # ---- Weckwort 'Hey Jarvis' (freihaendig reden ohne Knopf, opt-in) ----
    def _on_wake(self):
        """Weckwort erkannt -> exakt der Knopf-Sprachfluss (aufnehmen -> STT -> Assistent ->
        sprechen). Laeuft im AlwaysListen-Thread; dessen Mikro-Stream ist hier bereits zu."""
        try:
            self.voiceState.emit("wake", "detected")
            res = self._voice().listen_once(
                on_stage=lambda st: self.voiceState.emit("state", st))
            self._voice_converse(res)
        except Exception as e:  # noqa: BLE001
            self.voiceState.emit("state", "idle")
            log.warning("Weckwort on_wake: %s", e)

    def _apply_wake(self, on: bool) -> None:
        if on:
            if self._wake is None:
                try:
                    from aegis2.voice.always_listen import AlwaysListen
                    self._wake = AlwaysListen(
                        on_wake=self._on_wake,
                        on_state=lambda s: self.voiceState.emit("state", "listening"))
                except Exception as e:  # noqa: BLE001
                    log.warning("Weckwort nicht ladbar: %s", e)
                    return
            self._wake.start()
        elif self._wake is not None:
            self._wake.stop()

    @pyqtSlot(bool)
    def setWakeWord(self, on):
        """Settings-Toggle: freihaendiges 'Hey Jarvis' an/aus (persistiert + sofort aktiv)."""
        try:
            from aegis2.shared.db import get_db
            get_db().set_setting("wake_word_enabled", bool(on))
        except Exception:  # noqa: BLE001
            pass
        self._apply_wake(bool(on))

    @pyqtSlot(result=bool)
    def wakeWordOn(self):
        try:
            from aegis2.shared.db import get_db
            return bool(get_db().get_setting("wake_word_enabled", False))
        except Exception:  # noqa: BLE001
            return False

    @pyqtSlot(bool)
    def setConversationMode(self, on):
        """Settings-Toggle: nach einer Sprach-Antwort kurz weiterhören (Folgefrage ohne
        Weckwort). Persistiert; wirkt sofort beim nächsten Sprach-Turn."""
        try:
            from aegis2.shared.db import get_db
            get_db().set_setting("conversation_followup", bool(on))
        except Exception:  # noqa: BLE001
            pass

    @pyqtSlot(result=bool)
    def conversationModeOn(self):
        return self._conversation_on()

    @pyqtSlot()
    def initWake(self):
        """Beim App-Start: Weckwort-Lauscher starten, falls eingeschaltet (idempotent)."""
        try:
            from aegis2.shared.db import get_db
            if bool(get_db().get_setting("wake_word_enabled", False)):
                self._apply_wake(True)
        except Exception:  # noqa: BLE001
            pass

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

    @pyqtSlot()
    def greet(self):
        """Proaktive Begruessung beim Start — AEGIS meldet sich SELBST: begruesst, fasst den
        aktuellen Sicherheits-Stand KURZ zusammen und HOERT DANN freihaendig auf eine Antwort
        (Gespraechsmodus, kein Weckwort noetig). Genau EINMAL pro App-Start (idempotent).
        Startet ERST DANACH den Weckwort-Lauscher (keine Mikro-Kollision, kein Selbst-Trigger)."""
        if getattr(self, "_greeted", False):
            return
        self._greeted = True

        def _work():
            try:
                try:                       # STT (GPU) im Hintergrund vorwaermen -> 1. Sprachbefehl schnell
                    from aegis2.voice import stt as _stt
                    _stt.prewarm()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    from aegis2.shared import user_memory
                    name = user_memory.get_address()
                except Exception:  # noqa: BLE001
                    name = ""
                import datetime
                h = datetime.datetime.now().hour
                tg = ("Guten Morgen" if 5 <= h < 11 else "Guten Tag" if 11 <= h < 18
                      else "Guten Abend" if 18 <= h < 23 else "Hallo")
                who = (" " + name) if name else ""
                # Sicherheits-Stand NUR erwähnen, wenn es wirklich etwas zu melden gibt — KEIN
                # belangloser Füllsatz ("ich wache im Hintergrund über dein System" ist offen-
                # sichtlich und nervt). Alles ruhig -> einfach knapp + persönlich begrüßen.
                s = self._last_stats or {}
                try:
                    threats = int(s.get("threats_24h", 0) or 0)
                    quar = int(s.get("quarantine_pending", 0) or 0)
                except Exception:  # noqa: BLE001
                    threats, quar = 0, 0
                state = ""
                if threats > 0:
                    state = (f" Kurz vorweg: {threats} {'Bedrohungen' if threats != 1 else 'Bedrohung'} "
                             f"in den letzten 24 Stunden, {quar} in Quarantäne.")
                elif quar > 0:
                    state = (f" {quar} {'Objekte' if quar != 1 else 'Objekt'} "
                             f"warten noch in der Quarantäne auf dich.")
                # Vertrautheit: je mehr wir schon miteinander gemacht haben, desto lockerer der Ton.
                try:
                    from aegis2.shared import user_memory as _um2
                    fam = sum((_um2._load().get("command_counts") or {}).values())
                except Exception:  # noqa: BLE001
                    fam = 0
                import random as _rnd
                closers = (["Wie kann ich dir helfen?", "Was steht an?", "Womit kann ich helfen?"]
                           if fam < 25 else
                           ["Was brauchst du?", "Leg los.", "Was kann ich für dich tun?",
                            "Ich bin da — was steht an?", "Schieß los."])
                greeting = f"{tg}{who}.{state} {_rnd.choice(closers)}"
                # Sprechen + (bei Gespraechsmodus) freihaendig auf die Antwort warten — exakt
                # der normale Voice-Turn-Ablauf (TTS blockiert -> Mikro danach frei).
                self._voice_converse(
                    {"ok": True, "msg": greeting, "intent": "greet", "transcript": ""})
            except Exception as e:  # noqa: BLE001
                log.warning("greet: %s", e)
            finally:
                self.voiceState.emit("state", "idle")
                # Weckwort-Lauscher ERST JETZT starten (nach der Begruessung + erster Antwort).
                try:
                    self.initWake()
                except Exception:  # noqa: BLE001
                    pass
        threading.Thread(target=_work, daemon=True).start()

    def _models_missing(self) -> bool:
        """True NUR wenn das Erststart-Setup wirklich nötig ist (Ollama fehlt ODER ein
        benötigtes Modell ist noch nicht da). Bei jedem Zweifel/Fehler -> False, damit
        NIE ein ungewollter GB-Download startet. Auf Maschinen mit vorhandenen Modellen
        (Normalfall) liefert das False -> die Begrüßung läuft exakt wie bisher."""
        try:
            from aegis2.voice import ollama_setup as _os
            st = _os.status() or {}
            if not st.get("installed"):
                return True                      # Ollama selbst fehlt -> volles Turnkey-Setup
            from aegis2.shared.db import get_db
            db = get_db()
            llm = (db.get_setting("llm_model", "") or _os.best_model() or "").strip()
            vis = (db.get_setting("vision_model", "") or "llama3.2-vision").strip()
            for m in (llm, vis):
                if m and not _os._has_model_named(m):
                    return True
            return False
        except Exception as e:  # noqa: BLE001
            log.warning("_models_missing: %s", e)
            return False

    @pyqtSlot()
    def startupBoot(self):
        """ERSTSTART-SEQUENZ. Fehlen Modelle/Setup, kündigt AEGIS das Laden an (Stimme + sicht-
        barer Fortschritt über bootProgress -> #boot-overlay) und startet danach EINMAL sauber
        neu, damit alles frisch geladen ist. Sind die Modelle da (Normalfall), ganz normale
        Begrüßung. Idempotent pro Prozess; ein einmal gescheitertes Setup wird nicht in einer
        Schleife wiederholt (DB-Flag boot_setup_failed -> dann normaler Start + Knopf)."""
        if getattr(self, "_boot_started", False):
            return
        self._boot_started = True

        def _work():
            try:
                missing = self._models_missing()
            except Exception:  # noqa: BLE001
                missing = False
            if not missing:
                self.greet()
                return
            # Frühere Fehlversuche nicht endlos auto-wiederholen.
            try:
                from aegis2.shared.db import get_db
                if get_db().get_setting("boot_setup_failed", False):
                    self.greet()
                    return
            except Exception:  # noqa: BLE001
                pass

            self.bootProgress.emit("Ich lade meine KI-Modelle …", 1)
            try:
                from aegis2.voice.sir_speaker import speak_text
                speak_text("Einen Moment. Beim ersten Start lade ich meine Modelle. Das kann ein "
                           "paar Minuten dauern — danach starte ich einmal sauber neu, dann bin ich bereit.")
            except Exception:  # noqa: BLE001
                pass

            ok = False
            try:
                from aegis2.voice import ollama_setup as _os
                r = _os.install(progress=lambda s, p: self.bootProgress.emit(s or "", int(p))) or {}
                ok = bool(r.get("ok"))
            except Exception as e:  # noqa: BLE001
                log.warning("startupBoot install: %s", e)
                ok = False

            try:
                from aegis2.shared.db import get_db
                db = get_db()
                db.set_setting("boot_setup_done", bool(ok))
                db.set_setting("boot_setup_failed", not ok)
            except Exception:  # noqa: BLE001
                pass

            if ok:
                self.bootProgress.emit("Fertig — ich starte sauber neu.", 100)
                try:
                    from aegis2.voice.sir_speaker import speak_text
                    speak_text("Alles bereit. Ich starte jetzt einmal sauber neu.")
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(2)
                try:
                    import secrets as _sec
                    self._ipc.send({"t": "cmd", "name": "system.restart",
                                    "args": {}, "ref": _sec.token_hex(6)})
                except Exception as e:  # noqa: BLE001
                    log.warning("startupBoot restart: %s", e)
                    self.greet()
            else:
                self.bootProgress.emit("Konnte die Modelle nicht laden — ich mache normal weiter.", -1)
                self.greet()

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

    @pyqtSlot(result=str)
    def brainGet(self):
        """AEGIS-Brain laden (Identität/Prioritäten/Stimme/Regeln) — die Datei, die JARVIS
        bei jeder Antwort liest. Legt beim ersten Mal die Vorlage an."""
        try:
            from aegis2.shared import brain
            return brain.load()
        except Exception as e:  # noqa: BLE001
            return "# Fehler beim Laden des Brain: " + str(e)

    @pyqtSlot(str, result=bool)
    def brainSave(self, text):
        """AEGIS-Brain speichern (wirkt sofort beim nächsten Gespräch, kein Neustart nötig)."""
        try:
            from aegis2.shared import brain
            return bool(brain.save(text or ""))
        except Exception:  # noqa: BLE001
            return False

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
