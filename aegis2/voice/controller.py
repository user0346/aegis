"""Voice-Controller — Push-to-Talk-Pipeline, komplett lokal/gratis.

   record_until_silence  ->  STT (lokal/faster-whisper)  ->  Intent (Regex)
   ->  ActionRouter  ->  Ergebnis (fuer TTS + UI-Feedback)

Laeuft in einem Worker-Thread, blockiert die Oberflaeche nicht.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

log = logging.getLogger("aegis.voice.controller")


class VoiceController:
    def __init__(self, ui_cmd: Optional[Callable[[dict], None]] = None,
                 service_cmd: Optional[Callable[[dict], None]] = None,
                 prefer_local: bool = True,
                 status_cb: Optional[Callable[[], dict]] = None):
        from .actions import ActionRouter
        self.router = ActionRouter(ui_cmd=ui_cmd, service_cmd=service_cmd, status_cb=status_cb)
        self.prefer_local = prefer_local

    def listen_once(self, language: str = "de", on_stage=None) -> dict:
        """Eine Push-to-Talk-Runde: aufnehmen, verstehen, ausfuehren.
        on_stage(stage) wird mit 'listening'/'thinking' aufgerufen (UI-Feedback)."""
        from . import recorder, stt
        if on_stage: on_stage("listening")
        wav = recorder.record_until_silence()
        if not wav:
            return {"ok": False, "stage": "record", "msg": "Kein Audio / kein Mikrofon."}
        if on_stage: on_stage("thinking")
        text = stt.transcribe_wav(wav, language=language, prefer_local=self.prefer_local)
        if not text:
            return {"ok": False, "stage": "stt",
                    "msg": "Nichts verstanden (faster-whisper installiert?)."}
        return self.handle_text(text, language)

    def handle_text(self, text: str, language: str = "de") -> dict:
        """Pipeline ab Text — auch fuer Text-Eingabe ohne Mikrofon (gratis-Test)."""
        import re
        from . import intent as intent_mod
        # Wake-Wort-Prefix entfernen: "AEGIS status" -> "status"
        _wake = "aegis|\u00e4gis|\u00e4giz"
        try:
            from ..shared import user_memory
            _own = user_memory.get_wake_word()
            if _own:
                _wake += "|" + re.escape(_own.lower())
        except Exception:  # noqa: BLE001
            pass
        stripped = re.sub(r"^\s*(hey\s+|ey\s+|yo\s+|na\s+|hallo\s+)?(" + _wake + r")[\s,:!.?-]*",
                          "", text, flags=re.I).strip()
        # Nur das Weckwort gesagt ("ey jarvis", "aegis") -> Bereitschaft signalisieren,
        # NICHT den gespeicherten Kontext ausschuetten.
        if not stripped and re.search(r"\b(?:" + _wake + r")\b", text, re.I):
            return {"ok": True, "msg": "Ja? Womit kann ich dir helfen?",
                    "transcript": text, "intent": "greet"}
        clean = stripped or text
        # 1) DIREKTBEFEHL — nur EINDEUTIGE, verb-verankerte Befehle (öffne/spiele/beende,
        # sichere Tools wie "sfc /scannow", nackte URLs) feuern sofort. Stichwort-Intents
        # (scan/suche/status/...) laufen NICHT hier, sondern ueber das Modell (Schritt 3)
        # -> Routing nach BEDEUTUNG statt Substring ("scannow" startet keinen Scan mehr).
        cmd = intent_mod.classify_command(clean)
        if cmd.get("intent"):
            return self._finish(cmd, text)

        # 1b) Bekanntes Smalltalk-Wort ("hallo", "danke", "clear") -> direkt
        # Konversation. Deterministisch — das ratende Modell wird gar nicht gefragt.
        if clean.strip().lower().rstrip("?!.") in self._SMALLTALK:
            return self._finish({"intent": "query", "args": {"text": clean}}, text)

        # 2) NACKTER NAME — "discord", "spotify": als App/Website oeffnen statt raten.
        bare = self._resolve_bare(clean)
        if bare:
            return self._finish(bare, text)

        # 2b) DETERMINISTISCHE READ-ONLY-INFO-INTENTS — "was ist neu" (Changelog),
        # "was hast du gelernt", KB-/Status-/Threats-/USB-Abfragen. Diese SOLLEN
        # nicht vom Verstaendnis-Router als Smalltalk ("none") verworfen werden
        # (der Ollama-Prompt kennt sie nicht). Sicher, weil rein lesend.
        try:
            det = intent_mod.classify(clean)
            if det.get("intent") in ("whats_new", "learnings", "kb_status",
                                      "status", "threats", "usb", "scan_status"):
                return self._finish(det, text)
        except Exception:  # noqa: BLE001
            pass

        # 3) MODELL — VERSTÄNDNIS-ROUTER: klassifiziert natuerliche Sprache nach BEDEUTUNG
        # (volles Intent-Enum). Ist das Modell offline, faellt AEGIS auf die volle Regex
        # als Sicherheitsnetz zurueck (lieber funktionsfaehig mit seltenem Fehlgriff als
        # offline unbrauchbar).
        try:
            from . import llm
            if llm.available():
                smart = self._ollama_intent(clean)
                if smart:
                    return self._finish(smart, text)
            else:
                off = intent_mod.classify(clean)
                if off.get("confidence", 0) >= 0.8:
                    return self._finish(off, text)
        except Exception:  # noqa: BLE001
            pass

        # 4) UNSICHER -> Konversation (Persona/LLM). Nie einen Befehl erfinden.
        return self._finish({"intent": "query", "args": {"text": clean}}, text)

    def _finish(self, cls: dict, text: str) -> dict:
        result = self.router.dispatch(cls)
        result["transcript"] = text
        result["intent"] = cls.get("intent")
        # Konversations-Verlauf ZENTRAL pflegen — ALLE Turns (nicht nur freie LLM-Chats),
        # damit AEGIS den Bezug kennt, wenn der Nutzer auf die letzte Antwort eingeht.
        try:
            msg = (result.get("msg") or "").strip()
            if text and msg and cls.get("intent") not in ("greet",):
                h = self.router._hist
                h.append("Nutzer: " + text.strip())
                h.append("AEGIS: " + msg)
                del h[:-30]           # die letzten 15 Wortwechsel behalten
        except Exception:  # noqa: BLE001
            pass
        return result

    # Kurze Eingaben, die KEIN App-Befehl sind -> Konversation/Persona ueberlassen.
    _SMALLTALK = {
        "hallo", "hi", "hey", "moin", "na", "servus", "tach", "yo", "hej",
        "danke", "dankeschön", "merci", "thx", "ok", "okay", "jo", "ja", "nein",
        "ne", "nö", "hm", "hmm", "test", "clear", "cls", "reset", "leeren",
        "cool", "nice", "top", "super", "bitte", "los", "weiter",
    }

    def _resolve_bare(self, clean: str):
        """Nackte 1-2-Wort-Eingabe ohne Verb: installierte App oder bekannte Marke?
        Dann oeffnen. Sonst None (-> Modell/Konversation). So wird 'discord'
        geoeffnet, 'hallo' aber NICHT als Website missverstanden.
        Anti-Injection: App-Treffer nur ueber den indexierten Start-Menue-Index."""
        low = clean.strip().lower().rstrip("?!.")
        if not low or low in self._SMALLTALK:
            return None
        # benannter Shortcut (beliebige Wortzahl) -> gespeichertes Ziel abspielen/oeffnen
        try:
            from ..shared import user_memory
            if user_memory.get_alias(low):
                return {"intent": "play", "args": {"target": low}, "confidence": 0.92}
        except Exception:  # noqa: BLE001
            pass
        w = clean.split()
        if not (1 <= len(w) <= 2):
            return None
        # bekannte Marke/Dienst (youtube, discord, spotify, ...) -> open
        try:
            from .actions import SAFE_APPS
            if (low in self.router._SITE_NAMES or low in self.router._SITES
                    or low in SAFE_APPS):
                return {"intent": "open", "args": {"target": clean}, "confidence": 0.9}
        except Exception:  # noqa: BLE001
            pass
        # installierte App (indexierte .lnk)? -> open/fokus statt Doppelstart
        try:
            from . import app_index
            if app_index.find_app(clean):
                return {"intent": "open", "args": {"target": clean}, "confidence": 0.9}
        except Exception:  # noqa: BLE001
            pass
        return None

    # JSON-Schema fuer Ollama Structured-Outputs (Verstaendnis-Router). Das Enum deckt jetzt
    # ALLE bedeutungs-routbaren Intents ab — ABER bewusst NICHT die maechtigen/strukturierten
    # Pfade (run_command/shell/set_wake/set_alias/learn_url/remember/learn/forget): die
    # bleiben rein deterministisch (Regex). Das Schema laesst nur Enum-Werte zu, also kann
    # selbst eine manipulierte Eingabe ueber den Klassifikator KEINEN Shell-/Memory-Pfad
    # erzwingen. Die erreichbaren Aktionen sind read-only/UI oder bereits gegated (open/search).
    _INTENT_SCHEMA = {
        "type": "object",
        "properties": {
            "intent": {"type": "string",
                       "enum": ["open", "search", "play", "media", "close_app",
                                "scan", "scan_status", "status", "threats", "usb",
                                "whats_new", "learnings", "kb_status", "pause",
                                "knowledge", "none"]},
            "target": {"type": "string"},
            "site": {"type": "string"},
            "term": {"type": "string"},
        },
        "required": ["intent"],
    }

    def _ollama_intent(self, text: str):
        """Ollama als Intent-Parser via Structured-Output (erzwungenes JSON-Schema, temp=0).
        Versteht natuerliche Sprache + Fuellwoerter. Fallback, wenn Regex nicht greift."""
        try:
            from . import llm
            if not llm.available():
                return None
            prompt = (
                f"Nutzer-Eingabe: \u00ab{text}\u00bb\n"
                "Bestimme die gewuenschte Aktion. open=Website/App oeffnen, "
                "search=im Web/auf Plattform suchen, status/scan/threats/quarantine="
                "AEGIS-Funktion, none=Smalltalk/Frage/unklar. WICHTIG: eine FRAGE über AEGIS' "
                "Daten/Erkenntnisse (welche, was, wie viele ...) ist KEINE Aktion -> none. "
                "Bei kurzen/mehrdeutigen Eingaben und im Zweifel IMMER none. 'target'=Website/App bzw. Suchbegriff "
                "OHNE Fuellwoerter (mir, mal, bitte). 'site'=Plattform fuer search, falls "
                "genannt (youtube, spotify, google). Beispiel: \u00aboeffne youtube lofi "
                'music\u00bb -> {"intent":"search","target":"lofi music","site":"youtube"}.'
            )
            d = llm.ask_json(prompt, schema=self._INTENT_SCHEMA, num_predict=80)
            if not isinstance(d, dict):
                return None
            it = (d.get("intent") or "").strip().lower()
            tgt = (d.get("target") or "").strip()
            term = (d.get("term") or "").strip()
            # AEGIS-Read-/Status-Intents ohne Argumente -> direkt der passende Handler.
            if it in ("scan", "scan_status", "status", "threats", "usb",
                      "whats_new", "learnings", "kb_status", "pause"):
                return {"intent": it, "args": {}, "confidence": 0.7}
            if it == "open" and tgt:
                return {"intent": "open", "args": {"target": tgt}, "confidence": 0.7}
            if it == "search" and tgt:
                site = (d.get("site") or "").strip().lower()
                q = ("auf " + site + " " + tgt) if site else tgt
                return {"intent": "search", "args": {"query": q}, "confidence": 0.7}
            if it == "play" and tgt:
                low = tgt.lower()
                if low.startswith(("http://", "https://")) or "." in low.split(" ")[0]:
                    return {"intent": "open", "args": {"target": tgt}, "confidence": 0.7}
                return {"intent": "search", "args": {"query": tgt}, "confidence": 0.7}
            if it == "media":
                return {"intent": "media", "args": {"raw": text.lower()}, "confidence": 0.7}
            if it == "close_app" and tgt:
                return {"intent": "close_app", "args": {"name": tgt}, "confidence": 0.7}
            if it == "knowledge" and (term or tgt):
                return {"intent": "knowledge", "args": {"term": term or tgt, "text": text}, "confidence": 0.7}
            # 'none' ODER unklar -> Konversation (Persona/LLM). Kein erzwungener Befehl.
            return {"intent": "query", "args": {"text": text}, "confidence": 0.6}
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def stt_ready() -> bool:
        from . import stt
        return stt.local_stt_available()
