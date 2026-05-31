"""Self-Reflection / Learner-Loop.

Was tut dieses Modul tatsächlich:
  1. Periodisch (alle N Stunden) holt es die letzten M Events aus der DB.
  2. Schickt sie an Claude mit dem System-Prompt aus claude_client.propose_learning().
  3. Wenn Claude einen Vorschlag liefert, stellt es ihn in die Consent-Queue:
       action: "learning_write"
       title:  Claudes vorgeschlagener Titel
       detail: Body-Preview (max 280 chars)
       scope:  "section:<performance|bugs>"
  4. Sobald der User in der UI approved, ruft der UI/Service-Pfad
     cognition.actions.execute_learning_write(token, ...) auf. Das ist die
     einzige Stelle die in AEGIS_LEARNINGS.md schreibt.

Was es NICHT tut (bewusst):
  - Keine autonomen Schreibvorgänge.
  - Keine Heuristik-Mutation ohne User-Zustimmung.
  - Keine Kommunikation mit Claude wenn kein API-Key gesetzt ist.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from .db import Database
from .events import EventBus, Event, Severity, Category
from .modules.base import Module
from ..cognition import claude_client
from ..cognition.consent import get_manager
from ..cognition.secrets_store import get_secret


log = logging.getLogger("aegis2.learner")


class SelfReflector(Module):
    """Background-Reflektor. Default: alle 6 h, mindestens 30 Events nötig."""
    name = "SelfReflector"

    def __init__(self, bus: EventBus, db: Database,
                 interval_h: float = 6.0, min_events: int = 30,
                 sample_limit: int = 80,
                 first_run_after_events: int = 50):
        super().__init__(bus)
        self.db = db
        self.interval_s = max(60.0, interval_h * 3600)
        self.min_events = min_events
        self.sample_limit = sample_limit
        # First-reflect-trigger: nicht 6h warten beim allerersten Mal
        # sondern direkt nach N gesammelten Events das System lassen lernen.
        self.first_run_after_events = first_run_after_events
        self._last_run: float = 0.0
        self._proposals_count = 0
        self._first_run_done = False

    def run(self) -> None:
        # short settle, dann Loop
        self._stop.wait(30)
        while not self._stop.is_set():
            try:
                if self._should_run_now():
                    self._do_reflection_cycle()
            except Exception as e:  # noqa: BLE001
                self.emit(Severity.WARN, Category.SYSTEM,
                          f"Reflektor-Zyklus crashed: {type(e).__name__}: {e}")
            self._stop.wait(60)

    @staticmethod
    def _llm_available() -> bool:
        """LLM da? Lokales Ollama bevorzugt (gratis, offline), sonst Anthropic-Key."""
        try:
            from ..voice import llm
            if llm.available():
                return True
        except Exception:  # noqa: BLE001
            pass
        return bool(get_secret("anthropic_api_key"))

    def _should_run_now(self) -> bool:
        # Self-Learning muss vom Nutzer erlaubt sein (Master-Toggle in Settings).
        try:
            from ..cognition.gate import capability_enabled
            if not capability_enabled("learning"):
                return False
        except Exception:  # noqa: BLE001
            pass
        # Ein LLM muss verfuegbar sein: Ollama lokal ODER Anthropic-Key (opt-in).
        if not self._llm_available():
            return False
        # First-run-Trigger: nach N Events ohne 6h-Wait
        if not self._first_run_done:
            try:
                ev_count = self.db.count_events_last(seconds=24 * 3600)
            except Exception:  # noqa: BLE001
                ev_count = 0
            if ev_count >= self.first_run_after_events:
                self._first_run_done = True
                return True
            return False
        # Danach normale 6h-Intervalle
        if time.time() - self._last_run < self.interval_s:
            return False
        return True

    def _do_reflection_cycle(self) -> None:
        self._last_run = time.time()

        # Sample recent events from DB
        rows = self.db.recent_events(limit=self.sample_limit)
        if len(rows) < self.min_events:
            self.emit(Severity.INFO, Category.SYSTEM,
                      f"Reflektor: zu wenig Events ({len(rows)}/{self.min_events}) — übersprungen")
            return

        events = [dict(r) for r in rows]
        # Trim oversize messages so prompt stays compact
        for ev in events:
            if isinstance(ev.get("message"), str) and len(ev["message"]) > 240:
                ev["message"] = ev["message"][:240] + "…"

        result = claude_client.propose_learning(events)
        if not result.get("ok"):
            self.emit(Severity.WARN, Category.SYSTEM,
                      f"Reflektor: Claude-Fehler: {result.get('error','?')}")
            return
        prop = result.get("proposal")
        if not prop:
            # Claude entschied: nichts vorzuschlagen — das ist OK und KEIN Fehler
            self.emit(Severity.INFO, Category.SYSTEM,
                      "Reflektor: nichts Lernwertes aus diesem Zyklus")
            return

        # Queue als Consent-Request
        title = prop.get("title", "(ohne Titel)")[:120]
        section = prop.get("section", "performance")
        body = prop.get("body", "")
        detail_preview = body.replace("\n", " ").strip()
        if len(detail_preview) > 600:
            detail_preview = detail_preview[:597] + "…"

        # Dedup: denselben Vorschlag nicht wiederholt einreihen (sonst kommt er nach
        # OK/Nein immer wieder, weil der Reflektor dieselben Events erneut sieht).
        import hashlib as _hl
        thash = _hl.sha1((title or "").lower().strip().encode("utf-8")).hexdigest()[:16]
        seen = self.db.get_setting("reflector_seen", [])
        if not isinstance(seen, list):
            seen = []
        if thash in seen:
            self.emit(Severity.INFO, Category.SYSTEM,
                      "Reflektor: Vorschlag bereits bekannt — uebersprungen")
            return
        # Schon (aehnlich) in LEARNINGS vermerkt? -> gar nicht erst erneut vorschlagen.
        try:
            from .memory import find_learnings_file, _already_present
            _lf = find_learnings_file()
            if _lf.exists() and _already_present(_lf.read_text(encoding="utf-8"), title):
                self.emit(Severity.INFO, Category.SYSTEM,
                          "Reflektor: Erkenntnis steht schon in LEARNINGS — uebersprungen")
                return
        except Exception:  # noqa: BLE001
            pass

        cm = get_manager()
        # Nicht fluten: solange noch EIN Reflektor-Vorschlag offen ist, keinen neuen
        # einreihen (sonst stapeln sich aehnliche Erkenntnisse trotz Titel-Variation).
        try:
            for _p in cm.list_pending():
                if str(_p.get("title", "")).startswith("Erkenntnis vorschlagen"):
                    self.emit(Severity.INFO, Category.SYSTEM,
                              "Reflektor: es ist bereits ein Vorschlag offen — kein neuer")
                    return
        except Exception:  # noqa: BLE001
            pass
        cid = cm.request(
            action="learning_write",
            title=f"Erkenntnis vorschlagen: {title}",
            detail=detail_preview,
            requested_by="self-reflector",
            scope=f"section:{section}",
            severity="normal",
            ttl_sec=24 * 3600,    # Lern-Vorschläge dürfen lange in der Queue stehen
        )
        seen.append(thash)
        try:
            self.db.set_setting("reflector_seen", seen[-200:])
        except Exception:  # noqa: BLE001
            pass
        # Body+section MUST be associated with the request for execution.
        # We use a side-channel: the consent_manager stores the proposal
        # in a in-RAM map by consent-id. When user approves, the action
        # executor reads it from there.
        _PENDING_PROPOSALS[cid] = {"section": section, "title": title, "body": body}
        self._proposals_count += 1
        self.emit(Severity.QUARANTINE, Category.SYSTEM,
                  f"Lern-Vorschlag in Consent-Queue: <<{title}>>",
                  {"consent_id": cid, "section": section,
                   "proposal_no": self._proposals_count})
        try:
            self.db.inc_metric("learning_proposals", 1)
        except Exception:
            pass


_PENDING_PROPOSALS = {}


def get_pending_proposal(consent_id):
    return _PENDING_PROPOSALS.get(consent_id)


def consume_pending_proposal(consent_id):
    return _PENDING_PROPOSALS.pop(consent_id, None)
