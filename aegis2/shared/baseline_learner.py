"""Autonomer Baseline-Lerner — echtes, sicheres Selbstlernen aus EIGENER Telemetrie.

Unterschied zum SelfReflector (LLM-Vorschlaege -> Consent-Queue, [[learner.py]]):
dieses Modul schreibt AUTONOM, aber NUR deterministische FAKTEN ueber diesen PC —
keine Heuristik, keine LLM-Meinung. Fakten (wie viele Programme als normal etabliert
sind, wie viele Gefahren-Domains geblockt werden, was als boesartig gelernt wurde)
sind sicher ohne Zustimmung zu vermerken; sie

  * machen «was hast du gelernt» konkret,
  * geben dem lokalen Modell Situationsbewusstsein (llm_context),
  * treiben die Entwicklungs-Anzeige (insights-Zaehler + Wochen-Trend),
  * und erzeugen ein sichtbares Live-Event, sobald etwas Neues gefestigt wurde.

Jede Erkenntnis wird HOECHSTENS EINMAL geschrieben (seen-Set in DB + Titel-Dedup im
MemoryWriter). Reine Beobachtung, NIE autonome Aktionen (kein Quarantaene/Kill).
Abschaltbar via Setting 'enable_autonomous_learning'.
"""
from __future__ import annotations

import logging
import time

from .events import Severity, Category
from .modules.base import Module

log = logging.getLogger("aegis2.baseline_learner")


class BaselineLearner(Module):
    name = "BaselineLearner"

    def __init__(self, bus, db, interval_h: float = 2.0, first_after_s: float = 150.0):
        super().__init__(bus)
        self.db = db
        self.interval_s = max(300.0, interval_h * 3600)
        self.first_after_s = max(30.0, first_after_s)
        self._last = 0.0
        self._first_done = False

    def run(self) -> None:
        self._stop.wait(self.first_after_s)        # kurz nach Boot das erste Mal lernen
        while not self._stop.is_set():
            try:
                if self._enabled() and self._due():
                    self._cycle()
                    self._last = time.time()
            except Exception as e:  # noqa: BLE001
                self.emit(Severity.WARN, Category.SYSTEM,
                          f"Baseline-Lerner-Zyklus fehlgeschlagen: {type(e).__name__}: {e}")
            self._stop.wait(120)

    def _enabled(self) -> bool:
        try:
            return bool(self.db.get_setting("enable_autonomous_learning", True))
        except Exception:  # noqa: BLE001
            return True

    def _due(self) -> bool:
        if not self._first_done:
            self._first_done = True
            return True
        return (time.time() - self._last) >= self.interval_s

    def _cycle(self) -> None:
        from .memory import ensure_learnings_file, get_writer
        from .knowledge import learned_summary
        ensure_learnings_file()
        s = learned_summary(self.db)

        try:
            seen = self.db.get_setting("baseline_learn_seen", [])
            if not isinstance(seen, list):
                seen = []
        except Exception:  # noqa: BLE001
            seen = []

        writer = get_writer()
        new = 0
        for key, title, body in self._insights(s):
            if key in seen:
                continue
            try:
                writer.append("selflearn", title, body)
                seen.append(key)
                new += 1
            except Exception:  # noqa: BLE001
                pass

        # Snapshot IMMER aktualisieren (Trend der Entwicklungs-Anzeige lebt davon),
        # auch ohne neue Erkenntnis.
        try:
            from .development import record_snapshot
            record_snapshot(self.db)
        except Exception:  # noqa: BLE001
            pass

        if new:
            try:
                self.db.set_setting("baseline_learn_seen", seen[-300:])
            except Exception:  # noqa: BLE001
                pass
            try:
                self.db.inc_metric("autonomous_insights", new)
            except Exception:  # noqa: BLE001
                pass
            # Sichtbar im Live-Stream + Brain feuert.
            self.emit(Severity.INFO, Category.SYSTEM,
                      f"Selbstlernen: {new} neue Erkenntnis{'se' if new != 1 else ''} "
                      "aus eigener Beobachtung gefestigt.",
                      {"new": new, "self_learn": True})

    @staticmethod
    def _insights(s: dict):
        """(key, Titel, Body) fuer aktuell erfuellte Meilensteine. Jeder key wird nur
        EINMAL geschrieben. Reine Fakten aus learned_summary() — deterministisch."""
        out = []
        known = int(s.get("baseline_known", 0) or 0)
        if known >= 50:
            out.append(("base50", "Normalzustand dieses PCs gelernt",
                f"Ich habe genug beobachtet, um den Normalzustand dieses PCs zuverlaessig zu "
                f"kennen ({known} Programme/Objekte als normal eingestuft). Neue, unbekannte "
                f"ausfuehrbare Dateien — vor allem in Download-Ordnern — fallen mir dadurch frueher auf."))
        if known >= 500:
            out.append(("base500", "Breite Programm-Baseline aufgebaut",
                f"Meine Baseline umfasst ueber 500 bekannte Programme/Objekte ({known}). "
                f"Fehlalarme bei alltaeglicher Software sind dadurch selten geworden."))
        if known >= 1000:
            out.append(("base1000", "Sehr umfangreiche Baseline",
                f"Mit ueber 1000 bekannten Objekten ({known}) erkenne ich den Normalbetrieb "
                f"dieses PCs sehr genau — echte Abweichungen stechen klar heraus."))
        blocked = int(s.get("domains_blocked", 0) or 0)
        if blocked:
            cats = s.get("domains_by_cat", {}) or {}
            top = max(cats.items(), key=lambda x: x[1])[0] if cats else "Tracker/Werbung"
            out.append(("domains", "Domain-Schutz steht",
                f"Ich blockiere {blocked} bekannte Gefahren- und Tracker-Domains "
                f"(Schwerpunkt: {top}). Verbindungen dorthin erkenne ich und schlage an."))
        rep_bad = int(s.get("rep_bad", 0) or 0)
        if rep_bad >= 1:
            tb = ", ".join(str(b.get("ident", "")) for b in (s.get("top_bad") or [])[:3] if b.get("ident"))
            out.append(("rep1", "Bedrohungs-Gedaechtnis angelegt",
                f"Ich habe {rep_bad} Objekt(e) als boesartig erkannt und merke sie mir"
                + (f" (haeufig: {tb})" if tb else "") + " — eine Wiederbegegnung erkenne ich sofort."))
        pat = int(s.get("patterns_learned", 0) or 0)
        if pat >= 1:
            out.append(("patterns", "Erkennungs-Muster nachjustiert",
                f"Aus beobachteten Faellen habe ich {pat} Erkennungs-Muster verfeinert — "
                f"das senkt Fehlalarme speziell auf diesem PC."))
        qd = int(s.get("quarantine_decided", 0) or 0)
        if qd >= 1:
            out.append(("quar", "Aus deinen Entscheidungen gelernt",
                f"Aus deinen {qd} Quarantaene-Entscheidungen habe ich gelernt, was du als sicher "
                f"bzw. unerwuenscht ansiehst, und richte meine Bewertung danach aus."))
        return out
