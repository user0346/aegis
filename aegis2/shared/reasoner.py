"""Cognition-Reasoner — bindet das lokale Ollama ans Lernen.

Unklare/verdaechtige Events (die die Heuristik nicht eindeutig einordnet) gehen
gebuendelt an das lokale Ollama-Modell, das sie bewertet (Bedrohung? Begruendung?
Konfidenz?). Das Ergebnis fliesst GEWICHTET in den adaptiven Lern-Layer
(Reputation). So wird AEGIS ueber Ollamas Kontextverstaendnis schneller schlau,
OHNE dass Ollama allein entscheidet — konservativ, kein Fehlalarm-Sturm.

Laeuft nur, wenn Self-Learning erlaubt ist (Gate) UND Ollama lokal verfuegbar
ist. Alles lokal, kein Cloud-Key, keine Daten verlassen den PC.
"""
from __future__ import annotations

import logging
from collections import deque

from .events import EventBus, Event, Severity, Category
from .modules.base import Module

log = logging.getLogger("aegis2.reasoner")

_SYSTEM = (
    "Du bist AEGIS' Analyse-Kern fuer Windows-Endpoint-Security. Du bewertest "
    "verdaechtige System-Events. Antworte AUSSCHLIESSLICH als JSON-Objekt mit dem "
    "Schluessel 'verdicts' = Liste von Objekten "
    "{\"i\": <index>, \"threat\": true|false, \"confidence\": 0.0-1.0, "
    "\"reason\": \"<kurz, deutsch>\"}. Sei KONSERVATIV: nur klare Bedrohungen als "
    "threat=true mit hoher confidence. Normale System-, Update-, Treiber-, Spiel- "
    "und bekannte App-Prozesse sind KEINE Bedrohung."
)


class CognitionReasoner(Module):
    """Ollama-gestuetztes Reasoning ueber unklare Events -> beschleunigt das Lernen."""
    name = "CognitionReasoner"

    def __init__(self, bus: EventBus, db, interval_s: float = 20.0, batch: int = 6):
        super().__init__(bus)
        self.db = db
        self.interval_s = max(8.0, interval_s)
        self.batch = batch
        self._q: deque = deque(maxlen=150)
        bus.subscribe(self._on_event)

    def _on_event(self, ev: Event) -> None:
        try:
            if ev.source == self.name:          # eigene Events nicht erneut bewerten
                return
            md = ev.metadata or {}
            verdict = md.get("verdict", "")
            if ev.severity == "WARN" or verdict in ("suspicious", "unknown"):
                self._q.append({
                    "cat": ev.category, "src": ev.source,
                    "msg": (ev.message or "")[:160],
                    "name": md.get("name") or md.get("exe") or "",
                })
        except Exception:  # noqa: BLE001
            pass

    def _ready(self) -> bool:
        try:
            from ..cognition.gate import capability_enabled
            if not capability_enabled("learning"):
                return False
        except Exception:  # noqa: BLE001
            pass
        try:
            from ..voice import llm
            return llm.available()
        except Exception:  # noqa: BLE001
            return False

    def run(self) -> None:
        self._stop.wait(50)            # Boot-Delay: Ollama/Service hochfahren lassen
        while not self._stop.is_set():
            try:
                if self._q and self._ready():
                    self._reason_batch()
            except Exception as e:  # noqa: BLE001
                log.warning("reasoner cycle: %s", e)
            self._stop.wait(self.interval_s)

    def _reason_batch(self) -> None:
        items = []
        while self._q and len(items) < self.batch:
            items.append(self._q.popleft())
        if not items:
            return
        lines = [f'{i}: [{it["cat"]}] {it["src"]} {it["name"]} — {it["msg"]}'
                 for i, it in enumerate(items)]
        from ..voice import llm
        out = llm.ask_json("Bewerte diese Events:\n" + "\n".join(lines), system=_SYSTEM)
        verdicts = out.get("verdicts") if isinstance(out, dict) else None
        if not isinstance(verdicts, list):
            return
        for v in verdicts:
            try:
                i = int(v.get("i", -1))
                if not (0 <= i < len(items)):
                    continue
                it = items[i]
                ident = (it.get("name") or it.get("src") or "").lower()
                if not ident:
                    continue
                threat = bool(v.get("threat"))
                conf = float(v.get("confidence", 0) or 0)
                reason = str(v.get("reason", ""))[:160]
                kind = "proc" if it["cat"] == "PROCESS" else "generic"
                # GEWICHTET: Ollama ist ein Signal, nicht die Wahrheit (max 0.5).
                if threat and conf >= 0.6:
                    self.db.reputation_update(kind, ident, malicious=True,
                                              weight=min(0.5, conf * 0.5))
                    self.emit(Severity.WARN, Category.SYSTEM,
                              f"KI-Analyse: {ident} verdaechtig — {reason}",
                              {"verdict": "ai_suspicious",
                               "confidence": round(conf, 2), "ident": ident})
                # BEWUSSTE ASYMMETRIE: KEINE Entlastung (malicious=False) aus einer LLM-
                # Vermutung — genau das war die Wurzel der "Executor = harmlos"-Halluzination,
                # die sich sonst selbstverstaerkend in die Reputation einbrennt. Ein Objekt
                # wird ausschliesslich durch Signaturen/Heuristik/VirusTotal entlastet.
            except Exception:  # noqa: BLE001
                continue
