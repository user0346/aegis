"""Leichte statistische Anomalie-Erkennung — unsupervised, kein scikit-learn.

Online-Statistik (Welford running mean/variance) pro Verhaltens-Metrik. AEGIS
lernt die normale Event-Rate jeder Kategorie und flaggt starke statistische
Ausreisser (z-Score). Reine stdlib -> kein Zusatzpaket, kaum Last, kein
Trainings-Overhead. Geflaggte Ausreisser werden als WARN-Event gemeldet und
vom CognitionReasoner (Ollama) kontextuell bewertet -> mehrstufiges Lernen.

Konservativ: erst nach genug Baseline-Fenstern, nur bei klarem Ausreisser und
Mindest-Absolutwert (kein Fehlalarm bei 0 -> 1 Events).
"""
from __future__ import annotations

import math
from collections import defaultdict

from .events import EventBus, Event, Severity, Category
from .modules.base import Module


class RunningStat:
    """Welford'sches Online-Mittel/Varianz (numerisch stabil, O(1) Speicher)."""
    __slots__ = ("n", "mean", "m2")

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0

    def push(self, x: float) -> None:
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0

    def zscore(self, x: float) -> float:
        s = self.std
        return (x - self.mean) / s if s > 1e-6 else 0.0


class BehaviorAnomaly(Module):
    """Zaehlt Event-Raten pro Kategorie je Zeitfenster, lernt das Normal,
    flaggt starke Ausreisser als WARN (-> Reasoner bewertet sie mit Ollama)."""
    name = "BehaviorAnomaly"

    def __init__(self, bus: EventBus, window_s: float = 60.0, min_samples: int = 15,
                 z_threshold: float = 3.5, min_count: int = 5):
        super().__init__(bus)
        self.window_s = max(20.0, window_s)
        self.min_samples = min_samples
        self.z = z_threshold
        self.min_count = min_count
        self._counts: dict = defaultdict(int)
        self._stats: dict = defaultdict(RunningStat)
        bus.subscribe(self._on_event)

    def _on_event(self, ev: Event) -> None:
        try:
            # eigene + abgeleitete Events nicht mitzaehlen (kein Selbst-Feedback)
            if ev.source in (self.name, "CognitionReasoner"):
                return
            self._counts[ev.category] += 1
        except Exception:  # noqa: BLE001
            pass

    def run(self) -> None:
        self._stop.wait(self.window_s)        # erstes Fenster sammeln
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                pass
            self._stop.wait(self.window_s)

    def _tick(self) -> None:
        counts = dict(self._counts)
        self._counts.clear()
        # 1) aktuelle Fenster auf Ausreisser pruefen (gegen gelerntes Normal)
        for cat, c in counts.items():
            st = self._stats[cat]
            if st.n >= self.min_samples and c >= self.min_count:
                z = st.zscore(c)
                if z >= self.z:
                    self.emit(Severity.WARN, Category.SYSTEM,
                              f"Verhaltens-Anomalie: ungewoehnlich viele {cat}-Events "
                              f"({c} in {int(self.window_s)}s, normal ~{st.mean:.0f})",
                              {"verdict": "suspicious", "anomaly_cat": cat,
                               "count": c, "zscore": round(z, 1), "name": str(cat)})
            st.push(float(c))                 # Wert ins Normal-Modell lernen
        # 2) Kategorien, die in diesem Fenster still waren, lernen 0 (Stille = Normal)
        for cat in list(self._stats.keys()):
            if cat not in counts:
                self._stats[cat].push(0.0)
