"""Adaptiver Lern-Layer — AEGIS wird ueber Zeit besser, ueber alle Kategorien.

Fusioniert drei Signale zu einem finalen Verdikt:
  1. base_score   — statische Heuristik (classify_*/scanner)
  2. calibration  — gelernter Adjust pro Muster (aus approve/deny-Feedback)
  3. reputation   — laufender Ruf eines konkreten Objekts (sha/name/ip)
plus Multi-Signal-Boni (Drop-Zone, first-seen, unsigniert, seltene Verbindung ...).

Lernt aus JEDER Entscheidung (nicht nur Quarantaene-Freigaben) und wendet das
Gelernte sofort wieder an -> erkennt auch Unbekanntes schneller und kann direkt
blocken. Konservativ: trusted Pfade werden nie hochgestuft, Auto-Block hat eine
hohe Schwelle.
"""
from __future__ import annotations

BLOCK_THRESHOLD = 82
WARN_THRESHOLD = 50
REINFECT_THRESHOLD = 3   # ab so vielen Boese-Wertungen gilt ein Objekt als Re-Infektion

# Multi-Signal-Gewichte (additiv auf den Score)
SIGNAL_WEIGHTS = {
    "drop_zone":      12,   # liegt/laeuft in %TEMP%/AppData/ProgramData/Public
    "first_seen":      8,   # noch nie gesehen
    "unsigned":       10,   # keine gueltige Code-Signatur
    "untrusted_path":  8,   # nicht unter Windows/Program Files
    "net_rare_ip":    10,   # Verbindung zu seltener/neuer IP
    "exec_ext":        6,   # ausfuehrbare Endung
    "hidden_window":   8,   # laeuft ohne sichtbares Fenster
    "autostart":      10,   # nistet sich in Autostart/Run ein
    "double_ext":      9,   # z.B. rechnung.pdf.exe
}

# Pfade die NIE hochgestuft/geblockt werden (Signatur-Vertrauen)
_TRUSTED_PREFIXES = ("c:/windows/", "c:/program files/", "c:/program files (x86)/")


def _norm(path: str) -> str:
    return (path or "").lower().replace(chr(92), "/")


def is_trusted_path(path: str) -> bool:
    p = _norm(path)
    return bool(p) and p.startswith(_TRUSTED_PREFIXES)


def reputation_score_from(mal: float, ben: float) -> float:
    """Ruf aus mal/ben-Zahlen — in [-25 (zuverlaessig gut) .. +35 (zuverlaessig boese)]."""
    total = float(mal) + float(ben)
    if total <= 0:
        return 0.0
    ratio = float(mal) / total              # 0..1
    base = (ratio - 0.3) * 50               # 0.3 = neutral
    conf = min(1.0, total / 5.0)            # mehr Beobachtungen -> mehr Gewicht
    return max(-25.0, min(35.0, base * conf))


def reputation_score(db, kind: str, ident: str) -> float:
    """Ruf eines Objekts (DB-Lookup)."""
    try:
        row = db.reputation_get(kind, ident)
    except Exception:
        row = None
    if not row:
        return 0.0
    return reputation_score_from(row["mal_hits"], row["ben_hits"])


def learned_verdict(db, kind: str, ident: str, base_score: float,
                    base_verdict: str = "unknown", pattern_key: str = None,
                    signals: dict = None, path: str = "") -> dict:
    """Finales Verdikt aus base + calibration + reputation + Multi-Signal."""
    signals = signals or {}
    score = float(base_score or 0)

    # 1) gelernte Kalibrierung pro Muster
    if pattern_key:
        try:
            score = float(db.calibration_effective_score(pattern_key, int(round(score))))
        except Exception:
            pass

    # 2) Reputation des konkreten Objekts
    rep = reputation_score(db, kind, ident)
    score += rep

    # 3) Multi-Signal-Fusion
    fired = []
    for sig, on in signals.items():
        if on and sig in SIGNAL_WEIGHTS:
            score += SIGNAL_WEIGHTS[sig]
            fired.append(sig)

    score = max(0.0, min(100.0, score))
    trusted = is_trusted_path(path)

    if score >= BLOCK_THRESHOLD and not trusted:
        verdict = "block"
    elif score >= WARN_THRESHOLD:
        verdict = "warn"
    elif base_verdict in ("block", "warn"):
        verdict = "warn" if trusted else base_verdict
    else:
        verdict = "clean"

    return {"score": int(round(score)), "verdict": verdict,
            "reputation": round(rep, 1), "signals": fired,
            "block": verdict == "block" and not trusted,
            "trusted": trusted}


def learn_from_decision(db, kind: str, ident: str, decision: str,
                        pattern_key: str = None, category: str = "GENERIC",
                        base_score: int = 50) -> None:
    """Feedback aus einer Entscheidung -> Reputation + Kalibrierung anpassen.
    decision: 'denied'/'quarantined'/'malicious'/'blocked' = boese ;
              'approved'/'benign'/'clean' = gut."""
    bad = decision in ("denied", "quarantined", "malicious", "blocked")
    try:
        if bad:
            db.reputation_update(kind, ident, malicious=True, weight=1.0)
        else:
            db.reputation_pardon(kind, ident)   # User sagt gut -> boese Historie weg
    except Exception:
        pass
    if pattern_key:
        try:
            db.calibration_record_decision(
                pattern_key, category, int(base_score),
                "denied" if bad else "approved")
        except Exception:
            pass


def record_sighting(db, kind: str, ident: str, verdict: str) -> None:
    """Schwaches Signal aus automatischen Verdikten (geringeres Gewicht)."""
    if verdict in ("block", "malicious"):
        try: db.reputation_update(kind, ident, malicious=True, weight=0.4)
        except Exception: pass
    elif verdict in ("clean", "allow"):
        try: db.reputation_update(kind, ident, malicious=False, weight=0.2)
        except Exception: pass


def check_reinfection(db, kind: str, ident: str) -> int:
    """Wie oft wurde dieses Objekt schon als boese gewertet?

    >= REINFECT_THRESHOLD bedeutet: es kehrt trotz Block/Quarantaene immer
    wieder zurueck -> Persistenz-Malware, die sich neu aufsetzt. Der Aufrufer
    sollte dann haerter reagieren + CRITICAL alarmieren.
    """
    try:
        row = db.reputation_get(kind, ident)
        if row:
            return int(round(row["mal_hits"]))
    except Exception:  # noqa: BLE001
        pass
    return 0
