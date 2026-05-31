"""Wissens-Aggregat — was AEGIS bisher gelernt hat.

Zwei Zwecke:
  1. llm_context(db): kompakter Kontext fuer das lokale Ollama-Modell, damit es
     weiss, was AEGIS bereits gelernt/entschieden hat und situationsbewusst hilft
     (statt generisch). -> "das Gelernte an Ollama fuettern".
  2. status_report(db, stats): menschlicher Lagebericht (Voice + UI) — der
     "richtige" Statusbericht ueber Lage UND Wissensstand.

Alles defensiv (try/except): fehlt eine DB-Methode oder ist die DB gerade nicht
lesbar, bleibt das jeweilige Feld leer statt zu crashen.
"""
from __future__ import annotations

from typing import Optional


def _cell(row, key, default=0):
    """Liest eine Spalte aus sqlite3.Row ODER ein Attribut — tolerant."""
    try:
        v = row[key]
        return default if v is None else v
    except Exception:  # noqa: BLE001
        try:
            return getattr(row, key, default)
        except Exception:  # noqa: BLE001
            return default


def _short(s, n: int = 40) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def learned_summary(db) -> dict:
    """Aggregiert den kompletten Lernstand in ein flaches dict."""
    out = {
        "baseline_known": 0, "rep_total": 0, "rep_bad": 0, "rep_good": 0,
        "top_bad": [], "domains_blocked": 0, "domains_by_cat": {},
        "patterns_learned": 0, "quarantine_decided": 0,
    }
    try:
        out["baseline_known"] = int(db.baseline_counts().get("known", 0))
    except Exception:  # noqa: BLE001
        pass
    try:
        rep = list(db.reputation_all() or [])
        out["rep_total"] = len(rep)
        bad = [r for r in rep if float(_cell(r, "mal_hits")) > float(_cell(r, "ben_hits"))]
        out["rep_bad"] = len(bad)
        out["rep_good"] = sum(
            1 for r in rep
            if float(_cell(r, "ben_hits")) > 0
            and float(_cell(r, "ben_hits")) >= float(_cell(r, "mal_hits"))
        )
        bad.sort(key=lambda r: float(_cell(r, "mal_hits")), reverse=True)
        out["top_bad"] = [
            {"kind": str(_cell(r, "kind", "")), "ident": _short(_cell(r, "ident", "")),
             "mal": int(round(float(_cell(r, "mal_hits"))))}
            for r in bad[:5]
        ]
    except Exception:  # noqa: BLE001
        pass
    try:
        dbc = dict(db.domain_count_by_category() or {})
        out["domains_by_cat"] = dbc
        out["domains_blocked"] = sum(int(v) for v in dbc.values())
    except Exception:  # noqa: BLE001
        pass
    try:
        out["patterns_learned"] = len(list(db.calibration_all(limit=9999) or []))
    except Exception:  # noqa: BLE001
        pass
    try:
        decided = 0
        for r in (db.all_quarantine(limit=9999) or []):
            if str(_cell(r, "decision", "")) in ("approved", "denied", "deleted"):
                decided += 1
        out["quarantine_decided"] = decided
    except Exception:  # noqa: BLE001
        pass
    return out


def llm_context(db) -> str:
    """Kompakter Wissens-Kontext fuer Ollama (~1-2 Saetze, als System-Zusatz)."""
    s = learned_summary(db)
    txt = (f"Du hast bisher {s['baseline_known']} Programme als normal eingestuft, "
           f"{s['rep_bad']} Objekte als boesartig und {s['rep_good']} als gutartig, "
           f"{s['domains_blocked']} Domains blockiert und {s['patterns_learned']} "
           f"Erkennungs-Muster verfeinert.")
    if s["top_bad"]:
        tb = ", ".join(f"{b['kind']}:{b['ident']}" for b in s["top_bad"][:3])
        txt += f" Haeufigste Bedrohungen: {tb}."
    # Gelernte Erkenntnisse aus AEGIS_LEARNINGS einbeziehen -> AEGIS "wendet" sie an
    try:
        import re as _re
        from .memory import find_learnings_file
        lf = find_learnings_file()
        if lf.exists():
            titles = _re.findall(r"^###\s*\[[^\]]*\]\s*(.+?)\s+[—-]",
                                 lf.read_text(encoding="utf-8"), _re.M)
            if titles:
                txt += " Bisher gelernte Erkenntnisse: " + \
                       "; ".join(t.strip() for t in titles[-5:]) + "."
    except Exception:  # noqa: BLE001
        pass
    return txt


def learned_insights(db) -> str:
    """Was AEGIS WIRKLICH gelernt/reflektiert hat — echte Erkenntnisse aus
    AEGIS_LEARNINGS, NICHT der Zahlen-Statusbericht. Genau das, was der Nutzer
    bei «was hast du gelernt?» erwartet. Faellt ehrlich auf die Lern-Zahlen
    zurueck, wenn der Reflektor noch keine Erkenntnis ausformuliert hat."""
    insights = []
    try:
        import re as _re
        from .memory import find_learnings_file
        lf = find_learnings_file()
        if lf and lf.exists():
            txt = lf.read_text(encoding="utf-8")
            # Eintraege im Format: "### [section] Titel — Beschreibung"
            for m in _re.finditer(r"^###\s*(?:\[[^\]]*\]\s*)?(.+)$", txt, _re.M):
                title = m.group(1).strip()
                # alles ab dem Gedankenstrich ist Detail -> nur die Kern-Erkenntnis
                title = _re.split(r"\s+[—–-]\s+", title, 1)[0].strip(" —–-")
                if title:
                    insights.append(title)
    except Exception:  # noqa: BLE001
        pass
    if insights:
        recent = insights[-6:]
        body = " ".join(f"{i}. {t}." for i, t in enumerate(recent, 1))
        n = len(insights)
        head = (f"Ich habe {n} konkrete Erkenntnis{'se' if n != 1 else ''} "
                f"reflektiert und wende sie an. Die letzten:")
        return head + " " + body
    # Noch keine ausformulierte Erkenntnis -> ehrlich sagen + harte Lern-Zahlen geben
    s = learned_summary(db)
    if s["baseline_known"] or s["rep_bad"] or s["domains_blocked"]:
        return ("Ich habe noch keine Erkenntnis in Worte gefasst, aber konkret "
                f"gelernt: {s['baseline_known']} Programme als normal eingestuft, "
                f"{s['rep_bad']} Objekte als boesartig erkannt, {s['domains_blocked']} "
                f"Domains blockiert und {s['patterns_learned']} Erkennungs-Muster "
                "verfeinert. Sobald mein Reflektor daraus ein Muster zusammenfasst, "
                "erzaehle ich es dir hier.")
    return ("Ich habe noch nichts Konkretes gelernt — ich beobachte gerade erst "
            "und baue meine Baseline auf. Frag mich in ein paar Stunden nochmal.")


def status_report(db, stats: Optional[dict] = None) -> str:
    """Menschlicher Lagebericht — Lage + Betrieb + Gelerntes. Fuer Voice + UI."""
    stats = stats or {}
    s = learned_summary(db)
    threats = int(stats.get("threats_24h", 0) or 0)
    quar = int(stats.get("quarantine_pending", 0) or 0)
    events = int(stats.get("events_24h", 0) or 0)
    mods_run = int(stats.get("modules_running", 0) or 0)
    mods_tot = int(stats.get("modules_total", 0) or 0)

    lines = []
    if threats == 0 and quar == 0:
        lines.append("Lage ruhig: keine schwerwiegenden Bedrohungen in den letzten "
                     "24 Stunden.")
    elif threats == 0:
        lines.append(f"Keine akuten Bedrohungen. {quar} Datei"
                     f"{'en' if quar != 1 else ''} warten in der Quarantaene auf "
                     f"deine Entscheidung.")
    else:
        lines.append(f"Achtung: {threats} Bedrohung{'en' if threats != 1 else ''} in "
                     f"den letzten 24 Stunden, {quar} in Quarantaene.")
    if mods_tot:
        lines.append(f"{mods_run} von {mods_tot} Waechtern aktiv, {events} Ereignisse "
                     f"beobachtet.")
    lines.append(f"Gelernt: {s['baseline_known']} normale Programme, "
                 f"{s['rep_bad']} boesartige Objekte, {s['domains_blocked']} "
                 f"blockierte Domains, {s['patterns_learned']} verfeinerte Muster.")
    return " ".join(lines)
