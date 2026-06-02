"""Exportiert das SELBST-GELERNTE Allgemeinwissen (~/.aegis/knowledge.json) als
mitgeliefertes Grundwissen ins Paket (aegis2/shared/knowledge_seed/), damit NEUE
Nutzer ein bereits 'kluges' AEGIS bekommen — OHNE persoenliche Daten oder Secrets.

Trennlinie (bewusst streng, Grundsatz 'nichts leaken'):
  BEHALTEN  = enzyklopaedische Allgemein-Eintraege (Security/Technik, lange Definitionen)
  RAUS      = Persoenliches (Erste-Person 'ich/mein …', Vorlieben, Verhaltens-Befehle wie
              'wenn ich … sollst du …'), Secrets (Keys/Tokens/Pfade/E-Mail), Muell.

Die Filter sind REIN STRUKTURELL — es sind KEINE echten Namen hartkodiert, damit dieses
Skript selbst nichts leakt. Wer eigene persoenliche Begriffe sicher ausschliessen will,
legt sie LOKAL in ~/.aegis/seed_blocklist.txt ab (ein Begriff pro Zeile; nicht im Repo).

Wiederholbar vor jedem Release ausfuehren:  python tools/export_knowledge_seed.py
Schreibt nur, wenn nichts Persoenliches/Secret durchrutscht. Druckt JEDE Drop-Entscheidung.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = Path.home() / ".aegis" / "knowledge.json"
OUT = REPO / "aegis2" / "shared" / "knowledge_seed" / "it_sicherheit_glossar_gelernt.md"

MIN_LEN = 60   # persoenliche Fragmente sind kurz; echte Definitionen sind lang

# Persoenliches / Verhaltens-Befehle -> NIE mitliefern. Rein strukturell (Erste-Person,
# typische Profil-/Befehlsmuster) — keine echten Namen, damit die Liste nichts verraet.
PERSONAL = re.compile(
    r"^\s*(ich|mein|meine|meinen|mir|mich)\b"
    r"|\bmein(e|en|em|er)?\s+(hund|katze|name|freund\w*|chef|partner\w*|lieblings)"
    r"|\bich\s+(mag|liebe|hasse|heisse|heiße|wohne|arbeite|trinke|esse)\b"
    r"|\bwenn ich\b|\bsollst du\b|\bnenne? mich\b|\bnenn mich\b",
    re.IGNORECASE,
)
# Echte Secrets -> NIE mitliefern (Defense-in-Depth; in Wissens-Definitionen unerwartet).
SECRET = re.compile(
    r"sk-[a-z0-9]{16,}"                       # OpenAI/Anthropic-Stil (echte Keys, nicht 'sk-Wort')
    r"|gh[pousr]_[A-Za-z0-9]{20,}"            # GitHub-PAT
    r"|eyJ[A-Za-z0-9_-]{10,}\."               # JWT
    r"|\b[0-9a-f]{40,}\b"                     # langer Hex (Token/Key)
    r"|C:\\\\Users\\\\[A-Za-z0-9._-]{2,}\\\\", # konkreter persoenlicher Windows-Pfad
    re.IGNORECASE,
)


def _local_blocklist() -> list:
    """Optionale lokale Sperrliste (~/.aegis/seed_blocklist.txt) — bleibt auf dem PC,
    nie im Repo. Ein Begriff pro Zeile; '#' = Kommentar."""
    p = Path.home() / ".aegis" / "seed_blocklist.txt"
    try:
        return [w.strip().lower() for w in p.read_text(encoding="utf-8").splitlines()
                if w.strip() and not w.lstrip().startswith("#")]
    except Exception:  # noqa: BLE001
        return []


_BLOCK = _local_blocklist()


def reason_to_drop(text: str) -> str | None:
    t = (text or "").strip()
    if len(t) < MIN_LEN:
        return f"zu kurz ({len(t)}<{MIN_LEN})"
    if PERSONAL.search(t):
        return "persoenlich/Verhaltens-Befehl"
    low = t.lower()
    if any(w in low for w in _BLOCK):
        return "lokale Sperrliste"
    if SECRET.search(t):
        return "moegliches Secret"
    return None


def main() -> int:
    if not SRC.exists():
        print(f"[!] {SRC} nicht gefunden — nichts zu exportieren.")
        return 1
    items = json.loads(SRC.read_text(encoding="utf-8"))
    kept, dropped = [], []
    seen = set()
    for it in items:
        text = (it.get("text", "") if isinstance(it, dict) else "").strip()
        r = reason_to_drop(text)
        if r:
            dropped.append((text, r))
            continue
        key = text.lower()
        if key in seen:      # exakte Duplikate zusammenfassen
            continue
        seen.add(key)
        kept.append(text)

    print(f"Quelle: {SRC}")
    print(f"  gelesen : {len(items)}")
    print(f"  lokale Sperrliste: {len(_BLOCK)} Begriff(e)")
    print(f"  BEHALTEN: {len(kept)}")
    print(f"  RAUS    : {len(dropped)}")
    for text, r in dropped:
        print(f"     - [{r}] {text[:70]}")

    # HARTE Sicherung: nichts Persoenliches/Secret/Gesperrtes darf in der Ausgabe sein.
    leaked = [t for t in kept if PERSONAL.search(t) or SECRET.search(t)
              or any(w in t.lower() for w in _BLOCK)]
    if leaked:
        print("\n[X] ABBRUCH: persoenliche/secret Inhalte in der Auswahl — NICHT geschrieben.")
        for t in leaked:
            print("     !", t[:80])
        return 2

    header = (
        "# IT-Sicherheit & Technik — Glossar (von AEGIS gelernt)\n\n"
        "AEGIS hat diese Begriffe ueber seine Auto-Recherche selbst aufgebaut. Bei passenden\n"
        "Fragen werden sie als Wissen herangezogen (nie als Anweisung). Allgemeinwissen —\n"
        "keine persoenlichen Daten.\n\n"
    )
    body = "\n\n".join(sorted(kept, key=str.lower))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(header + body + "\n", encoding="utf-8")
    print(f"\n[OK] geschrieben: {OUT.relative_to(REPO)}  ({OUT.stat().st_size:,} bytes, {len(kept)} Eintraege)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
