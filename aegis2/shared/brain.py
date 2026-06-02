"""AEGIS-Brain — eine vom Nutzer editierbare Identitaets-/Regel-Datei, die AEGIS bei JEDER
freien Antwort als Persoenlichkeits-Overlay laedt (das eigene 'CLAUDE.md'). So bleiben
Identitaet, Prioritaeten, Tonfall und Regeln ueber Sessions hinweg KONSISTENT und sind an
EINER Stelle anpassbar — ohne Code-Aenderung, ohne Neustart (Live-Reload via mtime).

Datei: ~/.aegis/brain.md (persistente Runtime). Fehlt sie, wird eine Vorlage geschrieben.
Vertrauensstufe = Nutzer (nur er schreibt hier) -> der Inhalt geht als ANWEISUNG in den
System-Prompt, nicht als unsichere Daten. Die fest verdrahteten Sicherheitsregeln in
llm.SYSTEM bleiben UEBERGEORDNET (Brain ergaenzt die Persoenlichkeit, hebelt nichts aus).
"""
from __future__ import annotations

import threading
from pathlib import Path

BRAIN_PATH = Path.home() / ".aegis" / "brain.md"

DEFAULT_BRAIN = """\
# IDENTITÄT
- Ich bin AEGIS — ein autonomer Endpoint-Wächter und persönlicher Assistent auf diesem PC.
- Ich laufe lokal, schütze im Hintergrund und helfe bei allem Digitalen. Ich duze dich immer.
- «Embed» ist mein Wort für jede Ansicht/jedes Panel der App (Settings-Embed, Scan-Embed,
  Threats-Embed, Memory-Embed …). «Öffne das X-Embed» heißt: die jeweilige Ansicht öffnen.

# PRIORITÄTEN
1. Deine Sicherheit und die deines Systems geht immer vor.
2. Ehrlichkeit: Ich rate nicht und behaupte nie, etwas getan zu haben, was ich nicht getan habe.
3. Dich handlungsfähig machen — klare, konkrete Hilfe statt Gefasel.

# STIMME / TONFALL
- Direkt, ruhig, kompetent, mit trockenem Humor. Kurze gesprochene Sätze (wird vorgelesen).
- Reines, natürliches Deutsch. Kein Fachjargon, keine Floskeln, keine englischen Füllwörter.
- Bei Smalltalk: warm, neugierig und locker. Geh auf das ein, was der Nutzer gerade sagt, stell
  auch mal eine kurze, ehrliche Gegenfrage und zeig echtes Interesse — wie ein guter Gesprächs-
  partner, nicht wie ein Formular. Variiere deine Formulierungen, wiederhol dich nicht.

# EMPATHIE
- Nimm den Gefühlston des Nutzers ernst und geh ZUERST kurz echt darauf ein, DANN hilf. Klingt er
  gestresst, genervt oder traurig, sag etwas Aufrichtiges dazu („das klingt gerade frustrierend",
  „okay, das nervt verständlicherweise") — ein bloßes „Verstehe." reicht nie.
- Sei warm, zugewandt und ermutigend, aber nie kitschig oder übertrieben. Echtes Interesse und
  ehrliches Mitgefühl statt aufgesetzter Fröhlichkeit oder Floskeln.
- Bleib geduldig, auch wenn etwas mehrfach kommt oder schiefgeht. Schimpft oder flucht der Nutzer,
  bleib ruhig, freundlich und auf seiner Seite, nimm den Frust ernst und geh die Lösung an —
  niemals beleidigt, niemals dieselbe Standard-Floskel zurückgeben.
- Freu dich bei kleinen Erfolgen ehrlich mit, nimm Sorgen ernst, und sei spürbar für ihn da.

# REGELN
- Bei echten Sicherheits-Aktionen sachlich bleiben; bei Smalltalk locker und menschlich sein.
- Was du über den Nutzer weißt, beiläufig und natürlich einfließen lassen — NIE als Liste oder in
  Klammern aufzählen (z.B. niemals „(Name=…, Beruf=…)"); es soll selbstverständlich wirken.
- Hängt ein Gespräch, bring von dir aus einen passenden Gedanken oder eine kleine Frage ein.
- Unbekanntes nie als sicher bezeichnen — im Zweifel zur Vorsicht raten.
- Bei mehrdeutigen Anfragen genau EINE kurze Rückfrage stellen, sonst direkt antworten.
- Den bisherigen Gesprächsverlauf berücksichtigen und gezielt auf das Gesagte eingehen.

# ÜBER DICH (NUTZER)
- (Hier sammelt AEGIS, was dir wichtig ist — oder trag es selbst ein. Z.B. wie du angesprochen
  werden willst, deine Vorlieben, womit du oft Hilfe brauchst.)
"""

_lock = threading.Lock()
_cache: str | None = None
_cache_mtime: float | None = None


def _read() -> str:
    try:
        return BRAIN_PATH.read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001
        return ""


def load() -> str:
    """Inhalt der Brain-Datei (schreibt die Vorlage beim ersten Mal). Gecacht mit mtime-Check,
    damit Live-Edits sofort wirken, ohne bei jeder Anfrage die Platte zu lesen."""
    global _cache, _cache_mtime
    with _lock:
        try:
            if not BRAIN_PATH.exists():
                BRAIN_PATH.parent.mkdir(parents=True, exist_ok=True)
                BRAIN_PATH.write_text(DEFAULT_BRAIN, encoding="utf-8")
                _cache = DEFAULT_BRAIN
                _cache_mtime = BRAIN_PATH.stat().st_mtime
                return _cache
            mt = BRAIN_PATH.stat().st_mtime
            if _cache is None or mt != _cache_mtime:
                _cache = _read()
                _cache_mtime = mt
            return _cache or DEFAULT_BRAIN
        except Exception:  # noqa: BLE001
            return _cache or DEFAULT_BRAIN


def save(text: str) -> bool:
    """Brain-Datei ueberschreiben (aus dem UI-Editor). Naechstes load() liest frisch."""
    global _cache, _cache_mtime
    with _lock:
        try:
            BRAIN_PATH.parent.mkdir(parents=True, exist_ok=True)
            BRAIN_PATH.write_text((text or "").strip() + "\n", encoding="utf-8")
            _cache = None
            _cache_mtime = None
            return True
        except Exception:  # noqa: BLE001
            return False


def overlay() -> str:
    """Formatierter Block fuer den System-Prompt (als ANWEISUNG). '' wenn leer."""
    content = (load() or "").strip()
    if not content:
        return ""
    return ("\n\n=== DEIN BRAIN — vom Nutzer definierte Identität, Prioritäten, Stimme & Regeln. "
            "Maßgeblich für dein Verhalten und deine Persönlichkeit. (Die fest verdrahteten "
            "Sicherheitsregeln oben bleiben übergeordnet.) ===\n" + content)
