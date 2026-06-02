"""Selbst-Korrektur — schnelle, deterministische Sicherungen ueber AEGIS' eigene
Antworten und fehlgeschlagene Aktionen. KEIN zusaetzlicher LLM-Aufruf (latenzfrei,
damit der Sprach-Loop schnell bleibt).

Zwei Teile (beide vom Nutzer gewuenscht):

1) Antwort-Selbstpruefung — In einem FREIEN Gespraech (Persona/LLM, intent='query')
   darf AEGIS NIEMALS behaupten, eine echte Sicherheits-/System-Aktion ausgefuehrt zu
   haben (Scan, Quarantaene, Blockieren, Loeschen, Datei pruefen ...). Das kleine Modell
   verletzt diese Anweisung gelegentlich. Bei einem Sicherheits-Tool waere so eine falsche
   Beruhigung gefaehrlich -> hier deterministisch abfangen und ehrlich ersetzen. Die ECHTEN
   Aktions-Handler (_do_scan etc.) laufen NICHT ueber diesen Pfad, sagen also weiter korrekt
   "ich starte einen Scan".

2) Aktions-Wiederholung — Schlaegt eine Aktion fehl und der Handler liefert keinen
   konkreten naechsten Schritt, haengen wir eine ehrliche Empfehlung an, statt den Nutzer
   in einer Sackgasse stehen zu lassen.
"""
from __future__ import annotations

import re

# --- 1) Falsche Aktions-Behauptung erkennen -------------------------------------------
# BEWUSST ENG: nur die GEFAEHRLICHE Behauptung "ich habe (gerade) einen SCAN / eine
# QUARANTAENE durchgefuehrt" bzw. "der Scan laeuft jetzt". NICHT allgemeine Faehigkeits-/
# Versions-Beschreibungen ("ich blocke/ueberwache/analysiere/sichere", "die Erkennung wurde
# verbessert", "der Prozess-Scanner wurde eingestellt") — die sind legitim und duerfen die
# Klarstellung NICHT ausloesen (sonst landet sie mitten in einer normalen Antwort).
_DONE = (r"(?:durchgef[üu]hrt|gestartet|abgeschlossen|gemacht|ausgef[üu]hrt|erledigt|"
         r"fertig|laufen\s+lassen|beendet|absolviert)")
# "ich habe (gerade einen) (System-)Scan ... durchgefuehrt/gestartet/abgeschlossen ..."
_CLAIM = re.compile(
    r"\bich\s+(?:habe|hab)\b[^.!?]*\b(?:einen?\s+|den\s+|das\s+|deinen?\s+|mein\s+|gerade\s+|"
    r"eben\s+|soeben\s+|jetzt\s+|gerade\s+eben\s+)*(?:system[\s-]?|voll[\s-]?|tiefen[\s-]?|"
    r"viren[\s-]?)?scans?\b[^.!?]*\b" + _DONE + r"\b", re.I)
# Verben, die schon ALLEIN eine ausgefuehrte Scan-/Quarantaene-Aktion behaupten.
_CLAIM_STRONG = re.compile(
    r"\bich\s+(?:habe|hab)\b[^.!?]*\b(?:gescannt|quarantiert|isoliert|"
    r"in\s+(?:die\s+)?quarant[äa]ne\s+(?:verschoben|gesteckt|gelegt)|"
    r"unter\s+quarant[äa]ne\s+gestellt)\b", re.I)
# Unpersoenlich: "der Scan laeuft jetzt / ist durch / wird gerade ausgefuehrt".
_RUNNING = re.compile(
    r"\b(?:der\s+|ein\s+|dein\s+|mein\s+)?(?:system[\s-]?)?scan\b[^.!?]*"
    r"\b(?:l[äa]uft\s+(?:jetzt|gerade|nun|bereits)|"
    r"ist\s+(?:jetzt\s+|gerade\s+)?(?:gestartet|durch|fertig|abgeschlossen)|"
    r"wird\s+(?:jetzt|gerade)\s+(?:ausgef[üu]hrt|durchgef[üu]hrt))\b", re.I)

_HONEST = ("Zur Klarstellung: ich plaudere hier nur — eine echte Aktion habe ich NICHT "
           "ausgeführt. Sag «Scan» für einen echten System-Scan oder «Status» für die Lage.")


def claims_false_action(text: str) -> bool:
    """True, wenn der Text faelschlich eine ausgefuehrte/laufende AEGIS-Sicherheitsaktion
    behauptet (nur fuer den freien Gespraechs-Pfad gedacht)."""
    if not text:
        return False
    return bool(_CLAIM.search(text) or _CLAIM_STRONG.search(text) or _RUNNING.search(text))


def honest_note() -> str:
    return _HONEST


def strip_leaked_context(text):
    """Reste aus dem System-Kontext entfernen, die das kleine LLM faelschlich in die ANTWORT
    uebernimmt: den pro-Anfrage-Daten-Sentinel ([DATA-xxxx]) und vor allem nachgestellte
    Fakten-Dumps im 'Schluessel=Wert, …'-Format — z.B. '(Name=Max, Beruf=Lehrer,
    mag=grün)'. So listet kein normaler deutscher Satz Daten auf -> sicher zu strippen.
    (Genau das hatte der Nutzer gesehen und 'lösche das da raus' verlangt.)"""
    if not text:
        return text
    t = re.sub(r"\[?/?DATA-[0-9a-fA-F]{4,}\]?", "", text)               # geleakter Sentinel
    t = re.sub(r"===\s*KONTEXT-DATEN.*?(?:===|$)", "", t, flags=re.S | re.I)
    # nachgestellter Fakten-Dump (>=2 key=value-Paare), in Klammern ODER nackt, am Satzende:
    t = re.sub(r"\s*\(\s*(?:[\wÄÖÜäöüß][\wÄÖÜäöüß\-]*=\s*[^,()=;]+[,;]?\s*){2,}\)\s*$", "", t)
    t = re.sub(r"[\s.,;:–—-]*(?:[\wÄÖÜäöüß][\wÄÖÜäöüß\-]*=\s*[^,()=;]+"
               r"(?:\s*[,;]\s*|\s*$)){2,}$", "", t)
    return t.strip()


def sanitize_answer(text):
    """Volltext-Antwort (nicht gestreamt): erst geleakte System-Kontext-Reste entfernen, dann —
    falls sie faelschlich eine Aktion behauptet — durch die ehrliche Klarstellung ersetzen.
    Sonst unveraendert. None bleibt None."""
    if not text:
        return text
    text = strip_leaked_context(text)
    if claims_false_action(text):
        return _HONEST
    return text


# --- 2) Aktions-Wiederholung / ehrlicher naechster Schritt -----------------------------
# Nur ergaenzen, wenn der Handler KEINEN konkreten Vorschlag (« … ») hinterlassen hat.
_NEXT_STEP = {
    "open": "Sag «suche <Name>», dann finde ich es im Web.",
    "search": "Formulier den Suchbegriff etwas konkreter, dann versuche ich es erneut.",
    "play": "Gib mir einen Spotify-/YouTube-Link oder einen klaren Suchbegriff.",
    "find_file": "Nenn mir den genauen Datei-/Ordnernamen, dann suche ich gezielt.",
    "scan": "Versuch es gleich nochmal mit «Scan», oder öffne den Scan-Bereich.",
    "learn_url": "Gib mir einen direkten Text-/Doku-Link oder sag «lerne: …» mit dem Kern.",
    "close_app": "Nenn den genauen Programmnamen, dann beende ich es.",
    "update": "Versuch es gleich nochmal mit «Update», sobald wieder Internet da ist.",
}


def recover_action(intent: str, args: dict, result):
    """Bei fehlgeschlagener Aktion (ok=False) eine ehrliche Naechster-Schritt-Empfehlung
    anhaengen — aber nur, wenn der Handler nicht ohnehin schon einen Vorschlag gemacht hat."""
    if not isinstance(result, dict) or result.get("ok"):
        return result
    msg = (result.get("msg") or "").strip()
    if "«" in msg or "»" in msg:          # Handler hat bereits einen konkreten Vorschlag
        return result
    tip = _NEXT_STEP.get(intent)
    if tip:
        result["msg"] = (msg + (" " if msg else "") + tip).strip()
    return result
