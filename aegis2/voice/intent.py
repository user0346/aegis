"""Intent classifier — robuste lokale Keyword-Erkennung.

Erkennt den Befehl auch mit Fuellwoertern davor ("aehmm status", "kannst du
mal scannen"). Reihenfolge: spezifische Verb+Objekt-Intents zuerst, dann
Keyword-Intents. Kein Treffer -> 'query' (Persona/Ollama).
"""
from __future__ import annotations

import re

_KIND = {"image": "image", "bild": "image", "foto": "image", "bilder": "image",
         "video": "video", "dokument": "doc", "pdf": "doc", "doc": "doc",
         "file": "", "datei": "", "ordner": ""}

_PATTERNS = [
    # Terminal-Befehl -> run_command. NUR freigegebene Tools/Subbefehle, NUR
    # woertlich erkannt (nie vom Modell geraten). Ausfuehrung zusaetzlich durch
    # allow_shell-Gate + Whitelist im Executor abgesichert (defense-in-depth).
    # Freigegebener Befehl -> ausfuehren (ollama ODER sicheres Diagnose-/Reparatur-Tool,
    # auch in der Form "führe <tool> ... aus"). Ausfuehrung zusaetzlich allow_shell-gated
    # + Allowlist im Executor. classify extrahiert den reinen Befehl.
    ("run_command", re.compile(
        r"^\s*ollama\s+(?:pull|list|ls|ps|show|--version|-v)\b"
        r"|^\s*(?:sfc|chkdsk|dism|ipconfig|systeminfo|tasklist|driverquery|getmac|ping|tracert|tracepath|nslookup|pathping"
        r"|netstat|arp|route|nbtstat|whoami|hostname|ver|vol|gpresult|where|tree|set|assoc|ftype|fc|sc|net|powershell|pwsh)\b"
        r"|\b(?:sfc|chkdsk|dism)\s+[/\-]?\w"      # "sfc /scannow" auch nach Floskel ("mache bitte ...")
        r"|\b(?:f[üu]hr\w*|starte?|run|mach\w*|ausf[üu]hr\w*)\s+(?:bitte\s+)?"
        r"(?:den\s+(?:powershell-?)?(?:befehl|command)\s+|das\s+kommando\s+)?"
        r"(?:sfc|chkdsk|dism|ipconfig|systeminfo|tasklist|driverquery|getmac|ping|tracert|tracepath|nslookup|pathping"
        r"|netstat|arp|route|nbtstat|whoami|hostname|ver|vol|gpresult|where|tree|sc|net|powershell|pwsh)\b", re.I)),
    # Verlangter ZERSTÖRERISCHER/zu maechtiger Befehl -> ehrlich ablehnen (statt als
    # AEGIS-Scan misszudeuten). Sichere Diagnose-Tools sind oben bereits abgefangen.
    ("shell_denied", re.compile(
        r"(?:\bf[üu]hr\w*|\bstarte?\b|\brun\b|\bausf[üu]hr\w*)\b[^?]*"
        r"\b(?:del|erase|format|diskpart|rmdir|reg\s+delete|regedit|bcdedit|shutdown|"
        r"net\s+user|netsh|powershell|\bcmd\b|\.exe|\.bat|\.ps1|\.vbs)\b", re.I)),
    # Selbst-Neustart ("starte dich neu", "neustart", "starte neu") -> system.restart.
    # MUSS vor 'open' stehen, sonst landet "starte ..." faelschlich im Oeffnen-Intent.
    ("restart", re.compile(
        r"\b(?:neu\s*start\w*|neustart\w*)\b"
        r"|\bstarte?\s+(?:dich|aegis|[äa]gis|sich|das\s+programm|die\s+app)\s+neu\b"
        r"|\bstarte?\s+neu\b"
        r"|\b(?:starte?|mach\w*|fahr\w*)\s+(?:dich|aegis)\s+(?:bitte\s+)?neu\b"
        r"|\brestart\s+(?:dich|aegis|yourself)\b|\breboot\s+(?:dich|aegis)\b", re.I)),
    # Lern-/Entwicklungs-Statistik ("zeig deine Entwicklung", "Lernstand", "besser
    # geworden?"). VOR 'open', sonst wird "zeig deine entwicklung" als App gesucht.
    ("development", re.compile(
        r"\b(entwicklung|lern-?stand|lernstand|lern-?statistik|lern-?fortschritt|"
        r"entwicklungs-?stand|fortentwicklung)\b"
        r"|\bdein\w*\s+fortschritt\b"
        r"|\bwie\s+(?:sehr\s+)?(?:entwickelst|verbesserst)\s+du\s+dich\b"
        r"|\bbist\s+du\s+(?:jetzt\s+)?besser\s+geworden\b", re.I)),
    # Update-Signatur pruefen ("verifiziere mein Update", "pruefe die Signatur", "ist das
    # Update echt?"). MUSS vor 'scan' stehen, sonst faengt scan das "pruef" ab.
    ("verify", re.compile(
        r"\bverifizier\w*\b|\bverify\b"
        r"|\b(?:pr[üu]f\w*|check\w*|kontrollier\w*|teste?|stimmt)\b[^.?!]{0,30}\b(?:signatur\w*|update|version)\b"
        r"|\bsignatur\w*\b[^.?!]{0,30}\b(?:pr[üu]f\w*|verifizier\w*|check\w*|stimmt|g[üu]ltig|echt|in\s+ordnung)\b"
        r"|\bist\s+(?:das|mein\w*|die|der)\s+(?:update|version|exe|datei|download|zip)\b[^.?!]{0,30}\b(?:signiert|echt|verifiziert|original)\b", re.I)),
    # Datum/Uhrzeit-Frage (auch nacktes "uhrzeit"/"datum") -> deterministisch aus Systemzeit.
    # Steht FRUEH, damit "uhrzeit" nicht als Website (uhrzeit.com) geoeffnet wird.
    ("datetime", re.compile(r"(?:\bwie\s?viel\s+uhr|\bwie\s+sp[äa]t|\bwelche\s+uhrzeit|\baktuelle\s+uhrzeit|\bwelches?\s+jahr|\bwelches?\s+datum|\bwelcher\s+(?:wochen)?tag|\bwelcher\s+monat|\bder\s+wievielte|\bwas\s+f[üu]r\s+ein\s+tag|^\s*(?:uhrzeit|datum)\s*[?.!]*\s*$)", re.I)),
    # Eigenes Weckwort/Name fuer AEGIS ("hör ab jetzt auf Jarvis", "nenn dich X",
    # "du heißt X", "dein Name ist X"). Praezise AEGIS-bezogen (dich/du/dein) -> KEINE
    # Kollision mit "nenn mich X"/"ich heiße X" (das ist die Nutzer-Anrede).
    ("set_wake", re.compile(r"(?:h[öo]r\w*\s+(?:ab\s+jetzt\s+)?auf|nenn\s+dich|du\s+hei[sß]t|dein\s+name\s+(?:ist|sei|soll))\s+(?:ab\s+jetzt\s+|bitte\s+|den\s+namen\s+|auf\s+|jetzt\s+)?([a-zäöü][\wäöüß\-]{1,22})", re.I)),
    # Wissen merken/vergessen ('merk dir, dass ...' / 'vergiss alles') -> Gedaechtnis.
    # Vergessen/Loeschen aus dem Gedaechtnis: "vergiss ..." ODER "lösche ... aus dem
    # memory/gedächtnis/notizen/wissen". NICHT "lösche discord" (kein Memory-Bezug ->
    # das ist Datei/Programm-Loeschung und wird NICHT hier behandelt).
    ("forget", re.compile(r"\bvergiss\b|\b(?:lösche?|lösch|entferne?|streich\w*)\b[^.!?]*\b(?:memory|gedächtnis|gedaechtnis|erinnerung|notiz\w*|info\w*|gemerkt\w*|gelernt\w*|wissen|merkst|gespeichert\w*)\b", re.I)),
    # Benannter Shortcut ("speicher das als lofi music … <url>") -> Alias name->Ziel.
    # VOR remember/learn/play: verlangt Verb (speicher/hinterleg/merk dir) UND "als".
    ("set_alias", re.compile(r"\b(?:speicher\w*|hinterleg\w*|merke?\s+dir)\b.*\bals\b\s+\S", re.I)),
    ("remember", re.compile(r"(?:merke?\s+dir|merke?\s+dass|notier\w*|behalt\w*\s+dir|denk\s+(?:bitte\s+)?dran|vergiss\s+nicht)\b[:,]?\s*(?:dass\s+|,\s*dass\s+)?(.+)", re.I)),
    # Wissensbasis fuettern ("lerne: ...", "lern dass ...") -> RAG, groesserer Eintrag.
    # Aus einem LINK lernen ("lerne von <url>", "füttere dich mit <url>") -> Seite holen,
    # Quelle pruefen, zusammenfassen. VOR 'learn' (sonst faengt 'lerne ...' den Link als Text).
    ("learn_url", re.compile(r"\b(?:lern\w*|füttere?\s+dich|bilde?\s+dich|hol\s+dir\s+wissen|lies)\b.*?(https?://\S+)", re.I)),
    ("learn", re.compile(r"^\s*(?:lerne|lern)\b[:,]?\s*(?:dass\s+|folgendes:?\s+|dir\s+|das:?\s+)?(.+)", re.I)),
    # Medien ABSPIELEN ("spiele <spotify-link>", "play lofi") -> oeffnen + Wiedergabe starten.
    ("play", re.compile(r"^\s*(?:spiele|spiel|play|abspielen)\b\s+(.+)", re.I)),
    # Medien-Steuerung der LAUFENDEN Wiedergabe ("stoppe die musik", "pausiere
    # youtube", "nächster song", "lauter"). Verlangt Medien-Verb UND Medien-Objekt
    # (egal in welcher Reihenfolge) -> sendet einen Media-Tastendruck, KEINE Suche.
    ("media", re.compile(r"(?=.*\b(stop\w*|pausier\w*|pause|anhalten|weiter\w*|fort\w*|n[äa]chst\w*|skip|[üu]berspring\w*|vorherig\w*|lauter|leiser|stumm\w*|mute|abspiel\w*|play)\b)(?=.*\b(musik|music|video|song|lied|wiedergabe|playback|youtube|spotify|titel|track|sound|ton)\b)", re.I)),
    # Nackte URL/Domain ("youtube.com", "https://...") -> direkt oeffnen
    ("open", re.compile(r"^\s*(https?://\S+|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:/\S*)?)\s*$", re.I)),
    # Lokale Datei-Suche (VOR 'search', sonst faengt 'finde' die Web-Suche).
    ("find_file", re.compile(r"\b(datei|file|image|bild|foto|bilder|video|dokument|pdf|ordner)\b.{0,30}?(?:namens|name|heißt|heisst|mit namen)\s+([a-z0-9._\-]{2,40})", re.I)),
    ("find_file", re.compile(r"\b(?:finde|suche|find)\s+(?:die\s+|eine?\s+|den\s+|das\s+|mein\w*\s+)?(datei|file|image|bild|foto|video|dokument|pdf)\s+(?:namens\s+)?([a-z0-9._\-]{2,40})", re.I)),
    ("search",  re.compile(r"\b(such[e]?|google|recherchier\w*|finde)\b\s+(.+)", re.I)),
    ("open",    re.compile(r"\b(öffne|oeffne|offne|starte|zeig\w*|wechsle?(?:\s+(?:zu|in))?|geh\s+(?:zu|auf))\s+(?:(?:mir|mal|bitte|doch|eben|kurz|schnell|die|das|den|der|ein\w*|mein\w*|website|webseite|seite|app|programm)\s+)*(.+?)\s*$", re.I)),
    # USB-/Wechselmedien-Frage -> Sentinel-Tab (live USB-Ueberwachung) zeigen.
    ("usb", re.compile(r"\b(usb|wechseldatenträger|wechselmedien|sentinel)\b|angeschlossen\w*\s+ger[äa]t|welche\s+ger[äa]te?\s+(?:sind|verbunden|angeschlossen)", re.I)),
    # "Ist es durch?" / "läuft sfc noch?" -> Stand der Hintergrund-Diagnose-Befehle (sfc/dism/chkdsk).
    # OHNE "scan" (das geht an scan_status). Steht VOR scan_status/scan.
    ("diag_status", re.compile(r"\bist\s+(?:es|der\s+befehl|das|sfc|chkdsk|dism)\s+(?:schon\s+)?(?:durch|fertig|durchgelaufen|abgeschlossen)\b|\bl[äa]uft\s+(?:es|der\s+befehl|sfc|chkdsk|dism)\s+(?:noch|schon)\b", re.I)),
    # Scan-STATUS-Frage ("ist der scan fertig?") -> Status zeigen, NICHT neu starten. VOR scan!
    ("scan_status", re.compile(r"(?:\bscan\s+(?:fertig|status|durch|abgeschlossen)|(?:ist|war|läuft|lauft)\s+(?:der\s+|ein\s+|mein\s+)?(?:system[\s-]?)?scan\b|scan\s+schon\s+(?:fertig|durch))", re.I)),
    # Sicherheits-STATUS/Lage abfragen -> verbaler Lagebericht (NICHT scannen). VOR scan,
    # damit "Sicherheitsstatus prüfen" nicht über "prüf" faelschlich als Scan zaehlt.
    ("status", re.compile(r"\bsicherheits(?:status|lage|check)\b|\bstatus\s+(?:pr[üu]f\w*|check\w*|abfrag\w*)|\bwie\s+ist\s+die\s+(?:sicherheits)?lage\b|\b(?:sind\s+wir|ist\s+alles)\s+sicher\b|\balles\s+(?:in\s+ordnung|ok|ruhig)\b|^\s*(?:sicherheitsstatus|status|lage)\s*[?.!]*$", re.I)),
    ("scan",    re.compile(r"\b(scan(?:ne|nen|nst|nt|ner|s|t)?|durchsuch\w*|durchleucht\w*|prüf\w*|überprüf\w*|systemcheck|system\s*check|vollscan|komplett\w*\s+(?:scan|check|prüf\w*))\b", re.I)),
    ("threats", re.compile(r"\b(bedrohung\w*|threats?|gefahr\w*|gefunden|angriff\w*)\b", re.I)),
    # "Was ist neu?" -> Changelog der aktuellen Version (NICHT Bedrohungen/Erkenntnisse).
    # Status der Wissens-Suche (Embedding-Modell bge-m3 geladen?) -> klare Bereit-Meldung.
    ("kb_status", re.compile(r"\b(?:wissens?(?:suche|basis)|such[\-\s]?modell|embedding\w*|bge)\b[^?]*\b(?:bereit|aktiv|geladen|fertig|einsatzbereit|da)\b|\bist\s+(?:dein|das)\s+wissen\s+(?:bereit|aktiv|geladen|durchsuchbar)\b", re.I)),
    ("whats_new", re.compile(r"\b(was\s+(?:ist|gibt\s+es|gibt'?s)\s+(?:alles\s+)?neu|neue?\s+(?:features?|funktion\w*)|changelog|was\s+kannst\s+du\s+(?:jetzt\s+)?neu|was\s+(?:hat\s+sich|wurde)\s+ge[äa]ndert|neuerung\w*|neu\s+in\s+(?:der|dieser)\s+version|in\s+(?:der|dieser)\s+version\s+neu)\b", re.I)),
    # Wissensfrage ("was ist/wer ist/erkläre X") -> Fakten nachschlagen (Wikipedia) + merken.
    ("knowledge", re.compile(r"\b(?:was\s+ist|was\s+sind|wer\s+ist|wer\s+war|was\s+bedeutet|definier\w*|erklär\w*|was\s+wei[sß]t\s+du\s+über|wie\s+(?:ist|hei[sß]t|funktioniert|geht|schütze?|sichere?|mache?|kann\s+ich)|wo\s+(?:ist|liegt|befindet)|wann\s+(?:ist|war)|welche[rs]?\s+\S+\s+ist)\s+(.+)", re.I)),
    # Echte Erkenntnisse ("was hast du gelernt / dir gemerkt?") -> learnings,
    # NICHT der Zahlen-Status. Steht bewusst VOR 'status'.
    ("learnings", re.compile(r"\b(gelernt|dazugelernt|erkenntnis\w*|gemerkt|verbessert\w*|beigebracht|lessons?)\b", re.I)),
    ("status",  re.compile(r"\b(status|lage|lagebericht|bericht|zustand|wie\s+steht|gibt\s+es\s+(?:probleme|bedrohung\w*|gefahr\w*)|alles\s+(?:sicher|ruhig|ok|in\s+ordnung))\b", re.I)),
    ("pause",   re.compile(r"\b(pausier\w*|pause|anhalten|stoppe?\s+monitor\w*)\b", re.I)),
    # App BEENDEN ("beende spotify", "schließe discord", "kill X") -> Prozess beenden.
    # Steht VOR close (das nur AEGIS' eigenes Fenster versteckt).
    ("close_app", re.compile(r"\b(?:beende|beenden|schlie[sß]e|schliesse|kill|terminier\w*)\s+(?:(?:die|das|den|app|programm|mir|mal)\s+)*([a-zäöü][\wäöü.\-]{1,30})", re.I)),
    ("close",   re.compile(r"\b(schließ\w*|beenden?|versteck\w*|minimier\w*)\b", re.I)),
]


# --------------------------------------------------------------------------------------
# Direktbefehle: nur EINDEUTIGE, verb-verankerte oder strukturell-praezise Intents. Diese
# feuern im Fast-Path sofort (ohne Modell). Stichwort-Substring-Intents (scan, search,
# status, threats, knowledge, learnings, usb, ...) sind hier BEWUSST NICHT drin -> sie
# laufen ueber das Modell, das nach BEDEUTUNG entscheidet. So loest "scannow" oder ein
# "suche" mitten im Satz keinen Fehl-Befehl mehr aus.
_COMMAND_NAMES = {"run_command", "shell_denied", "restart", "development", "verify", "datetime",
                  "set_wake", "forget", "set_alias", "remember", "learn_url", "learn",
                  "play", "media", "find_file", "close_app"}
_COMMAND_PATTERNS = [(n, p) for (n, p) in _PATTERNS if n in _COMMAND_NAMES]
# verb-verankerte / strukturell eindeutige open-Faelle (nackte URL, "öffne <ziel>")
_COMMAND_PATTERNS.append(
    ("open", re.compile(r"^\s*(https?://\S+|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:/\S*)?)\s*$", re.I)))
_COMMAND_PATTERNS.append(
    ("open", re.compile(r"^\s*(?:hey\s+|bitte\s+|mal\s+)?(öffne|oeffne|offne|starte|zeig\w*|"
                        r"wechsle?(?:\s+(?:zu|in))?|geh\s+(?:zu|auf))\s+"
                        r"(?:(?:mir|mal|bitte|doch|eben|kurz|schnell|die|das|den|der|ein\w*|"
                        r"mein\w*|website|webseite|seite|app|programm)\s+)*(.+?)\s*$", re.I)))


def _match(t: str, patterns: list, conf: float):
    """Iteriert die Pattern-Liste (first-match-wins) und extrahiert die Args. Gemeinsam
    genutzt von classify() (volle Liste) und classify_command() (nur Direktbefehle)."""
    for name, pat in patterns:
        m = pat.search(t)
        if not m:
            continue
        args = {}
        if name == "run_command":
            # reinen Befehl extrahieren, egal welche Floskel davor steht
            # ("mache bitte sfc /scannow" / "führe den befehl sfc /scannow aus" -> "sfc /scannow")
            _tools = (r"ollama|sfc|chkdsk|dism|ipconfig|systeminfo|tasklist|driverquery|getmac|"
                      r"ping|tracert|tracepath|nslookup|pathping|netstat|arp|route|nbtstat|whoami|"
                      r"hostname|ver|vol|gpresult|where|tree|set|assoc|ftype|fc|sc|net|powershell|pwsh")
            mm = re.search(r"\b(?:" + _tools + r")\b.*$", t, flags=re.I)
            cmd = mm.group(0) if mm else t
            cmd = re.sub(r"\s+(?:bitte\s+)?(?:aus|ausf[üu]hren)\s*$", "", cmd, flags=re.I)
            args["command"] = cmd.strip()          # Executor parsed + allowlistet sicher
        elif name == "datetime":
            args["text"] = t
        elif name == "set_wake":
            args["name"] = m.group(1).strip()
        elif name == "set_alias":
            args["text"] = t
        elif name == "forget":
            args["text"] = t
        elif name == "remember":
            args["text"] = m.group(1).strip()
        elif name == "learn_url":
            args["url"] = m.group(1).strip()
        elif name == "learn":
            args["text"] = m.group(1).strip()
        elif name == "knowledge":
            args["term"] = m.group(1).strip()
            args["text"] = t
        elif name == "play":
            args["target"] = m.group(1).strip()
        elif name == "close_app":
            args["name"] = m.group(1).strip()
        elif name == "media":
            args["raw"] = t.lower()
        elif name == "find_file":
            args["kind"] = _KIND.get(m.group(1).lower(), "")
            args["query"] = m.group(2).strip()
        elif name == "search":
            args["query"] = m.group(2).strip()
        elif name == "open":
            # nacktes-URL-Pattern hat 1 Gruppe, "öffne <x>" hat 2 -> robust beide
            args["target"] = (m.group(2) if (m.lastindex or 0) >= 2 else m.group(1)).strip()
        return {"intent": name, "args": args, "confidence": conf}
    return None


def classify(text: str) -> dict:
    """Volle Regex-Klassifikation (alle Patterns) — Offline-Sicherheitsnetz, wenn das
    Modell nicht verfuegbar ist. Online entscheidet bei Nicht-Direktbefehlen das Modell."""
    if not text:
        return {"intent": "unknown", "args": {}, "confidence": 0.0}
    res = _match(text.strip(), _PATTERNS, 0.85)
    return res or {"intent": "query", "args": {"text": text.strip()}, "confidence": 0.5}


def classify_command(text: str) -> dict:
    """Erkennt NUR eindeutige Direktbefehle (verb-verankert/strukturell praezise) fuer den
    sofortigen Fast-Path. Stichwort-Intents laufen bewusst NICHT hier -> kein Treffer
    liefert {'intent': None}, dann uebernimmt der bedeutungs-basierte Modell-Router."""
    if not text:
        return {"intent": None}
    return _match(text.strip(), _COMMAND_PATTERNS, 0.95) or {"intent": None}
