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
        r"|netstat|arp|route|nbtstat|whoami|hostname|ver|vol|gpresult|where|tree|set|assoc|ftype|fc|sc|net|query|klist|schtasks|powershell|pwsh)\b"
        r"|\b(?:sfc|chkdsk|dism)\s+[/\-]?\w"      # "sfc /scannow" auch nach Floskel ("mache bitte ...")
        r"|\b(?:f[üu]hr\w*|starte?|run|mach\w*|ausf[üu]hr\w*)\s+(?:bitte\s+)?"
        r"(?:den\s+(?:powershell-?)?(?:befehl|command)\s+|das\s+kommando\s+)?"
        r"(?:sfc|chkdsk|dism|ipconfig|systeminfo|tasklist|driverquery|getmac|ping|tracert|tracepath|nslookup|pathping"
        r"|netstat|arp|route|nbtstat|whoami|hostname|ver|vol|gpresult|where|tree|sc|net|query|klist|schtasks|powershell|pwsh)\b", re.I)),
    # Verlangter ZERSTÖRERISCHER/zu maechtiger Befehl -> ehrlich ablehnen (statt als
    # AEGIS-Scan misszudeuten). Sichere Diagnose-Tools sind oben bereits abgefangen.
    ("shell_denied", re.compile(
        r"(?:\bf[üu]hr\w*|\bstarte?\b|\brun\b|\bausf[üu]hr\w*)\b[^?]*"
        r"\b(?:del|erase|format|diskpart|rmdir|reg\s+delete|regedit|bcdedit|shutdown|"
        r"net\s+user|netsh|powershell|\bcmd\b|\.exe|\.bat|\.ps1|\.vbs)\b", re.I)),
    # SYSTEM-POWER ("starte meinen PC neu", "fahr den Rechner herunter") -> pc_power.
    # MUSS vor 'restart' UND 'open' stehen: sonst landet es als AEGIS-Selbstneustart
    # oder im Oeffnen-Intent ("PC neu" als App). AEGIS startet NICHT wirklich neu —
    # der Handler fragt nur nach Bestaetigung (echte Power-Aktion bleibt beim Nutzer).
    ("pc_power", re.compile(
        r"\b(?:starte?|fahre?|fahr|mach\w*|schalte?)\s+"
        r"(?:(?:mir|meinen|meine|den|das|die|bitte|mal|doch)\s+)*"
        r"(?:pc|rechner|computer|system|laptop|notebook|maschine|kiste)\s+"
        r"(?:(?:bitte|mal|jetzt|wieder|komplett|ganz)\s+)*"
        r"(?:neu(?:\s*start\w*)?|herunter\w*|runter\w*|aus|ab)\b"
        r"|\b(?:fahr\w*|schalte?)\s+(?:(?:mir|meinen|den|das|die|bitte|mal)\s+)*"
        r"(?:pc|rechner|computer|system|laptop|notebook)\s+(?:herunter|runter|aus|ab)\b"
        r"|\b(?:pc|rechner|computer|system)[- ]?(?:neustart|neu\s*start\w*|herunterfahren|runterfahren)\b", re.I)),
    # Selbst-Neustart ("starte dich neu", "neustart", "starte neu") -> system.restart.
    # MUSS vor 'open' stehen, sonst landet "starte ..." faelschlich im Oeffnen-Intent.
    ("restart", re.compile(
        r"\b(?:neu\s*start\w*|neustart\w*)\b"
        r"|\bstarte?\s+(?:dich|aegis|[äa]gis|sich|das\s+programm|die\s+app)\s+neu\b"
        r"|\bstarte?\s+neu\b"
        r"|\b(?:starte?|mach\w*|fahr\w*)\s+(?:dich|aegis)\s+(?:bitte\s+)?neu\b"
        r"|\brestart\s+(?:dich|aegis|yourself)\b|\breboot\s+(?:dich|aegis)\b", re.I)),
    # Sprachausgabe per Befehl steuern ("sei ruhig" -> TTS aus, "sprich wieder" -> an).
    # tts_unmute steht VOR tts_mute, damit "sprich wieder" nicht als "sprich nicht" missgeht.
    ("tts_unmute", re.compile(
        r"\b(?:sprich\s+(?:wieder|weiter|laut|mit\s+mir)|red(?:e)?\s+(?:wieder|weiter)"
        r"|sag\s+(?:wieder\s+)?(?:was|etwas)|sprachausgabe\s+(?:wieder\s+)?an|stimme\s+(?:wieder\s+)?an"
        r"|du\s+darfst\s+wieder\s+(?:reden|sprechen)|nicht\s+mehr\s+stumm)\b", re.I)),
    ("tts_mute", re.compile(
        r"\b(?:sei\s+(?:bitte\s+)?(?:ruhig|still|leise)|schweig\w*|halt\s+(?:den\s+mund|die\s+klappe)"
        r"|sprich\s+nicht(?:\s+mehr)?|red(?:e)?\s+nicht(?:\s+mehr)?|nicht\s+mehr\s+(?:reden|sprechen)"
        r"|kein\w*\s+(?:sprachausgabe|stimme|gerede)(?:\s+mehr)?|sprachausgabe\s+aus|stumm\s+dich)\b", re.I)),
    # Lern-/Entwicklungs-Statistik ("zeig deine Entwicklung", "Lernstand", "besser
    # geworden?"). VOR 'open', sonst wird "zeig deine entwicklung" als App gesucht.
    # NUR der Lern-/Fortschritts-Sinn (Statistik). NICHT "wie lange bist du in Entwicklung"
    # oder "wer ist dein Entwickler" — das ist Identitaet/Herkunft (-> 'identity', steht davor).
    ("development", re.compile(
        r"\b(lern-?stand|lernstand|lern-?statistik|lern-?fortschritt|entwicklungs-?stand|fortentwicklung)\b"
        r"|\b(?:deine?n?|meine?)\s+entwicklung\b"
        r"|\b(?:zeig\w*|zeige?|wie\s+ist|wie\s+l[äa]uft|wie\s+steht\s+es\s+um)\b[^?]{0,25}\bentwicklung\b"
        r"|\bdein\w*\s+fortschritt\b"
        r"|\bwie\s+(?:sehr\s+)?(?:entwickelst|verbesserst)\s+du\s+dich\b"
        r"|\bbist\s+du\s+(?:jetzt\s+)?besser\s+geworden\b", re.I)),
    # Identitaet/Herkunft ("wer hat dich entwickelt", "wer ist dein Entwickler", "wie lange
    # bist du in Entwicklung", "wer/was bist du"). VOR development+knowledge, sonst landet
    # "wer ist dein Entwickler" als Wikipedia-Suche oder Lernstand.
    ("identity", re.compile(
        r"\bwer\s+(?:hat\s+dich\s+(?:entwickelt|programmiert|gemacht|gebaut|erschaffen|geschrieben)"
        r"|ist\s+dein\s+(?:entwickler|macher|sch[öo]pfer|programmierer|erfinder)"
        r"|steckt\s+hinter\s+dir)\b"
        r"|\bvon\s+wem\s+(?:bist|wurdest|stammst)\s+du\b"
        r"|\bwie\s+lange\s+(?:bist\s+du|gibt\s+es\s+dich|existierst\s+du)\b[^?]{0,40}\b(?:entwicklung|entwickelt|her|schon|alt)\b"
        r"|\bseit\s+wann\s+(?:gibt\s+es\s+dich|bist\s+du|existierst\s+du)\b"
        r"|\bwer\s+bist\s+du\b|\bwas\s+bist\s+du\s+(?:eigentlich|genau|f[üu]r)\b", re.I)),
    # Aktuelle Nachrichten / Weltgeschehen (Tagesschau-RSS). VOR knowledge ("was ist X").
    ("news", re.compile(
        r"\b(nachrichten|news|schlagzeilen|tagesschau)\b"
        r"|\bwas\s+(?:ist|gibt'?s|gibt\s+es|passiert|geht|l[äa]uft)\b[^?]{0,30}\b(?:in\s+der\s+welt|auf\s+der\s+welt|gerade\s+so|so\s+ab|heute\s+so)\b"
        r"|\baktuelle?s?\s+(?:nachrichten|news|lage|geschehen|ereignisse|meldungen|weltlage)\b"
        r"|\bweltgeschehen\b|\bwas\s+los\s+(?:ist\s+)?(?:in|auf)\s+der\s+welt\b", re.I)),
    # Update-Signatur pruefen ("verifiziere mein Update", "pruefe die Signatur", "ist das
    # Update echt?"). MUSS vor 'scan' stehen, sonst faengt scan das "pruef" ab.
    ("verify", re.compile(
        r"\bverifizier\w*\b|\bverify\b"
        r"|\b(?:pr[üu]f\w*|check\w*|kontrollier\w*|teste?|stimmt)\b[^.?!]{0,30}\b(?:signatur\w*|update|version)\b"
        r"|\bsignatur\w*\b[^.?!]{0,30}\b(?:pr[üu]f\w*|verifizier\w*|check\w*|stimmt|g[üu]ltig|echt|in\s+ordnung)\b"
        r"|\bist\s+(?:das|mein\w*|die|der)\s+(?:update|version|exe|datei|download|zip)\b[^.?!]{0,30}\b(?:signiert|echt|verifiziert|original)\b", re.I)),
    # "Gibt es ein Update?" / "Update" / "nach Updates suchen" -> ECHTER Versions-
    # Vergleich gegen GitHub + klare Antwort. NACH 'verify' (damit "ist das Update
    # echt/signiert" dort bleibt) und VOR query/search (sonst schwafelt das Modell,
    # statt wirklich zu pruefen).
    ("update", re.compile(
        r"^\s*updat\w*\s*[?.!]*\s*$"                              # nacktes "Update/Updates", auch Tippfehler "Updatre"
        r"|\bgib\w*\b[^.?!]{0,18}\bupdates?\b"                    # "gibt es ein update", auch "gibt esd ein update"
        r"|\bist\s+[^.?!]{0,22}\b(?:update|version)\b[^.?!]{0,18}\b(?:da|verf[üu]gbar|drau[sß]en|online|raus|neuer)\b"
        r"|\b(?:update|neue\s+version)\b[^.?!]{0,12}\b(?:verf[üu]gbar|vorhanden|drau[sß]en)\b"
        r"|\bnach\s+(?:neuen\s+)?updates?\s+(?:such\w*|pr[üu]f\w*|schau\w*|seh\w*|guck\w*|suchen|sehen)\b"
        r"|\b(?:such\w*|schau\w*|guck\w*)\s+(?:mal\s+)?(?:bitte\s+)?nach\s+(?:einem\s+|neuen\s+)?updates?\b"
        r"|\bkann\s+ich\s+(?:das\s+|dich\s+|aegis\s+)?(?:jetzt\s+)?(?:updaten|aktualisier\w*)\b"
        r"|\b(?:aktualisier\w*|update)\s+dich\b"
        r"|\bbin\s+ich\s+(?:noch\s+)?(?:auf\s+dem\s+neuesten\s+stand|aktuell)\b", re.I)),
    # Datum/Uhrzeit-Frage (auch nacktes "uhrzeit"/"datum") -> deterministisch aus Systemzeit.
    # Steht FRUEH, damit "uhrzeit" nicht als Website (uhrzeit.com) geoeffnet wird.
    ("datetime", re.compile(r"(?:\bwie\s?viel\s+uhr|\bwie\s+sp[äa]t|\bwelche\s+uhrzeit|\baktuelle\s+uhrzeit|\bwelches?\s+jahr|\bwelches?\s+datum|\bwelcher\s+(?:wochen)?tag|\bwelcher\s+monat|\bder\s+wievielte|\bwas\s+f[üu]r\s+ein\s+tag|\bwelcher\s+tag\s+ist\b|\bwas\s+ist\s+(?:heute|morgen|[üu]bermorgen|gestern|vorgestern)\b|\b(?:tag|datum)\s+(?:ist|haben\s+wir|von)\s+(?:heute|morgen|[üu]bermorgen|gestern|vorgestern)\b|^\s*(?:[üu]bermorgen|vorgestern|morgen|gestern)\s*[?.!]*\s*$|^\s*(?:uhrzeit|datum)\s*[?.!]*\s*$)", re.I)),
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
    ("media", re.compile(
        r"(?=.*\b(stop\w*|pausier\w*|pause|anhalten|weiter\w*|fort\w*|n[äa]chst\w*|skip|[üu]berspring\w*|vorherig\w*|vorspul\w*|lauter|leiser|stumm\w*|mute|abspiel\w*|play)\b)(?=.*\b(musik|music|video|song|lied|wiedergabe|playback|youtube|spotify|titel|track|sound|ton)\b)"
        r"|\b(?:mach(?:'?s)?\s+(?:es\s+|mal\s+|bitte\s+|die\s+musik\s+|den\s+ton\s+|etwas\s+)*)?(?:lauter|leiser)\b"
        r"|^\s*(?:vorspul\w*|zur[üu]ckspul\w*|n[äa]chstes?\s+(?:lied|song|titel)|vorheriges?\s+(?:lied|song|titel)|n[äa]chster\s+(?:song|titel))\s*[.!]*\s*$", re.I)),
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
    # Explizite "erzähl mir was über X / was kannst du zum Thema X sagen / was weißt du über X"
    # -> Wissens-Lookup. Verb-verankert + eindeutig (steht VOR der breiten Wissensfrage + ist
    # unten im Fast-Path, weil das Modell sowas sonst manchmal faelschlich als 'status' routet).
    ("knowledge", re.compile(
        r"\b(?:was\s+kannst\s+du\s+(?:mir\s+)?(?:dazu\s+|dar[üu]ber\s+)?(?:sagen|erz[äa]hlen|berichten)\s+(?:[üu]ber|zu(?:m\s+thema)?|von)"
        r"|(?:erz[äa]hl\w*|sag\s+mir|berichte\w*)\s+(?:mir\s+)?(?:was\s+|etwas\s+|mehr\s+|kurz\s+)?(?:[üu]ber|zu(?:m\s+thema)?|von)"
        r"|was\s+wei[sß]t\s+du\s+(?:[üu]ber|zu(?:m\s+thema)?))\s+(.+)", re.I)),
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
_COMMAND_NAMES = {"run_command", "shell_denied", "pc_power", "restart", "tts_mute",
                  "tts_unmute", "identity", "news", "development", "verify", "datetime",
                  "set_wake", "forget", "set_alias", "remember", "learn_url", "learn",
                  "play", "media", "find_file", "close_app"}
_COMMAND_PATTERNS = [(n, p) for (n, p) in _PATTERNS if n in _COMMAND_NAMES]
# EINDEUTIGE Scan-Kommandos (ganze Eingabe = Scan-Befehl) deterministisch -> startet IMMER
# einen echten Scan, nie vom Modell faelschlich als 'status'/'open' geroutet (genau der Bug:
# "scan"/"führe ein scan aus" lieferte den Lagebericht statt zu scannen). Steht VOR 'open',
# sonst faengt "starte einen scan" das Oeffnen-Pattern. "ist der scan fertig" bleibt durch die
# ^...$-Anker ausgeschlossen -> das ist scan_status.
_COMMAND_PATTERNS.append(("scan", re.compile(
    r"^\s*(?:hey\s+\w+[\s,]+)?"
    # flexibler Vorlauf: nur Fuell-/Verb-/Artikelwoerter (deutsche Wortstellung) + "scan"
    r"(?:(?:kannst\s+du|k[öo]nntest\s+du|w[üu]rdest\s+du|f[üu]hr\w*|start\w*|mach\w*|beginn\w*|"
    r"lauf\w*|los|bitte|mal|jetzt|doch|mir|einen?|den|das|ein|mein|system|voll|komplett)\s+)*"
    r"(?:system[\s-]?|voll[\s-]?|komplett[\s-]?)?scann?(?:e|en|t|st)?"
    # optionaler Nachlauf: aus/durch/jetzt bzw. machen/starten/ausfuehren ...
    r"(?:\s+(?:aus|durch|jetzt|bitte|mach\w*|start\w*|ausf[üu]hr\w*|durchf[üu]hr\w*|"
    r"mein\s+system|das\s+system|über\s+\S+))*"
    r"\s*[?.!]*\s*$", re.I)))
# verb-verankerte / strukturell eindeutige open-Faelle (nackte URL, "öffne <ziel>")
_COMMAND_PATTERNS.append(
    ("open", re.compile(r"^\s*(https?://\S+|[a-z0-9][a-z0-9\-]*\.[a-z]{2,}(?:/\S*)?)\s*$", re.I)))
_COMMAND_PATTERNS.append(
    ("open", re.compile(r"^\s*(?:hey\s+|bitte\s+|mal\s+)?(öffne|oeffne|offne|starte|zeig\w*|"
                        r"wechsle?(?:\s+(?:zu|in))?|geh\s+(?:zu|auf))\s+"
                        r"(?:(?:mir|mal|bitte|doch|eben|kurz|schnell|die|das|den|der|ein\w*|"
                        r"mein\w*|website|webseite|seite|app|programm)\s+)*(.+?)\s*$", re.I)))
# Explizite "erzähl mir über X"-Wissensfragen deterministisch in den Fast-Path (das Modell routet
# sie sonst manchmal faelschlich auf 'status'/'lage', z.B. "was kannst du mir zum thema spyware sagen").
_COMMAND_PATTERNS.append(
    ("knowledge", re.compile(
        r"\b(?:was\s+kannst\s+du\s+(?:mir\s+)?(?:dazu\s+|dar[üu]ber\s+)?(?:sagen|erz[äa]hlen|berichten)\s+(?:[üu]ber|zu(?:m\s+thema)?|von)"
        r"|(?:erz[äa]hl\w*|sag\s+mir|berichte\w*)\s+(?:mir\s+)?(?:was\s+|etwas\s+|mehr\s+|kurz\s+)?(?:[üu]ber|zu(?:m\s+thema)?|von)"
        r"|was\s+wei[sß]t\s+du\s+(?:[üu]ber|zu(?:m\s+thema)?))\s+(.+)", re.I)))
# Die beiden folgenden Patterns stehen per insert(0,...) VOR allen anderen Direktbefehlen
# (insb. vor 'run_command', das 'systeminfo' als Windows-Tool faengt) — sie sind streng
# ^...$-verankert und matchen nur ihre exakte Form, koennen also nichts kapern.
# "settings"/"app settings"/"(die) einstellungen" -> AEGIS' EIGENE Einstellungen (eigener
# arg-loser Intent, kein 'open'-Ziel-Raten -> oeffnete sonst fuzzy-gematcht NVIDIA). Ein-Token-
# Komposita wie "systemeinstellungen"/"netzwerkeinstellungen" matchen bewusst NICHT.
_COMMAND_PATTERNS.insert(0, ("app_settings", re.compile(
    r"^\s*(?:hey\s+\w+[\s,]+)?(?:[öo]ffne\s+|oeffne\s+|zeig\w*\s+|geh\s+(?:zu|auf)\s+|"
    r"wechsle?\s+(?:zu|in)\s+)?(?:mir\s+|mal\s+|bitte\s+|die\s+|das\s+|den\s+|hier\s+|"
    r"in\s+der\s+)*(?:app[\s-]?|aegis[\s-]?)?(?:settings|einstellungen)"
    r"(?:\s+(?:vom?|im|in\s+der|der\s+app|app|hier|system))*\s*[?.!]*$", re.I)))
# "systeminfo"/"info vom system"/"(noch) mehr infos"/"wie ist die auslastung" -> ECHTE
# Systemwerte (psutil) statt vom LLM erfundener Telemetrie oder Lexikon-Web-Suche nach "Info".
# ^...$-anker: "info über spyware" bleibt eine Wissensfrage (matcht hier NICHT).
_COMMAND_PATTERNS.insert(0, ("sysinfo", re.compile(
    r"^\s*(?:hey\s+\w+[\s,]+)?"
    r"(?:wie(?:\s+\w+){0,3}\s+(?:die|der|das|es|mein\w*|deine?)\s+)?"          # "wie (hoch) ist die …"
    r"(?:gib\s+mir\s+|zeig\w*\s+(?:mir\s+)?|sag\s+mir\s+|hol\w*\s+)?"
    r"(?:noch\s+)?(?:viel\s+)?(?:mehr\s+|weitere?\s+|l[äa]ngere?\s+|ausf[üu]hrlich\w*\s+|"
    r"genauere?\s+)?(?:system[\s-]?)?(?:infos?|information(?:en)?|auslastung|systemauslastung)"
    r"(?:\s+(?:vom?|[üu]ber|im|in|zur?|zum?|des|der|das|die|mein\w*|hier|system\w*|pc|"
    r"rechner\w*|computer\w*|aktuell\w*|jetzt|bitte|l[äa]nger\w*|mehr|noch|infos?|"
    r"information(?:en)?|details?|ausf[üu]hrlich\w*|genauer\w*))*\s*[?.!]*$", re.I)))
# «Embed» = Nutzer-Begriff für eine App-Ansicht. "Settings-Embed", "öffne das Scan-Embed",
# "embed threats", "Memory Embed" -> das Panel öffnen (Handler löst den Namen auf). Greift nur,
# wenn das Wort "embed" vorkommt -> kapert keine normalen Befehle.
_COMMAND_PATTERNS.insert(0, ("open_embed", re.compile(
    r"^\s*(?:hey\s+\w+[\s,]+)?(?:[öo]ffne\s+|oeffne\s+|zeig\w*\s+|geh\s+zu\s+|wechsle?\s+(?:zu|in)\s+|"
    r"starte?\s+|gib\s+mir\s+)?(?:das\s+|die\s+|den\s+|mir\s+|mal\s+|bitte\s+)*"
    r"(?:(?P<a>[a-zäöü][\wäöü\-]*)[\s-]+embeds?|embeds?(?:[\s-]+(?P<b>[a-zäöü][\wäöü\-]*))?)"
    r"\s*[?.!]*$", re.I)))
# «füge diesen Song zu Favoriten hinzu» / «like den Song» -> laufenden Titel liken/merken.
# Verlangt Add-/Like-Kontext -> kapert NICHT «spiele meine Lieblingssongs» (das ist Play).
_COMMAND_PATTERNS.insert(0, ("favorite_song", re.compile(
    r"\b(?:f[üu]g\w*|hinzuf[üu]g\w*|pack\w*|speicher\w*)\b[^.!?]{0,45}"
    r"\b(?:favorit\w*|lieblingssong\w*|lieblingslied\w*|lieblingstitel\w*|liked\s*songs?|gelikt\w*)\b"
    r"|\b(?:favorit\w*|lieblingssong\w*|liked\s*songs?)\b[^.!?]{0,30}\bhinzu\w*"
    r"|\b(?:lik(?:e|en|t|st)?)\b\s+(?:den\s+|diesen\s+|das\s+|die\s+|mal\s+|bitte\s+)*"
    r"(?:song|lied|titel|track)\b", re.I)))
# Bare Panel-Namen (auch ohne das Wort «Embed») -> das Panel WIRKLICH öffnen, statt dass das
# Modell nur darüber plaudert. NUR Namen ohne eigenes Verhalten (settings->app_settings,
# scan->Scan-Aktion, threats->threats, usb/sentinel->usb bleiben unberührt).
_COMMAND_PATTERNS.insert(0, ("open_embed", re.compile(
    r"^\s*(?:[öo]ffne\s+|oeffne\s+|zeig\w*\s+(?:mir\s+)?|geh\s+zu\s+|wechsle?\s+(?:zu|in)\s+)?"
    r"(?:das\s+|die\s+|den\s+|mir\s+|mal\s+|bitte\s+)*"
    r"(?P<a>dashboard|übersicht|uebersicht|netzwerk|network|verbindungen|quarant[äa]ne|"
    r"quarantine|memory|gedächtnis|gedaechtnis|erinnerung)\s*[?.!]*$", re.I)))
# «wie bist du aufgebaut» / «deine Architektur» -> Architektur-Embed (visuelles Diagramm), NICHT
# Status. Steht VOR status/knowledge. «wie bist du drauf» o.ä. matcht NICHT (verlangt Aufbau-Wort).
_COMMAND_PATTERNS.insert(0, ("architecture", re.compile(
    r"\bwie\s+(?:bist|funktionier\w*|arbeitest)\s+du\b[^.!?]{0,25}\b(?:aufgebaut|gebaut|strukturiert|aufgestellt|aufgebau\w*)\b"
    r"|\bworaus\s+(?:bestehst\s+du|besteht\s+aegis)\b"
    r"|\bwie\s+funktionierst\s+du\b"
    r"|\b(?:deine?|dein)\s+(?:architektur|grundaufbau|aufbau|struktur)\b"
    r"|\bzeig\w*\s+(?:mir\s+)?(?:deine?|dein)\s+(?:architektur|aufbau|struktur)\b", re.I)))
# «was ist das?» / «schau auf meinen Bildschirm» -> AEGIS macht einen Screenshot + erkennt ihn
# (lokales Vision-Modell, nur auf Zuruf). «was ist das» EXAKT -> Screen; längere Wissensfragen nicht.
_COMMAND_PATTERNS.insert(0, ("screen_analyze", re.compile(
    r"\b(?:schau\w*|sieh|guck\w*|blick\w*)\b[^.!?]*\b(?:bildschirm|screen|monitor|display)\b"
    r"|\bwas\s+(?:siehst|erkennst)\s+du\b"
    r"|\b(?:was|wer|wo)\s+(?:ist|sind)\b[^.!?]*\bauf\s+(?:dem|meinem)\s+(?:bildschirm|screen|monitor)\b"
    r"|\bmach\w*\s+(?:mir\s+|einen?\s+|mal\s+|bitte\s+)*screenshot\b"
    r"|\banalysier\w*\b[^.!?]*\b(?:bildschirm|screen|monitor|das\s+hier|den\s+screen)\b"
    r"|^\s*was\s+ist\s+das(?:\s+(?:hier|denn|auf\s+dem\s+bildschirm))?\s*[?.!]*$", re.I)))
# «welches Modell nutzt du» / «was für eine KI bist du» -> ehrlich das aktive Modell nennen,
# NICHT der Status-Lagebericht (genau dieser Fehlschuss: das kleine Router-Modell wirft kurze
# Fragen oft auf «status»). «was IST ein modell» (Wissensfrage) matcht NICHT.
_COMMAND_PATTERNS.insert(0, ("which_model", re.compile(
    r"\b(?:welches?|was\s+f[üu]r\s+ein\w*)\s+(?:ki[\s-]?|ai[\s-]?|sprach[\s-]?)?"
    r"(?:modell|model|llm|ki|ai)\b"
    r"|\bmit\s+welchem\s+(?:modell|model|llm)\b"
    r"|\bwelche\s+(?:ki|ai)\s+(?:nutzt|bist|verwendest|benutzt|l[äa]uft)\b"
    r"|^\s*(?:welches\s+|dein\s+)?mod[ae]l+\s*[?.!]*$"     # bare «Model?» / «Modell?»
    r"|^\s*(?:welches?\s+)?(?:ki|llm)\s*[?.!]*$", re.I)))
# «was kannst du» / «deine Fähigkeiten» -> Fähigkeiten-Embed. «was kannst du mir über X sagen»
# (Wissensfrage, NICHT am Satzende) matcht NICHT -> bleibt Wissens-Lookup.
_COMMAND_PATTERNS.insert(0, ("capabilities", re.compile(
    r"^\s*was\s+kannst\s+du(?:\s+alles)?\s*[?.!]*$"
    r"|\b(?:deine?|welche)\s+f[äa]higkeit\w*\b"
    r"|\bzeig\w*\s+(?:mir\s+)?(?:was\s+du\s+(?:alles\s+)?kannst|deine?\s+f[äa]higkeit\w*|deine?\s+skills)\b"
    r"|\bwozu\s+bist\s+du\s+(?:alles\s+)?f[äa]hig\b"
    r"|^\s*(?:commands?|kommandos?|befehle?|befehlsliste|skills?)\s*[?.!]*$"
    r"|\b(?:command\w*|befehl\w*|kommando\w*)[\s-]+(?:liste|embed|übersicht)\b", re.I)))
# «schließe/blende den Chat aus» -> Chat-Panel ausblenden (NICHT close_app «chat läuft nicht»,
# NICHT Status). «zeig den Chat» holt es zurück. insert(0) -> schlägt close_app/status.
_COMMAND_PATTERNS.insert(0, ("show_chat", re.compile(
    r"\b(?:zeig\w*|[öo]ffne|einblend\w*|hol\w*)\b[^.!?]*\bchat\b|\bchat\s+(?:zeigen|einblenden|zur[üu]ck|her)\b", re.I)))
_COMMAND_PATTERNS.insert(0, ("hide_chat", re.compile(
    r"\b(?:schlie[sß]\w*|beend\w*|blend\w*|versteck\w*|ausblend\w*|mach\s+(?:den\s+)?chat\s+(?:zu|aus))\b[^.!?]*\bchat\b"
    r"|\bchat\s+(?:aus|zu|weg|ausblenden|schlie[sß]en|verstecken|ausmachen|verbergen)\b", re.I)))
# Tippfehler-/Verhörer-tolerant: «nächster Song» auch als «nester», «nächster songt» -> nächster Titel.
_COMMAND_PATTERNS.insert(0, ("media", re.compile(
    r"^\s*(?:n[äae]chst\w*|n[äae]st\w*|nex\w*|skip)\s*"
    r"(?:lied\w*|song\w*|titel\w*|track\w*|titl\w*)?\s*[?.!]*$", re.I)))
# «ist das sicher: <Link/Text>» / «prüf diesen Link» -> Link gegen Blocklist+Heuristik prüfen,
# sonst Text vom LLM auf Betrug bewerten. «ist alles/mein system sicher» bleibt Status (anderes Wort).
_COMMAND_PATTERNS.insert(0, ("check_safety", re.compile(
    r"\bist\s+(?:das|dies|dieser?\s+(?:link|seite|text|nachricht|mail|datei|anhang))\s+"
    r"(?:sicher|ein\s+betrug|betrug|scam|phishing|fake|gef[äa]hrlich|seri[öo]s)\b"
    r"|\bist\s+[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}\S*\s+(?:sicher|seri[öo]s)\b"
    r"|\b(?:pr[üu]f\w*|check\w*|analysier\w*)\b[^.!?]{0,30}\b(?:link|url|seite|nachricht|mail|ob\s+(?:das|es|der|die)\s+sicher)\b"
    r"|^\s*ist\s+das\s+sicher\b", re.I)))
# Update-Fragen deterministisch (Modell-Router warf «hast du ein update» fälschlich auf «status»).
_COMMAND_PATTERNS.insert(0, ("update", re.compile(
    r"^\s*updat\w*\s*[?.!]*$"
    r"|\b(?:hast\s+du|gibt\s+es|gibts|haben\s+wir|ist\s+(?:ein|eine))\b[^.?!]{0,16}\bupdates?\b"
    r"|\b(?:update|neue\s+version)\b[^.?!]{0,14}\b(?:verf[üu]gbar|vorhanden|da|drau[sß]en|raus)\b"
    r"|\bnach\s+(?:neuen\s+)?updates?\s+(?:such\w*|pr[üu]f\w*|schau\w*|guck\w*)\b"
    r"|\bbin\s+ich\s+(?:noch\s+)?(?:auf\s+dem\s+neuesten\s+stand|aktuell)\b"
    r"|\b(?:aktualisier\w*|update)\s+(?:dich|aegis)\b", re.I)))
# «hebe X hervor» / «bring X nach vorne» -> NUR fokussieren (kein Start, wenn schon läuft).
_COMMAND_PATTERNS.insert(0, ("focus_window", re.compile(
    r"^\s*(?:heb\w*|hol\w*|bring\w*)\s+(?:mir\s+|das\s+|die\s+|den\s+|mal\s+)*"
    r"(?P<app>[a-zäöü][\wäöü.\-]{1,30})\s+(?:hervor|nach\s+vorne|in\s+den\s+vordergrund|vor)\b"
    r"|^\s*fokussier\w*\s+(?:mir\s+|das\s+|den\s+)*(?:fenster\s+(?:von\s+)?)?"
    r"(?P<app2>[a-zäöü][\wäöü.\-]{1,30})\b", re.I)))
# «verschiebe X auf den Hauptmonitor/main screen» -> Fenster auf den Primärmonitor ziehen.
_COMMAND_PATTERNS.insert(0, ("move_window", re.compile(
    r"^\s*(?:verschieb\w*|zieh\w*|beweg\w*|setz\w*|pack\w*|hol\w*)\s+"
    r"(?:mir\s+|das\s+|die\s+|den\s+|mal\s+)*(?P<app>[a-zäöü][\wäöü.\-]{1,30})\s+"
    r"(?:auf|zum|in|nach)\s+(?:den\s+|das\s+|meinen\s+|mein\s+)*"
    r"(?:haupt\w*|main|prim[äa]r\w*|erst\w*|monitor|bildschirm|screen)\b", re.I)))


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
                      r"hostname|ver|vol|gpresult|where|tree|set|assoc|ftype|fc|sc|net|query|klist|schtasks|powershell|pwsh")
            mm = re.search(r"\b(?:" + _tools + r")\b.*$", t, flags=re.I)
            cmd = mm.group(0) if mm else t
            cmd = re.sub(r"\s+(?:bitte\s+)?(?:aus|ausf[üu]hren)\s*$", "", cmd, flags=re.I)
            # Sprach-Verhoerer von "sfc /scannow" normalisieren: STT macht aus "/" Worte
            # und zerlegt "scannow" ("sfc slash scannow"/"sfc scan now"/"sfc slash scan now").
            cmd = re.sub(r"\bscan\s+now\b", "scannow", cmd, flags=re.I)
            cmd = re.sub(r"\b(?:slash|schr[äa]gstrich)\b", "/", cmd, flags=re.I)
            cmd = re.sub(r"/\s+", "/", cmd)                 # "/ scannow" -> "/scannow"
            args["command"] = cmd.strip()          # Executor parsed + allowlistet sicher
        elif name == "datetime":
            args["text"] = t
        elif name == "pc_power":
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
        elif name in ("identity", "news"):
            args["text"] = t
        elif name == "find_file":
            args["kind"] = _KIND.get(m.group(1).lower(), "")
            args["query"] = m.group(2).strip()
        elif name == "search":
            args["query"] = m.group(2).strip()
        elif name == "open":
            # nacktes-URL-Pattern hat 1 Gruppe, "öffne <x>" hat 2 -> robust beide
            args["target"] = (m.group(2) if (m.lastindex or 0) >= 2 else m.group(1)).strip()
        elif name == "open_embed":
            args["target"] = ((m.groupdict().get("a") or m.groupdict().get("b") or "")).strip()
        elif name == "screen_analyze":
            args["text"] = t
        elif name == "check_safety":
            args["text"] = t
        elif name == "focus_window":
            args["target"] = (m.groupdict().get("app") or m.groupdict().get("app2") or "").strip()
        elif name == "move_window":
            args["target"] = (m.groupdict().get("app") or "").strip()
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
