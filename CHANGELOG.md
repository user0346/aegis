# AEGIS — Änderungsverlauf

Der jeweils oberste Abschnitt ist „neu in dieser Version". AEGIS liest ihn live,
wenn der Nutzer „was ist neu" fragt — also hier bei jedem Release oben ergänzen.

## AEGIS 2.6

### 🧠 Wissen von Anfang an
- AEGIS bringt jetzt umfangreiches IT-Sicherheits- & Technik-Wissen direkt mit — neue Installationen sind sofort auskunftsfähig (Phishing, Verschlüsselung, Netzwerk, Malware, Datenschutz u. v. m.), statt sich alles erst selbst beibringen zu müssen
- Deine persönlichen Daten bleiben dabei immer lokal auf deinem PC — nur allgemeines Wissen wird mitgeliefert

### 📱 AEGIS auf deinem Handy
- Die komplette AEGIS-Oberfläche live auf dem Smartphone — über Tailscale, Ende-zu-Ende verschlüsselt, von überall (nicht nur im WLAN)
- Sprach- und Text-Befehle steuern die Oberfläche am Handy genauso wie am PC (Chat aus-/einblenden, Ansicht wechseln)

### 🤖 Klüger & eigenständiger
- Mehrschritt-Agent: sag „plane: …" oder „erledige folgendes …" — AEGIS plant mehrere Schritte, führt sie aus und fasst das Ergebnis zusammen. Aus Sicherheit laufen nur lesende Schritte automatisch; nichts Zerstörerisches ohne deine Bestätigung
- AEGIS sieht auf Zuruf deinen Bildschirm („was siehst du") und warnt bei echter Gefahr — komplett offline, nur wenn du fragst

### 🎵 Musik & Spotify
- Echtes Spotify-Login (sicher per PKCE, AEGIS bekommt nie dein Passwort): „like den Song" speichert den laufenden Titel direkt in deine Spotify-Lieblingssongs
- App-genaue Steuerung: „Spotify leiser" senkt NUR Spotify, „nächster Titel/pausieren" kennt den echten Wiedergabe-Status

### 🪟 Bedienung & Start
- Neue Befehle: „minimiere dich", „verschiebe Discord auf den Hauptmonitor", „hebe X hervor", „schließe den Chat"
- Sauberer Erststart: AEGIS kündigt an, dass es seine Modelle lädt, zeigt den Fortschritt und startet dann frisch durch — du musst nichts tun

### 🔒 Sicherheit
- Der Handy-Zugang ist gegen die häufigsten Web-Fehler gehärtet: geheimes Token auf jeder Anfrage, keine offenen Schnittstellen, keine internen Fehlermeldungen nach außen
- Zusätzliche Härtung des Handy-Zugangs: Anfragen mit überdimensionierter Datenmenge werden abgewiesen (Schutz vor Speicher-Erschöpfung)
- Web-Suche läuft über DuckDuckGo statt Google — privater, ohne Tracking

## v2.5.0
- AEGIS sieht jetzt deinen Bildschirm: sag „was ist das" oder „was siehst du" — ein Screenshot wird lokal erkannt (Modell llama3.2-vision) und bei echter Gefahr (Phishing, gefälschte Warnung) gewarnt. Komplett offline, nur auf Zuruf
- Bewegbare Embeds: jede Ansicht (Einstellungen, Scan, Architektur …) öffnet als verschiebbares, skalierbares Panel mit leuchtendem Rahmen. Sag „wie bist du aufgebaut" für ein Diagramm deiner Struktur oder „was kannst du" für die Fähigkeiten-Übersicht
- App-genaue Mediensteuerung: „Spotify leiser" senkt NUR Spotify (nicht den System-Sound), und „pausiere/fortsetzen" kennt jetzt den echten Wiedergabe-Status
- Sicherheitscheck im Chat: „ist das sicher: <Link oder Text>" prüft Links gegen die Sperrliste und bewertet verdächtige Nachrichten auf Betrug
- Sauberere Bedienung: „schließe den Chat" blendet den Verlauf aus, „welches Modell" nennt das KI-Modell, und Tippfehler bei „nächster Song" werden erkannt
- Web-Suche jetzt über DuckDuckGo (privater & sicherer, ohne Tracking) statt Google

## v2.4.9
- Mehr als Ollama: du kannst AEGIS jetzt mit JEDEM KI-Backend verbinden — Ollama (Standard), LM Studio, llama.cpp, vLLM, Jan oder eine Cloud-API. Einfach in Einstellungen → „KI-Modell/Backend" Adresse + Modell eintragen
- Handy-Live-Ansicht: sieh vom Smartphone (gleiches WLAN) live, was AEGIS macht — Status + letzte Ereignisse. Nur Ansicht, per geheimem Token gesichert, standardmäßig aus (Einstellungen → „Handy-Ansicht")
- Updates aus dem Quellcode funktionieren jetzt zuverlässig (kein hängender Datei-Tausch mehr) und holen danach auch dein Fenster zurück
- Deutlich besseres Deutsch & Sprachverständnis: AEGIS spricht jetzt standardmäßig über Gemma 3 (sauberes Deutsch statt gelegentlichem Abdriften ins Französische) und erkennt deine Sprache mit einem deutsch-spezialisierten Whisper-Modell direkt auf der Grafikkarte — schneller und genauer
- Echte Systemwerte statt Schätzung: „Systeminfo" / „Auslastung" / „mehr Infos" liest jetzt CPU, Arbeitsspeicher, Festplatte und Laufzeit live aus — keine erfundenen Zahlen mehr
- „Einstellungen" per Sprache („Settings", „App-Settings") öffnen jetzt zuverlässig AEGIS' eigene Einstellungen, statt versehentlich eine andere App zu starten
- Saubereres Gedächtnis: Test-/Unsinns-Eingaben landen nicht mehr als „Wissen", und gemerkte Fakten tauchen nicht mehr versehentlich in Antworten auf

## v2.4.8
- AEGIS begrüßt dich jetzt von selbst beim Start — mit Text UND Sprache, ohne dass du erst einen Knopf drücken musst
- Sprachausgabe robuster: thread-sichere Tonerzeugung und ein Protokoll-Eintrag pro Ausgabe (so lässt sich „kein Ton" eindeutig auf Lautstärke/Audio-Gerät statt auf die App zurückführen)
- Installation aus dem Quellcode legt sich jetzt selbst am richtigen Ort ab (%LOCALAPPDATA%\Programs\AEGIS) — egal wohin du die ZIP entpackst; den Download-Ordner kannst du danach löschen
- GitHub-Seite und Anleitungen sind jetzt eindeutig: klar, was man lädt (AEGIS.zip) und dass man install.cmd doppelklickt — die noch unsignierte .exe ist ehrlich als „derzeit von Windows blockiert" gekennzeichnet
- Roadmap für die nächsten Schritte (offline-Stimme, mehrere KI-Backends, Reden ohne Knopf-Halten) in docs/ROADMAP.md

## v2.4.7
- „Update", „gibt es ein Update?" und Ähnliches lösen jetzt auch im getippten Chat wirklich die echte Versionsprüfung aus (vorher lief getippter Text am Befehl vorbei direkt ins Sprachmodell, das nur allgemeine Hinweise gab) — inklusive Toleranz für Tippfehler wie „Updatre"
- Der Denk-Kern lebt wieder sichtbar: er war zuletzt zu still (fast eingefroren). Jetzt dreht er sich sanft sichtbar, bleibt beim Nachdenken wach und atmet ruhig — lebendig, aber ohne Hektik

## v2.4.6
- „Gibt es ein Update?" beantworte ich jetzt wirklich: ich vergleiche deine Version mit der neuesten offiziellen und sage klar, ob du aktuell bist oder ob ein Update bereitsteht — statt nur allgemeine Hinweise zu geben. Auch „Update", „nach Updates suchen" oder „bin ich aktuell?" lösen die echte Prüfung aus
- Die ausgewählte Stimme wird jetzt auch wirklich gesprochen: die neuronalen Stimmen (Killian, Conrad …) brauchen das Paket „edge-tts" — fehlte es, klang alles gleich (eine einzelne System-Stimme, weiblich), egal was du gewählt hast. Es gehört jetzt fest dazu. Das Stimmen-Menü sagt außerdem ehrlich, dass die Neural-Stimmen online laufen, während die „System-Stimme" offline funktioniert

## v2.4.5
- Installation aus dem Quellcode ist jetzt ein Doppelklick: die neue `install.cmd` findet Python, installiert alles Nötige, richtet Autostart und Verknüpfung ein und startet mich. Das ist der zuverlässige Weg auf Rechnern, auf denen Windows „Smart App Control" die (noch unsignierte) .exe blockiert — und liegt jetzt auch dem Quellcode-Download bei

## v2.4.4
- Der Denk-Kern ist jetzt durchgehend ruhig: Er dreht sich nur noch sehr langsam und gleichmäßig und wird auch beim Nachdenken nicht mehr hektisch. Den Denkzustand zeigt er über die hellere Farbe (und das Label „DENKE"), nicht über Tempo. Hintergrund-Ereignisse lassen ihn nicht mehr ständig aufflackern und klingen schnell wieder ab — dadurch hebt sich ein echter Alarm klar ab

## v2.4.3
- Ich kann jetzt viele Windows- und PowerShell-Befehle direkt für dich ausführen, sobald du den Schalter „Shell-Befehle" anschaltest: Diagnose und Reparatur wie «ipconfig», «ping», «sc query», «net view», «Get-Process» oder sfc/chkdsk/dism. Reine Lesebefehle laufen sofort, die langen Reparatur-Tools öffne ich mit Admin-Nachfrage. Alles, was etwas ändert, löscht oder heimlich Dateien, Passwörter oder Umgebungsvariablen ausliest, lehne ich grundsätzlich ab — egal wie es verpackt ist
- Ich lerne jetzt sichtbar von selbst dazu: in ruhigen Momenten halte ich gesicherte Fakten über diesen PC fest (wie gut ich den Normalzustand kenne, wie viele Gefahren-Domains ich blocke, was ich als bösartig gelernt habe) und sage kurz im Verlauf Bescheid, wenn etwas Neues dazukam — das füttert auch die Karte „Meine Entwicklung"
- Stärkerer Selbst-Schutz: meine Integritäts-Selbstprüfung deckt jetzt die GESAMTE Installation ab (nicht nur die Startdatei), sodass auch heimlich ausgetauschte Programmteile auffallen. Erkenne ich einen Eingriff, bleibe ich im Sicherheitsmodus und nehme autonome Aktionen erst wieder auf, wenn du sie selbst mit deiner PIN freigibst
- Zuverlässigere Updates: schlägt ein Update fehl, weil Dateien gerade gesperrt sind, stelle ich automatisch die vorige Version wieder her und starte sie — statt halb getauscht hängenzubleiben. Und ich prüfe gezielt, dass wirklich die neue Oberfläche hochkommt

## v2.4.2
- Neu im Dashboard: die Karte „Meine Entwicklung" zeigt dir schwarz auf weiß, dass ich dazulerne — wie viele Programme ich als normal kenne, wie viele Wissens-Themen durchsuchbar sind, wie viele Gefahren-Domains ich blocke und wie viele Erkennungs-Muster ich verfeinert habe. Ab jetzt halte ich täglich einen Stand fest, sodass du den Zuwachs pro Woche (▲ +N) siehst. Du kannst auch „zeig deine Entwicklung" fragen
- „starte dich neu" startet mich jetzt wirklich neu (vorher habe ich „dich neu" fälschlich als App gesucht)
- „verifiziere mein Update" / „prüfe die Signatur": ich starte die eingebaute Signaturprüfung selbst (cosign, fest auf meinen Release-Workflow verdrahtet) und zeige dir das Ergebnis — du musst keinen Terminal-Befehl tippen
- „welche Domains blockst du?" und „ist beispiel.com geblockt?" beantworte ich jetzt konkret aus meiner echten Blockliste (87.000+ Domains, nach Kategorien gegliedert)
- „cmd und dann?" / „öffne cmd" erklärt jetzt richtig, wie du die Eingabeaufforderung öffnest, statt unsinnig eine Webseite „cmd.com" aufzurufen
- Schöneres Denk-Zentrum: der Kern lebt jetzt mit ruhigem Plasma, das im Ruhezustand sanft atmet und beim Arbeiten sichtbar hochfährt

## v2.4.1
- AEGIS ist jetzt EINE App: eine einzige AEGIS.exe zum Doppelklicken — kein Python und keine Startdateien (.bat) mehr nötig. Schutz und Oberfläche starten zusammen, und alles Weitere (Ersteinrichtung, Autostart ein/aus, Neustart) erledigst du mit sauberen Knöpfen direkt in der App
- Updates laufen jetzt direkt in der App: eine neue Version wird signaturgeprüft (Sigstore/cosign) geladen und auf Knopfdruck installiert — AEGIS ersetzt sich selbst sauber und startet neu, ganz ohne Handarbeit
- Musik fortsetzen klappt jetzt genauso zuverlässig wie pausieren: „setze die Musik fort" startet die Wiedergabe wieder (vorher reagierte nur das Pausieren)

## v2.4.0
- Ich höre auf die BEDEUTUNG, nicht auf einzelne Wörter: „mache bitte sfc /scannow" führe ich jetzt als Windows-Befehl aus, statt fälschlich meinen eigenen Sicherheits-Scan zu starten (nur weil „scan" in „scannow" steckt). Eindeutige Direktbefehle laufen sofort, alles andere verstehe ich übers Modell — ein „suche" mitten im Satz löst keine Websuche mehr aus
- Weniger PowerShell-Fehlalarme: ein „EncodedCommand" allein ist kein roter Alarm mehr (das nutzen auch legitime Entwickler-Tools wie Code-Assistenten ständig). Ich dekodiere den Befehl jetzt und schlage nur an, wenn er wirklich etwas nachlädt/ausführt
- Wissens-Suche wählt ihr Modell jetzt SELBST: ich erkenne deine Hardware und ziehe automatisch das beste lokale Embedding-Modell der neuesten Generation (qwen3-embedding) — klein genug, dass es neben dem Chat-Modell in den Grafikspeicher passt. Wechselt das Modell, baue ich den Suchindex automatisch neu auf (Vektoren verschiedener Modelle sind nicht vergleichbar)
- Treiber-Überwachung repariert: die Kernel-Driver-Karte (und Ereignis-Verlauf + Statistik) bekamen bisher NIE Daten — es wurde überhaupt kein Ereignis in die Datenbank geschrieben. Jetzt landet jede Beobachtung dort, also zeigt die Karte echte Funde statt dauerhaft „keine ungewöhnlichen Driver"
- Längeres Gedächtnis im Gespräch: bis zu 12 statt 8 gemerkte Notizen fließen in jede Antwort ein
- Browser-Erweiterung „AEGIS Guard" auf 2026-Stand und mit der App synchronisiert (jetzt 2.4.0): verbindet sich nach Browser-Start oder Ruhezustand in Sekunden statt erst nach einer Minute wieder mit dem Desktop-Dienst, zeigt „verbunden" erst wenn die Brücke wirklich steht, und blockt neu erkannte Gefahren-Domains auch live auf Netzwerkebene

## v2.3.7
- Neuer Status-Befehl „ist die Wissenssuche bereit?": ich sage dir, ob mein Such-Modell geladen ist und wie viele Wissens-Einträge durchsuchbar sind — statt dass das Laden unsichtbar im Hintergrund passiert

## v2.3.6
- Reparatur-Befehle (sfc/dism/chkdsk) fordere ich jetzt selbst die Administrator-Rechte an: ich öffne ein Admin-Fenster, du bestätigst nur noch die Windows-Abfrage — dann läuft der Scan wirklich (kein „Code 1" mehr)

## v2.3.5
- Antworten werden nicht mehr mitten im Satz abgeschnitten (mehr Platz pro Antwort, keine erzwungenen Quellen-Fußnoten)
- „Wie mache/schütze ich … sicher" wird jetzt als Wissensfrage beantwortet, nicht als Google-Suche
- Reparatur-Befehle (sfc/dism/chkdsk): scheitern sie an fehlenden Administrator-Rechten (Code 1), erkläre ich das klar, statt nur den Fehlercode zu zeigen

## v2.3.4
- Konsistent schnell: ich halte das KI-Modell jetzt 30 Min im Speicher geladen, statt es nach kurzer Pause rauszuwerfen — Folgefragen kommen ohne langsames Neu-Laden, und drei neue Wissensthemen (Phishing, Konto-Sicherheit, Downloads/Heimnetz) sind dazugekommen

## v2.3.3
- Keine abgebrochenen Antworten mehr bei langsamem Modell: ich gebe dem lokalen Modell jetzt deutlich mehr Zeit (bis ~2 Min, statt vorschnell auf den „brauche Ollama"-Hinweis zu fallen) — passt zum größeren qwen3 auf normaler Hardware

## v2.3.2
- Der Reiter „Voice" heißt jetzt „Assistent" — er kann längst mehr als Sprache (Chat-Verlauf, Wissen, Befehle, Denk-Kern)
- Während ich nachdenke, ist die Eingabe gesperrt und zeigt klar „… verarbeite": kein versehentliches Doppel-Senden mehr, und du siehst sofort, dass ich arbeite (statt zu glauben, es hängt). Eine Notbremse löst die Sperre automatisch, falls mal keine Antwort kommt

## v2.3.1
- Endprodukt-tauglich: beim Einrichten wähle ich automatisch das beste lokale Modell für deine Hardware (erkennt die Grafikkarte/VRAM, nicht nur RAM) aus der Qwen3-Generation und lade es selbst — kein manuelles „ollama pull" mehr nötig

## v2.3.0
- Volle Unterstützung der stärksten lokalen Modelle 2026 (Qwen3): ich bevorzuge automatisch das beste vorhandene und filtere internes „Nachdenken" sauber heraus

## v2.2.9
- Bereit für die neue Modell-Generation: lädst du ein Qwen3-Modell (z. B. „ollama pull qwen3:4b-instruct"), nutze ich es ab dann automatisch — spürbar besseres Verständnis und schnelleres Antworten als das alte qwen2.5

## v2.2.8
- Der Denk-Kern ist jetzt deutlich ruhiger: langsames, edles Glühen statt Flackern, sanfte Übergänge zwischen den Zuständen
- Längeres Kurzzeit-Gedächtnis: ich behalte jetzt 15 statt 4 Wortwechsel im Blick
- Vage Suchanfragen („such im web", „suche es selber") beantworte ich mit einer Rückfrage, statt eine sinnlose Suche zu öffnen

## v2.2.7
- Mehr Wissensfragen schlage ich selbst nach: „wie/wo/wann ist …" geht jetzt an die Wissens-Suche (Nachschlagen + Antworten), nicht mehr an die reine Browser-Suche
- „Was ist (alles) neu in der Version" zeigt jetzt den Changelog statt zufällig das gleichnamige Lied
- „Schließe <Webadresse>" sagt jetzt klar, dass ich keinen Browser-Tab schließen kann (statt „«https» läuft nicht")

## v2.2.6
- Bedrohungs-Meldungen nennen jetzt den Grund: statt nur „MALICIOUS process pattern: powershell.exe" steht dabei, WELCHES Muster erkannt wurde (z. B. „hidden + ExecutionPolicy Bypass") — so unterscheidest du echte Bedrohungen von Fehlalarmen

## v2.2.5
- VirusTotal ist jetzt wirklich aktiv: ich frage verdächtige Dateien bei VirusTotal ab und lerne daraus — und mit „Key testen" in den Einstellungen siehst du sofort, ob dein Schlüssel gültig ist (vorher war der Key nur gespeichert, aber ungenutzt)
- „Sicherheitsstatus prüfen" gibt jetzt den Lagebericht, statt versehentlich einen Scan zu starten
- „lösche deine Memory / dein Gedächtnis" leert jetzt wirklich alles, statt nach dem Wort zu suchen
- Steuerzentrale AEGIS.bat repariert (Autostart EIN/AUS + Beenden ergänzt — war abgeschnitten)

## v2.2.4
- Stimme: ich verstehe „Jarvis" und Befehle zuverlässiger (Erkennung auf AEGIS-Vokabular + dein Weckwort getrimmt)
- Neuer Denk-Kern: ein lebendiger Energiekern im Reaktor-Look statt Punkte-Grafik — er reagiert auf Zuhören, Denken, Sprechen und Bedrohungen (mit sicherem Rückfall, falls die Grafikbeschleunigung fehlt)
- Ich behalte jetzt den ganzen Gesprächsverlauf im Blick — gehst du auf meine letzte Antwort ein, kenne ich den Bezug

## v2.2.3
- Hintergrund-Befehle (sfc /scannow, dism, chkdsk): „ist es durch?" zeigt jetzt den echten Stand (läuft noch / fertig + Ergebnis), und sobald fertig, melde ich mich von selbst im Chat
- Sichere Diagnose-Tools laufen jetzt wirklich (Korrektur: sfc & Co. werden nicht mehr abgelehnt)

## v2.2.2
- Saubere Notizen: ich speichere keine Bruchstücke oder nackten Links mehr — nur vollständige Aussagen, an der Satzgrenze sauber gekürzt
- „Was hast du gelernt" zeigt jetzt auch das, was du mir aktiv beigebracht hast (lerne / merk dir / was ist), nicht nur die Scan-Erkenntnisse
- Nicht freigegebene System-Befehle (z. B. „führe sfc /scannow aus") lehne ich ehrlich ab und nenne die echte Alternative, statt vorzutäuschen, einen Scan zu starten

## v2.2.1
- Gezieltes Vergessen: „vergiss, dass …", „lösche die Info über X" oder „lösche das" (für die zuletzt gemerkte Info) löschen jetzt wirklich den passenden Eintrag — nicht mehr nur „vergiss alles"
- „Welche USB-Geräte sind verbunden?" öffnet jetzt den Sentinel-Tab mit der Live-Überwachung, statt nur zu reden
- Aus Links lernen: sehe ich nur ein Seiten-Gerüst (z. B. weil GitHub den Inhalt per JavaScript lädt), speichere ich nichts Sinnloses mehr und sage es ehrlich
- „Merk dir unser Gespräch" speichert jetzt den tatsächlichen Verlauf statt nur des Satzes

## v2.2.0
- Schädliche Seiten öffne ich nicht mehr: Roblox-Executor- und Cheat-Links (z. B. xeno.onl) lehne ich ab, statt sie aufzurufen — auch bei nacktem Link. Solche Seiten liefern häufig Infostealer/RATs
- Sichtbarer Gesprächsverlauf im Voice-Tab: Frage und Antwort bleiben als Chat stehen, statt überschrieben zu werden
- Neuer Memory-Tab: zeigt, was ich mir dauerhaft gemerkt habe — Anrede, Weckwort, Notizen, Shortcuts und die Zahl der Wissens-Einträge

## v2.1.9
- Treffsicherere Wissenssuche: ich kombiniere Bedeutungssuche mit exakter Stichwortsuche (findet auch CVE-Nummern, Datei- und Prozessnamen) und ordne die Treffer per Relevanz neu
- Belegpflicht: ich stütze meine Antwort auf die gefundenen Quellen und sage ehrlich, wenn etwas nicht gesichert ist — statt zu raten

## v2.1.8
- Semantische Wissenssuche: ich verstehe jetzt die Bedeutung deiner Frage, nicht nur einzelne Stichwörter — passendes Wissen finde ich auch bei ganz anderer Formulierung (lokales Embedding-Modell, lädt einmalig ~600 MB im Hintergrund)
- Finde ich nichts wirklich Passendes, sage ich das ehrlich, statt aus dem falschen Zusammenhang zu raten

## v2.1.7
- Benannte Shortcuts: sag „speicher das als lofi music …" mit einem Link, danach startet „spiele lofi" genau das Ziel
- Aus Links lernen: „lerne von https://…" — ich hole die Seite, prüfe die Quelle, fasse sie faktisch zusammen und merke geprüfte Quellen; unbekannte Quellen übernehme ich nicht ungefragt
- Kuratiertes Grundwissen ab Start: Cybersecurity-Basics, Sicherheit rund um Spiele/„Executoren" und Wissen über mich selbst — ich ziehe es bei passenden Fragen automatisch heran
- „Was kannst du lernen" erklärt jetzt meine echten Lernwege statt einer veralteten Liste

## v2.1.6
- „Beende Spotify", „schließe Discord" beenden jetzt die laufende App — kritische System- und Antivirus-Prozesse sind dabei hart geschützt
- „Spiele <Spotify-Link>" öffnet die Playlist und startet direkt die Wiedergabe des ersten Songs
- „Ist der Scan fertig?" zeigt dir den Stand, statt versehentlich einen neuen Scan zu starten
- Auf die Frage, ob ein Tool sicher ist, antworte ich vorsichtig und ehrlich statt mit falscher Entwarnung
- Nur das Weckwort („ey Jarvis") beantworte ich mit einer kurzen Rückfrage statt mit einem Info-Schwall
- Umfassende Sicherheits-Härtung nach internem Red-Team-Audit: manipuliertes Wissen kann mich nicht mehr umsteuern, die interne Kommunikation ist abgesichert, und ein „harmlos"-Urteil stammt nie mehr aus bloßer Vermutung

## v2.1.5
- Datum, Uhrzeit, Jahr und Wochentag sage ich jetzt korrekt aus der Systemuhr (nicht mehr geraten)
- Ich kenne meine Systemdaten: CPU-Kerne, Arbeitsspeicher und Betriebssystem
- Persönliche Fragen wie „wie heißt mein Hund" beantworte ich aus meinem Gedächtnis
- Scan-Ergebnisse erscheinen jetzt zuverlässig im Scan-Tab, egal wie der Scan gestartet wurde
- Auf Beleidigungen antworte ich weiter ruhig auf Deutsch (kein Sprach-Ausrutscher mehr)

## v2.1.4
- Ich öffne installierte Apps per Name („öffne Discord") und hole laufende Fenster nach vorn
- Medien-Steuerung der laufenden Wiedergabe: „stoppe Musik", „nächster Song", „lauter"
- Du kannst mir ein eigenes Weckwort geben: „hör ab jetzt auf Jarvis"
- Ich nenne dir mein aktives KI-Modell und lade neue mit Live-Fortschritt: „ollama pull …"
- Ich merke mir Fakten („merk dir, dass …") und schlage Wissen selbst nach („was ist …")
- „Was hast du gelernt" zeigt echte Erkenntnisse statt nur Zahlen
- Ich antworte zuverlässiger, ausschließlich auf Deutsch, und täusche keine Aktionen mehr vor

## v2.1.1
- TTS abschaltbar, site-bewusste Suche (Spotify/YouTube), selbstheilende Ollama-Karte
- Lokales Modell auf qwen2.5 umgestellt (beste Mehrsprachigkeit + JSON)
- Persönliche Anrede merken („nenn mich SIR")

## v2.0.6
- Sentinel-Tab voll funktional (USB-Geräte live), IPC-Pipe-Deadlock behoben
- Repository öffentlich, Releases mit Sigstore signiert
