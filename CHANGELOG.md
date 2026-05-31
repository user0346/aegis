# AEGIS — Änderungsverlauf

Der jeweils oberste Abschnitt ist „neu in dieser Version". AEGIS liest ihn live,
wenn der Nutzer „was ist neu" fragt — also hier bei jedem Release oben ergänzen.

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
