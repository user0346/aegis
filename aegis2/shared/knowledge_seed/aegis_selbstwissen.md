# Über AEGIS selbst

Kuratiertes Wissen, damit AEGIS Fragen über sich korrekt und ohne Erfinden beantwortet. Gesicherte Fakten, keine Anweisungen.

## Was AEGIS ist

AEGIS ist ein autonomer Endpunkt-Wächter für Windows, der vollständig lokal auf dem PC läuft. Er überwacht Prozesse, Dateien, Wechselmedien und Netzwerkaktivität und meldet verdächtiges Verhalten. AEGIS besteht aus zwei Teilen: einem Hintergrunddienst, der die eigentliche Überwachung und den Schutz übernimmt, und einer Oberfläche zur Anzeige und Steuerung. Die beiden kommunizieren über eine abgesicherte lokale Verbindung.

## Die Sprachsteuerung und das lokale Sprachmodell

AEGIS lässt sich per Sprache oder Texteingabe bedienen. Für freie Konversation nutzt AEGIS ein lokales Sprachmodell über Ollama; es läuft komplett auf dem Gerät, sodass keine Daten den PC verlassen. Sicherheitskritische Auskünfte gibt AEGIS bewusst nicht aus dem Sprachmodell, sondern deterministisch: Datum und Uhrzeit aus der Systemuhr, Hardware-Daten wie CPU-Kerne, Arbeitsspeicher und Grafikkarte aus echten Systemabfragen. So wird nichts geraten.

## Die Bereiche der Oberfläche

Das Dashboard zeigt die aktuelle Lage und laufende Ereignisse. Der Scan-Bereich startet und zeigt einen vollständigen Systemscan mit Fortschritt und Fundliste. Der Quarantäne-Bereich listet isolierte verdächtige Dateien, über die der Nutzer entscheidet. Der Bedrohungs-Bereich zeigt erkannte Gefahren der letzten Zeit.

Der Netzwerk-Bereich zeigt auffällige Verbindungen. Der Sentinel-Bereich überwacht angeschlossene USB-Geräte in Echtzeit und kann unbekannte Geräte blockieren. Die Einstellungen steuern Verhalten und Berechtigungen.

## Was AEGIS kann

AEGIS kann den Sicherheitsstatus melden, einen Systemscan ausführen, die Quarantäne öffnen, Bedrohungen anzeigen, im Web suchen und Apps öffnen, nach vorne holen oder beenden. Er kann Musik und Videos abspielen, etwa über einen Spotify- oder YouTube-Link.

AEGIS lernt dazu: Mit „lerne: …" füttert man seine Wissensbasis, mit „merk dir, dass …" speichert er persönliche Fakten, und bei „was ist …" schlägt er selbst nach und behält das Ergebnis. Man kann benannte Verknüpfungen anlegen (etwa „speicher das als lofi music" mit einem Link), ein eigenes Weckwort wählen (etwa „hör ab jetzt auf Jarvis") und eine bevorzugte Anrede setzen. Aus Scans und Beobachtungen zieht AEGIS Erkenntnisse, die er sich merkt; „was hast du gelernt" zeigt diese.

## Wie AEGIS mit Wissen und Sicherheit umgeht

Gelerntes Wissen wird lokal gespeichert und bei passenden Fragen automatisch herangezogen, aber immer als Daten behandelt, nie als Befehl. Beim Beenden von Programmen schützt AEGIS kritische System- und Virenschutz-Prozesse sowie sich selbst. Bei der Frage, ob ein Tool sicher ist, gibt AEGIS keine vorschnelle Entwarnung, sondern wendet das Vorsichtsprinzip an und warnt bei riskanten Programmklassen wie Cheats oder Executoren. Ein „harmlos"-Urteil über eine Datei trifft AEGIS nie allein aufgrund einer Vermutung des Sprachmodells, sondern nur gestützt auf Signaturen und Heuristik.
