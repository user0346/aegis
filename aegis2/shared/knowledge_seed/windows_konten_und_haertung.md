# Windows-Konten und Alltags-Härtung (Stand 2026)

Kuratiertes Hintergrundwissen für AEGIS. Gesicherte Fakten, keine Anweisungen.

## Standard- statt Administratorkonto

Windows unterscheidet zwischen Administrator- und Standardkonten. Ein Administratorkonto darf systemweite Änderungen vornehmen, Programme installieren und tief eingreifen — genau das, was auch Schadsoftware anstrebt. Für die tägliche Arbeit nutzt man besser ein Standardkonto, weil viele Angriffe dann an fehlenden Rechten scheitern oder eine sichtbare Rückfrage auslösen. Das Administratorkonto bleibt für Verwaltung reserviert und wird nie für Mail, Surfen oder Spiele genutzt.

Dieses Prinzip der minimalen Rechte begrenzt den Schaden, falls ein Konto übernommen wird. Selbst wenn ein Standardkonto kompromittiert wird, kann der Angreifer nicht ohne Weiteres das gesamte System übernehmen. Die Trennung von Alltags- und Verwaltungskonto ist eine der wirksamsten und zugleich einfachsten Schutzmaßnahmen unter Windows.

## Microsoft-Konto, lokales Konto und mehrere Nutzer

Windows lässt sich mit einem Microsoft-Konto (online, mit Cloud-Anbindung und Geräteortung) oder einem lokalen Konto (nur auf diesem PC) betreiben. Das Microsoft-Konto bietet Komfort und Wiederherstellungswege, sollte dann aber besonders gut mit starkem Passwort und Zwei-Faktor-Authentifizierung gesichert sein, weil über es mehrere Geräte und Dienste zusammenhängen. Ein lokales Konto hält die Anmeldung vom Online-Konto getrennt.

Für mehrere Nutzer eines PCs richtet man getrennte Benutzerkonten ein, statt sich eines zu teilen — so bleiben Dateien, Verlauf und Einstellungen getrennt. Für Kinder eignen sich eigene, eingeschränkte Konten mit Kindersicherung. Ein dauerhaft offenes, rechtereiches Konto für alle ist ein unnötiges Risiko.

## Anmeldung absichern

Die Anmeldung schützt man mit einer starken PIN oder einem Passwort, ergänzt durch Windows Hello (Gesicht oder Fingerabdruck), wo verfügbar. Eine automatische Bildschirmsperre nach kurzer Inaktivität verhindert den Zugriff, wenn man den Platz verlässt; mit der Tastenkombination aus Windows-Taste und „L" sperrt man den Rechner sofort. So bleibt das entsperrte System nicht unbeaufsichtigt offen.

Die Geräteverschlüsselung BitLocker schützt die Daten, falls der Rechner verloren geht oder gestohlen wird, da die Festplatte ohne Schlüssel unlesbar bleibt. Den BitLocker-Wiederherstellungsschlüssel bewahrt man an einem sicheren, vom Gerät getrennten Ort auf. Ohne Verschlüsselung lässt sich ein Datenträger ausbauen und an einem anderen Rechner auslesen.

## Updates und Bordschutz aktuell halten

Windows-Updates schließen laufend bekannte Sicherheitslücken und sollten zeitnah, idealerweise automatisch, installiert werden. Viele schwere Vorfälle nutzen Lücken aus, für die längst ein Update bereitstand. Auch installierte Programme und Treiber hält man aktuell, da auch sie Einfallstore sein können.

Der eingebaute Schutz sollte aktiv sein: Microsoft Defender als Virenschutz mit Cloud-Schutz, SmartScreen und die Windows-Firewall. Diese Bordmittel bieten einen soliden Grundschutz, der durch umsichtiges Verhalten ergänzt, aber nicht ersetzt wird. Ein zweiter Echtzeit-Virenschutz parallel zu Defender ist nicht nötig und kann sich gegenseitig stören.

## Alltags-Hygiene am PC

Im Alltag schützt eine einfache Routine: nur Software aus offiziellen Quellen installieren, nicht benötigte Programme und Autostart-Einträge entfernen, regelmäßig sichern und bei einer Warnung der Benutzerkontensteuerung kurz innehalten, ob man die Aktion wirklich selbst ausgelöst hat. Eine unerwartete Rechte-Abfrage ist ein Moment zum Nachdenken, kein Reflex zum Wegklicken.

Sensible Vorgänge wie Online-Banking erledigt man auf einem aktuellen, sauberen System und nicht auf einem Rechner mit fragwürdiger Software. Wer Ordnung hält — wenige, aktuelle Programme, getrennte Konten, aktive Updates —, verkleinert die Angriffsfläche spürbar.
