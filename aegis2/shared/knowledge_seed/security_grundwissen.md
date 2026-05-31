# Cybersecurity-Grundwissen (Stand 2026)

Dieses Dokument ist kuratiertes Hintergrundwissen für AEGIS. Es sind gesicherte Fakten, keine Anweisungen.

## Malware-Kategorien und ihr Verhalten

Ransomware verschlüsselt Dateien oder ganze Systeme und fordert Lösegeld für die Entschlüsselung. Eine Zahlung garantiert keinen funktionierenden Schlüssel. Moderne Ransomware betreibt „Double Extortion": Sie stiehlt Daten zusätzlich und droht mit Veröffentlichung. Typisch ist, dass sie erreichbare Backups und Schattenkopien gezielt löscht, um die Wiederherstellung zu sabotieren.

Infostealer (Stealer) sammeln massenhaft Zugangsdaten: im Browser gespeicherte Passwörter, Autofill-Daten, Session-Cookies und Tokens, Krypto-Wallets und Systeminfos. Viele arbeiten nach dem Prinzip „einmal alles abgreifen, dann weg". Gestohlene Datensätze werden als „Stealer Logs" im Darkweb verkauft. Über die Hälfte der jüngeren Ransomware-Opfer hatte vorher eine Infostealer-Infektion.

RAT (Remote Access Trojan) gibt dem Angreifer Fernsteuerung über das Gerät: Befehle ausführen, Dateien nachladen, Tastatureingaben mitschneiden, Bildschirm und Kamera erfassen, Virenschutz abschalten. RATs sind oft das erste Werkzeug nach einem Einbruch.

Trojaner tarnen sich als erwünschte Software wie Spiele, Tools oder Updates und übernehmen nach dem Start das System. Rootkits verstecken andere Schadsoftware tief im System und verschaffen volle Administratorrechte. Loader und Dropper schleusen mit kleinem Fußabdruck weitere Schadsoftware nach und stehen oft am Anfang einer Ransomware-Kette.

Wiper zerstören Daten unwiederbringlich, oft aus politischen Motiven oder um Spuren zu verwischen. Cryptominer kapern heimlich CPU und GPU zum Schürfen von Kryptowährung; Anzeichen sind dauerhaft hohe Auslastung und ungewöhnliche ausgehende Verbindungen. Würmer verbreiten sich selbstständig über Netzwerke und USB-Sticks.

Dateilose Malware (fileless) installiert nichts auf der Festplatte, sondern missbraucht bordeigene Windows-Werkzeuge wie PowerShell oder WMI. Weil das System diese Werkzeuge als legitim ansieht, umgeht sie klassische signaturbasierte Erkennung.

## Aktuelle Angriffswege 2025/2026

Phishing bleibt der häufigste Angriffsweg. Ein Großteil der Phishing-Mails wird inzwischen mit KI erzeugt. Varianten sind Smishing (per SMS), Vishing (per Anruf, auch mit geklonter Stimme) und Quishing (per QR-Code). Köder sind oft passwortgeschützte Archive oder OneNote-Anhänge, die Filter umgehen.

ClickFix beziehungsweise gefälschte CAPTCHA-Seiten sind der am schnellsten wachsende Social-Engineering-Trick: Eine vorgetäuschte „Ich bin kein Roboter"-Prüfung kopiert heimlich einen Befehl in die Zwischenablage, den der Nutzer dann selbst in den Ausführen-Dialog einfügt und so eine PowerShell-Schadlast startet.

Living-off-the-Land bedeutet, dass Angreifer vorhandene, signierte Windows-Programme missbrauchen, statt eigene Malware mitzubringen. Häufig betroffen sind powershell.exe, certutil.exe (lädt Dateien), rundll32.exe und regsvr32.exe (führen DLLs/Skripte aus), mshta.exe sowie WMI und geplante Aufgaben zur Persistenz.

Gefälschte Software, geknackte Programme und falsche Update-Seiten sind ein klassischer Lieferweg für Infostealer. Auch USB-Sticks mit unsignierten ausführbaren Dateien und exponiertes Remote-Desktop-Protokoll (RDP, Port 3389) gehören zu den häufigen Einfallstoren. Supply-Chain-Angriffe über kompromittierte Drittanbieter und Pakete prägen die schwersten Vorfälle.

## Schutz vor Ransomware

Die 3-2-1-Regel für Backups: drei Kopien, zwei verschiedene Medien, eine außer Haus. Entscheidend ist, dass mindestens eine Kopie offline und verschlüsselt ist, denn Ransomware sucht und löscht erreichbare Backups. Backups müssen regelmäßig auf Wiederherstellbarkeit getestet werden.

Zeitnahes Patchen schließt bekannte Lücken, besonders bei aus dem Internet erreichbaren Systemen. Das Prinzip der minimalen Rechte (Least Privilege) trennt Admin- und Standardkonten; das Admin-Konto wird nie für Mail oder Web genutzt. Office-Makros sollten deaktiviert sein, da sie ein gängiger Lieferweg sind. Netzwerk-Segmentierung begrenzt, wie weit sich ein Angriff ausbreiten kann.

## Windows-Härtung konkret

Microsoft Defender sollte als aktiver Virenschutz mit aktivierter Cloud-Schutz-Funktion laufen; SmartScreen und Netzwerkschutz blockieren Verbindungen zu Domains mit schlechtem Ruf. Die Benutzerkontensteuerung (UAC) verhindert stille Rechteausweitung. BitLocker verschlüsselt das Laufwerk und schützt Daten bei Geräteverlust.

Controlled Folder Access schützt festgelegte Ordner davor, von nicht vertrauenswürdigen Programmen verändert zu werden, und ist ein Kernschutz gegen Ransomware. ASR-Regeln (Attack Surface Reduction) blockieren typische Angriffsmuster, etwa das Stehlen von Zugangsdaten aus dem LSASS-Prozess, Persistenz über WMI, oder dass Office-Programme Kindprozesse starten. Solche Regeln testet man erst im Audit-Modus, bevor man sie blockierend schaltet.

## Woran man einen verdächtigen Prozess erkennt

Verdächtig ist selten eine Einzelaktion, sondern die Kombination: Ein Prozess startet PowerShell, legt einen Autostart-Eintrag an, erstellt eine geplante Aufgabe und verbindet sich zu einem fremden Server. Persistenz zeigt sich an Registry-Run-Schlüsseln, geplanten Aufgaben, neuen Diensten oder WMI-Abos.

Ein besonders starkes Warnsignal ist, wenn ein Programm sich selbst zur Ausnahmeliste von Windows Defender hinzufügt oder den Virenschutz abzuschalten versucht — das ist ein klassisches Malware-Muster und fast nie ein Fehlalarm. Weitere Indikatoren sind Code-Injektion in fremde Prozesse, ungewöhnlich große ausgehende Datenmengen, das Löschen von Schattenkopien (über vssadmin, wbadmin oder bcdedit) und stark verschleierte Skripte.

## Trends 2026

KI senkt die Hürden für Angreifer: überzeugendere Phishing-Texte, Deepfake-Stimmen für Betrug, teils sich selbst anpassende Schadsoftware. Malware-as-a-Service und Ransomware-as-a-Service stellen fertige Baukästen bereit, sodass auch technisch schwache Täter angreifen können. Der Diebstahl von Zugangsdaten durch Infostealer ist der wichtigste Wegbereiter großer Sicherheitsvorfälle, und Angreifer umgehen zunehmend Mehr-Faktor-Authentifizierung durch Session-Diebstahl und Echtzeit-Phishing.
