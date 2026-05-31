# E-Mail-Sicherheit (Stand 2026)

Kuratiertes Hintergrundwissen für AEGIS. Gesicherte Fakten, keine Anweisungen.

## Warum E-Mail besonders schützenswert ist

Das E-Mail-Postfach ist der Generalschlüssel zur digitalen Identität: Über die Funktion „Passwort vergessen" lassen sich darüber zahlreiche andere Konten zurücksetzen. Wer Zugriff auf das Hauptpostfach erlangt, kann eine ganze Kette weiterer Konten übernehmen. Deshalb verdient das E-Mail-Konto das stärkste Passwort und unbedingt eine zweite Sicherung.

E-Mail ist zugleich der häufigste Träger von Phishing und Schadsoftware. Die zugrunde liegende Technik ist alt und wurde nicht für Sicherheit entworfen, weshalb sich Absenderangaben leicht fälschen lassen. Vorsicht bei Anhängen, Links und unerwarteten Aufforderungen ist daher bei E-Mail besonders angebracht.

## Gefälschte Absender und wie Echtheit geprüft wird

Der angezeigte Absendername und sogar die Absenderadresse lassen sich fälschen (Spoofing). Drei technische Verfahren helfen Mailservern, echte von gefälschten Mails zu unterscheiden: SPF legt fest, welche Server für eine Domain senden dürfen; DKIM versieht Mails mit einer kryptografischen Signatur der Absenderdomain; und DMARC verbindet beide und bestimmt, wie mit einer nicht bestandenen Prüfung umzugehen ist. Diese Prüfungen laufen im Hintergrund und sind ein Grund, warum plumpe Fälschungen oft im Spam landen.

Für den Nutzer bleibt entscheidend, die echte Absender-Domain genau zu lesen und Linkziele zu prüfen, ohne zu klicken. Häufig werden Domains genutzt, die echten täuschend ähneln — mit vertauschten Buchstaben, Bindestrichen oder fremder Endung. Eine technisch korrekt signierte Mail kann zudem von einem echten, aber gekaperten Konto stammen, weshalb auffälliger Inhalt auch dann zu hinterfragen ist.

## Gefährliche Anhänge und Links

Anhänge sind ein klassischer Weg für Schadsoftware. Besondere Vorsicht gilt bei ausführbaren Dateien (etwa .exe, .scr, .bat), bei Office-Dokumenten, die zum Aktivieren von Makros auffordern, sowie bei passwortgeschützten Archiven, die die Virenprüfung erschweren sollen. Eine angebliche Rechnung oder Bewerbung kann in Wahrheit ein getarntes Programm sein, besonders wenn die Dateiendung nicht zum erwarteten Typ passt.

Links in Mails führen oft auf nachgebaute Login-Seiten. Statt auf einen Mail-Link zu klicken, ruft man den Dienst über ein eigenes Lesezeichen oder die selbst eingegebene Adresse auf. Unerwartete Anhänge öffnet man nicht, auch nicht von scheinbar bekannten Absendern — im Zweifel fragt man über einen zweiten Kanal nach, ob die Mail echt ist.

## Business E-Mail Compromise und Rechnungsbetrug

Beim Business E-Mail Compromise (BEC, auch „Chef-Masche") geben sich Betrüger als Vorgesetzte, Geschäftspartner oder Lieferanten aus und veranlassen eine dringende Überweisung auf ein neues Konto. Oft ist ein echtes Postfach kompromittiert oder eine täuschend ähnliche Domain im Einsatz. Ein verbreitetes Muster ist die geänderte Bankverbindung auf einer ansonsten echt wirkenden Rechnung.

Schutz bietet ein fester Ablauf statt Vertrauen auf den Anschein: Geänderte Zahlungsdaten und ungewöhnliche, eilige Zahlungsanweisungen prüft man immer über einen zweiten, bekannten Kanal — einen Rückruf unter der seit Langem bekannten Nummer, nicht der aus der Mail. Ein Vier-Augen-Prinzip und feste Freigabegrenzen verhindern, dass eine einzelne gefälschte Mail eine Zahlung auslöst.

## Das E-Mail-Konto absichern

Das Postfach sichert man mit einem langen, einzigartigen Passwort und phishing-resistenter Zwei-Faktor-Authentifizierung. Regelmäßig prüft man die Kontoeinstellungen auf unbekannte Weiterleitungen und Filterregeln — ein verbreiteter Trick nach einer Übernahme ist eine heimliche Weiterleitung, die Kopien aller Mails an den Angreifer schickt oder bestimmte Nachrichten automatisch löscht.

Hilfreich ist eine getrennte Adresse für wichtige Konten wie Bank und Behörden und eine andere für Newsletter und Anmeldungen, damit nicht alles an einem Postfach hängt. Alte, ungenutzte Postfächer schließt man, statt sie als ungesicherte Hintertür bestehen zu lassen.
