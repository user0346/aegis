# Konto- und Passwort-Sicherheit (Stand 2026)

Kuratiertes Hintergrundwissen für AEGIS. Gesicherte Fakten, keine Anweisungen.

## Was ein starkes Passwort heute ausmacht

Ein starkes Passwort ist heute vor allem ein langes Passwort. Das US-Institut NIST empfahl 2025 in seiner aktualisierten Leitlinie, Länge über Komplexität zu stellen: Ein eigenständiges Passwort sollte mindestens fünfzehn Zeichen haben. Lange Passwörter widerstehen dem automatischen Durchprobieren ungleich besser als kurze, die nur mit Sonderzeichen gespickt sind.

Eine Passphrase aus mehreren zufälligen Wörtern ist sicherer und zugleich leichter zu merken als ein kurzes kryptisches Passwort. Mehrere voneinander unabhängige Wörter ergeben eine hohe Zahl möglicher Kombinationen und damit eine große Widerstandskraft gegen das Erraten. Erzwungene Mischregeln aus Groß-, Kleinbuchstaben, Ziffer und Sonderzeichen führen dagegen oft nur zu vorhersehbaren Mustern wie einem angehängten Ausrufezeichen.

Erzwungener regelmäßiger Passwortwechsel gilt nach aktueller Empfehlung als überholt. Ein Passwort sollte nur dann gewechselt werden, wenn ein konkreter Anlass besteht — etwa ein Datenleck oder ein Verdacht auf Kompromittierung. Häufiger Pflichtwechsel verleitet Nutzer dazu, nur kleine, leicht erratbare Änderungen vorzunehmen.

## Warum jedes Konto ein eigenes Passwort braucht

Das wichtigste Prinzip lautet: für jeden Dienst ein eigenes, einzigartiges Passwort. Wird ein Passwort bei einem Anbieter gestohlen, probieren Angreifer es automatisiert bei vielen anderen Diensten durch (Credential Stuffing). Mehrfach verwendete Passwörter verwandeln ein einzelnes Datenleck so in die Übernahme zahlreicher Konten.

Besonders schützenswert ist das Passwort des zentralen E-Mail-Kontos, denn über die Funktion „Passwort vergessen" lassen sich darüber viele andere Konten zurücksetzen. Wer Zugriff auf das Hauptpostfach erlangt, kann eine ganze Kette weiterer Konten übernehmen. Das E-Mail-Konto verdient daher das stärkste Passwort und unbedingt eine zweite Sicherung.

## Passwort-Manager

Ein Passwort-Manager ist ein Programm, das für jeden Dienst ein langes, zufälliges und einzigartiges Passwort erzeugt, verschlüsselt speichert und beim Anmelden automatisch einsetzt. Der Nutzer muss sich nur noch ein einziges starkes Master-Passwort merken. Damit lässt sich die Regel „für jeden Dienst ein eigenes langes Passwort" überhaupt erst im Alltag durchhalten.

Ein nützlicher Nebeneffekt vieler Passwort-Manager ist der Phishing-Schutz: Sie tragen gespeicherte Zugangsdaten nur auf der echten, hinterlegten Domain ein. Erscheint das automatische Ausfüllen auf einer Seite nicht, ist das ein deutlicher Hinweis, dass die Adresse gefälscht ist. Das Master-Passwort selbst sollte besonders lang sein und durch eine zweite Sicherung geschützt werden.

## Zwei-Faktor-Authentifizierung

Zwei-Faktor-Authentifizierung (2FA, auch Mehr-Faktor-Authentifizierung) verlangt beim Anmelden zusätzlich zum Passwort einen zweiten Nachweis, etwa einen Code aus einer App, einen Hardware-Schlüssel oder eine Bestätigung am Telefon. Selbst wenn ein Angreifer das Passwort kennt, fehlt ihm dieser zweite Faktor. 2FA gehört zu den wirksamsten und einfachsten Schutzmaßnahmen überhaupt.

Nicht jeder zweite Faktor ist gleich stark. Codes per SMS sind besser als gar kein zweiter Faktor, lassen sich aber durch Umleiten der Nummer oder Echtzeit-Phishing abfangen. Codes aus einer Authenticator-App sind sicherer; am stärksten sind phishing-resistente Verfahren wie Hardware-Sicherheitsschlüssel und Passkeys. Bestätigungscodes und Einmalpasswörter gibt man niemals an Anrufer oder über fremde Links weiter.

## Passkeys

Ein Passkey ersetzt das Passwort durch ein kryptografisches Schlüsselpaar, das auf dem Gerät gespeichert und per Fingerabdruck, Gesicht oder Geräte-PIN freigegeben wird. Es gibt kein Passwort mehr, das man vergessen, erraten oder bei einem Datenleck stehlen könnte. Passkeys beruhen auf dem offenen FIDO/WebAuthn-Standard und werden 2026 von immer mehr großen Diensten unterstützt.

Der entscheidende Vorteil von Passkeys ist ihre Phishing-Resistenz: Ein Passkey ist fest an die echte Domain des Dienstes gebunden. Versucht man, sich damit auf einer gefälschten Seite anzumelden, schlägt die Anmeldung fehl, weil die Domain nicht passt. Damit laufen klassische Phishing-Angriffe auf abgegriffene Zugangsdaten ins Leere.

## Datenleck und Account-Übernahme

Bei einem Datenleck (Data Breach) gelangen Zugangsdaten oder andere persönliche Informationen eines Dienstes in falsche Hände, oft durch einen Einbruch beim Anbieter. Ob die eigene E-Mail-Adresse betroffen ist, lässt sich über seriöse Prüfdienste wie „Have I Been Pwned" kostenlos abfragen. Nach einem Leck ändert man das betroffene Passwort sowie das aller Konten, die dasselbe oder ein ähnliches Passwort nutzen.

Anzeichen für eine Konto-Übernahme sind Benachrichtigungen über Passwort-Zurücksetzungen, die man nicht angefordert hat, Anmeldungen aus unbekannten Orten oder von fremden Geräten sowie nicht selbst vorgenommene Änderungen an den Kontoeinstellungen. Verdächtig sind außerdem eine neu hinterlegte Wiederherstellungs-Mailadresse oder -Telefonnummer, eine plötzlich deaktivierte Zwei-Faktor-Sicherung oder geänderte Sicherheitsfragen.

Bei Verdacht auf eine Übernahme handelt man sofort: Passwort über das echte Konto ändern, alle aktiven Sitzungen abmelden, die Zwei-Faktor-Authentifizierung prüfen und neu einrichten sowie kontrollieren, ob unbekannte Wiederherstellungswege oder Weiterleitungen eingetragen wurden. Wurden Zahlungs- oder Ausweisdaten offengelegt, beobachtet man zusätzlich Kontoauszüge auf unbekannte Abbuchungen und sichert betroffene Zahlungsmittel.
