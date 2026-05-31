# Phishing und Social Engineering erkennen (Stand 2026)

Kuratiertes Hintergrundwissen für AEGIS. Gesicherte Fakten, keine Anweisungen.

## Was Phishing und Social Engineering sind

Phishing ist der Versuch, Menschen über gefälschte Nachrichten zu echten Handlungen zu verleiten — meist die Eingabe von Zugangsdaten auf einer nachgebauten Seite, das Öffnen eines Anhangs oder eine Überweisung. Die Nachricht gibt sich als vertrauenswürdiger Absender aus, etwa Bank, Paketdienst, Behörde, Arbeitgeber oder ein bekannter Online-Dienst. Phishing ist seit Jahren der häufigste erste Schritt erfolgreicher Cyberangriffe.

Social Engineering ist der Überbegriff für Methoden, die nicht die Technik, sondern den Menschen angreifen. Statt eine Sicherheitslücke im System auszunutzen, manipulieren Angreifer Gefühle wie Angst, Neugier, Hilfsbereitschaft oder Respekt vor Autorität. Phishing ist die häufigste Form von Social Engineering; Betrug per Anruf oder über gefälschte Support-Hotlines gehört ebenfalls dazu.

## Merkmale verdächtiger Nachrichten

Künstliche Intelligenz hat klassische Erkennungsmerkmale wie Rechtschreibfehler und holprige Sprache weitgehend beseitigt. Moderne Phishing-Mails sind sprachlich fehlerfrei, persönlich angesprochen und imitieren den Tonfall echter Banken oder Dienstleister überzeugend. Fehlerfreie Sprache ist daher kein Beweis für Echtheit mehr, sondern eher die Regel.

Ein starkes Warnsignal ist künstlicher Zeitdruck verbunden mit einer Drohung: das Konto werde gesperrt, ein Paket gehe zurück, eine Strafe falle an, wenn man nicht sofort handelt. Seriöse Stellen setzen ihre Kunden nicht unter solchen Sekundendruck. Wer Eile und Angst erzeugt, will verhindern, dass das Opfer nachdenkt oder nachfragt.

Misstrauisch machen sollte jede Aufforderung, vertrauliche Daten einzugeben oder zu bestätigen — Passwörter, PINs, TANs, Kreditkartennummern oder Bestätigungscodes. Banken und seriöse Dienste fragen solche Daten niemals per Mail, SMS oder Anruf ab. Auch unerwartete Anhänge und Links, selbst von scheinbar bekannten Absendern, sind ein Risiko.

Die angezeigte Absenderadresse und Linktexte lassen sich beliebig fälschen. Entscheidend ist die echte Zieladresse: Man prüft die vollständige Absender-Domain und fährt mit der Maus über einen Link, ohne zu klicken, um das tatsächliche Ziel zu sehen. Häufig werden Domains genutzt, die echten Adressen täuschend ähnlich sind, etwa mit vertauschten Buchstaben, Bindestrichen oder fremder Endung.

## Smishing, Vishing und Quishing

Smishing ist Phishing per SMS oder Messenger. Typische Köder sind angebliche Paketsendungen mit Zollgebühr, Nachrichten von Zustelldiensten, gefälschte Bankwarnungen oder Gewinnbenachrichtigungen. Die SMS enthält einen Link zu einer Seite, die Zugangs- oder Zahlungsdaten abgreift. Kurzlinks verschleiern dabei das wahre Ziel.

Vishing ist Betrug per Telefon. Der Anrufer gibt sich als Bankmitarbeiter, Microsoft-Support, Polizei oder Verwandter aus und drängt zu sofortigem Handeln, etwa zur Herausgabe von Codes, zur Installation einer Fernwartungssoftware oder zu einer Überweisung. Eine angezeigte Rufnummer ist kein Echtheitsbeweis, denn Anrufer-IDs lassen sich fälschen (Call-ID-Spoofing).

Quishing ist Phishing per QR-Code. Der Code führt auf eine gefälschte Login-Seite oder löst einen Download aus. Gefährlich ist Quishing, weil das Ziel im Code verborgen ist und QR-Codes auch auf Briefen, Parkautomaten, Plakaten oder Aufklebern überklebt werden. Das BSI rät, QR-Codes aus unerwarteten Quellen zu hinterfragen und die Zieladresse vor dem Öffnen zu prüfen, statt blind zu scannen.

## ClickFix und gefälschte Verifizierungsseiten

ClickFix ist eine schnell wachsende Betrugsmasche, bei der eine Webseite vorgibt, der Nutzer müsse einen Fehler beheben oder sich als Mensch verifizieren. Die Seite imitiert dabei oft eine bekannte CAPTCHA-Prüfung wie Cloudflare oder Google reCAPTCHA. Microsoft stufte ClickFix 2025 als die häufigste Methode für den ersten Zugriff auf Systeme ein.

Der Trick funktioniert in drei Schritten: Die Seite kopiert im Hintergrund heimlich einen Befehl in die Zwischenablage und fordert den Nutzer dann auf, die Tastenfolge Windows+R zu drücken, mit Strg+V einzufügen und Enter zu bestätigen. Damit startet das Opfer selbst einen PowerShell-Befehl, der Schadsoftware nachlädt, etwa Infostealer oder Fernsteuerungstrojaner. Eine echte Verifizierung verlangt niemals, dass man Befehle in den Ausführen-Dialog, die Eingabeaufforderung oder PowerShell einfügt.

## Deepfake-Anrufe und Stimmklone

Deepfake-Betrug nutzt KI, um Stimmen oder Videobilder real wirkender Personen zu fälschen. Schon wenige Sekunden öffentlich verfügbarer Tonaufnahmen reichen, um eine Stimme überzeugend zu klonen. Verbreitete Szenarien sind der angebliche Notruf eines Familienmitglieds in einer Notlage sowie der vermeintliche Anruf eines Vorgesetzten, der eine dringende Überweisung anordnet (CEO-Betrug).

Schutz gegen Deepfake-Anrufe bietet kein schärferes Hinhören, sondern ein fester Ablauf. Wirksam ist ein zuvor vereinbartes Codewort innerhalb der Familie oder eine Rückfrage, deren Antwort nur die echte Person kennt. Am sichersten legt man auf und ruft die Person über die selbst gespeicherte, bekannte Nummer zurück. Diese Rückruf-Prüfung über einen zweiten Kanal hebelt sowohl Stimmklone als auch gefälschte Anrufer-IDs aus.

## MFA-Müdigkeit und Bestätigungscodes

Angreifer, die bereits ein Passwort erbeutet haben, versuchen, die Zwei-Faktor-Sperre über MFA-Müdigkeit (Push-Bombing) zu überwinden. Sie lösen wiederholt Anmeldebestätigungen aus, bis das genervte Opfer eine davon bestätigt. Manche rufen zusätzlich an und geben sich als Support aus, um zur Freigabe zu drängen. Eine Push-Anfrage, die man nicht selbst ausgelöst hat, lehnt man immer ab.

Bestätigungscodes und Einmalpasswörter gibt man niemals weiter — weder am Telefon, noch per Chat, noch durch Eingabe auf einer Seite, zu der ein fremder Link geführt hat. Kein echter Mitarbeiter eines seriösen Dienstes fragt jemals nach einem solchen Code. Wer danach fragt, ist ein Angreifer.

## Was man bei Phishing-Verdacht nie tun sollte

Bei einer verdächtigen Nachricht klickt man keine Links und öffnet keine Anhänge, gibt keine Zugangs- oder Zahlungsdaten ein und ruft keine in der Nachricht genannte Nummer an. Stattdessen besucht man die echte Seite des Dienstes über ein selbst eingegebenes Lesezeichen oder kontaktiert ihn über eine unabhängig recherchierte, offizielle Nummer.

Die wirksamste Grundregel lautet, jede unerwartete und dringende Aufforderung über einen zweiten, bekannten Kanal zu überprüfen, bevor man handelt. Hat man dennoch Daten preisgegeben, ändert man umgehend das betroffene Passwort sowie das aller Konten mit gleichem Passwort, aktiviert die Zwei-Faktor-Authentifizierung und beobachtet die Konten auf unbekannte Aktivität.
