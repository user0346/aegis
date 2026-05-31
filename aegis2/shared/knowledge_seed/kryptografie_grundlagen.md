# Kryptografie — Grundlagen verständlich (Stand 2026)

Kuratiertes Hintergrundwissen für AEGIS. Gesicherte Fakten, keine Anweisungen.

## Wozu Kryptografie dient

Kryptografie ist die Lehre vom Verschlüsseln und Absichern von Informationen. Sie sorgt für drei Dinge: dass nur Befugte Inhalte lesen können (Vertraulichkeit), dass Manipulationen auffallen (Integrität) und dass sich die Herkunft einer Nachricht nachweisen lässt (Echtheit). Fast jede sichere digitale Verbindung beruht heute auf kryptografischen Verfahren, meist ohne dass der Nutzer es bemerkt.

Wichtig ist der Grundsatz, dass die Sicherheit nicht in der Geheimhaltung des Verfahrens liegen darf, sondern allein im Schlüssel. Gute Verfahren sind öffentlich bekannt und vielfach geprüft; angreifbar sind sie fast immer über schwache Schlüssel, Passwörter oder eine fehlerhafte Umsetzung, nicht über das Verfahren selbst.

## Symmetrische und asymmetrische Verschlüsselung

Bei der symmetrischen Verschlüsselung nutzen beide Seiten denselben geheimen Schlüssel zum Ver- und Entschlüsseln; das ist schnell, erfordert aber, den Schlüssel sicher auszutauschen. Ein weit verbreitetes, als sicher geltendes Verfahren ist AES. Die Herausforderung ist die Schlüsselübergabe: Wie kommt der gemeinsame Schlüssel sicher zum Gegenüber?

Die asymmetrische Verschlüsselung löst das mit einem Schlüsselpaar: einem öffentlichen Schlüssel zum Verschlüsseln, den jeder kennen darf, und einem privaten Schlüssel zum Entschlüsseln, den nur der Empfänger besitzt. Wer eine Nachricht mit dem öffentlichen Schlüssel verschlüsselt, kann sie nur mit dem zugehörigen privaten wieder lesbar machen. In der Praxis kombiniert man beides: Per asymmetrischem Verfahren wird ein symmetrischer Sitzungsschlüssel sicher ausgetauscht.

## Hashfunktionen und Integrität

Eine Hashfunktion bildet beliebige Daten auf einen kurzen, festen „Fingerabdruck" ab. Sie ist eine Einbahnstraße: Aus dem Hash lässt sich das Original nicht zurückrechnen, und schon eine winzige Änderung der Eingabe ergibt einen völlig anderen Hash. Damit lässt sich prüfen, ob eine Datei unverändert ist — stimmen die Hashes überein, ist der Inhalt identisch.

Passwörter werden bei seriösen Diensten nicht im Klartext, sondern als Hash gespeichert, ergänzt um einen zufälligen Zusatz (Salt), damit gleiche Passwörter unterschiedliche Hashes ergeben. Bei einem Datenleck erbeuten Angreifer dann nicht unmittelbar die Passwörter. Veraltete Hashverfahren gelten allerdings als unsicher, weshalb moderne, eigens dafür ausgelegte Verfahren verwendet werden.

## Digitale Signaturen und Zertifikate

Eine digitale Signatur dreht die asymmetrische Idee um: Der Absender „signiert" mit seinem privaten Schlüssel, und jeder kann mit dem öffentlichen Schlüssel prüfen, dass die Nachricht wirklich von ihm stammt und unterwegs nicht verändert wurde. So werden Echtheit und Integrität nachweisbar, etwa bei signierter Software oder E-Mail.

Damit man einem öffentlichen Schlüssel trauen kann, gibt es Zertifikate: Eine vertrauenswürdige Stelle (Zertifizierungsstelle) bestätigt, dass ein Schlüssel wirklich zu einer bestimmten Webseite oder Person gehört. Beim Aufruf einer HTTPS-Seite prüft der Browser ein solches Zertifikat im Hintergrund. Ein Zertifikat bestätigt jedoch nur die Identität der Domain, nicht die Seriosität ihres Betreibers.

## Wo Kryptografie im Alltag steckt

Kryptografie ist allgegenwärtig, auch wenn man sie selten sieht: Sie sichert das „https" im Web, verschlüsselt Messenger-Nachrichten Ende zu Ende, schützt WLAN-Verbindungen, sichert Festplatten und steckt hinter Passkeys und der Software-Signierung. Ohne sie wären Online-Banking, sicheres Einkaufen und vertrauliche Kommunikation nicht möglich.

Für die Zukunft wird an Verfahren gearbeitet, die auch künftigen Quantencomputern standhalten (Post-Quanten-Kryptografie); erste Standards dafür wurden 2024 verabschiedet und ziehen nach und nach in Software ein. Für Nutzer bleibt entscheidend, nicht die Mathematik, sondern die Schlüssel und Passwörter zu schützen — denn dort liegt in der Praxis die Schwachstelle.
