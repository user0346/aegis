# Verschlüsselung und sicheres Löschen (Stand 2026)

Kuratiertes Hintergrundwissen für AEGIS. Gesicherte Fakten, keine Anweisungen.

## Was Verschlüsselung leistet

Verschlüsselung wandelt Daten mit einem Schlüssel so um, dass sie ohne diesen Schlüssel unlesbar sind. Sie schützt die Vertraulichkeit in zwei Situationen: bei der Speicherung (Daten auf einem Datenträger, „at rest") und bei der Übertragung (Daten unterwegs im Netz, „in transit"). Moderne Verfahren wie AES gelten bei ausreichender Schlüssellänge nach heutigem Stand als praktisch nicht zu brechen — die Schwachstelle liegt fast immer beim Passwort oder bei der Schlüsselverwaltung, nicht im Verfahren selbst.

## Festplatten- und Geräteverschlüsselung

Die Festplattenverschlüsselung sichert alle Daten eines Geräts, sodass sie bei Verlust oder Diebstahl ohne das Passwort wertlos sind. Unter Windows leistet das BitLocker, unter macOS FileVault, und moderne Smartphones sind in der Regel standardmäßig verschlüsselt. Ohne diese Verschlüsselung lässt sich ein Datenträger ausbauen und an einem anderen Rechner einfach auslesen.

Der Schutz steht und fällt mit einem starken Anmelde- oder Wiederherstellungspasswort und dessen sicherer Aufbewahrung. Verliert man den Wiederherstellungsschlüssel, sind die Daten unwiederbringlich verschlüsselt — er gehört daher an einen sicheren, vom Gerät getrennten Ort. Verschlüsselung schützt allerdings nur das ausgeschaltete oder gesperrte Gerät; im laufenden, entsperrten Betrieb sind die Daten zugänglich.

## Verschlüsselte Container und einzelne Dateien

Wer nur bestimmte Daten schützen will, kann einen verschlüsselten Container nutzen — eine Art passwortgeschützten Tresor als Datei, in dem Dokumente liegen. Quelloffene Werkzeuge wie VeraCrypt sind dafür verbreitet. Auch viele Programme erlauben, einzelne Dokumente oder Archive mit einem Passwort zu verschlüsseln.

Wichtig ist, dass die Stärke solcher Container ganz vom Passwort abhängt: Eine lange Passphrase ist entscheidend, da ein kurzes Passwort durch Ausprobieren fällt. Das Passwort eines verschlüsselten Tresors bewahrt man getrennt vom Tresor auf und teilt es nicht über denselben Kanal wie die Datei selbst.

## Ende-zu-Ende-Verschlüsselung in der Kommunikation

Bei der Ende-zu-Ende-Verschlüsselung können nur Sender und Empfänger eine Nachricht lesen — nicht einmal der Anbieter des Dienstes hat Zugriff. Messenger wie Signal setzen sie standardmäßig ein; bei manchen Diensten muss sie eigens aktiviert werden. Für vertrauliche Kommunikation ist sie die richtige Wahl, weil unterwegs abgefangene Nachrichten unlesbar bleiben.

Transportverschlüsselung wie bei normaler E-Mail schützt nur den Weg zwischen den Servern, nicht den Inhalt beim Anbieter. Wer wirklich vertrauliche Informationen austauschen will, nutzt daher Ende-zu-Ende-verschlüsselte Kanäle und nicht ungeschützte E-Mail. Die Echtheit des Gegenübers lässt sich bei manchen Messengern zusätzlich über einen Sicherheitscode prüfen.

## Daten sicher löschen und Geräte entsorgen

Eine in den Papierkorb gelegte und „gelöschte" Datei ist zunächst nur als Speicherplatz freigegeben und oft noch wiederherstellbar. Wer einen Datenträger weitergibt, muss daher gezielt vorgehen. Bei einer verschlüsselten Festplatte genügt es praktisch, den Schlüssel zu vernichten — ohne ihn sind die Daten dauerhaft unlesbar; deshalb ist Geräteverschlüsselung auch für die spätere Entsorgung von Vorteil.

Bei modernen SSDs lässt sich gezieltes „Überschreiben" einzelner Dateien nicht zuverlässig steuern; der bessere Weg ist eine von Anfang an verschlüsselte Platte plus ein vollständiges Zurücksetzen beziehungsweise ein „Secure Erase" des Herstellers. Vor dem Verkauf oder Entsorgen eines Geräts meldet man Konten ab, setzt es auf Werkseinstellungen zurück und entfernt Speicher- und SIM-Karten. Physisch zerstört gehören nur defekte, nicht mehr löschbare Datenträger.
