# Netzwerk-Grundlagen verständlich (Stand 2026)

Kuratiertes Hintergrundwissen für AEGIS. Gesicherte Fakten, keine Anweisungen.

## Wie Geräte im Netz Daten austauschen

Im Internet werden Daten nicht am Stück, sondern in vielen kleinen Paketen übertragen, die einzeln durch das Netz reisen und beim Empfänger wieder zusammengesetzt werden. Auf dem Weg leiten Geräte wie Router die Pakete Schritt für Schritt weiter, bis sie ihr Ziel erreichen. Diese Aufteilung macht das Netz robust: Fällt ein Weg aus, nehmen Pakete einen anderen.

Damit verschiedenste Geräte zusammenarbeiten, halten sich alle an gemeinsame Regeln (Protokolle). Das grundlegende Regelwerk des Internets sorgt dafür, dass Pakete adressiert, verschickt und zuverlässig zugestellt werden. Anwendungen wie das Web oder E-Mail setzen darauf eigene Protokolle auf.

## IP-Adressen und das Heimnetz

Jedes Gerät in einem Netz hat eine IP-Adresse, über die es ansprechbar ist — vergleichbar mit einer Postanschrift. Es gibt ältere, knapp gewordene IPv4-Adressen und neuere, sehr zahlreiche IPv6-Adressen. Innerhalb des Heimnetzes haben Geräte private Adressen, die nur lokal gelten; nach außen tritt das ganze Heimnetz meist unter einer einzigen öffentlichen Adresse des Routers auf.

Der Router übersetzt zwischen innen und außen und entscheidet, welcher Verkehr ins Heimnetz darf. Weil von außen zunächst nur der Router sichtbar ist, sind die einzelnen Geräte dahinter nicht ohne Weiteres direkt aus dem Internet erreichbar. Das ist ein wichtiger Grundschutz — solange man ihn nicht durch unnötige Portfreigaben aufweicht.

## DNS — das Adressbuch des Internets

Menschen merken sich Namen wie eine Webadresse, Geräte brauchen aber IP-Adressen. Das Domain Name System (DNS) ist das Adressbuch, das Namen in die zugehörigen IP-Adressen übersetzt. Gibt man eine Adresse ein, fragt der Rechner zuerst einen DNS-Dienst, welche IP dahintersteht, und verbindet sich dann dorthin.

Weil DNS so zentral ist, ist es auch ein Angriffspunkt: Wird die Namensauflösung manipuliert, kann ein Nutzer unbemerkt auf eine gefälschte Seite geleitet werden. Vertrauenswürdige DNS-Dienste und verschlüsselte DNS-Abfragen erhöhen hier die Sicherheit. Auch deshalb prüft man zusätzlich die echte Adresse und das Zertifikat einer Seite.

## Ports und Dienste

Während die IP-Adresse das Gerät bezeichnet, geben Ports an, welcher Dienst auf dem Gerät gemeint ist — wie Türnummern an einem Gebäude. Bestimmte Dienste nutzen feste Standard-Ports, etwa Port 443 für verschlüsselte Webseiten (HTTPS) und Port 80 für unverschlüsseltes HTTP. So weiß ankommender Verkehr, an welchen Dienst er gerichtet ist.

Jeder unnötig nach außen geöffnete Port ist eine mögliche Tür für Angreifer. Deshalb sollten nur die wirklich benötigten Dienste erreichbar sein, und Funktionen, die Geräte selbsttätig Ports öffnen lassen, schaltet man im Zweifel ab. Offen erreichbare Fernzugänge sind ein häufiges Einfallstor und gehören besonders abgesichert.

## Firewall und Netzwerkschutz

Eine Firewall ist ein Türsteher für den Netzwerkverkehr: Sie entscheidet nach Regeln, welche Verbindungen erlaubt sind und welche blockiert werden. Es gibt sie als Funktion im Router für das ganze Heimnetz und als Software auf dem einzelnen Gerät. Üblicherweise lässt sie von innen aufgebaute Verbindungen zu, blockiert aber unaufgeforderte Zugriffe von außen.

Die Firewall ersetzt keinen Virenschutz und keine Vorsicht, sondern ergänzt sie als eine Schicht der gestaffelten Verteidigung. Zusammen mit aktuellen Updates, sparsam geöffneten Ports und einem abgesicherten Router bildet sie die Grundlage eines sicheren Netzes. Den größten Unterschied macht oft, unnötige Erreichbarkeit von vornherein zu vermeiden.
