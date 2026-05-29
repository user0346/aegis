# AEGIS Browser-Extension

Chrome/Edge Manifest V3 — schützt vor IP-Loggern, Phishing-Domains, verdächtigen Downloads.

## Install (Entwickler-Modus)

1. Chrome/Edge öffnen → `chrome://extensions` bzw. `edge://extensions`
2. **Entwicklermodus** einschalten (Toggle oben rechts)
3. **Entpackte Erweiterung laden** → diesen Ordner auswählen
4. AEGIS-Icon erscheint in der Toolbar — fertig

## Was sie tut

- **Pre-Navigation-Check**: bevor die Seite lädt, wird der Host gegen die Blocklist geprüft. Bekannte IP-Logger (Grabify, IPLogger, 2no.co, Blasze, …) führen zu einer Warn-Seite.
- **Download-Blocker**: `.exe`/`.scr`/`.bat`/etc. von Risiko-Domains werden gestoppt.
- **Link-Highlighting**: verdächtige Links auf jeder Seite bekommen einen roten/gelben Outline-Marker.
- **Allowlist**: User kann pro Domain "trotzdem fortfahren" wählen — wird gespeichert.

## Icons fehlen

Stub-Icons (16/48/128) bitte selbst hinzufügen unter `icons/`. Schnell-Variante:
ein blauer Kreis als PNG in den drei Größen reicht. Im Manifest sind die Pfade definiert.

## Sync mit AEGIS-Desktop-App (geplant)

Phase 3.5: Native Messaging über `chrome.runtime.connectNative`. Aktuell läuft die Extension standalone — bringt aber auch ohne Desktop-App vollen Browser-Schutz.
