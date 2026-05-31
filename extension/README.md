# AEGIS Browser-Guard

Manifest V3 Browser-Erweiterung für **Brave / Chrome / Edge**. Schützt vor
IP-Loggern, Tracking-/Phishing-Domains und verdächtigen Downloads — und koppelt
sich optional an die AEGIS-Desktop-App.

Feste Extension-ID: `bocgjfbkopfjpnnhfoofmmkfpmdchfnl`

## Was sie tut

- **declarativeNetRequest** — 38 bekannte IP-Logger-/Grabber-Domains
  (Grabify, IPLogger, 2no.co, Blasze, …) werden auf Netzwerkebene blockiert,
  bevor überhaupt eine Verbindung aufgebaut wird.
- **Pre-Navigation-Warnung** — ruft die Seite eine Risiko-Domain auf, landet
  der Tab auf einer Dark-Glass-Warnseite mit voller URL + „trotzdem fortfahren".
- **Download-Blocker** — `.exe/.scr/.bat/.ps1/.js/.msi/…` von Risiko-Domains
  werden abgebrochen + als Benachrichtigung gemeldet.
- **Link-Highlighting** — verdächtige Links bekommen auf jeder Seite einen Marker.
- **Allowlist** — pro Domain „trotzdem fortfahren", wird lokal gespeichert.
- **Desktop-Kopplung** (Native Messaging) — meldet blockierte Navigationen und
  Downloads an die AEGIS-Desktop-App (erscheinen im Live-Stream) und zieht die
  Blocklist live aus der Desktop-Threat-Intel.

## Installation

### 1 — Extension laden

1. Browser öffnen → `brave://extensions` (bzw. `chrome://extensions` /
   `edge://extensions`)
2. **Entwicklermodus** einschalten (Toggle oben rechts)
3. **Entpackte Erweiterung laden** → **diesen `extension/`-Ordner** auswählen
4. Das Schild-Icon erscheint in der Toolbar. Die ID muss
   `bocgjfbkopfjpnnhfoofmmkfpmdchfnl` sein (durch den `key` im Manifest fixiert).

Ab hier läuft der volle Browser-Schutz — auch ohne Desktop-Kopplung.

### 2 — Desktop-Kopplung aktivieren (optional)

Einmalig den Native-Messaging-Host registrieren (kein Admin nötig, nur HKCU):

```
python aegis2\setup\install_native_host.py
```

Danach Browser neu starten. Die Extension verbindet sich automatisch mit der
Desktop-App; blockierte Ereignisse tauchen im AEGIS-Live-Stream auf.

Deinstallation der Kopplung: die drei `NativeMessagingHosts\com.aegis.guard`
Schlüssel unter `HKCU\Software\{Google\Chrome, BraveSoftware\Brave-Browser,
Microsoft\Edge}` löschen.

## Aufbau

| Datei | Zweck |
|-------|-------|
| `manifest.json` | MV3-Manifest, feste ID (`key`), Berechtigungen, DNR-Ruleset |
| `rules.json` | 38 declarativeNetRequest-Blockregeln |
| `blocklist.js` | dieselben Domains für die JS-Laufzeitprüfung |
| `background.js` | Service-Worker: Navigation/Downloads + Native-Messaging |
| `content.js` | Link-Highlighting im Seiteninhalt |
| `popup.html/js` | Toolbar-Popup mit Statistik (Dark Glass) |
| `warn.html/css/js` | Warnseite bei blockierter Navigation |
| `icons/` | Schild-Icons 16/48/128 |

Der Host-Code liegt in der Desktop-App: `aegis2/setup/native_host.py`
(+ `install_native_host.py` als Registrar).
