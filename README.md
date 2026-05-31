# AEGIS

Windows endpoint security companion. Complements Windows Defender.

[![Latest Release](https://img.shields.io/github/v/release/user0346/aegis?label=latest&color=blue)](https://github.com/user0346/aegis/releases/latest)
[![Signed by Sigstore](https://img.shields.io/badge/signed-Sigstore%20keyless-blue)](https://search.sigstore.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## Installation

**Voraussetzung:** [Python 3.11+](https://www.python.org/downloads/) — beim Setup
**„Add python.exe to PATH"** anhaken.

1. **[→ Neuestes Release öffnen](https://github.com/user0346/aegis/releases/latest)**
   und unter **Assets** die Datei **`AEGIS.zip`** herunterladen.
   *(Nicht die große `AEGIS-windows-x64.zip` und nicht „Source code (zip)" — siehe
   Hinweis unten.)*
2. Rechtsklick auf die ZIP → **Eigenschaften** → **„Zulassen"/„Entsperren"** anhaken
   → **OK**, dann **entpacken**.
3. Im entpackten Ordner **`install.cmd`** doppelklicken. Das installiert die
   Abhängigkeiten, legt AEGIS am richtigen Ort ab (`%LOCALAPPDATA%\Programs\AEGIS`),
   richtet Autostart + Verknüpfung + Integritäts-Basis ein und startet es. **Fertig.**

Das ist der empfohlene, zuverlässige Weg auf jedem Windows 10/11. Den heruntergeladenen
Ordner darfst du danach löschen.

<details>
<summary>Manuelle Schritte (statt <code>install.cmd</code>)</summary>

```cmd
py -3 -m pip install -r requirements_v2.txt
py -3 bin\aegis_app.py --setup
pyw -3 bin\aegis_app.py
```

Optionale Sprachsteuerung: `py -3 -m pip install -r requirements_v2_voice.txt`
</details>

---

## ⚠️ Zur `.exe`-Version (Smart App Control)

Das Release enthält auch ein fertiges `AEGIS-windows-x64.zip` mit `AEGIS.exe`. Diese
`.exe` ist **noch nicht Authenticode-signiert** und wird deshalb von **Windows Smart
App Control** auf aktuellen Systemen **komplett blockiert** — ohne „Trotzdem
ausführen". Bitte bis zur Signierung den Weg oben (`AEGIS.zip` + `install.cmd`)
verwenden; die Python-Laufzeit selbst ist signiert, daher läuft der Quellcode-Weg
überall.

---

## Optional: Download verifizieren

Jedes Release ist mit [Sigstore](https://sigstore.dev) (keyless OIDC) signiert. Wer
möchte, prüft `AEGIS.zip` vor dem Entpacken:

```cmd
winget install --id sigstore.cosign

cosign verify-blob ^
  --certificate AEGIS.zip.crt ^
  --signature AEGIS.zip.sig ^
  --certificate-identity-regexp "https://github.com/user0346/aegis/.*" ^
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" ^
  AEGIS.zip
```

Erwartet: `Verified OK`. Alles andere → Datei verwerfen.

---

## Updates

AEGIS updates itself in the background. New releases are signed with the
same Sigstore pipeline and verified on every install.

---

## Security disclosure

For vulnerability reports, see [SECURITY.md](SECURITY.md). Please do not
open public issues for security topics.

---

## License

[MIT](LICENSE). See the file for the full text.
