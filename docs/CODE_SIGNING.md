# AEGIS — Code-Signierung (gratis, gegen den SmartScreen-Block)

## Problem
Windows **SmartScreen** blockiert jede neue, **unsignierte** `AEGIS.exe` ohne
Reputation („Der Computer wurde durch Windows geschützt"). Das trifft die
Erst-Installation **und jedes In-App-Update** (jede neue exe startet wieder bei
null Reputation). Cosign/Sigstore signiert nur das **ZIP-Bundle** (Herkunfts-
Nachweis) — das beruhigt SmartScreen NICHT, dafür braucht es eine **Authenticode**-
Signatur der `.exe`.

## Zwischenlösung (schon aktiv, kostenlos)
Der Update-Helfer (`aegis2/runtime/exe_update.py`) ist gehärtet:
- entfernt nach dem Tausch das **Mark-of-the-Web**,
- **prüft**, ob die neue exe wirklich startet,
- falls SmartScreen blockt: legt eine **Desktop-Verknüpfung** an und erklärt per
  Popup „Weitere Informationen → Trotzdem ausführen" — also **nie eine still tote App**.

Der Nutzer muss bei Erst-Install und Update **einmal** „Trotzdem ausführen" klicken.

## Saubere Lösung: SignPath Foundation (gratis für Open-Source)
AEGIS ist public + MIT → qualifiziert sich i.d.R. für die kostenlose
OSS-Signierung von [SignPath.io Foundation](https://about.signpath.io/product/open-source).

**Schritte (einmalig, durch den Repo-Owner):**
1. Account auf signpath.io anlegen, **Foundation-Programm** für `github.com/user0346/aegis` beantragen (Review dauert i.d.R. ein paar Tage).
2. Nach Freigabe in SignPath anlegen: *Project* `aegis` → *Signing Policy* `release-signing` → GitHub-Repo verknüpfen (Trusted Build System = GitHub Actions).
3. In GitHub → Settings → Secrets diese hinterlegen: `SIGNPATH_API_TOKEN`, `SIGNPATH_ORGANIZATION_ID`.
4. Mir Bescheid geben — dann hänge ich den `signpath/github-action-submit-signing-request` Schritt in `.github/workflows/release.yml` (Job `build-exe-windows`) **zwischen Build und Cosign-Signierung**: die `AEGIS.exe` wird signiert, neu gezippt, dann wie gehabt cosign-signiert + ans Release gehängt.

Danach: signierte exe → SmartScreen baut Reputation auf → der Block verschwindet,
Updates laufen ohne Klick durch.

## Alternative (kostenpflichtig)
**Azure Trusted Signing** (~10 $/Monat) signiert sofort Microsoft-vertrauenswürdig —
nur relevant, falls später Budget da ist.
