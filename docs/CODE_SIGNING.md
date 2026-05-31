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

**Exakte Schritte (einmalig, nur der Repo-Owner kann sie tun — Konto/Identität):**
1. **Konto:** auf https://signpath.io kostenlos registrieren.
2. **OSS-Antrag:** auf https://about.signpath.io/product/open-source das **Foundation-Programm** für `https://github.com/user0346/aegis` beantragen (MIT + public). Review dauert i.d.R. ein paar Tage.
3. **Nach Freigabe** in SignPath: ein **Project** anlegen (merke dir den *project-slug*, z.B. `aegis`), eine **Signing Policy** (merke dir den *signing-policy-slug*, z.B. `release-signing`), GitHub als *Trusted Build System* verknüpfen, und einen **API-Token** erzeugen. Notiere zusätzlich deine **Organization ID**.
4. **GitHub:** Repo → *Settings → Secrets and variables → Actions → New repository secret* — zwei Secrets anlegen: `SIGNPATH_API_TOKEN` (der Token) und `SIGNPATH_ORGANIZATION_ID` (die Org-ID).
5. **Mir die zwei Slugs nennen** (project-slug + signing-policy-slug) → ich setze sie in `release.yml` (stehen aktuell als Platzhalter `aegis`/`release-signing`) und cutte ein signiertes Release.

Der CI-Signier-Schritt ist in `.github/workflows/release.yml` (Job `build-exe-windows`, zwischen *Build* und *Zip*) **schon eingebaut** und **gegen die aktuelle `action.yml` von `signpath/github-action-submit-signing-request` verifiziert** (Parameter `api-token`, `organization-id`, `project-slug`, `signing-policy-slug`, `github-artifact-id`, `wait-for-completion`, `output-artifact-directory` stimmen). Er ist **inaktiv**, solange die Secrets aus Schritt 4 fehlen → die heutige CI bleibt unverändert.

Danach: signierte exe → SmartScreen/Smart App Control vertraut ihr (Reputation baut sich auf) → Block verschwindet, Install + Updates laufen ohne Klick durch. **Wichtig (Smart App Control):** SAC ist strenger als SmartScreen und baut Vertrauen erst über die Microsoft-Cloud auf — eine frisch signierte App kann anfangs noch geprüft werden, wird dann aber erkannt. Ohne Signatur bleibt SAC eine harte Wand.

## Alternative (kostenpflichtig)
**Azure Trusted Signing** (~10 $/Monat) signiert sofort Microsoft-vertrauenswürdig —
nur relevant, falls später Budget da ist.
