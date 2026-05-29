# Security Policy — AEGIS

## Supported Versions

Aktuell wird nur die jeweils letzte v2.x.y Release-Linie aktiv mit
Sicherheits-Patches versorgt. Aeltere Versionen sollten nicht produktiv
eingesetzt werden.

| Version | Supported |
|---------|-----------|
| 2.x     | ja        |
| < 2.0   | nein      |

---

## Reporting a Vulnerability

**Bitte oeffne KEIN public GitHub Issue** fuer Sicherheitsluecken.

Schicke stattdessen einen Bericht an den Maintainer:

- GitHub Private Vulnerability Report:
  https://github.com/user0346/aegis/security/advisories/new
- Alternativ: GitHub `@user0346` direkt via private channel kontaktieren

**Bitte enthalte:**
1. Betroffene Version(en)
2. Reproduktions-Schritte (PoC wenn moeglich)
3. Erwartetes vs. tatsaechliches Verhalten
4. Impact-Einschaetzung (lokale Eskalation, RCE, Datenleak, etc.)
5. Vorgeschlagener Fix wenn vorhanden

**Erwartete Reaktionszeiten:**

| Phase | Ziel-SLA |
|---|---|
| Erstantwort | 72h |
| Triage (Severity + Plan) | 7 Tage |
| Fix-Release | 30 Tage bei High/Critical, 90 Tage bei Medium/Low |

---

## Coordinated Disclosure

Wir folgen Standard Coordinated Disclosure. Reporter werden im Release-
Note und Security-Advisory genannt (oder anonym wenn gewuenscht).

Bitte gib uns **mindestens 30 Tage** vor Public-Disclosure, damit ein
Fix released und User Zeit zum Update haben.

---

## Threat-Model

AEGIS ist Endpoint-Security-Software, die auf Windows-Maschinen lokal
laeuft. Relevante Threat-Surfaces:

| Surface | Mitigations |
|---|---|
| **Update-Pipeline** | Sigstore keyless OIDC signing + Rekor Transparency-Log. Verifikation prueft Cert-Identity gegen Repo-URL. Modifizierte ZIP wird abgelehnt. |
| **IPC zwischen UI und Service** | Named-Pipe mit DACL-Restriction + DPAPI-encrypted Token + JSON-Schema-Validation. Nur User-Session und SYSTEM koennen verbinden. |
| **Lokale Secrets** | API-Keys, Consent-Install-Secret, IPC-Token via Windows DPAPI verschluesselt (Key gebunden an User-Account). |
| **Brute-Force auf Pin** | Exponential-Backoff nach 3 Versuchen, 24h Hard-Lock nach 12. |
| **Code-Integrity** | TrustedInstaller-ACL + WDAC-Policy. System-Files koennen nur von Updater (signed) modifiziert werden. |
| **Cognition-Prompt-Injection** | Output-Sanitizer mit Allowlist, Consent-Layer fuer alle elevated Actions. Claude darf nichts ohne signed Token ausfuehren. |
| **Router/ARP-Spoofing** | Gateway-MAC-Pin + DNS-Server-Pin + Anomaly-Watcher emitten Sir-Mode-Alert. |

---

## Out of Scope

| Topic | Warum |
|---|---|
| DDoS auf User-Endpoint | Upstream-Problem (Router/ISP), nicht Endpoint-loesbar |
| Pre-Boot-Persistence (BIOS/UEFI Implants) | Wir lesen TPM-PCRs zur Detection, koennen Bootkit aber nicht entfernen |
| Zero-Days in Drittsoftware | Wir koennen melden, nicht patchen |
| Bugs in Windows Defender/Service | Direkt bei Microsoft melden |

---

## Disclosure-Hall-of-Fame

(Liste mit credited Reportern wird hier ergaenzt sobald erste Reports
verifiziert wurden.)

---

## Cryptographic Guarantees

- **Update-Integritaet:** Sigstore keyless OIDC, Cert-Lifetime 10min,
  Eintrag permanent in Rekor-Transparency-Log
- **Update-Authentication:** Cert-Identity muss
  `https://github.com/user0346/aegis/.github/workflows/release.yml.*`
  matchen
- **Lokale Secrets:** DPAPI mit `CRYPTPROTECT_LOCAL_MACHINE = 0`
  (User-bound, nicht Maschine-bound)
- **Consent-Token:** HMAC-SHA256 mit Install-Secret (urlsafe-48 generiert)
- **TLS:** TLS 1.2+ enforced fuer alle Out-Going-Calls (Anthropic, GitHub, VT)
