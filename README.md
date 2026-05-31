# AEGIS

Windows endpoint security companion. Complements Windows Defender.

[![Latest Release](https://img.shields.io/github/v/release/user0346/aegis?label=latest&color=blue)](https://github.com/user0346/aegis/releases/latest)
[![Signed by Sigstore](https://img.shields.io/badge/signed-Sigstore%20keyless-blue)](https://search.sigstore.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## Download

The only supported way to get AEGIS is via signed releases.

**[→ Latest Release](https://github.com/user0346/aegis/releases/latest)**

Do not run unsigned builds. Do not download from third-party mirrors.

---

## Verify (recommended)

Every release is cryptographically signed with
[Sigstore](https://sigstore.dev) keyless OIDC. Verify before install:

```cmd
winget install --id sigstore.cosign

cosign verify-blob ^
  --certificate AEGIS.zip.crt ^
  --signature AEGIS.zip.sig ^
  --certificate-identity-regexp "https://github.com/user0346/aegis/.*" ^
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" ^
  AEGIS.zip
```

Expected: `Verified OK`

Anything else means the file has been tampered with — discard it.

---

## Install

Extract the verified ZIP and follow the instructions in the included
`INSTALL.txt`.

---

## Run from source (works even with Smart App Control)

Windows **Smart App Control** blocks unsigned executables outright — there is no
"run anyway". Until the `.exe` is Authenticode-signed, the reliable path on such
machines is to run AEGIS from source: the Python runtime itself is signed, so the
OS allows it.

**One click:**

1. Install [Python 3.11+](https://www.python.org/downloads/) and tick
   *"Add python.exe to PATH"* in the installer.
2. Get the code — `git clone https://github.com/user0346/aegis` (or download the
   source ZIP and extract it).
3. Double-click **`install.cmd`**. It installs the dependencies, runs first-time
   setup (autostart + shortcut + integrity baseline) and launches AEGIS.

**Manual equivalent:**

    py -3 -m pip install -r requirements_v2.txt
    py -3 bin\aegis_app.py --setup
    pyw -3 bin\aegis_app.py

Optional voice control: `py -3 -m pip install -r requirements_v2_voice.txt`

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
