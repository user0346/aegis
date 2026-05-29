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
