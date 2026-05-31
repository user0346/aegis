"""GitHub-Releases-basierter Update-Checker mit Sigstore-Verifikation.

Zero-Trust Update-Flow (2026 best practice):
  1. GET https://api.github.com/repos/{OWNER}/{REPO}/releases/latest
  2. Parse Assets: AEGIS.zip + AEGIS.zip.sig + AEGIS.zip.crt
  3. Download alle drei
  4. Verify Sigstore-Bundle:
     - Cert-Identity muss zu erwartetem GitHub-Workflow passen
     - Issuer muss token.actions.githubusercontent.com sein
     - Signature gegen ZIP-Bytes verifizieren
     - Rekor-Inclusion-Proof prüfen (Transparency Log)
  5. Match Cert-Identity gegen erwarteten Workflow → schützt vor
     Repo-Übernahme: nur Builds von DEINEM Workflow zählen
  6. Speichere validated ZIP nach ~/.aegis/updates/staged.zip
  7. Emit Event mit Approval-Request

Bei Update-Approval (UI Pin-confirm):
  → setup/auto_update.py übernimmt Atomic-Swap

Sigstore-Bibliothek ist optional. Ohne sie: SHA-only Check + Warnung.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import hashlib
from pathlib import Path
from typing import Optional

from .. import __version__
from .db import Database
from .events import EventBus, Event, Severity, Category
from .modules.base import Module


log = logging.getLogger("aegis2.github_updater")

_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
_COSIGN_DIR = Path.home() / ".aegis" / "bin"
_COSIGN_LOCAL = _COSIGN_DIR / "cosign.exe"


UPDATE_DIR = Path.home() / ".aegis" / "updates"
STAGED_ZIP = UPDATE_DIR / "staged.zip"
STAGED_META = UPDATE_DIR / "staged.json"


def parse_version(v: str) -> tuple:
    try:
        base = v.lstrip("v").split("-", 1)[0]
        return tuple(int(p) for p in base.split("."))
    except Exception:  # noqa: BLE001
        return (0,)


def fetch_latest_release(repo: str, timeout: int = 12) -> Optional[dict]:
    """Hole letztes Release über GitHub-API. Repo-Format: 'owner/name'."""
    if "/" not in repo:
        return None
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(
        url, headers={"User-Agent": f"AEGIS/{__version__}",
                      "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        log.warning("GitHub API fetch failed: %s", e)
        return None


def _download(url: str, dest: Path, timeout: int = 60) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"AEGIS/{__version__}"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                log.warning("Download HTTP %s for %s", getattr(resp, "status", "?"), url)
                return False
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("Download failed (%s): %s", url, e)
        return False


def cosign_path() -> Optional[str]:
    """Pfad zu einem nutzbaren cosign — im PATH oder lokal unter ~/.aegis/bin."""
    p = shutil.which("cosign")
    if p:
        return p
    if _COSIGN_LOCAL.exists():
        return str(_COSIGN_LOCAL)
    return None


def ensure_cosign(timeout: int = 180) -> Optional[str]:
    """Stellt cosign bereit (idempotent, self-bootstrapping). Reihenfolge:
      1) bereits vorhanden (PATH oder ~/.aegis/bin) -> zurueck
      2) winget install sigstore.cosign (User-Kontext)
      3) Direkt-Download der offiziellen Windows-Binary von github.com/sigstore/cosign

    Returns Pfad oder None. Bei None bleibt die Update-Verifikation fail-closed.
    Hinweis: der Bootstrap-Download laeuft ueber HTTPS von der offiziellen
    sigstore/cosign-Release-Seite (Verifier-Bootstrap — kann sich nicht selbst pruefen).
    """
    p = cosign_path()
    if p:
        return p
    if sys.platform != "win32":
        return None
    # (2) winget
    try:
        subprocess.run(
            ["winget", "install", "--id", "sigstore.cosign", "--silent",
             "--accept-package-agreements", "--accept-source-agreements",
             "--disable-interactivity"],
            capture_output=True, text=True, timeout=timeout, creationflags=_NO_WINDOW)
        w = shutil.which("cosign")
        if w:
            log.info("cosign via winget bereitgestellt")
            return w
    except Exception as e:  # noqa: BLE001
        log.info("cosign winget-Install nicht moeglich: %s", e)
    # (3) Direkt-Download der offiziellen Binary (latest release)
    try:
        rel = fetch_latest_release("sigstore/cosign") or {}
        url = None
        for a in rel.get("assets", []):
            if (a.get("name") or "").lower() == "cosign-windows-amd64.exe":
                url = a.get("browser_download_url")
                break
        if url:
            _COSIGN_DIR.mkdir(parents=True, exist_ok=True)
            if _download(url, _COSIGN_LOCAL):
                try:
                    _COSIGN_LOCAL.chmod(0o700)
                except Exception:  # noqa: BLE001
                    pass
                log.info("cosign nach %s heruntergeladen", _COSIGN_LOCAL)
                return str(_COSIGN_LOCAL)
    except Exception as e:  # noqa: BLE001
        log.warning("cosign Direkt-Download fehlgeschlagen: %s", e)
    return None


def verify_sigstore(zip_path: Path, sig_path: Path, cert_path: Path,
                    expected_repo: str,
                    expected_workflow: str = ".github/workflows/release.yml"
                    ) -> tuple[bool, str]:
    """Sigstore-keyless verification.

    expected_repo: 'owner/name' — only signatures from this repo's workflow accepted
    expected_workflow: must match the workflow path that ran the signing

    Returns (verified, reason).
    """
    cosign = ensure_cosign()
    if not cosign:
        return False, "cosign nicht verfuegbar (Auto-Install via winget/Download fehlgeschlagen)."
    # Cert-Identity muss exakt mit diesem Repo+Workflow beginnen, gefolgt von '@<tag-ref>'.
    # Schuetzt vor Repo-Uebernahme: nur Builds aus DEINEM Workflow zaehlen.
    identity_re = ("^https://github.com/" + re.escape(expected_repo) + "/"
                   + re.escape(expected_workflow) + "@")
    cmd = [
        cosign, "verify-blob",
        "--certificate", str(cert_path),
        "--signature", str(sig_path),
        "--certificate-identity-regexp", identity_re,
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
        str(zip_path),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=120,
                              creationflags=_NO_WINDOW)
    except Exception as e:  # noqa: BLE001
        return False, f"verify-error: {type(e).__name__}: {e}"
    if proc.returncode == 0:
        return True, "verified"
    err = (proc.stderr or b"").decode("utf-8", "ignore").strip().splitlines()
    reason = err[-1][:200] if err else f"rc={proc.returncode}"
    return False, f"cosign verify-blob failed: {reason}"


def sha256_of_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ============================================================
#  Updater Module
# ============================================================

class GitHubUpdateChecker(Module):
    """Pollt GitHub-Releases, validiert, staged Update für User-Approval."""
    name = "GitHubUpdater"

    def __init__(self, bus: EventBus, db: Database,
                 interval_h: float = 24.0):
        super().__init__(bus)
        self.db = db
        self.interval_s = max(3600.0, interval_h * 3600)
        self._last_check = 0.0
        self._last_notified_version: Optional[str] = None

    def run(self) -> None:
        # 10-min Boot-Delay
        self._stop.wait(600)
        while not self._stop.is_set():
            try:
                if time.time() - self._last_check >= self.interval_s:
                    self._check_once()
                    self._last_check = time.time()
            except Exception as e:  # noqa: BLE001
                self.emit(Severity.WARN, Category.SYSTEM,
                          f"GitHubUpdater Error: {type(e).__name__}: {e}")
            self._stop.wait(900)

    def _check_now(self) -> None:
        """Force an immediate check (called via IPC update.check)."""
        try:
            self._check_once()
            self._last_check = time.time()
        except Exception as e:  # noqa: BLE001
            log.warning("forced check failed: %s", e)

    def _check_once(self) -> None:
        repo = self.db.get_setting("update_github_repo", "")
        if not repo:
            return    # Not configured
        rel = fetch_latest_release(repo)
        if not rel:
            return

        tag = rel.get("tag_name", "")
        if not tag or tag == self._last_notified_version:
            return
        if parse_version(tag) <= parse_version(__version__):
            return    # already up to date or older

        # Phase 7: respect user's "skip this version" decision
        skipped = (self.db.get_setting("update_skipped_versions", "") or "")
        skipped_tags = set(t.strip() for t in skipped.split(",") if t.strip())
        if tag.lstrip("v") in skipped_tags:
            return

        # Phase 7: respect "remind me later" snooze
        try:
            remind_after = int(self.db.get_setting("update_remind_after_ts", "0") or 0)
            remind_ver   = (self.db.get_setting("update_remind_version", "") or "").lstrip("v")
            if remind_ver == tag.lstrip("v") and time.time() < remind_after:
                return   # still snoozed
        except (ValueError, TypeError):
            pass

        # Find assets
        zip_asset = sig_asset = cert_asset = None
        for a in rel.get("assets", []):
            n = a.get("name", "")
            if n == "AEGIS.zip": zip_asset = a
            elif n == "AEGIS.zip.sig": sig_asset = a
            elif n == "AEGIS.zip.crt" or n == "AEGIS.zip.pem": cert_asset = a
        if not zip_asset:
            self.emit(Severity.WARN, Category.SYSTEM,
                      f"Release {tag} hat keine AEGIS.zip — skip")
            return

        UPDATE_DIR.mkdir(parents=True, exist_ok=True)
        if not _download(zip_asset["browser_download_url"], STAGED_ZIP):
            return
        zip_sha = sha256_of_file(STAGED_ZIP)

        # Sigstore verification (best-effort)
        sig_ok = None
        sig_reason = "no signature provided"
        if sig_asset and cert_asset:
            sig_path = UPDATE_DIR / "staged.zip.sig"
            cert_path = UPDATE_DIR / "staged.zip.crt"
            if _download(sig_asset["browser_download_url"], sig_path) and \
               _download(cert_asset["browser_download_url"], cert_path):
                sig_ok, sig_reason = verify_sigstore(STAGED_ZIP, sig_path,
                                                     cert_path, expected_repo=repo)

        meta = {
            "version": tag,
            "current": __version__,
            "downloaded_at": time.time(),
            "sha256": zip_sha,
            "signature_verified": sig_ok,
            "signature_reason": sig_reason,
            "release_url": rel.get("html_url", ""),
            "release_notes": (rel.get("body", "") or "")[:1500],
            "size_bytes": STAGED_ZIP.stat().st_size,
            "expected_repo": repo,
        }
        STAGED_META.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        self._last_notified_version = tag

        severity = Severity.INFO if sig_ok else Severity.WARN
        self.emit(severity, Category.SYSTEM,
                  f"Update verfügbar: {tag} (Signatur: {sig_reason})",
                  meta)
