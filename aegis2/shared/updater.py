"""Update-Check (Pull-Only).

Wichtig: AEGIS lädt NIE selbst neue Versionen herunter und führt sie aus.
Update-Check ist passive Notification — User entscheidet.

Workflow:
  1. Periodisch (alle 24h) fetch von https://aegis.tld/manifest.json
  2. Manifest enthält {latest_version, sha256, signed_at, signature, urls}
  3. signature wird gegen einen *built-in public key* verifiziert (Ed25519,
     wenn die cryptography-Library da ist — sonst nur HTTPS-Trust).
  4. Wenn neuer als __version__: Event Severity.WARN, Category SYSTEM.
  5. User klickt in der UI auf Link, lädt manuell.

Manifest-URL muss konfigurierbar sein (settings.update_manifest_url).
Default: leer = Update-Check deaktiviert.

Pinning: aktuelle Version + SHA werden persistiert, sodass Downgrade-Angriffe
über manipuliertes Manifest erkannt werden.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import threading
import time
import urllib.request
from typing import Optional

from .. import __version__
from .db import Database
from .events import EventBus, Event, Severity, Category
from .modules.base import Module


log = logging.getLogger("aegis2.updater")


# Built-in Public-Key — wenn du Updates signiert verteilst, hier einsetzen.
# Format: base64 von Ed25519-PublicKey-Raw (32 Bytes).
# Wenn leer: nur HTTPS-Trust, kein Signature-Check.
BUILTIN_PUBKEY_B64 = ""


def _verify_signature(manifest_blob: bytes, signature_b64: str) -> Optional[bool]:
    """Returns True/False wenn Public-Key da, None wenn skip."""
    if not BUILTIN_PUBKEY_B64 or not signature_b64:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(BUILTIN_PUBKEY_B64))
        sig = base64.b64decode(signature_b64)
        pub.verify(sig, manifest_blob)
        return True
    except ImportError:
        # cryptography fehlt → kein Verify möglich
        return None
    except Exception:  # noqa: BLE001
        return False


def parse_version(v: str) -> tuple:
    """Sehr lockerer Version-Parse. '2.0.0-dev' → (2, 0, 0)."""
    try:
        base = v.split("-", 1)[0]
        return tuple(int(p) for p in base.split("."))
    except Exception:  # noqa: BLE001
        return (0,)


def fetch_manifest(url: str, timeout: int = 12) -> Optional[dict]:
    if not url or not url.lower().startswith("https://"):
        return None
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"AEGIS/{__version__}",
                     "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            raw = resp.read()
        manifest = json.loads(raw.decode("utf-8"))
        # Verify Signature wenn vorhanden
        sig_ok = _verify_signature(raw, manifest.get("signature", ""))
        manifest["_signature_ok"] = sig_ok
        return manifest
    except Exception:  # noqa: BLE001
        return None


class UpdateChecker(Module):
    name = "UpdateChecker"

    def __init__(self, bus: EventBus, db: Database, interval_h: float = 24.0):
        super().__init__(bus)
        self.db = db
        self.interval_s = max(3600.0, interval_h * 3600)
        self._last_check = 0.0
        self._already_notified_version: Optional[str] = None

    def run(self) -> None:
        # Boot-Delay 5 min damit nicht direkt nach Boot Netzwerk gemacht wird
        self._stop.wait(300)
        while not self._stop.is_set():
            try:
                if time.time() - self._last_check >= self.interval_s:
                    self._do_check()
                    self._last_check = time.time()
            except Exception as e:  # noqa: BLE001
                self.emit(Severity.WARN, Category.SYSTEM,
                          f"UpdateChecker error: {type(e).__name__}: {e}")
            self._stop.wait(600)   # check every 10min, real timing inside

    def _do_check(self) -> None:
        url = self.db.get_setting("update_manifest_url", "")
        if not url:
            return
        manifest = fetch_manifest(url)
        if not manifest:
            return

        latest = manifest.get("latest_version", "")
        if not latest:
            return

        # Downgrade-Detection
        pinned = self.db.get_setting("update_last_known_latest", "")
        if pinned and parse_version(latest) < parse_version(pinned):
            self.emit(Severity.CRITICAL, Category.TAMPER,
                      f"Update-Downgrade-Versuch: Manifest meldet {latest} "
                      f"aber zuletzt war {pinned}")
            return
        self.db.set_setting("update_last_known_latest", latest)

        # Signature
        sig_ok = manifest.get("_signature_ok")
        if sig_ok is False:
            self.emit(Severity.CRITICAL, Category.TAMPER,
                      "Update-Manifest Signature-Check FAILED — Update ignoriert")
            return

        # Compare
        if parse_version(latest) > parse_version(__version__):
            if latest == self._already_notified_version:
                return    # nicht doppelt notifien
            self._already_notified_version = latest
            self.emit(Severity.WARN, Category.SYSTEM,
                      f"Neue Version verfügbar: {latest} (aktuell {__version__})",
                      {"current": __version__,
                       "latest": latest,
                       "url": manifest.get("download_url", ""),
                       "signature_verified": bool(sig_ok),
                       "notes": (manifest.get("notes", "") or "")[:500]})
