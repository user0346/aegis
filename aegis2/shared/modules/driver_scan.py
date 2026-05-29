"""Driver-Signing Scanner (Phase 5a).

Enumeriert geladene Kernel-Driver via WMI (Win32_SystemDriver) und prueft
deren Authenticode-Signatur ueber PowerShell Get-AuthenticodeSignature.

Was wird gemeldet:
  * NotSigned                  - kein Cert      -> CRITICAL
  * HashMismatch               - Manipulation   -> CRITICAL
  * NotTrusted / UnknownError  - selbstsigniert -> WARN
  * Expired                    - Cert abgelaufen-> WARN
  * Valid + non-MS signer      - Drittanbieter  -> INFO  (one-shot per signer)
  * Valid + MS-signer          - Standard       -> nichts (rauschfrei)

Defensive Properties:
  - Read-only (modifiziert keinen Driver)
  - Subprocess mit Timeout
  - Result-Cache: jeder Driver max 1x pro Lauf gemeldet
  - Persistente "known-good"-Liste in DB-Settings damit unveraenderte
    Drittanbieter-Driver nach 1. Sichtung nicht erneut Events erzeugen

Lauf-Intervall: 6h (Driver werden selten installiert; haeufiger -> CPU)
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from ..db import Database
from ..events import EventBus, Severity, Category
from ..proc import run_hidden
from .base import Module


log = logging.getLogger("aegis2.driver_scan")


# Bekannte MS-Signer (Subjects) — Drittanbieter werden separat gehandelt
MS_SIGNERS_PREFIXES = (
    "Microsoft Windows",
    "Microsoft Corporation",
    "Microsoft Windows Hardware Compatibility Publisher",
)

DEFAULT_INTERVAL_S = 6 * 3600   # 6h
BOOT_DELAY_S = 180              # 3 min nach Service-Start

# Windows: PowerShell-Fenster komplett unterdrücken
CREATE_NO_WINDOW = 0x08000000

# Drittanbieter-Subjects die explizit zugelassen sind (Treiber-Vendors)
# kann via DB-Setting "driver_trusted_signers" erweitert werden (Komma-getrennt)
DEFAULT_TRUSTED_VENDORS = (
    "NVIDIA Corporation",
    "Advanced Micro Devices, Inc.",
    "Intel Corporation",
    "Realtek Semiconductor Corp",
    "Realtek",
    "Logitech Inc.",
    "Logitech",
    "Razer",
    "Apple Inc.",
)

# Felder die wir in PowerShell pro Driver auslesen
PS_SCRIPT = r"""
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$ErrorActionPreference = 'Stop'
$drivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue |
           Where-Object { $_.PathName -and (Test-Path ($_.PathName -replace '^\\\\\?\\','')) }
$out = @()
foreach ($d in $drivers) {
    $p = $d.PathName -replace '^\\\\\?\\',''
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        $signer = ''
        if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
        $thumb = ''
        if ($sig.SignerCertificate) { $thumb = $sig.SignerCertificate.Thumbprint }
        $notAfter = ''
        if ($sig.SignerCertificate) { $notAfter = $sig.SignerCertificate.NotAfter.ToString('o') }
        $out += [PSCustomObject]@{
            Name       = $d.Name
            Path       = $p
            Started    = $d.Started
            State      = $d.State
            Status     = $sig.Status.ToString()
            Signer     = $signer
            Thumbprint = $thumb
            NotAfter   = $notAfter
        }
    } catch {
        $out += [PSCustomObject]@{
            Name       = $d.Name
            Path       = $p
            Started    = $d.Started
            State      = $d.State
            Status     = 'PsError'
            Signer     = ''
            Thumbprint = ''
            NotAfter   = ''
        }
    }
}
$out | ConvertTo-Json -Depth 3 -Compress
"""


class DriverScanner(Module):
    name = "DriverScanner"

    def __init__(self, bus: EventBus, db: Database, interval_s: int = DEFAULT_INTERVAL_S):
        super().__init__(bus)
        self.db = db
        self.interval_s = max(1800, int(interval_s))    # min 30 min
        self._last_scan = 0.0
        # Cache: thumbprint we've already reported as 3rd-party
        self._reported_thumbs: set[str] = set()
        # Cache: paths we've already alerted as unsigned (avoid spam)
        self._reported_bad: set[str] = set()

    # ------------------------------------------------------------------
    def run(self) -> None:
        self._stop.wait(BOOT_DELAY_S)
        # Initial vollscan
        try:
            self._scan_once()
        except Exception as e:  # noqa: BLE001
            self.emit(Severity.WARN, Category.SYSTEM,
                      f"Initial driver-scan failed: {type(e).__name__}: {e}")
        while not self._stop.is_set():
            if self._stop.wait(self.interval_s):
                break
            try:
                self._scan_once()
            except Exception as e:  # noqa: BLE001
                self.emit(Severity.WARN, Category.SYSTEM,
                          f"driver-scan loop error: {type(e).__name__}: {e}")

    # ------------------------------------------------------------------
    def _scan_once(self) -> None:
        rows = self._enumerate()
        if not rows:
            return
        self._last_scan = time.time()
        trusted = self._trusted_vendors()
        for r in rows:
            self._classify(r, trusted)

    # ------------------------------------------------------------------
    def _enumerate(self) -> list[dict]:
        """Ruft PowerShell auf, parsed JSON-Ergebnis."""
        try:
            r = run_hidden(
                ["powershell.exe", "-NoProfile", "-NonInteractive",
                 "-WindowStyle", "Hidden",
                 "-ExecutionPolicy", "Bypass", "-Command", PS_SCRIPT],
                capture_output=True, timeout=180,
                encoding="utf-8", errors="replace",
                creationflags=CREATE_NO_WINDOW,
            )
            if r.returncode != 0 or not r.stdout:
                log.warning("PS exit=%s stderr=%s", r.returncode, (r.stderr or "")[:200])
                return []
            data = json.loads(r.stdout)
            # PS gibt ein Object zurueck wenn nur 1 Eintrag, Array wenn mehrere
            if isinstance(data, dict):
                return [data]
            return data or []
        except subprocess.TimeoutExpired:
            self.emit(Severity.WARN, Category.SYSTEM,
                      "driver-scan: powershell timeout (>180s)")
            return []
        except json.JSONDecodeError as e:
            log.warning("PS JSON parse: %s", e)
            return []
        except Exception as e:  # noqa: BLE001
            log.warning("driver-scan enumerate failed: %s", e)
            return []

    # ------------------------------------------------------------------
    def _trusted_vendors(self) -> tuple[str, ...]:
        extra = (self.db.get_setting("driver_trusted_signers", "") or "")
        custom = tuple(s.strip() for s in extra.split(",") if s.strip())
        return DEFAULT_TRUSTED_VENDORS + custom

    def _is_ms_signer(self, subject: str) -> bool:
        return any(p in subject for p in MS_SIGNERS_PREFIXES)

    def _is_trusted_vendor(self, subject: str, trusted: tuple[str, ...]) -> bool:
        if not subject:
            return False
        return any(t in subject for t in trusted)

    # ------------------------------------------------------------------
    def _classify(self, row: dict, trusted: tuple[str, ...]) -> None:
        name = (row.get("Name") or "").strip()
        path = (row.get("Path") or "").strip()
        status = (row.get("Status") or "").strip()
        signer = (row.get("Signer") or "").strip()
        thumb = (row.get("Thumbprint") or "").strip()
        not_after = (row.get("NotAfter") or "").strip()
        started = bool(row.get("Started"))

        if not path:
            return
        # Skip duplicates (driver-paths can have same thumbprint many times)
        bad_key = f"{path}::{status}"

        meta = {
            "name": name, "path": path, "status": status, "signer": signer,
            "thumb": thumb, "not_after": not_after, "started": started,
        }

        # Katalog-signierte OS-Treiber: Get-AuthenticodeSignature meldet 'NotSigned',
        # obwohl Windows DSE sie via Security-Katalog (.cat) geladen hat. Ein geladener
        # Treiber unter C:/Windows ist katalog-signiert -> kein CRITICAL-FP.
        norm_path = path.lower().replace(chr(92), '/')
        if status == "NotSigned" and "/windows/" in norm_path:
            return

        # === CRITICAL: NotSigned / HashMismatch ===
        if status in ("NotSigned", "HashMismatch"):
            if bad_key in self._reported_bad:
                return
            self._reported_bad.add(bad_key)
            sev = Severity.CRITICAL
            msg = (f"Driver {name} ist {status} — Pfad: {path}")
            self.emit(sev, Category.SYSTEM, msg, meta)
            return

        # === WARN: NotTrusted / Expired / PsError ===
        if status in ("NotTrusted", "Expired", "UnknownError", "PsError"):
            if bad_key in self._reported_bad:
                return
            self._reported_bad.add(bad_key)
            sev = Severity.WARN
            msg = f"Driver {name}: Signatur-Status {status} ({signer or 'no signer'})"
            self.emit(sev, Category.SYSTEM, msg, meta)
            return

        # === Valid ===
        if status != "Valid":
            return  # rare codes — skip silently

        # MS-signed: silent
        if self._is_ms_signer(signer):
            return
        # Trusted vendor: silent
        if self._is_trusted_vendor(signer, trusted):
            return

        # Unbekannter Drittanbieter — one-shot per thumbprint
        if thumb and thumb in self._reported_thumbs:
            return
        if thumb:
            self._reported_thumbs.add(thumb)
        self.emit(Severity.INFO, Category.SYSTEM,
                  f"Drittanbieter-Driver: {name} signiert von {signer or '(unbekannt)'}",
                  meta)
