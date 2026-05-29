"""Self-Protection-Modul — schützt AEGIS vor Manipulation.

Drei Aufgaben:
  1. Integrity-Verify: SHA-256 aller eigenen .py-Files pinnt sich beim ersten
     Boot in DB. Jeder weitere Boot vergleicht. Mismatch → CRITICAL +
     safe_mode=True (Auto-Quarantäne aus, alle Aktionen brauchen Consent).

  2. Defender-Exclusion-Watchdog: alle 5 min PowerShell-Query
     `(Get-MpPreference).ExclusionPath`. Wenn AEGIS-Ordner nicht mehr drin →
     CRITICAL Event + Re-Apply versuchen (braucht Admin → wenn nicht da, Notify).

  3. Hosts-File-Watchdog: liest hosts-Datei alle 2 min. Wenn AEGIS-Block-Section
     manuell rausgenommen wurde → restore + CRITICAL Event.

Boundary: dieses Modul kann NICHT verhindern dass der Service gekillt wird
(das verhindert die sc.exe failure recovery-policy). Es kann nur erkennen
+ reagieren wenn der User-Prozess noch lebt.
"""
from __future__ import annotations

import hashlib
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from ..db import Database
from ..events import EventBus, Event, Severity, Category
from ..proc import run_hidden
from .base import Module


log = logging.getLogger("aegis2.self_protect")


SAFE_MODE_FLAG = Path.home() / ".aegis" / ".safe_mode"


# ============================================================
#  Integrity (SHA-Pin)
# ============================================================

def _hash_file(p: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def collect_integrity_targets(root: Path) -> dict[str, str]:
    """Pin alle .py-Files unter aegis2/ und bin/. Returns {relpath: sha256}."""
    out = {}
    for d in [root / "aegis2", root / "bin"]:
        if not d.exists():
            continue
        for p in d.rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            sha = _hash_file(p)
            if sha:
                rel = str(p.relative_to(root)).replace("\\", "/")
                out[rel] = sha
    return out


# ============================================================
#  Self-Protect Module
# ============================================================

class SelfProtect(Module):
    name = "SelfProtect"

    def __init__(self, bus: EventBus, db: Database, project_root: Path,
                 hosts_check_interval_s: int = 120,
                 defender_check_interval_s: int = 300):
        super().__init__(bus)
        self.db = db
        self.root = project_root
        self.hosts_iv = hosts_check_interval_s
        self.defender_iv = defender_check_interval_s
        self._last_hosts_check = 0.0
        self._last_defender_check = 0.0
        self._safe_mode = False

    def run(self) -> None:
        # Initial: Integrity-Check vs. DB-Pin
        try:
            self._integrity_boot_check()
        except Exception as e:  # noqa: BLE001
            self.emit(Severity.WARN, Category.SYSTEM,
                      f"SelfProtect Integrity-Boot crashed: {e}")

        # Loop
        while not self._stop.is_set():
            try:
                now = time.time()
                if now - self._last_hosts_check >= self.hosts_iv:
                    self._last_hosts_check = now
                    self._hosts_watchdog()
                if now - self._last_defender_check >= self.defender_iv:
                    self._last_defender_check = now
                    self._defender_watchdog()
            except Exception as e:  # noqa: BLE001
                self.emit(Severity.WARN, Category.SYSTEM,
                          f"SelfProtect Loop-Fehler: {type(e).__name__}: {e}")
            self._stop.wait(30)

    # ---- Integrity ----
    def _integrity_boot_check(self) -> None:
        current = collect_integrity_targets(self.root)
        # Pinned hashes aus Settings
        pinned_raw = self.db.get_setting("integrity_pinned_hashes")
        if not pinned_raw or not isinstance(pinned_raw, dict):
            # Erst-Boot: pinne alles
            self.db.set_setting("integrity_pinned_hashes", current)
            self.db.set_setting("integrity_pinned_at", time.time())
            self.emit(Severity.INFO, Category.TAMPER,
                      f"Integrity: {len(current)} Files erstmals gepinnt")
            return

        # Compare
        mismatches = []
        missing = []
        added = []
        for rel, sha in pinned_raw.items():
            if rel not in current:
                missing.append(rel)
            elif current[rel] != sha:
                mismatches.append(rel)
        for rel in current:
            if rel not in pinned_raw:
                added.append(rel)

        if mismatches or missing:
            # Tamper detected → safe mode + critical event
            self._enter_safe_mode("integrity-mismatch")
            self.emit(Severity.CRITICAL, Category.TAMPER,
                      f"INTEGRITY-BREACH: {len(mismatches)} Files geändert, "
                      f"{len(missing)} fehlen",
                      {"mismatches": mismatches[:10],
                       "missing": missing[:10],
                       "added": added[:10]})
        elif added:
            # Nur neue Files → mildere Warnung, ist normal nach Update
            self.emit(Severity.WARN, Category.TAMPER,
                      f"Integrity: {len(added)} neue Files seit Pin",
                      {"added": added[:10]})
        else:
            self.emit(Severity.INFO, Category.TAMPER,
                      f"Integrity: {len(current)} Files unverändert")

    def _enter_safe_mode(self, reason: str) -> None:
        if self._safe_mode:
            return
        self._safe_mode = True
        try:
            SAFE_MODE_FLAG.parent.mkdir(parents=True, exist_ok=True)
            SAFE_MODE_FLAG.write_text(f"{int(time.time())} {reason}",
                                     encoding="utf-8")
        except OSError:
            pass
        # auto-demote autonomy
        try:
            from ..cognition.autonomy import get_autonomy  # type: ignore
            get_autonomy().on_critical_threat(f"safe_mode:{reason}")
        except Exception:  # noqa: BLE001
            pass

    # ---- Hosts ----
    def _hosts_watchdog(self) -> None:
        if sys.platform != "win32":
            return
        hosts = Path(r"C:\Windows\System32\drivers\etc\hosts")
        if not hosts.exists():
            return
        try:
            content = hosts.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        has_block = "# === AEGIS SINKHOLE START ===" in content
        had_block = bool(self.db.get_setting("hosts_block_was_present"))
        if had_block and not has_block:
            self.emit(Severity.CRITICAL, Category.TAMPER,
                      "AEGIS-Block-Section in hosts wurde entfernt - Restore-Versuch")
            # Re-Apply via DnsSinkhole-Logik (vereinfacht: nur Marker)
            self._restore_hosts_marker()
        self.db.set_setting("hosts_block_was_present", has_block)

    def _restore_hosts_marker(self) -> None:
        # Re-Apply braucht eigentlich DnsSinkhole. Hier nur Marker-only.
        hosts = Path(r"C:\Windows\System32\drivers\etc\hosts")
        marker = ("\n# === AEGIS SINKHOLE START ===\n"
                  "# Restored after manipulation\n"
                  "# === AEGIS SINKHOLE END ===\n")
        try:
            with open(hosts, "a", encoding="utf-8") as f:
                f.write(marker)
            self.emit(Severity.INFO, Category.TAMPER,
                      "Hosts-Marker wiederhergestellt")
        except (OSError, PermissionError) as e:
            self.emit(Severity.WARN, Category.TAMPER,
                      f"Hosts-Restore fehlgeschlagen (Admin nötig?): {e}")

    # ---- Defender-Exclusion ----
    def _defender_watchdog(self) -> None:
        if sys.platform != "win32":
            return
        # Get aktuelle Exclusion-Pfade
        try:
            r = run_hidden(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-MpPreference).ExclusionPath -join ';'"],
                capture_output=True, text=True, timeout=10
            )
            current = (r.stdout or "").strip().lower()
        except Exception:  # noqa: BLE001
            return
        root_lc = str(self.root).lower()
        was_excluded = bool(self.db.get_setting("defender_was_excluded"))
        is_excluded = root_lc in current
        if was_excluded and not is_excluded:
            self.emit(Severity.CRITICAL, Category.TAMPER,
                      "Defender-Exclusion für AEGIS wurde entfernt - Re-Apply Versuch")
            try:
                run_hidden(
                    ["powershell", "-NoProfile", "-Command",
                     f"Add-MpPreference -ExclusionPath '{self.root}'"],
                    capture_output=True, text=True, timeout=10
                )
                self.emit(Severity.INFO, Category.TAMPER,
                          "Defender-Exclusion re-applied (sofern Admin)")
            except Exception as e:  # noqa: BLE001
                self.emit(Severity.WARN, Category.TAMPER,
                          f"Re-Apply fehlgeschlagen: {e}")
        self.db.set_setting("defender_was_excluded", is_excluded)
