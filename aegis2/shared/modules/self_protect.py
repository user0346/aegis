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
                 defender_check_interval_s: int = 45):
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
            # Nur neue Files. collect_integrity_targets() sammelt AUSSCHLIESSLICH
            # .py unter aegis2/ und bin/ — ein hier neu auftauchendes File ist also
            # ein fremdes .py mitten im Code-Baum. Das ist ein klassischer
            # Dropper-/Backdoor-Vektor und darf NICHT als "normal nach Update"
            # durchgewunken werden. Prominent zur Pruefung melden (kein Auto-
            # Safe-Mode, da auch ein legitimes Update Files hinzufuegt, aber der
            # Mensch muss draufschauen). REVIEW-Flag fuer das UI.
            self.emit(Severity.WARN, Category.TAMPER,
                      f"INTEGRITY-REVIEW: {len(added)} unerwartete neue .py-Datei(en) "
                      f"im Code-Baum (aegis2/, bin/) — fremder Code? Bitte prüfen",
                      {"added": added[:10],
                       "needs_review": True,
                       "reason": "unexpected_added_code_files"})
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

    # ---- Defender-Exclusion (Self-Protect + Malware-Tarn-Erkennung) ----
    def _defender_watchdog(self) -> None:
        if sys.platform != "win32":
            return
        # Alle 3 Exclusion-Typen holen: Pfade, Prozesse, Dateiendungen
        try:
            r = run_hidden(
                ["powershell", "-NoProfile", "-Command",
                 "$p=Get-MpPreference; "
                 "Write-Output ('PATH=' + ($p.ExclusionPath -join '|')); "
                 "Write-Output ('PROC=' + ($p.ExclusionProcess -join '|')); "
                 "Write-Output ('EXT='  + ($p.ExclusionExtension -join '|'))"],
                capture_output=True, text=True, timeout=10)
            out = r.stdout or ""
        except Exception:  # noqa: BLE001
            return

        # Windows gibt die Defender-Ausschluss-Liste NUR an Admin/SYSTEM frei
        # (Anti-Spaeh-Haertung). Als normaler User kommt "Must be an administrator
        # to view exclusions" -> dann NICHT als Baseline lernen (sonst Muell) und
        # einmalig informieren. Voll funktionsfaehig erst im System-Dienst-Modus.
        if "must be an administrator" in out.lower() or "n/a" in out.lower():
            if self.db.get_setting("defender_excl_baseline") is not None:
                self.db.set_setting("defender_excl_baseline", None)  # kaputte Baseline verwerfen
            if not self.db.get_setting("defender_admin_warned"):
                self.emit(Severity.WARN, Category.TAMPER,
                          "Defender-Ausschluss-Ueberwachung braucht Admin-/Dienst-Rechte "
                          "(Windows gibt die Liste sonst nicht frei). Wird aktiv, sobald "
                          "AEGIS als System-Dienst laeuft.")
                self.db.set_setting("defender_admin_warned", True)
            return

        def _parse(prefix):
            for line in out.splitlines():
                if line.startswith(prefix):
                    rest = line[len(prefix):].strip()
                    return [x.strip().lower() for x in rest.split("|") if x.strip()]
            return []

        cur = ({("path", p) for p in _parse("PATH=")}
               | {("proc", p) for p in _parse("PROC=")}
               | {("ext", e) for e in _parse("EXT=")})

        root_lc = str(self.root).lower()
        own = {("path", root_lc),
               ("proc", "aegis-core.exe"), ("proc", "aegis-shell.exe"),
               ("proc", "pythonw.exe"), ("proc", "python.exe")}

        base_raw = self.db.get_setting("defender_excl_baseline")
        if not isinstance(base_raw, list):
            # Erst-Lauf: bestehende Ausschluesse als legitime Baseline lernen
            self.db.set_setting("defender_excl_baseline", [list(x) for x in cur])
            self.db.set_setting("defender_was_excluded", ("path", root_lc) in cur)
            self.emit(Severity.INFO, Category.TAMPER,
                      f"Defender-Ausschluss-Baseline gelernt: {len(cur)} Eintraege")
            return
        baseline = {tuple(x) for x in base_raw}

        # NEUE fremde Ausschluesse = klassisches Malware-Tarnverhalten
        suspicious = cur - baseline - own
        reported = {tuple(x) for x in (self.db.get_setting("defender_excl_reported") or [])}
        kind_de = {"path": "Pfad", "proc": "Prozess", "ext": "Dateiendung"}
        for kind, val in sorted(suspicious - reported):
            self.emit(Severity.CRITICAL, Category.TAMPER,
                      f"Neuer Defender-Ausschluss ({kind_de.get(kind, kind)}): {val} "
                      f"— Malware tarnt sich oft so vor dem Virenschutz",
                      {"exclusion_kind": kind, "exclusion_value": val,
                       "status": "ERKANNT"})
        # gemeldete = aktuelle Verdaechtige (entfernte fallen raus -> Re-Add meldet erneut)
        self.db.set_setting("defender_excl_reported", [list(x) for x in suspicious])

        # Self-Protection: AEGIS-eigener Ausschluss entfernt?
        is_excluded = ("path", root_lc) in cur
        if bool(self.db.get_setting("defender_was_excluded")) and not is_excluded:
            # Re-Apply versuchen. Den Pfad NICHT in den Befehl interpolieren,
            # sondern als Argument uebergeben ($args[0]) — verhindert PowerShell-
            # Injection ueber einen praeparierten Pfad.
            reapplied = False
            try:
                r = run_hidden(
                    ["powershell", "-NoProfile", "-Command",
                     "Add-MpPreference -ExclusionPath $args[0]",
                     str(self.root)],
                    capture_output=True, text=True, timeout=10)
                reapplied = (getattr(r, "returncode", 1) == 0)
            except Exception:  # noqa: BLE001
                reapplied = False

            if reapplied:
                # Re-Apply erfolgreich -> Ausschluss wieder da. Baseline darf jetzt
                # auf "exkludiert" zuruecksetzen.
                self.emit(Severity.CRITICAL, Category.TAMPER,
                          "Defender-Ausschluss fuer AEGIS wurde entfernt - "
                          "automatisch wiederhergestellt")
                self.db.set_setting("defender_was_excluded", True)
            else:
                # Re-Apply FEHLGESCHLAGEN (i.d.R. fehlende Adminrechte). NICHT die
                # Baseline auf is_excluded (=False) setzen — sonst wuerde der
                # naechste Lauf den fehlenden Ausschluss als Normalzustand sehen
                # und nie wieder warnen (fail-closed: lieber weiter melden).
                # Rate-Limit, damit es nicht alle 45s spammt.
                now = time.time()
                last = self.db.get_setting("defender_reapply_failed_at") or 0
                try:
                    last = float(last)
                except (TypeError, ValueError):
                    last = 0.0
                if now - last >= 1800:  # max. alle 30 min
                    self.emit(Severity.CRITICAL, Category.TAMPER,
                              "Defender-Ausschluss fuer AEGIS wurde entfernt - "
                              "Re-Apply fehlgeschlagen (Adminrechte noetig). "
                              "Schutz vor Selbst-Quarantaene derzeit NICHT aktiv.")
                    self.db.set_setting("defender_reapply_failed_at", now)
                # defender_was_excluded bleibt True -> weiter ueberwachen/melden.
        else:
            # Normalfall (Ausschluss vorhanden oder noch nie gesetzt): Baseline
            # auf den aktuellen Stand bringen.
            self.db.set_setting("defender_was_excluded", is_excluded)
