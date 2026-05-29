"""QuarantineManager — moves suspicious files into ACL-protected vault.

EXEs werden umbenannt (.quar) damit Windows sie nicht versehentlich startet.
Helper-Klasse, kein Module (kein eigener Thread).
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Optional

from ..db import Database
from ..events import EventBus, Event, Severity, Category
from .. import threat_intel as ti


QUARANTINE_DIR = Path.home() / ".aegis" / "quarantine"


class QuarantineManager:
    def __init__(self, bus: EventBus, db: Database):
        self.bus = bus
        self.db = db
        self.vault = QUARANTINE_DIR
        self.vault.mkdir(parents=True, exist_ok=True)

    def quarantine(self, original_path: Path, reason: str,
                   sha256_hash: Optional[str] = None) -> Optional[int]:
        try:
            if not original_path.exists():
                return None
            if not sha256_hash:
                sha256_hash = ti.file_sha256(original_path)
            if not sha256_hash:
                return None
            vault_name = f"{sha256_hash[:16]}_{int(time.time())}_{original_path.name}.quar"
            vault_path = self.vault / vault_name
            try:
                shutil.move(str(original_path), str(vault_path))
            except (OSError, PermissionError) as e:
                self.bus.emit(Event(Severity.CRITICAL, Category.QUARANTINE,
                    f"Quarantine MOVE fehlgeschlagen: {original_path.name} ({e})",
                    "QuarantineManager",
                    {"path": str(original_path), "error": str(e)}))
                return None
            try:
                size = vault_path.stat().st_size
            except OSError:
                size = 0
            self.db.upsert_file(sha256_hash, str(original_path), size, "", "quarantined")
            self.db.set_file_status(sha256_hash, "quarantined")
            qid = self.db.add_quarantine(sha256_hash, str(original_path),
                                         str(vault_path), reason)
            self.bus.emit(Event(Severity.QUARANTINE, Category.QUARANTINE,
                f"QUARANTINISIERT: {original_path.name} ({reason})",
                "QuarantineManager",
                {"sha256": sha256_hash, "original_path": str(original_path),
                 "vault_path": str(vault_path), "reason": reason,
                 "size": size, "quarantine_id": qid}))
            return qid
        except Exception as e:  # noqa: BLE001
            self.bus.emit(Event(Severity.CRITICAL, Category.QUARANTINE,
                f"Quarantine-Fehler: {e}", "QuarantineManager"))
            return None

    def approve(self, quarantine_id: int, restore_to: Optional[Path] = None,
                notes: str = "") -> bool:
        rows = [r for r in self.db.pending_quarantine() if r["id"] == quarantine_id]
        if not rows:
            return False
        q = rows[0]
        vault_path = Path(q["vault_path"])
        target = restore_to or Path(q["original_path"])
        if not vault_path.exists():
            self.db.decide_quarantine(quarantine_id, "deleted", "vault file missing")
            return False
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(vault_path), str(target))
            self.db.decide_quarantine(quarantine_id, "approved", notes)
            self.db.set_file_status(q["sha256"], "allowed")
            self.db.record_decision("file_hash", q["sha256"], "allow", notes)
            # Lerne: dieser Quarantäne-Grund war ein False-Positive
            try:
                self.db.calibration_record_decision(
                    f"quar:{q['reason']}", "FILE", 50, "approved")
                self.db.inc_metric("calibration_updates", 1)
            except Exception:  # noqa: BLE001
                pass
            self.bus.emit(Event(Severity.INFO, Category.QUARANTINE,
                f"APPROVED: {target.name} aus Vault freigegeben",
                "QuarantineManager",
                {"sha256": q["sha256"], "target": str(target)}))
            return True
        except (OSError, PermissionError) as e:
            self.bus.emit(Event(Severity.CRITICAL, Category.QUARANTINE,
                f"Approve fehlgeschlagen: {e}", "QuarantineManager"))
            return False

    def deny(self, quarantine_id: int, notes: str = "") -> bool:
        rows = [r for r in self.db.pending_quarantine() if r["id"] == quarantine_id]
        if not rows:
            return False
        q = rows[0]
        self.db.decide_quarantine(quarantine_id, "denied", notes)
        self.db.set_file_status(q["sha256"], "blocked")
        self.db.record_decision("file_hash", q["sha256"], "deny", notes)
        # Lerne: dieser Quarantäne-Grund war korrekt
        try:
            self.db.calibration_record_decision(
                f"quar:{q['reason']}", "FILE", 50, "denied")
            self.db.inc_metric("calibration_updates", 1)
        except Exception:  # noqa: BLE001
            pass
        self.bus.emit(Event(Severity.INFO, Category.QUARANTINE,
            f"DENIED: {Path(q['original_path']).name} - bleibt blocked",
            "QuarantineManager", {"sha256": q["sha256"]}))
        return True

    def delete_forever(self, quarantine_id):
        for q in self.db.all_quarantine():
            if q["id"] == quarantine_id:
                vp = Path(q["vault_path"])
                if vp.exists():
                    try:
                        vp.unlink()
                    except OSError:
                        pass
                self.db.decide_quarantine(quarantine_id, "deleted", "user delete")
                self.bus.emit(Event(Severity.INFO, Category.QUARANTINE,
                    f"GELOESCHT: {Path(q['original_path']).name}",
                    "QuarantineManager"))
                return True
        return False
