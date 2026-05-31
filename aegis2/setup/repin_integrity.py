"""Setzt die SelfProtect-Integritaets-Baseline neu (nach legitimem Update/Deploy)
und entfernt das Safe-Mode-Flag.

Hintergrund: SelfProtect pinnt beim ersten Start die SHA-256 aller .py-Files.
Aendert sich danach Code (Update), meldet AEGIS einen INTEGRITY-BREACH und geht
in den Safe-Mode. Nach einem BEWUSSTEN Update neu pinnen -> kein Fehlalarm.

  python aegis2\\setup\\repin_integrity.py
"""
import sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def main():
    from aegis2.shared.db import get_db
    from aegis2.shared.modules.self_protect import (
        collect_integrity_targets, SAFE_MODE_FLAG)
    db = get_db()
    targets = collect_integrity_targets(ROOT)
    db.set_setting("integrity_pinned_hashes", targets)
    db.set_setting("integrity_pinned_at", time.time())
    removed = False
    try:
        if SAFE_MODE_FLAG.exists():
            SAFE_MODE_FLAG.unlink()
            removed = True
    except OSError:
        pass
    print("Integritaets-Baseline neu gepinnt: %d Files." % len(targets))
    print("Safe-Mode-Flag: %s" % ("entfernt" if removed else "war nicht gesetzt"))
    print("\nWICHTIG: nach jedem bewussten Code-Update erneut ausfuehren.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("FEHLER:", e)
