"""AEGIS Watchdog — Respawn-Schutz, Background-Shim.

Duenner Wrapper: Logik liegt importierbar in aegis2.runtime.watchdog.
Start aus dem Quellcode:  pyw bin/aegis_watchdog.pyw
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == "__main__":
    from aegis2.runtime.watchdog import main
    sys.exit(main())
