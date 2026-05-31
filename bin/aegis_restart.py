"""AEGIS sauberer Neustart / Stop — Shim.

Duenner Wrapper: Logik liegt importierbar in aegis2.runtime.restart
(frozen-aware Kill-Matching + Respawn). Aufruf:
  py bin/aegis_restart.py          -> beenden + frisch starten
  py bin/aegis_restart.py stop     -> nur beenden
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == "__main__":
    from aegis2.runtime.restart import main
    stop_only = len(sys.argv) > 1 and sys.argv[1].lower() == "stop"
    raise SystemExit(main(stop_only=stop_only))
