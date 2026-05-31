"""AEGIS Service-Core — Background-Shim (kein Konsolen-Fenster).

Duenner Wrapper: die eigentliche Logik liegt jetzt importierbar in
aegis2.runtime.service (damit sie auch die gefrorene AEGIS.exe aufrufen kann).
Start aus dem Quellcode:  pyw bin/aegis_core_background.pyw
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == "__main__":
    from aegis2.runtime.service import main
    sys.exit(main())
