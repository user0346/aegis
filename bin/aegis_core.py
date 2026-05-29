"""Entry point: Service-Core (foreground mode for dev).

Run as service:  py -m aegis2.service.service install / start
Run foreground:  py bin/aegis_core.py --foreground
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    from aegis2.service.core import main
    sys.exit(main(foreground="--foreground" in sys.argv))
