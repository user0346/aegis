"""Entry point: UI-Shell.

Run:  py bin/aegis_shell.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    from aegis2.ui.app import run
    sys.exit(run())
