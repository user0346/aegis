"""Baut die einzelne, direkt ausfuehrbare AEGIS.exe (onedir) via PyInstaller.

Ergebnis:  dist/AEGIS/AEGIS.exe  (windowed, kein Konsolenfenster). Diese eine
Binary uebernimmt alle Rollen per Flag (s. bin/aegis_app.py) — der Endnutzer
doppelklickt nur AEGIS.exe.

Aufruf:
  py tools/build_exe.py
  py tools/build_exe.py --dist <pfad>   # alternatives Ausgabe-Verzeichnis (Staging)
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "tools" / "aegis.spec"


def main(argv: list[str]) -> int:
    dist = ROOT / "dist"
    if "--dist" in argv:
        dist = Path(argv[argv.index("--dist") + 1]).resolve()
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--log-level=WARN",
        "--distpath", str(dist),
        "--workpath", str(ROOT / "build"),
        str(SPEC),
    ]
    print("->", " ".join(cmd))
    rc = subprocess.call(cmd)
    if rc == 0:
        print("OK:", dist / "AEGIS" / "AEGIS.exe")
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
