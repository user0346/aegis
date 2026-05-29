"""Build AEGIS.zip for release.

Wird von .github/workflows/release.yml aufgerufen. Produziert den
identischen Bundle-Inhalt wie der manuelle Build — so dass User die
gleiche ZIP-Struktur erwarten.

Output: ./AEGIS.zip im Repo-Root.
"""
from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_ZIP = REPO_ROOT / "AEGIS.zip"

EXCLUDE_NAMES = {"__pycache__", ".git", ".github", ".pytest_cache",
                 "tools", ".venv", "AEGIS.zip", "AEGIS.zip.sig",
                 "AEGIS.zip.crt", "public"}
EXCLUDE_SUFFIXES = (".pyc", ".pyo")


def should_skip(path: Path) -> bool:
    if path.name in EXCLUDE_NAMES:
        return True
    if any(part in EXCLUDE_NAMES for part in path.parts):
        return True
    if path.suffix in EXCLUDE_SUFFIXES:
        return True
    return False


def build() -> int:
    print(f"Building {OUT_ZIP} from {REPO_ROOT}")
    n_files = 0
    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(REPO_ROOT):
            root_path = Path(root)
            dirs[:] = [d for d in dirs if not should_skip(root_path / d)]
            for f in files:
                full = root_path / f
                if should_skip(full):
                    continue
                arc = "AEGIS/" + str(full.relative_to(REPO_ROOT)).replace("\\", "/")
                zf.write(full, arc)
                n_files += 1
    size = OUT_ZIP.stat().st_size
    print(f"Done: {n_files} files, {size:,} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(build())
