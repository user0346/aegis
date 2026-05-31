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

# Verzeichnisse/Dateinamen, die NIE ins Release-ZIP gehoeren.
EXCLUDE_NAMES = {
    "__pycache__", ".git", ".github", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "tools", ".venv", "venv", "env", "ENV", "node_modules",
    "dist", "build", "public", "updates", "quarantine", ".aegis",
    "AEGIS.zip", "AEGIS.zip.sig", "AEGIS.zip.crt", "AEGIS.zip.cbundle",
    # lokale State-/Secret-Dateien (falls versehentlich im Arbeitsverzeichnis):
    "ipc_token", "secrets.bin", "service.pid", "audit.jsonl",
    ".env", "staged.zip", "staged.json",
    ".ext_id", "install_host_log.txt", "generated_indexed_rulesets",
}
# Suffixe, die NIE ins Release-ZIP gehoeren (State, Secrets, Build-Muell).
EXCLUDE_SUFFIXES = (
    ".pyc", ".pyo", ".pyd",
    ".db", ".db-journal", ".sqlite", ".sqlite3",
    ".log", ".env",
    ".key", ".pem", ".p12", ".pfx", ".cer", ".crt", ".sig",
    ".bak", ".old", ".tmp", ".temp", ".dump", ".bkp",
    ".bat", ".cmd", ".ps1",   # Dev-Scripts raus; Endnutzer-Launcher via INCLUDE_BAT
)
# Dateinamen, die diese Substrings enthalten, werden ebenfalls ausgeschlossen.
_EXCLUDE_SUBSTR = ("api_key", "api-key", "apikey",
                   "access_token", "access-token",
                   "private_key", "signing_key",
                   "ipc_token", "host_log", "ext_id")

# Endnutzer-Launcher, die TROTZ .bat-Ausschluss ins ZIP MUESSEN (sonst kein Starter).
INCLUDE_BAT = {
    "AEGIS.bat",   # einziger Endnutzer-Launcher (alles ueber das Menue)
}


def should_skip(path: Path) -> bool:
    name = path.name
    if name in EXCLUDE_NAMES:
        return True
    if any(part in EXCLUDE_NAMES for part in path.parts):
        return True
    # Endnutzer-Launcher trotz .bat-Ausschluss behalten
    if name in INCLUDE_BAT:
        return False
    if path.suffix.lower() in EXCLUDE_SUFFIXES:
        return True
    low = name.lower()
    if any(s in low for s in _EXCLUDE_SUBSTR):
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
