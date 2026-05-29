"""Installiert den pre-commit Hook fuer secret_scan.py.

Nach `git clone`: einmal `py -3.13 tools/install_hooks.py` ausfuehren.
Danach blockiert jeder `git commit` automatisch wenn Secrets im Diff sind.

Hook-Pfad: .git/hooks/pre-commit
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


HOOK_CONTENT = r"""#!/usr/bin/env bash
# AEGIS pre-commit hook — runs secret_scan.py
# Auto-installed by tools/install_hooks.py
set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"

# Try py launcher first (Windows), fall back to python3
if command -v py >/dev/null 2>&1; then
    PY="py -3.13"
elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
else
    PY="python"
fi

$PY "$REPO_ROOT/tools/secret_scan.py"
"""


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    hooks_dir = repo_root / ".git" / "hooks"
    if not hooks_dir.exists():
        print(f"[ERR] {hooks_dir} fehlt — bist du in einem git-Repo?")
        return 1

    hook = hooks_dir / "pre-commit"
    hook.write_text(HOOK_CONTENT, encoding="utf-8", newline="\n")

    # chmod +x (no-op on Windows but harmless)
    try:
        mode = hook.stat().st_mode
        hook.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass

    print(f"[OK] pre-commit Hook installiert: {hook}")
    print("Jeder `git commit` ruft jetzt secret_scan.py auf.")
    print("Block-Findings -> Commit wird abgebrochen.")
    print("WARN-Findings  -> Commit darf weiter.")
    print()
    print("Quick-Test:  py -3.13 tools/secret_scan.py --all")
    return 0


if __name__ == "__main__":
    sys.exit(main())
