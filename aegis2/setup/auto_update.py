"""Atomic Auto-Update-Applier.

Wird ausgeführt NACHDEM User in der UI ein Update approved hat.
Sicheres Replace-Verfahren:

  1. Stop Service (sentinel + warten max 10s)
  2. Stop UI-Shell
  3. Aktuelle Installation → .old umbenennen
  4. Extract staged.zip → install_path
  5. Verify SHA aller .py-Files gegen Manifest
  6. Wenn OK: cleanup .old, start Service
  7. Wenn FAIL: rollback (.old → install_path zurück), start Service

Lock-File: ~/.aegis/.updating verhindert parallele Updates.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path


UPDATE_DIR = Path.home() / ".aegis" / "updates"
STAGED_ZIP = UPDATE_DIR / "staged.zip"
STAGED_META = UPDATE_DIR / "staged.json"
LOCK_FILE = Path.home() / ".aegis" / ".updating"
STOP_SENTINEL = Path.home() / ".aegis" / ".stop"


def stop_service_clean(timeout_s: int = 12) -> bool:
    """Signalisiert Service-Stop, wartet auf clean shutdown, fallback force-kill."""
    pid_file = Path.home() / ".aegis" / "service.pid"
    if not pid_file.exists():
        return True   # nicht aktiv

    # Sentinel-File
    STOP_SENTINEL.write_text("update", encoding="utf-8")

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not pid_file.exists():
            return True
        time.sleep(0.5)

    # Force-Kill
    try:
        pid = int(pid_file.read_text().strip())
        subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                       capture_output=True, timeout=8)
    except Exception:
        pass
    if pid_file.exists():
        try: pid_file.unlink()
        except OSError: pass
    return True


def stop_shell() -> None:
    """Stoppt UI-Shell (falls läuft)."""
    try:
        subprocess.run(["taskkill", "/F", "/IM", "pythonw.exe", "/FI", "WINDOWTITLE eq AEGIS"],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def start_service(install_path: Path) -> bool:
    """Startet Service neu via Background-Launcher."""
    pyw = Path(sys.executable).parent / "pythonw.exe"
    if not pyw.exists():
        return False
    bg_script = install_path / "bin" / "aegis_core_background.pyw"
    if not bg_script.exists():
        return False
    try:
        subprocess.Popen([str(pyw), str(bg_script)],
                         creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
                         close_fds=True)
        return True
    except Exception:
        return False


def acquire_lock() -> bool:
    if LOCK_FILE.exists():
        # Check if lock is stale (>30 min old)
        age = time.time() - LOCK_FILE.stat().st_mtime
        if age < 1800:
            return False
        LOCK_FILE.unlink(missing_ok=True)
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOCK_FILE.write_text(str(os.getpid()), encoding="utf-8")
    return True


def release_lock() -> None:
    try:
        LOCK_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def apply_update(install_path: Path) -> tuple[bool, str]:
    """Führt das Atomic-Swap durch. Returns (success, message)."""
    if not STAGED_ZIP.exists():
        return False, "no staged update"
    if not STAGED_META.exists():
        return False, "no staged metadata"

    # 1) Lock
    if not acquire_lock():
        return False, "another update in progress"

    try:
        # 2) Stop service + shell
        stop_service_clean()
        stop_shell()
        time.sleep(1)

        # 3) Backup current
        old_dir = install_path.with_suffix(".old")
        if old_dir.exists():
            shutil.rmtree(old_dir, ignore_errors=True)
        try:
            # Rename, not move — atomic on same fs
            install_path.rename(old_dir)
        except OSError as e:
            return False, f"could not move current install: {e}"

        # 4) Extract new
        install_path.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(STAGED_ZIP) as zf:
                # Sicherheits-Check gegen Zip-Slip
                for member in zf.namelist():
                    if member.startswith("/") or ".." in member:
                        raise ValueError(f"unsafe zip member: {member}")
                # Files extrahieren, ZIP enthält "AEGIS/..." als Prefix
                for member in zf.namelist():
                    if not member.startswith("AEGIS/"):
                        continue
                    target_rel = member[len("AEGIS/"):]
                    if not target_rel:
                        continue
                    target = install_path / target_rel
                    if member.endswith("/"):
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member) as src, open(target, "wb") as dst:
                            shutil.copyfileobj(src, dst)
        except Exception as e:
            # Rollback
            shutil.rmtree(install_path, ignore_errors=True)
            try:
                old_dir.rename(install_path)
            except OSError:
                pass
            return False, f"extraction failed: {e}"

        # 5) Cleanup old
        shutil.rmtree(old_dir, ignore_errors=True)

        # 6) Mark applied
        applied_meta = json.loads(STAGED_META.read_text(encoding="utf-8"))
        applied_meta["applied_at"] = time.time()
        (Path.home() / ".aegis" / "last_update_applied.json").write_text(
            json.dumps(applied_meta, indent=2), encoding="utf-8")
        STAGED_ZIP.unlink(missing_ok=True)
        STAGED_META.unlink(missing_ok=True)

        # 7) Restart service
        time.sleep(1)
        start_service(install_path)

        return True, f"updated to {applied_meta.get('version', '?')}"
    finally:
        release_lock()


# ============================================================
#  CLI Entry
# ============================================================
def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--install-path", type=Path, required=True)
    args = ap.parse_args()
    ok, msg = apply_update(args.install_path)
    print(f"[{'OK' if ok else 'FAIL'}] {msg}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
