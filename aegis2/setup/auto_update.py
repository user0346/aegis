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

import hashlib
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

SERVICE_NAME = "AegisCore"
# Erwartete Prozess-Namen fuer den AEGIS-Background-Core.
_EXPECTED_PROC_NAMES = {"pythonw.exe", "python.exe"}


def _pid_is_aegis_process(pid: int) -> bool:
    """Validiert per psutil, dass <pid> wirklich der AEGIS-Core ist.

    SICHERHEIT: ~/.aegis/service.pid ist world-writable; ein Angreifer koennte
    dort eine fremde PID hineinschreiben. Da dieser Helper ELEVATED laufen kann,
    wuerde ein ungeprueftes 'taskkill /F /PID' einen beliebigen (auch System-)
    Prozess killen. Wir verifizieren daher VOR dem Kill:
      1. der Prozess existiert,
      2. sein Name ist pythonw.exe/python.exe (erwarteter AEGIS-Interpreter),
      3. seine Kommandozeile referenziert das AEGIS-Install-Tree
         (Skript unterhalb von ROOT) — das ist die AEGIS-spezifische Identitaet,
         genau wie sie der Background-Launcher und aegis_restart.py verwenden.
    Schlaegt eine Pruefung fehl (oder fehlt psutil), wird NICHT gekillt
    (fail-closed).
    """
    try:
        import psutil
    except Exception:  # noqa: BLE001
        return False
    try:
        if not psutil.pid_exists(pid):
            return False
        proc = psutil.Process(pid)
        name = (proc.name() or "").lower()
        if name not in _EXPECTED_PROC_NAMES:
            return False
        try:
            cmdline = " ".join(proc.cmdline() or []).lower()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return False
        # Muss eine AEGIS-Script-Referenz aus dem Install-Tree enthalten.
        root = str(Path(__file__).resolve().parents[2]).lower()
        if "aegis" not in cmdline:
            return False
        if root not in cmdline and "aegis_core_background" not in cmdline:
            return False
        return True
    except Exception:  # noqa: BLE001
        return False


def stop_service_clean(timeout_s: int = 12) -> bool:
    """Signalisiert Service-Stop, wartet auf clean shutdown, fallback force-kill."""
    pid_file = Path.home() / ".aegis" / "service.pid"
    if not pid_file.exists():
        return True   # nicht aktiv

    # Sentinel-File
    STOP_SENTINEL.write_text("update", encoding="utf-8")

    # Bevorzugt: regulaerer SCM-Stop des Windows-Service (kein PID-Vertrauen noetig).
    try:
        subprocess.run(["sc.exe", "stop", SERVICE_NAME],
                       capture_output=True, timeout=8)
    except Exception:  # noqa: BLE001
        pass

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not pid_file.exists():
            return True
        time.sleep(0.5)

    # Force-Kill — NUR wenn die PID validiert als AEGIS-Prozess erkannt wird.
    try:
        pid = int(pid_file.read_text().strip())
        if _pid_is_aegis_process(pid):
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=8)
        # sonst: gespoofte/fremde PID -> NICHT killen (fail-closed).
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


def _verify_staged_integrity() -> tuple[bool, str]:
    """RE-verifiziert die gestagte Update-Datei gegen die ECHTE Signatur + SHA.

    SICHERHEIT: Verlaesst sich NICHT auf das (faelschbare) signature_verified-Flag
    in staged.json. Eine lokale Malware koennte staged.json + staged.zip schreiben
    und das Flag auf true setzen — deshalb pruefen wir hier die tatsaechliche
    Sigstore-Signatur gegen den erwarteten Workflow + den ZIP-SHA neu. Ohne
    gueltige Signatur wird NICHT installiert.
    """
    try:
        meta = json.loads(STAGED_META.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return False, f"meta unreadable: {e}"

    # 1) SHA der staged.zip muss zum Manifest passen (kein Austausch nach Staging)
    want_sha = (meta.get("sha256") or "").lower()
    if not want_sha:
        return False, "no sha256 in metadata"
    h = hashlib.sha256()
    try:
        with open(STAGED_ZIP, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError as e:
        return False, f"cannot hash staged zip: {e}"
    if h.hexdigest().lower() != want_sha:
        return False, "sha256 mismatch (staged zip tampered)"

    # 2) Sigstore-Signatur ERNEUT gegen die echten .sig/.crt verifizieren
    sig_path = UPDATE_DIR / "staged.zip.sig"
    cert_path = UPDATE_DIR / "staged.zip.crt"
    repo = meta.get("expected_repo", "")
    if not (sig_path.exists() and cert_path.exists() and repo):
        return False, "signature material missing — refusing unsigned update"
    try:
        from ..shared.github_updater import verify_sigstore
    except Exception as e:  # noqa: BLE001
        return False, f"verifier unavailable: {e}"
    ok, reason = verify_sigstore(STAGED_ZIP, sig_path, cert_path, expected_repo=repo)
    if not ok:
        return False, f"signature re-verification failed: {reason}"
    return True, "verified"


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
        # 1.5) SICHERHEIT: Integritaet RE-verifizieren (Signatur + SHA), bevor
        # irgendetwas ersetzt wird. Schuetzt vor gefaelschtem staged.json-Flag,
        # CLI-Direktaufruf und manipulierter staged.zip.
        ok, reason = _verify_staged_integrity()
        if not ok:
            return False, f"integrity check failed: {reason}"

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
        # SICHERHEIT: Canonical Zip-Slip-Guard. Der alte Substring-Check
        # (".." in member) war unzureichend — er liess absolute Pfade ("/x"),
        # Backslash-Pfade ("..\\x"), Drive-Letter ("C:\\x") und UNC-Pfade
        # ("\\\\srv\\x") durch und konnte legitime Namen mit ".." faelschlich
        # blocken. Wir aufloesen daher fuer JEDEN Member das echte Ziel und
        # stellen sicher, dass es real INNERHALB von install_path liegt; sonst
        # wird der Member abgelehnt (fail-closed, KEINE Extraktion).
        install_root = install_path.resolve()
        try:
            with zipfile.ZipFile(STAGED_ZIP) as zf:
                # Files extrahieren, ZIP enthält "AEGIS/..." als Prefix
                for member in zf.namelist():
                    if not member.startswith("AEGIS/"):
                        continue
                    target_rel = member[len("AEGIS/"):]
                    if not target_rel:
                        continue

                    # Frueh harte, offensichtlich boesartige Formen ablehnen,
                    # bevor wir ueberhaupt joinen (Drive-Letter / UNC / absolut).
                    rel_norm = target_rel.replace("\\", "/")
                    if (rel_norm.startswith("/")
                            or rel_norm.startswith("//")
                            or (len(rel_norm) >= 2 and rel_norm[1] == ":")):
                        raise ValueError(f"unsafe zip member (absolute/drive): {member}")

                    target = install_path / target_rel
                    # Kanonischer Containment-Check: resolve() loest '..',
                    # Symlinks und gemischte Separatoren auf. Das aufgeloeste
                    # Ziel MUSS install_root selbst oder ein Nachfahre sein.
                    resolved = target.resolve()
                    if resolved != install_root and install_root not in resolved.parents:
                        raise ValueError(f"unsafe zip member (escapes install dir): {member}")

                    if member.endswith("/"):
                        resolved.mkdir(parents=True, exist_ok=True)
                    else:
                        resolved.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member) as src, open(resolved, "wb") as dst:
                            shutil.copyfileobj(src, dst)
        except Exception as e:
            # Rollback: frischen (evtl. unvollstaendigen) Baum verwerfen und
            # das .old-Backup zuruecksetzen. Das Backup existiert hier noch,
            # weil wir es erst NACH erfolgreicher Extraktion loeschen.
            shutil.rmtree(install_path, ignore_errors=True)
            try:
                old_dir.rename(install_path)
            except OSError:
                pass
            return False, f"extraction failed: {e}"

        # 5) Cleanup old — ERST JETZT, nach vollstaendig erfolgreicher
        # Extraktion. Vorher behalten wir .old als einzige Rollback-Quelle,
        # damit ein Crash mitten in Schritt 4 keine kaputte Installation ohne
        # Wiederherstellungspfad hinterlaesst.
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
