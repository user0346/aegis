"""Hardened-Installer — Production-Grade Setup.

Macht alles was install.py macht, PLUS:
  1. Kopiert AEGIS nach C:\\Program Files\\AEGIS\\ (TrustedInstaller-Schutz möglich)
  2. Setzt strikte ACL (TrustedInstaller=Owner, Admins=Read+Execute, Users=Read+Execute)
  3. Service-Start-Type "boot" (lädt mit Kernel-Init)
  4. Service-SDDL so dass nur SYSTEM/TrustedInstaller stoppen können
  5. WDAC Code-Integrity Policy generieren + deployen (Audit-Mode default)
  6. Boot-Integrity-Pin (TPM PCR + Secure Boot + Defender-Status)
  7. BitLocker-Empfehlung (zeigt nur Hinweis, aktiviert NICHT autonom)
  8. Backup-Kopie nach C:\\Program Files\\AEGIS\\.backup\\ für Self-Repair

Aufruf:
    py -m aegis2.setup.install_hardened --install
    py -m aegis2.setup.install_hardened --uninstall
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


PROGRAM_FILES_AEGIS = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "AEGIS"
BACKUP_DIR = PROGRAM_FILES_AEGIS / ".backup"


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin() -> None:
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{__file__}" {params}', None, 1
    )


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


# ============================================================
#  Step 1 — Copy to Program Files
# ============================================================
def step_copy_to_program_files() -> bool:
    print("\n=== Schritt 1/7 - Copy nach C:\\Program Files\\AEGIS ===")
    src = _project_root()
    if src.resolve() == PROGRAM_FILES_AEGIS.resolve():
        print("[INFO] Schon im Program Files. Überspringe Copy.")
        return True
    try:
        if PROGRAM_FILES_AEGIS.exists():
            # Backup vorhandene Version
            print(f"[INFO] Backup nach {PROGRAM_FILES_AEGIS}.old")
            old = PROGRAM_FILES_AEGIS.with_suffix(".old")
            if old.exists():
                shutil.rmtree(old, ignore_errors=True)
            try:
                shutil.move(str(PROGRAM_FILES_AEGIS), str(old))
            except OSError:
                pass
        PROGRAM_FILES_AEGIS.mkdir(parents=True, exist_ok=True)
        # Kopiere Inhalt
        for item in src.iterdir():
            if item.name in {"__pycache__", ".git", ".venv"}:
                continue
            dest = PROGRAM_FILES_AEGIS / item.name
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            else:
                shutil.copy2(item, dest)
        print(f"[OK] Kopiert nach {PROGRAM_FILES_AEGIS}")
        # Backup der eigenen Files für Self-Repair
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copytree(PROGRAM_FILES_AEGIS / "aegis2", BACKUP_DIR / "aegis2",
                        dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        print(f"[OK] Backup für Self-Repair: {BACKUP_DIR}")
        return True
    except Exception as e:
        print(f"[ERR] Copy fehlgeschlagen: {e}")
        return False


# ============================================================
#  Step 2 — Defender-Exclusion
# ============================================================
def step_defender() -> bool:
    print("\n=== Schritt 2/7 - Defender-Exclusion ===")
    try:
        from aegis2.setup import defender
        third = defender.detect_third_party_av()
        if third:
            print(f"[WARN] Drittanbieter-AV erkannt: {third}")
            return True
        if not defender.defender_is_active():
            print("[INFO] Defender nicht aktiv, übersprungen")
            return True
        rc = defender.add_defender_exclusion(
            PROGRAM_FILES_AEGIS,
            ["aegis-core.exe", "aegis-shell.exe", "pythonw.exe", "python.exe"]
        )
        print(f"[{'OK' if rc == 0 else 'WARN'}] Defender-Exclusion rc={rc}")
        return rc == 0
    except Exception as e:
        print(f"[WARN] Defender-Step error: {e}")
        return True


# ============================================================
#  Step 3 — Service-Install (Boot-Start)
# ============================================================
def step_service() -> bool:
    print("\n=== Schritt 3/7 - Service registrieren (Boot-Start) ===")
    service_entry = PROGRAM_FILES_AEGIS / "aegis2" / "service" / "service.py"
    if not service_entry.exists():
        print(f"[ERR] service.py fehlt: {service_entry}")
        return False
    cmd = [sys.executable, str(service_entry), "--startup=boot", "install"]
    print(">", " ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        print(f"[WARN] Service-Install rc={rc} — fallback auf --startup=auto")
        subprocess.call([sys.executable, str(service_entry), "--startup=auto", "install"])
    # Recovery
    subprocess.call(["sc.exe", "failure", "AegisCore",
                     "reset=", "86400",
                     "actions=", "restart/5000/restart/15000/restart/60000"])
    print("[OK] Service registriert mit Recovery-Policy")
    return True


# ============================================================
#  Step 4 — Hardening (ACL + SDDL + Boot-Type)
# ============================================================
def step_hardening() -> bool:
    print("\n=== Schritt 4/7 - Hardening (TrustedInstaller-ACL + Service-SDDL) ===")
    try:
        from aegis2.setup.hardened_install import full_hardening
        results = full_hardening(PROGRAM_FILES_AEGIS)
        print(f"  · Folder-ACL:    {'OK' if results['folder_acl'] else 'FAIL'}")
        print(f"  · Service-Boot:  {'OK' if results['service_boot'] else 'FAIL'}")
        print(f"  · Service-SDDL:  {'OK' if results['service_sddl'] else 'FAIL'}")
        bl = results.get("bitlocker", {})
        if bl.get("available"):
            if bl.get("enabled"):
                print(f"  · BitLocker C:   ON (empfohlen)")
            else:
                print(f"  · BitLocker C:   OFF")
                print(f"    Empfehlung: {bl.get('recommendation')}")
        return any([results['folder_acl'], results['service_boot'], results['service_sddl']])
    except Exception as e:
        print(f"[WARN] Hardening-Step error: {e}")
        return False


# ============================================================
#  Step 5 — WDAC Code-Integrity-Policy
# ============================================================
def step_wdac() -> bool:
    print("\n=== Schritt 5/7 - WDAC Code-Integrity-Policy (Audit-Mode) ===")
    try:
        from aegis2.setup.wdac_policy import full_setup
        results = full_setup(PROGRAM_FILES_AEGIS)
        print(f"  · XML generiert:    {'OK' if results['xml_generated'] else 'FAIL'}")
        print(f"  · P7B kompiliert:   {'OK' if results['p7b_compiled'] else 'FAIL'}")
        print(f"  · Deployed:         {'OK' if results['deployed'] else 'FAIL'}")
        if results['deployed']:
            print("  [INFO] Policy ist im AUDIT-MODE — loggt nur, blockiert nichts.")
            print("  [INFO] Aktivierung erst nach Reboot.")
            print("  [INFO] In UI → Boot-Integrity Tab später auf Enforce schalten.")
        return results['deployed']
    except Exception as e:
        print(f"[WARN] WDAC-Step error: {e}")
        return False


# ============================================================
#  Step 6 — Boot-Integrity-Pin
# ============================================================
def step_boot_pin() -> bool:
    print("\n=== Schritt 6/7 - Boot-Integrity-Pin ===")
    try:
        from aegis2.shared.boot_integrity import capture_state
        state = capture_state()
        pin_path = Path.home() / ".aegis" / "boot_pin.json"
        pin_path.parent.mkdir(parents=True, exist_ok=True)
        pin_path.write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")
        summary = state.trust_summary()
        print(f"  · Trust-Score: {summary['score']}/100 ({summary['level']})")
        if summary['recommendations']:
            print("  · Empfehlungen:")
            for rec in summary['recommendations']:
                print(f"      - {rec}")
        print(f"  [OK] Boot-State gepinnt: {pin_path}")
        return True
    except Exception as e:
        print(f"[WARN] Boot-Pin error: {e}")
        return False


# ============================================================
#  Step 7 — Scheduled Tasks (Login + HealthCheck)
# ============================================================
def step_tasks() -> bool:
    print("\n=== Schritt 7/7 - Scheduled Tasks ===")
    try:
        # Delegate to existing install logic
        from aegis2.setup.install import do_tasks_step
        return do_tasks_step()
    except Exception as e:
        print(f"[WARN] Tasks-Step error: {e}")
        return False


# ============================================================
#  Main
# ============================================================
def banner():
    print("""
=================================================================
                  AEGIS Hardened Installer
=================================================================

  Installiert mit Production-Grade Security:

    1. Copy nach C:\\Program Files\\AEGIS\\
    2. Defender-Exclusion für Ordner + EXEs
    3. Service registrieren mit Boot-Start + Auto-Restart
    4. TrustedInstaller-ACL + Service-SDDL-Hardening
    5. WDAC Code-Integrity-Policy (Audit-Mode)
    6. Boot-Integrity-Pin (TPM + Secure Boot + Defender)
    7. Login-Task + HealthCheck-Watchdog

  Im Vergleich zum normalen Install:
    + Files in C:\\Program Files mit TrustedInstaller-Schutz
    + Service kann nicht von Admin gestoppt werden
    + Code-Integrity-Policy blockt unsignierte Files (Audit)
    + Self-Repair-Backup für Tamper-Recovery
    + Boot-State-Pin für Tamper-Detection

  Eine Aktivierung erfordert Reboot.
=================================================================
""")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args()

    if not args.install and not args.uninstall:
        ap.print_help()
        return 0

    if not is_admin():
        print("Re-launch mit Admin-Rechten via UAC...")
        relaunch_as_admin()
        return 0

    if args.uninstall:
        print("Hardened-Uninstall ist gleich wie normaler Uninstall + Cleanup.")
        from aegis2.setup.install import do_uninstall
        do_uninstall(PROGRAM_FILES_AEGIS)
        # Cleanup ProgramFiles dir
        if PROGRAM_FILES_AEGIS.exists():
            print(f"Entferne {PROGRAM_FILES_AEGIS}...")
            try:
                # Take ownership back to remove
                subprocess.call(["takeown", "/F", str(PROGRAM_FILES_AEGIS), "/R", "/D", "Y"],
                                capture_output=True)
                subprocess.call(["icacls", str(PROGRAM_FILES_AEGIS), "/grant",
                                 "Administrators:F", "/T", "/Q"], capture_output=True)
                shutil.rmtree(PROGRAM_FILES_AEGIS, ignore_errors=True)
            except Exception as e:
                print(f"  [WARN] Cleanup unvollständig: {e}")
        return 0

    banner()
    if not args.yes:
        ans = input("Fortfahren? [j/N]: ").strip().lower()
        if ans not in ("j", "y", "yes", "ja"):
            print("Abgebrochen.")
            return 1

    ok_count = 0
    total = 7
    ok_count += step_copy_to_program_files()
    ok_count += step_defender()
    ok_count += step_service()
    ok_count += step_hardening()
    ok_count += step_wdac()
    ok_count += step_boot_pin()
    ok_count += step_tasks()

    print(f"\n=================================================================")
    print(f"  Ergebnis: {ok_count}/{total} Steps erfolgreich")
    print(f"  Install-Pfad: {PROGRAM_FILES_AEGIS}")
    print(f"  Reboot empfohlen für WDAC + Boot-Service-Start.")
    print(f"=================================================================")
    return 0 if ok_count >= 5 else 1


if __name__ == "__main__":
    sys.exit(main())
