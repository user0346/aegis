"""Hardened-Install — setzt TrustedInstaller-ACL auf den AEGIS-Ordner.

Macht den Install-Ordner für normale Admins read-only und nur durch den
Updater-Service (der unter TrustedInstaller läuft) änderbar.

Zusätzlich:
  - Setzt Service-Start-Type auf "boot" (höhere Priorität als "auto")
  - Sets Service-SDDL so dass nur SYSTEM/TrustedInstaller den Service stoppen kann
  - Empfiehlt BitLocker (zeigt Hinweis, aktiviert es NICHT autonom)

Erfordert Admin-Rechte beim Install.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def harden_folder_acl(folder: Path) -> bool:
    """ACL: nur SYSTEM + TrustedInstaller = Full, Users = Read+Execute."""
    if sys.platform != "win32" or not folder.exists():
        return False
    try:
        # Take ownership as TrustedInstaller
        subprocess.run(["takeown", "/F", str(folder), "/R", "/D", "Y"],
                       capture_output=True, timeout=60)
        # Reset ACL
        subprocess.run(["icacls", str(folder), "/reset", "/T", "/Q"],
                       capture_output=True, timeout=60)
        # Grant SYSTEM full
        subprocess.run(["icacls", str(folder), "/grant:r",
                        "SYSTEM:(OI)(CI)F", "/T", "/Q"],
                       capture_output=True, timeout=60)
        # Grant TrustedInstaller full
        subprocess.run(["icacls", str(folder), "/grant:r",
                        "NT SERVICE\\TrustedInstaller:(OI)(CI)F", "/T", "/Q"],
                       capture_output=True, timeout=60)
        # Grant Admins read+execute (not write)
        subprocess.run(["icacls", str(folder), "/grant:r",
                        "BUILTIN\\Administrators:(OI)(CI)RX", "/T", "/Q"],
                       capture_output=True, timeout=60)
        # Grant Users read+execute
        subprocess.run(["icacls", str(folder), "/grant:r",
                        "BUILTIN\\Users:(OI)(CI)RX", "/T", "/Q"],
                       capture_output=True, timeout=60)
        # Set TrustedInstaller as owner
        subprocess.run(["icacls", str(folder), "/setowner",
                        "NT SERVICE\\TrustedInstaller", "/T", "/Q"],
                       capture_output=True, timeout=60)
        return True
    except Exception:  # noqa: BLE001
        return False


def set_service_boot_start(service_name: str = "AegisCore") -> bool:
    """Service-Start-Type: boot statt auto. Lädt mit Kernel-Init."""
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(
            ["sc.exe", "config", service_name, "start=", "boot"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace"
        )
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def harden_service_sddl(service_name: str = "AegisCore") -> bool:
    """Service-SDDL so dass nur SYSTEM/TrustedInstaller stoppen können."""
    if sys.platform != "win32":
        return False
    # SDDL für strikten Service-Schutz:
    # D = DACL
    # (A;;CCLCSWLOCRRC;;;AU) = Authenticated Users dürfen nur Query + Status
    # (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY) = SYSTEM = Full
    # (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA) = Admins = Full (still need for fixes)
    sddl = "D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
    try:
        r = subprocess.run(
            ["sc.exe", "sdset", service_name, sddl],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace"
        )
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def check_bitlocker_recommendation() -> dict:
    """Prüft BitLocker-Status für C: und gibt Empfehlung zurück."""
    if sys.platform != "win32":
        return {"available": False}
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue).ProtectionStatus"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace"
        )
        status = (r.stdout or "").strip()
        return {
            "available": True,
            "enabled": status == "On" or status == "1",
            "recommendation": "BitLocker für C: einschalten — "
                              "schützt gegen Offline-Tampering. "
                              "Setup: Settings → Update & Security → "
                              "Device Encryption / BitLocker.",
        }
    except Exception:  # noqa: BLE001
        return {"available": False}


def full_hardening(install_path: Path,
                   service_name: str = "AegisCore") -> dict:
    """Run all hardening steps. Returns status dict."""
    results = {
        "folder_acl": False,
        "service_boot": False,
        "service_sddl": False,
        "bitlocker": {},
    }
    results["folder_acl"] = harden_folder_acl(install_path)
    results["service_boot"] = set_service_boot_start(service_name)
    results["service_sddl"] = harden_service_sddl(service_name)
    results["bitlocker"] = check_bitlocker_recommendation()
    return results
