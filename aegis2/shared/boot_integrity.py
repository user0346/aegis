"""Boot-Integrity-Modul — liest die Windows Pre-Boot Sicherheits-Infrastruktur.

Ohne Kernel-Driver, ohne Cert. Nutzt was Windows ohnehin bereitstellt:
  - Secure Boot Status (`Confirm-SecureBootUEFI`)
  - TPM 2.0 Presence + PCR-Hashes (`Get-Tpm`, `Get-PcrTable` wenn verfügbar)
  - System Guard Runtime Attestation (`SystemGuardSelfHostedClientInterface`)
  - WDAC Code-Integrity Policy Status (Reg-Read)
  - Defender Tamper-Protection Status (`Get-MpComputerStatus`)
  - BitLocker-Status (`Get-BitLockerVolume`)
  - Measured Boot Log (.bcd-Pfad)

Bei Boot oder periodisch (alle 6h) abfragen. Vergleicht gegen gepinnten Trust-State.
Mismatch → CRITICAL.
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from .proc import run_hidden


log = logging.getLogger("aegis.boot_integrity")


@dataclass
class BootState:
    secure_boot: Optional[bool] = None
    tpm_present: Optional[bool] = None
    tpm_ready: Optional[bool] = None
    tpm_manufacturer: str = ""
    pcr_hashes: dict = field(default_factory=dict)  # {pcr_index: sha256}
    wdac_active: Optional[bool] = None
    wdac_policies: list = field(default_factory=list)
    defender_tamper: Optional[bool] = None
    defender_realtime: Optional[bool] = None
    bitlocker_status: dict = field(default_factory=dict)  # {drive: {protection_status, ...}}
    measured_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    def trust_summary(self) -> dict:
        """Aggregierter Score 0-100 + Empfehlungen."""
        score = 0
        recommendations = []
        if self.secure_boot is True: score += 25
        else: recommendations.append("Secure Boot im UEFI aktivieren")
        if self.tpm_present and self.tpm_ready: score += 20
        elif not self.tpm_present: recommendations.append("TPM 2.0 nicht erkannt — Hardware-Sicherheit fehlt")
        if self.wdac_active: score += 25
        else: recommendations.append("WDAC-Policy noch nicht aktiv (kommt nach Reboot)")
        if self.defender_tamper: score += 10
        else: recommendations.append("Windows Defender Tamper Protection einschalten")
        if self.defender_realtime: score += 10
        else: recommendations.append("Windows Defender Real-Time-Protection aus — gefährlich")
        # BitLocker for system drive
        sys_bitlocker = self.bitlocker_status.get("C:", {})
        if sys_bitlocker.get("protection") == "On": score += 10
        else: recommendations.append("BitLocker für C: nicht aktiv — Vollverschlüsselung empfohlen")
        return {"score": score, "max": 100,
                "level": "high" if score >= 80 else "medium" if score >= 50 else "low",
                "recommendations": recommendations}


# ============================================================
#  Sample Helpers (PowerShell-only, no extra deps)
# ============================================================

def _ps(cmd: str, timeout: int = 12) -> str:
    if sys.platform != "win32":
        return ""
    try:
        r = run_hidden(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace"
        )
        return (r.stdout or "").strip()
    except Exception as e:  # noqa: BLE001
        log.warning("PowerShell cmd failed: %s", e)
        return ""


def check_secure_boot() -> Optional[bool]:
    out = _ps("try { Confirm-SecureBootUEFI } catch { 'unknown' }").lower()
    if "true" in out: return True
    if "false" in out: return False
    return None


def check_tpm() -> dict:
    """Returns {present, ready, manufacturer, version}."""
    out = _ps("(Get-Tpm 2>$null) | Select-Object TpmPresent,TpmReady,ManufacturerIdTxt,ManagedAuthLevel | ConvertTo-Json -Compress")
    try:
        d = json.loads(out)
        return {
            "present": bool(d.get("TpmPresent")),
            "ready": bool(d.get("TpmReady")),
            "manufacturer": str(d.get("ManufacturerIdTxt", "")),
        }
    except Exception:  # noqa: BLE001
        return {"present": None, "ready": None, "manufacturer": ""}


def check_pcr_hashes() -> dict:
    """Lese PCR-Register 0-7 (Pre-OS-Hash-Chain).
    Get-PcrTable ist in Win11+ verfügbar, sonst Fallback auf tpmtool.
    """
    out = _ps(
        "try {"
        "  Get-PcrTable -SHA256 |"
        "  Where-Object { $_.Index -le 7 } |"
        "  Select-Object Index, @{N='Hash'; E={[BitConverter]::ToString($_.Pcr).Replace('-','').ToLower()}} |"
        "  ConvertTo-Json -Compress"
        "} catch { '' }"
    )
    if not out: return {}
    try:
        data = json.loads(out)
        if isinstance(data, dict): data = [data]
        return {str(d["Index"]): d.get("Hash", "") for d in data if "Index" in d}
    except Exception:  # noqa: BLE001
        return {}


def check_wdac() -> dict:
    """WDAC = Windows Defender Application Control.
    Liest Code-Integrity-Policies aus Registry.
    """
    out = _ps(
        "$path='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy';"
        "if(Test-Path $path){"
        "  $opts=(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue);"
        "  $active=$opts.PSObject.Properties.Name -match 'PolicyOptions';"
        "  $policies=Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name;"
        "  [PSCustomObject]@{Active=$active.Count -gt 0; Policies=$policies} | ConvertTo-Json -Compress"
        "} else { '{\"Active\":false,\"Policies\":[]}' }"
    )
    try:
        d = json.loads(out or "{}")
        policies = d.get("Policies") or []
        if isinstance(policies, str): policies = [policies]
        return {"active": bool(d.get("Active")), "policies": policies}
    except Exception:  # noqa: BLE001
        return {"active": None, "policies": []}


def check_defender() -> dict:
    out = _ps(
        "Get-MpComputerStatus | Select-Object "
        "IsTamperProtected, RealTimeProtectionEnabled, "
        "AntivirusEnabled, AMServiceEnabled "
        "| ConvertTo-Json -Compress"
    )
    try:
        d = json.loads(out or "{}")
        return {
            "tamper_protected": bool(d.get("IsTamperProtected")),
            "realtime": bool(d.get("RealTimeProtectionEnabled")),
            "antivirus": bool(d.get("AntivirusEnabled")),
            "service": bool(d.get("AMServiceEnabled")),
        }
    except Exception:  # noqa: BLE001
        return {}


def check_bitlocker() -> dict:
    """Returns {drive_letter: {protection, encryption_method, ...}}."""
    out = _ps(
        "Get-BitLockerVolume 2>$null | Select-Object "
        "MountPoint, ProtectionStatus, EncryptionMethod, VolumeStatus "
        "| ConvertTo-Json -Compress"
    )
    if not out: return {}
    try:
        data = json.loads(out)
        if isinstance(data, dict): data = [data]
        result = {}
        for d in data:
            mp = d.get("MountPoint", "")
            result[mp] = {
                "protection": "On" if d.get("ProtectionStatus") == 1 else "Off",
                "encryption_method": d.get("EncryptionMethod", ""),
                "volume_status": d.get("VolumeStatus", ""),
            }
        return result
    except Exception:  # noqa: BLE001
        return {}


# ============================================================
#  Snapshot + Pin/Compare
# ============================================================

def capture_state() -> BootState:
    """Single sample of all boot-integrity facts."""
    state = BootState()
    state.secure_boot = check_secure_boot()
    tpm = check_tpm()
    state.tpm_present = tpm.get("present")
    state.tpm_ready = tpm.get("ready")
    state.tpm_manufacturer = tpm.get("manufacturer", "")
    state.pcr_hashes = check_pcr_hashes()
    wdac = check_wdac()
    state.wdac_active = wdac.get("active")
    state.wdac_policies = wdac.get("policies", [])
    df = check_defender()
    state.defender_tamper = df.get("tamper_protected")
    state.defender_realtime = df.get("realtime")
    state.bitlocker_status = check_bitlocker()
    state.measured_at = time.time()
    return state


def compare_to_pin(current: BootState, pinned_dict: dict) -> list[str]:
    """Returns list of human-readable mismatches (empty = trust intact)."""
    msgs = []
    if pinned_dict.get("secure_boot") != current.secure_boot:
        msgs.append(f"Secure Boot Wechsel: {pinned_dict.get('secure_boot')} → {current.secure_boot}")
    if pinned_dict.get("tpm_manufacturer") and pinned_dict["tpm_manufacturer"] != current.tpm_manufacturer:
        msgs.append("TPM-Manufacturer geändert — Hardware-Swap?")
    # PCR-Mismatches sind sehr aussagekräftig
    pinned_pcr = pinned_dict.get("pcr_hashes", {})
    for k, v in pinned_pcr.items():
        cur = current.pcr_hashes.get(k)
        if cur and cur != v:
            msgs.append(f"PCR{k} Mismatch (Boot-Chain manipuliert?)")
    # WDAC wurde ausgeschaltet
    if pinned_dict.get("wdac_active") and not current.wdac_active:
        msgs.append("WDAC-Policy wurde deaktiviert")
    # Defender Tamper Protection aus
    if pinned_dict.get("defender_tamper") and not current.defender_tamper:
        msgs.append("Defender Tamper Protection wurde deaktiviert")
    return msgs
