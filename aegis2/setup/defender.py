"""Autonome Defender-Exclusion mit User-Consent.

Wichtig — was wir machen UND warum es nicht heimlich ist:

  * AEGIS verlangt EINMAL beim Install eine UAC-Erhöhung. Dabei zeigt
    Windows selbst den Befehl (PowerShell + Add-MpPreference) an, also
    sieht der User exakt was passiert.
  * Wir loggen jede Exclusion in ~/.aegis/audit.jsonl.
  * Wir bieten ein Remove (Remove-MpPreference) im Uninstall.

Plattformen:
  - Defender (Win10/Win11 builtin) -> wird via Add-MpPreference gesetzt.
  - Drittanbieter-AV (Avast, Norton, McAfee, Kaspersky, ESET, Bitdefender)
    -> NICHT autonom (jede Suite hat anderen API); wir geben dem User
    nur eine Klick-Anleitung.

Status-Codes:
  0 OK gesetzt
  1 User-Cancel
  2 Defender nicht aktiv (Drittanbieter erkannt)
  3 PowerShell-Fehler
  4 Kein Windows
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path


AUDIT_PATH = Path.home() / ".aegis" / "audit.jsonl"

KNOWN_THIRD_PARTY_AV = [
    ("Avast",       ["AvastSvc", "AvastUI"]),
    ("AVG",         ["AVGSvc"]),
    ("Norton",      ["NortonSecurity", "ccSvcHst"]),
    ("McAfee",      ["mcshield", "McUICnt"]),
    ("Kaspersky",   ["avp"]),
    ("ESET",        ["egui", "ekrn"]),
    ("Bitdefender", ["vsserv", "bdagent"]),
    ("Malwarebytes",["MBAMService"]),
]


def _audit(record: dict) -> None:
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        record["ts"] = time.time()
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass


def detect_third_party_av() -> list[str]:
    """Liefert Namen erkannter Drittanbieter-AVs (kann leer sein)."""
    if sys.platform != "win32":
        return []
    try:
        r = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=8
        )
        out = (r.stdout or "").lower()
    except Exception:  # noqa: BLE001
        return []
    found = []
    for name, processes in KNOWN_THIRD_PARTY_AV:
        for p in processes:
            if p.lower() + ".exe" in out:
                found.append(name)
                break
    return found


def defender_is_active() -> bool:
    """True wenn Defender als primärer AV läuft."""
    if sys.platform != "win32":
        return False
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-MpComputerStatus).AntivirusEnabled"],
            capture_output=True, text=True, timeout=8
        )
        return "true" in (r.stdout or "").lower()
    except Exception:  # noqa: BLE001
        return False


def add_defender_exclusion(folder: Path, processes: list[str]) -> int:
    """
    Fügt Ordner + EXE-Namen zur Defender-Ausschlussliste hinzu.
    MUSS aus elevatem (Admin-)Prozess heraus laufen.
    Ohne Elevation gibt PowerShell zwar keine Fehlermeldung, aber die
    Exclusion landet nicht - check via Get-MpPreference.
    """
    if sys.platform != "win32":
        return 4

    if not defender_is_active():
        third_party = detect_third_party_av()
        _audit({"event": "defender_skip",
                "reason": "defender_inactive",
                "third_party_detected": third_party})
        return 2

    ps_lines = [
        # Folder-Exclusion
        f"Add-MpPreference -ExclusionPath '{folder}'",
    ]
    for proc in processes:
        ps_lines.append(f"Add-MpPreference -ExclusionProcess '{proc}'")
    # Verify
    ps_lines.append("(Get-MpPreference).ExclusionPath -join ';'")

    script = "; ".join(ps_lines)
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=20
        )
    except Exception as e:  # noqa: BLE001
        _audit({"event": "defender_error", "error": str(e)})
        return 3

    stdout = r.stdout or ""
    success = str(folder) in stdout

    _audit({
        "event": "defender_exclusion_set" if success else "defender_exclusion_failed",
        "folder": str(folder),
        "processes": processes,
        "powershell_rc": r.returncode,
        "verified": success,
    })

    return 0 if success else 3


def remove_defender_exclusion(folder: Path, processes: list[str]) -> int:
    """Reverse — entfernt die Exclusions wieder beim Uninstall."""
    if sys.platform != "win32":
        return 4
    if not defender_is_active():
        return 2

    ps_lines = [f"Remove-MpPreference -ExclusionPath '{folder}'"]
    for proc in processes:
        ps_lines.append(f"Remove-MpPreference -ExclusionProcess '{proc}'")
    script = "; ".join(ps_lines)
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=20
        )
    except Exception as e:  # noqa: BLE001
        _audit({"event": "defender_remove_error", "error": str(e)})
        return 3

    _audit({"event": "defender_exclusion_removed",
            "folder": str(folder), "processes": processes,
            "powershell_rc": r.returncode})
    return 0 if r.returncode == 0 else 3


def explain_third_party_steps(av_name: str, folder: Path) -> str:
    """User-friendly Anleitung für Drittanbieter-AVs (nicht autonom setzbar)."""
    base = (f"Drittanbieter-AV erkannt: {av_name}. "
            f"Bitte folgenden Ordner manuell zur Ausnahmeliste hinzufügen:\n\n"
            f"  {folder}\n\n")
    hints = {
        "Avast": "Menü → Schutz → Kerneinstellungen → Ausnahmen → Pfad hinzufügen.",
        "AVG": "Menü → Einstellungen → Ausnahmen → Datei/Ordner.",
        "Norton": "Einstellungen → Antivirus → Scans und Risiken → Ausschlüsse.",
        "McAfee": "Einstellungen → Echtzeit-Scan → Ausschlussdateien.",
        "Kaspersky": "Einstellungen → Untersuchung → Vertrauenswürdige Zone.",
        "ESET": "Setup → Computer-Schutz → Ausschlussfilter.",
        "Bitdefender": "Schutz → Antivirus → Einstellungen → Ausnahmen.",
        "Malwarebytes": "Einstellungen → Ausschlüsse → Ordner hinzufügen.",
    }
    return base + (hints.get(av_name, "Siehe AV-Dokumentation für Exclusion-Pfad."))
