"""AEGIS Defender-Diagnose — zeigt, warum der Ausschluss-Alarm (nicht) kommt.

Vergleicht die AKTUELLEN Defender-Ausschluesse mit der von AEGIS gelernten
Baseline. Damit sieht man sofort, ob (a) der neue Code ueberhaupt lief,
(b) der Test-Ausschluss sichtbar ist, (c) er als 'neu' zaehlt.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _ps_exclusions():
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "$p=Get-MpPreference; "
         "Write-Output ('PATH='+($p.ExclusionPath -join '|')); "
         "Write-Output ('PROC='+($p.ExclusionProcess -join '|')); "
         "Write-Output ('EXT='+($p.ExclusionExtension -join '|'))"],
        capture_output=True, text=True, timeout=15)
    return r.stdout or "", r.stderr or ""


def main():
    print("=" * 64)
    print(" AEGIS  ·  Defender-Ausschluss-Diagnose")
    print("=" * 64)

    print("\n[1] AKTUELLE Defender-Ausschluesse (was AEGIS jetzt sehen wuerde):")
    try:
        out, err = _ps_exclusions()
        for line in out.splitlines():
            print("    " + line)
        if not out.strip():
            print("    (PowerShell gab nichts zurueck)")
        if err.strip():
            print("    PowerShell-FEHLER: " + err.strip()[:400])
    except Exception as e:  # noqa: BLE001
        print("    PowerShell-Aufruf fehlgeschlagen:", e)

    print("\n[2] GESPEICHERTE Baseline (was AEGIS als legitim gelernt hat):")
    try:
        from aegis2.shared.db import get_db
        db = get_db()
        base = db.get_setting("defender_excl_baseline")
        if base is None:
            print("    >>> KEINE Baseline gespeichert.")
            print("    >>> Heisst: der neue Defender-Code lief noch NIE.")
            print("    >>> -> Deploy fehlt (Stop/REPIN/SETUP) ODER Service laeuft nicht.")
        else:
            for x in base:
                print("    ", x)
            print("    --- bereits als verdaechtig gemeldet ---")
            print("    ", db.get_setting("defender_excl_reported"))
    except Exception as e:  # noqa: BLE001
        print("    DB-Lesen fehlgeschlagen:", e)

    print("\n[3] Deutung:")
    print("    - Steht dein Test-Ausschluss unter [1] aber NICHT unter [2]")
    print("      -> AEGIS muss ihn beim naechsten Check (<=45s) als NEU melden.")
    print("    - Steht er unter [1] UND [2] -> als 'legitim' gelernt (kein Alarm).")
    print("      -> Test-Ausschluss entfernen, 1 Min warten, dann NEU hinzufuegen.")
    print("    - Baseline = None -> neuer Code lief nicht -> Deploy pruefen.")
    print("=" * 64)
    try:
        input("\nEnter zum Schliessen ...")
    except EOFError:
        pass


if __name__ == "__main__":
    main()
