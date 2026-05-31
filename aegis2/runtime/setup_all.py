"""AEGIS Ersteinrichtung (--setup): Autostart + Verknuepfungen + Integritaets-Baseline.

Der Browser-Native-Host (Brave/Chrome/Edge-Guard) wird nur best-effort und nur
aus dem Quellcode mitgenommen — er ist optional und haengt an einem vorhandenen
extension/-Ordner. Die Kern-Endpoint-Sicherung haengt NICHT davon ab.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _create_shortcuts() -> None:
    """Desktop- + Startmenue-Verknuepfung auf die laufende AEGIS.exe (nur frozen).

    Damit hat der Endnutzer ein sauberes Icon, statt die .exe im Ordner suchen zu
    muessen. Best-effort: scheitert es (z.B. ohne pywin32), wird es still uebersprungen."""
    if not getattr(sys, "frozen", False):
        return
    target = sys.executable                      # …/AEGIS.exe
    workdir = str(Path(target).parent)
    try:
        import win32com.client  # type: ignore  (pywin32, im Bundle)
        shell = win32com.client.Dispatch("WScript.Shell")
    except Exception:  # noqa: BLE001
        return
    folders = [
        Path(os.environ.get("USERPROFILE", "")) / "Desktop",
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows"
        / "Start Menu" / "Programs",
    ]
    for folder in folders:
        try:
            if not str(folder).strip():
                continue
            folder.mkdir(parents=True, exist_ok=True)
            lnk = shell.CreateShortcut(str(folder / "AEGIS.lnk"))
            lnk.TargetPath = target
            lnk.WorkingDirectory = workdir
            lnk.IconLocation = target + ",0"
            lnk.Description = "AEGIS Guard"
            lnk.Save()
            print("Verknuepfung:", folder / "AEGIS.lnk")
        except Exception:  # noqa: BLE001
            pass


def main() -> int:
    # 1) Autostart beim Login (HKCU Run, kein Admin) — frozen-aware (s. install_autostart).
    try:
        from aegis2.setup import install_autostart
        install_autostart.install()
        print("Autostart eingerichtet.")
    except Exception as e:  # noqa: BLE001
        print("Autostart fehlgeschlagen:", e)

    # 2) Desktop-/Startmenue-Verknuepfung (nur gefrorene App).
    _create_shortcuts()

    # 3) Browser-Native-Host — optional, nur Quellcode mit vorhandener extension/.
    try:
        from aegis2.shared import launcher
        if not launcher.is_frozen():
            import importlib
            importlib.import_module("aegis2.setup.install_native_host")  # laeuft on import
    except Exception:  # noqa: BLE001
        pass  # Browser-Guard ist optional — kein Abbruch der Einrichtung.

    # 4) Integritaets-Baseline setzen (Repin) — kein Fehlalarm nach Deploy.
    try:
        from aegis2.setup import repin_integrity
        repin_integrity.main()
    except Exception as e:  # noqa: BLE001
        print("Repin fehlgeschlagen:", e)

    print("\nEinrichtung abgeschlossen.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
