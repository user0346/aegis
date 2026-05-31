"""AEGIS-Autostart beim Login einrichten/entfernen (HKCU Run-Key, kein Admin).

Zwei fensterlose Eintraege (pythonw): Background-Service + UI-Shell (Tray).
  Einrichten:  python aegis2\\setup\\install_autostart.py
  Entfernen:   python aegis2\\setup\\install_autostart.py --uninstall
"""
import sys, winreg
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_exe = Path(sys.executable)
PYW = _exe.with_name("pythonw.exe")
if not PYW.exists():
    PYW = _exe
SERVICE = ROOT / "bin" / "aegis_core_background.pyw"
SHELL   = ROOT / "bin" / "aegis_shell.py"

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALS = [
    ("AEGIS Guard Service", '"%s" "%s"' % (PYW, SERVICE)),
    ("AEGIS Guard UI",      '"%s" "%s"' % (PYW, SHELL)),
]


def install():
    if not SERVICE.exists():
        print("WARN: Service-Script fehlt:", SERVICE)
    k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY)
    for name, cmd in VALS:
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, cmd)
        print("gesetzt:", name)
    winreg.CloseKey(k)
    print("\nAutostart EIN. Service + UI (Tray) starten ab dem naechsten Login automatisch.")


def uninstall():
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE)
    except FileNotFoundError:
        print("Run-Key nicht vorhanden."); return
    for name, _ in VALS:
        try:
            winreg.DeleteValue(k, name); print("entfernt:", name)
        except FileNotFoundError:
            print("war nicht gesetzt:", name)
    winreg.CloseKey(k)
    print("\nAutostart AUS.")


if __name__ == "__main__":
    if "--uninstall" in sys.argv:
        uninstall()
    else:
        install()
