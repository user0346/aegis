"""AEGIS-Autostart beim Login einrichten/entfernen (HKCU Run-Key, kein Admin).

EIN fensterloser Eintrag startet die App; die UI sorgt selbst dafuer, dass der
Hintergrund-Service laeuft (s. bin/aegis_app.py). Frozen-aware:
  Gefroren:   "<...>\\AEGIS.exe"
  Quellcode:  "<pythonw>" "<...>\\bin\\aegis_app.py"

  Einrichten:  python aegis2\\setup\\install_autostart.py
  Entfernen:   python aegis2\\setup\\install_autostart.py --uninstall
"""
import sys
import winreg
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

# Aktueller Wertname + alle frueheren (fuer sauberes Entfernen/Migrieren).
VALUE_NAME = "AEGIS Guard"
_LEGACY_NAMES = ["AEGIS Guard Service", "AEGIS Guard UI"]


def _pythonw() -> str:
    cand = Path(sys.executable).with_name("pythonw.exe")
    return str(cand) if cand.exists() else sys.executable


def _command() -> str:
    """Autostart-Kommando — gefrorene .exe ODER Quellcode-Entry."""
    if getattr(sys, "frozen", False):
        return '"%s"' % Path(sys.executable)
    entry = ROOT / "bin" / "aegis_app.py"
    return '"%s" "%s"' % (_pythonw(), entry)


def _delete_all(k) -> None:
    for name in [VALUE_NAME, *_LEGACY_NAMES]:
        try:
            winreg.DeleteValue(k, name)
        except FileNotFoundError:
            pass


def install():
    k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY)
    _delete_all(k)                       # alte/doppelte Eintraege migrieren
    winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, _command())
    winreg.CloseKey(k)
    print("Autostart EIN:", VALUE_NAME)
    print("Kommando:", _command())
    print("AEGIS (Service + UI/Tray) startet ab dem naechsten Login automatisch.")


def uninstall():
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE)
    except FileNotFoundError:
        print("Run-Key nicht vorhanden.")
        return
    _delete_all(k)
    winreg.CloseKey(k)
    print("Autostart AUS.")


if __name__ == "__main__":
    if "--uninstall" in sys.argv:
        uninstall()
    else:
        install()
