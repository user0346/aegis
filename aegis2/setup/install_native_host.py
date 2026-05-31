"""Installiert den AEGIS Native-Messaging-Host fuer Brave/Chrome/Edge.
Kein Admin noetig (HKCU). Aufruf:  python aegis2/setup/install_native_host.py
"""
import os, sys, json, winreg
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]            # AEGIS_V2
EXT_DIR = ROOT / "extension"
HOST_PY = ROOT / "aegis2" / "setup" / "native_host.py"
EXT_ID = (EXT_DIR / ".ext_id").read_text(encoding="utf-8").strip()

_exe = Path(sys.executable)
PY = _exe.with_name("python.exe") if _exe.name.lower() == "pythonw.exe" else _exe

INSTALL_DIR = Path(os.environ["LOCALAPPDATA"]) / "AEGIS" / "nativehost"
INSTALL_DIR.mkdir(parents=True, exist_ok=True)

launcher = INSTALL_DIR / "aegis_native_host.bat"
launcher.write_text('@echo off\r\n"%s" "%s"\r\n' % (PY, HOST_PY), encoding="utf-8")

manifest = {
    "name": "com.aegis.guard",
    "description": "AEGIS Guard Native Host",
    "path": str(launcher),
    "type": "stdio",
    "allowed_origins": ["chrome-extension://%s/" % EXT_ID],
}
mf = INSTALL_DIR / "com.aegis.guard.json"
mf.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

KEYS = [
    r"Software\Google\Chrome\NativeMessagingHosts\com.aegis.guard",
    r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.aegis.guard",
    r"Software\Microsoft\Edge\NativeMessagingHosts\com.aegis.guard",
]
for k in KEYS:
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, k)
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(mf))
        winreg.CloseKey(key)
        print("registriert:", k.split("\\")[1])
    except Exception as e:
        print("FEHLER", k, e)

print("\nNative-Host installiert.")
print("Extension-ID :", EXT_ID)
print("Launcher     :", launcher)
print("Host-Manifest:", mf)
print("\nWICHTIG: Die Extension muss mit GENAU dieser ID geladen sein")
print("(feste ID via manifest key) — sonst verweigert der Host die Verbindung.")
