"""AEGIS-Laufzeit-Rollen (importierbar): Core-Service, Watchdog, Restart, Setup.

Diese Module kapseln die frueher in bin/*.pyw eingebettete Logik, damit sie
sowohl aus dem Quellcode (bin/aegis_app.py) als auch aus der gefrorenen
PyInstaller-Binary (AEGIS.exe --core/--watchdog/...) aufgerufen werden kann.
"""
