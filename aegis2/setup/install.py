"""End-User-Installer.

Macht in einem Schritt mit User-Consent:
  1. Defender-Exclusion für Projektordner + pythonw.exe + AEGIS-Prozesse
  2. Windows-Service AegisCore registrieren (Boot-Start)
  3. Scheduled Task \\AEGIS\\Shell (User-Login)
  4. Scheduled Task \\AEGIS\\HealthCheck (alle 15 min, Service-Watchdog)

Wenn nicht-elevated gestartet: re-launched sich selbst mit UAC.

Aufruf:
    py -m aegis2.setup.install --install
    py -m aegis2.setup.install --uninstall
    py -m aegis2.setup.install --install --no-defender    # skip Defender-Step
    py -m aegis2.setup.install --install --no-service     # nur Tasks
"""
from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import sys
import textwrap
from pathlib import Path

# Make sibling packages importable when run as script
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


SERVICE_NAME = "AegisCore"
TASK_SHELL = r"\AEGIS\Shell"
TASK_HC = r"\AEGIS\HealthCheck"


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _python_w() -> str:
    base = Path(sys.executable).parent
    pw = base / "pythonw.exe"
    return str(pw) if pw.exists() else sys.executable


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:  # noqa: BLE001
        return False


def relaunch_as_admin() -> None:
    """ShellExecute mit 'runas' Verb -> UAC-Prompt."""
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{__file__}" {params}', None, 1
    )


# ============================================================
#  Defender step
# ============================================================
def do_defender_step(folder: Path) -> int:
    print("\n=== Schritt 1/3 - Defender-Exclusion ===")
    from aegis2.setup import defender

    third_party = defender.detect_third_party_av()
    if third_party:
        print(f"Drittanbieter-AV erkannt: {', '.join(third_party)}")
        print(defender.explain_third_party_steps(third_party[0], folder))
        return 2

    if not defender.defender_is_active():
        print("Windows Defender ist nicht aktiv. Schritt uebersprungen.")
        return 2

    processes = ["aegis-core.exe", "aegis-shell.exe",
                 "pythonw.exe", "python.exe"]
    print(f"Setze Defender-Exclusion fuer:")
    print(f"  Ordner:    {folder}")
    print(f"  Prozesse:  {', '.join(processes)}")
    rc = defender.add_defender_exclusion(folder, processes)
    if rc == 0:
        print("[OK] Defender-Exclusion gesetzt.")
    else:
        print(f"[WARN] Defender-Exclusion fehlgeschlagen (rc={rc}).")
        print("       AEGIS laeuft trotzdem, aber Defender wird evtl. alarmieren.")
    return rc


# ============================================================
#  Service step
# ============================================================
def do_service_step() -> bool:
    print("\n=== Schritt 2/3 - Windows Service AegisCore ===")
    root = _project_root()
    service_entry = root / "aegis2" / "service" / "service.py"
    if not service_entry.exists():
        print(f"[ERR] service.py fehlt: {service_entry}")
        return False

    cmd = [sys.executable, str(service_entry), "--startup=auto", "install"]
    print(">", " ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        print(f"[ERR] Service-Install fehlgeschlagen (rc={rc}).")
        return False

    # Failure-Recovery
    print("> sc.exe failure -> Auto-Restart 5s / 15s / 60s")
    subprocess.call([
        "sc.exe", "failure", SERVICE_NAME,
        "reset=", "86400",
        "actions=", "restart/5000/restart/15000/restart/60000",
    ])
    print("> sc.exe start AegisCore")
    subprocess.call(["sc.exe", "start", SERVICE_NAME])
    print("[OK] Service registriert und gestartet.")
    return True


# ============================================================
#  Scheduled tasks
# ============================================================
def _write_task_xml(content: str, name: str) -> Path:
    path = Path(os.environ.get("TEMP", str(Path.cwd()))) / f"aegis_{name}.xml"
    path.write_text(content, encoding="utf-16")
    return path


def do_tasks_step() -> bool:
    print("\n=== Schritt 3/3 - Scheduled Tasks ===")
    root = _project_root()
    pyw = _python_w()
    shell_entry = root / "bin" / "aegis_shell.py"
    hc_entry = root / "bin" / "aegis_healthcheck.py"

    # Healthcheck-Script lazy erzeugen
    if not hc_entry.exists():
        hc_entry.write_text(_HEALTHCHECK_PY, encoding="utf-8")

    # ---- Shell-Task (User, Login, LeastPrivilege) ----
    xml_shell = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>AEGIS Shell (UI) - User-Login Autostart</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <Hidden>true</Hidden>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{pyw}</Command>
      <Arguments>"{shell_entry}"</Arguments>
      <WorkingDirectory>{root}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""
    p = _write_task_xml(xml_shell, "shell")
    rc1 = subprocess.call(["schtasks", "/Create", "/TN", TASK_SHELL,
                           "/XML", str(p), "/F"])
    if rc1 == 0:
        print(f"[OK] Task '{TASK_SHELL}' registriert (Login-Trigger).")
    else:
        print(f"[WARN] Shell-Task-Create rc={rc1}")

    xml_hc = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
    <CalendarTrigger>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Repetition><Interval>PT15M</Interval></Repetition>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings><Hidden>true</Hidden><Priority>7</Priority></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{pyw}</Command>
      <Arguments>"{hc_entry}"</Arguments>
    </Exec>
  </Actions>
</Task>
"""
    p = _write_task_xml(xml_hc, "hc")
    rc2 = subprocess.call(["schtasks", "/Create", "/TN", TASK_HC,
                           "/XML", str(p), "/F"])
    if rc2 == 0:
        print(f"[OK] Task '{TASK_HC}' registriert (Boot + 15min).")
    else:
        print(f"[WARN] HealthCheck-Task-Create rc={rc2}")
    return rc1 == 0 and rc2 == 0


_HEALTHCHECK_PY = """
import subprocess
SERVICE = "AegisCore"
r = subprocess.run(["sc.exe", "query", SERVICE], capture_output=True, text=True)
if "RUNNING" not in (r.stdout or ""):
    subprocess.call(["sc.exe", "start", SERVICE])
"""


def do_uninstall(folder):
    print("\n=== Uninstall ===")
    subprocess.call(["sc.exe", "stop", SERVICE_NAME])
    service_entry = _project_root() / "aegis2" / "service" / "service.py"
    subprocess.call([sys.executable, str(service_entry), "remove"])
    subprocess.call(["schtasks", "/Delete", "/TN", TASK_SHELL, "/F"])
    subprocess.call(["schtasks", "/Delete", "/TN", TASK_HC, "/F"])
    try:
        from aegis2.setup import defender
        processes = ["aegis-core.exe", "aegis-shell.exe", "pythonw.exe", "python.exe"]
        defender.remove_defender_exclusion(folder, processes)
        print("[OK] Defender-Exclusion entfernt.")
    except Exception as e:
        print(f"[WARN] Defender-Cleanup: {e}")
    print("\nUninstall fertig.")
    return 0


def banner():
    print(textwrap.dedent("""
    =============================================================
                          A E G I S
                Autonomous Endpoint Guardian
                     - Installer V2 -
    =============================================================

    Was der Installer macht (mit deiner einmaligen Zustimmung):

      1. Defender-Exclusion fuer den AEGIS-Ordner und die
         pythonw.exe / AEGIS-EXEs.
      2. AegisCore als Windows-Service registrieren mit
         Auto-Restart-Policy.
      3. Scheduled Task fuer die UI-Shell bei User-Login
         + Healthcheck-Watchdog alle 15 Minuten.

    Alle Aktionen werden in
       %USERPROFILE%\\.aegis\\audit.jsonl
    geloggt.

    Uninstall mit:  py -m aegis2.setup.install --uninstall
    """).strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--no-defender", action="store_true")
    ap.add_argument("--no-service", action="store_true")
    ap.add_argument("--no-tasks", action="store_true")
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args()

    folder = _project_root()
    if not args.install and not args.uninstall:
        ap.print_help()
        return 0

    if not is_admin():
        print("Re-launch mit Admin-Rechten via UAC...")
        relaunch_as_admin()
        return 0

    if args.uninstall:
        return do_uninstall(folder)

    banner()
    if not args.yes:
        print()
        ans = input("Mit Installation fortfahren? [j/N]: ").strip().lower()
        if ans not in ("j", "y", "yes", "ja"):
            print("Abgebrochen.")
            return 1

    ok = True
    if not args.no_defender:
        do_defender_step(folder)
    if not args.no_service:
        ok &= do_service_step()
    if not args.no_tasks:
        ok &= do_tasks_step()

    print("\n" + ("[FERTIG] Installation erfolgreich." if ok else "[TEILWEISE] Installation mit Warnungen."))
    print("Status pruefen: AEGIS_Status.bat")
    print("UI starten:     AEGIS_Shell.bat  (oder beim naechsten Login automatisch)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
