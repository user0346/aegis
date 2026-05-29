"""Windows Service wrapper via pywin32.

Install: `python service.py install`
Start  : `python service.py start`
Stop   : `python service.py stop`
Remove : `python service.py remove`

The service runs aegis2.service.core.main() under LocalSystem.
Failure-Recovery: configured by setup/install.py via `sc.exe failure`.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import win32serviceutil  # type: ignore
    import win32service  # type: ignore
    import win32event  # type: ignore
    import servicemanager  # type: ignore
    HAS_PYWIN = True
except ImportError:
    HAS_PYWIN = False


if HAS_PYWIN:
    _ServiceBase = win32serviceutil.ServiceFramework
else:
    _ServiceBase = object


class AegisService(_ServiceBase):
    _svc_name_ = "AegisCore"
    _svc_display_name_ = "AEGIS Core (Endpoint Guardian)"
    _svc_description_ = ("Headless monitor for files, processes, network, and "
                         "IP-loggers. Companion to Windows Defender.")

    def __init__(self, args):
        if HAS_PYWIN:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_evt = win32event.CreateEvent(None, 0, 0, None)

    def SvcDoRun(self):
        if HAS_PYWIN:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
        # Defer import so service can even register without core import errors
        from .core import main as core_main
        # Run blocking
        try:
            core_main(foreground=False)
        except SystemExit:
            pass

    def SvcStop(self):
        if HAS_PYWIN:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_evt)
        # Core honours signal via stop_flag; sending TERM not available under SCM.
        # Instead we set a sentinel file that core polls.
        sentinel = Path.home() / ".aegis" / ".stop"
        sentinel.parent.mkdir(parents=True, exist_ok=True)
        sentinel.write_text("stop", encoding="utf-8")


def main() -> int:
    if not HAS_PYWIN:
        print("pywin32 required: pip install pywin32", file=sys.stderr)
        return 1
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AegisService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(AegisService)
    return 0


if __name__ == "__main__":
    sys.exit(main())
