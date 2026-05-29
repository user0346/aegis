"""AEGIS-Shell entrypoint — QApplication + tray + main window."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# ─── CRITICAL: QtWebEngine-Setup MUSS vor QApplication passieren ──────────
from PyQt6.QtCore import Qt, QCoreApplication
QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)
# Chromium-Flag: Defender-CodeIntegrity-Check kann renderer blockieren
os.environ.setdefault(
    "QTWEBENGINE_CHROMIUM_FLAGS",
    "--disable-features=RendererCodeIntegrity",
)

from PyQt6.QtCore import QSharedMemory
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QMessageBox

# WebEngine NICHT hier vorladen — wird in window.py defered erst nach show()
# initialisiert. Sonst blockiert Chromium-Spawn die UI.

from .bridge import AegisBridge
from .window import AegisWindow


SINGLE_KEY = "AEGIS-V2-SHELL-SINGLE"
LOG_PATH = Path.home() / ".aegis" / "shell.log"


def _setup_logging() -> logging.Logger:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_PATH), filemode="a",
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        level=logging.INFO,
    )
    return logging.getLogger("aegis.shell")


def _single_instance(app: QApplication) -> bool:
    shm = QSharedMemory(SINGLE_KEY)
    if shm.attach():
        return False
    shm.create(1)
    app._aegis_shm = shm  # keep alive
    return True


def run() -> int:
    log = _setup_logging()
    log.info("=" * 60)
    log.info("AEGIS Shell start, PID=%d, Python=%s", os.getpid(), sys.version)

    def _excepthook(t, v, tb):
        import traceback
        log.critical("UNCAUGHT:\n%s", "".join(traceback.format_exception(t, v, tb)))
        sys.__excepthook__(t, v, tb)
    sys.excepthook = _excepthook

    try:
        app = QApplication(sys.argv)
        app.setApplicationName("AEGIS Shell")
        app.setOrganizationName("AEGIS")
        try:
            from PyQt6.QtGui import QIcon
            _ico = Path(__file__).resolve().parent / "assets" / "aegis.ico"
            if _ico.exists():
                app.setWindowIcon(QIcon(str(_ico)))
        except Exception:
            pass
        app.setQuitOnLastWindowClosed(False)
        log.info("QApplication created")

        if not _single_instance(app):
            log.info("Second instance - exiting")
            return 0

        bridge = AegisBridge()
        log.info("Bridge created")

        # Start Sir-Speaker (Edge-TTS poller für notifications.jsonl)
        sir = None
        try:
            from aegis2.voice.sir_speaker import SirSpeaker
            sir = SirSpeaker(
                on_speak_start=lambda t: bridge.push_voice("sir_start", t[:200]),
                on_speak_end=lambda t: bridge.push_voice("sir_end", ""),
            )
            sir.start()
            app._aegis_sir = sir
            log.info("SirSpeaker started")
        except Exception:
            log.exception("SirSpeaker failed to start (TTS optional)")

        window = AegisWindow(bridge)
        log.info("Window constructed")
        window.show()
        log.info("Window.show() returned")

        if QSystemTrayIcon.isSystemTrayAvailable():
            tray = QSystemTrayIcon()
            tray.setToolTip("AEGIS Shell")
            menu = QMenu()
            a_show = QAction("Open AEGIS")
            a_show.triggered.connect(
                lambda: (window.showNormal(), window.raise_(), window.activateWindow())
            )
            menu.addAction(a_show)
            a_quit = QAction("Quit Shell")
            a_quit.triggered.connect(lambda: (bridge.stop(), app.quit()))
            menu.addAction(a_quit)
            tray.setContextMenu(menu)
            tray.show()
            app._aegis_tray = tray
            log.info("Tray created")

        log.info("Entering app.exec()")
        rc = app.exec()
        log.info("app.exec() returned %d", rc)
        bridge.stop()
        return rc
    except Exception:
        log.exception("run() crashed")
        try:
            QMessageBox.critical(None, "AEGIS Shell",
                f"Start fehlgeschlagen. Log: {LOG_PATH}")
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(run())
