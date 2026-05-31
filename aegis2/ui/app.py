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
    """True = wir sind die erste Instanz. Eine zweite Instanz signalisiert der
    ersten (Fenster nach vorn holen) und gibt False zurueck."""
    try:
        from PyQt6.QtNetwork import QLocalServer, QLocalSocket
        sock = QLocalSocket()
        sock.connectToServer(SINGLE_KEY)
        if sock.waitForConnected(300):
            sock.write(b"show\n"); sock.flush(); sock.waitForBytesWritten(300)
            sock.disconnectFromServer()
            return False
        QLocalServer.removeServer(SINGLE_KEY)        # stale socket cleanup
        server = QLocalServer()
        if server.listen(SINGLE_KEY):
            def _on_conn():
                c = server.nextPendingConnection()
                w = getattr(app, "_aegis_window", None)
                if w is not None:
                    w.showNormal(); w.raise_(); w.activateWindow()
                if c:
                    c.disconnectFromServer()
            server.newConnection.connect(_on_conn)
            app._aegis_ls = server
            return True
    except Exception:
        pass
    # Fallback: QSharedMemory (nur Detektion, ohne Fenster-Signal)
    shm = QSharedMemory(SINGLE_KEY + "-shm")
    if shm.attach():
        return False
    shm.create(1)
    app._aegis_shm = shm
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

        # CRITICAL -> topmost Alert-Popup (auch ueber Vollbild-Spiele sichtbar)
        try:
            from aegis2.ui.alert_overlay import show_alert
            bridge.criticalAlert.connect(show_alert)
            log.info("Critical-Alert-Overlay verdrahtet")
        except Exception:  # noqa: BLE001
            log.exception("Alert-Overlay-Verdrahtung fehlgeschlagen (optional)")

        # Datei-Suche: erst Nutzer-Bestaetigung (Dialog), dann sucht die Bridge
        def _ask_file_search(query, kind):
            from PyQt6.QtWidgets import QMessageBox
            label = {"image": "Bildern", "video": "Videos",
                     "doc": "Dokumenten"}.get(kind, "Dateien")
            ok = QMessageBox.question(
                None, "AEGIS — Datei-Suche",
                f"AEGIS darf nach «{query}» in deinen {label} suchen?\n\n"
                f"Nur Desktop, Downloads, Dokumente, Bilder, Videos, Musik — "
                f"nur Namen/Pfade, keine Inhalte.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if ok == QMessageBox.StandardButton.Yes:
                bridge.runFileSearch(query, kind)
        try:
            bridge.fileSearchAsk.connect(_ask_file_search)
        except Exception:  # noqa: BLE001
            log.exception("fileSearchAsk-Verdrahtung fehlgeschlagen (optional)")

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
        app._aegis_window = window   # fuer Single-Instance "show"-Signal
        log.info("Window constructed")
        window.show()
        log.info("Window.show() returned")

        if QSystemTrayIcon.isSystemTrayAvailable():
            from PyQt6.QtGui import QIcon
            tray = QSystemTrayIcon()
            _tico = Path(__file__).resolve().parent / "assets" / "aegis.ico"
            if _tico.exists():
                tray.setIcon(QIcon(str(_tico)))
            elif not app.windowIcon().isNull():
                tray.setIcon(app.windowIcon())
            tray.setToolTip("AEGIS Guard \u2013 aktiv")

            def _show_win():
                window.showNormal(); window.raise_(); window.activateWindow()

            def _close_ui():
                # Nur die Oberflaeche schliessen — der Hintergrund-Schutz laeuft weiter.
                setattr(window, "_force_quit", True)
                bridge.stop()
                app.quit()

            def _stop_protection():
                from PyQt6.QtWidgets import QMessageBox, QInputDialog, QLineEdit
                import time as _t
                if QMessageBox.warning(
                        window, "AEGIS Guard",
                        "Damit wird der KOMPLETTE Echtzeit-Schutz beendet "
                        "(nicht nur das Fenster). Dein System ist danach UNGESCHÜTZT. "
                        "Wirklich beenden?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                        QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                    return
                # Owner-Pin verlangen, falls gesetzt — schützt vor Beenden durch Dritte.
                # Fail-open: laedt das Pin-Modul nicht, wird der Owner NICHT ausgesperrt.
                try:
                    from aegis2.cognition.autonomy import has_owner_pin, verify_owner_pin
                    if has_owner_pin():
                        pin, ok = QInputDialog.getText(
                            window, "Owner-Pin bestätigen",
                            "Zum Beenden des Schutzes den Owner-Pin/das Passwort eingeben:",
                            QLineEdit.EchoMode.Password)
                        if not ok:
                            return
                        if not verify_owner_pin((pin or "").strip()):
                            QMessageBox.critical(window, "AEGIS Guard",
                                                 "Falscher Pin — Schutz bleibt aktiv.")
                            return
                except Exception:  # noqa: BLE001
                    pass
                try:
                    (Path.home() / ".aegis" / ".stop").write_text(
                        str(int(_t.time())), encoding="utf-8")
                except Exception:
                    pass
                setattr(window, "_force_quit", True)
                bridge.stop()
                app.quit()

            menu = QMenu()
            a_show = QAction("AEGIS öffnen")
            a_show.triggered.connect(_show_win)
            menu.addAction(a_show)
            a_close = QAction("Oberfläche schließen (Schutz läuft weiter)")
            a_close.triggered.connect(_close_ui)
            menu.addAction(a_close)
            menu.addSeparator()
            a_quit = QAction("Schutz komplett beenden")
            a_quit.triggered.connect(_stop_protection)
            menu.addAction(a_quit)
            tray.setContextMenu(menu)

            def _on_activated(reason):
                if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                              QSystemTrayIcon.ActivationReason.DoubleClick):
                    _show_win()
            tray.activated.connect(_on_activated)
            tray.show()
            app._aegis_tray = tray
            log.info("Tray created (icon=%s)", _tico.exists())

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
