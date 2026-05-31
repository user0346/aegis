"""Main window — WebEngine wird DEFERRED nach show() geladen.

Warum: QWebEngineView()-Konstruktor + Chromium-Renderer-Spawn kann auf
Win11 mit Defender 10-60 Sekunden blockieren beim ersten Lauf. Wenn das
im __init__ vor show() passiert, friert das Fenster ein und Windows
zeigt "Keine Rückmeldung".

Lösung: Window mit nur einem QLabel als zentralem Widget zeigen. Danach
in einem QTimer.singleShot(0, ...)-Callback (also nachdem die erste
Event-Loop-Iteration durch ist) den WebEngineView aufbauen.
"""
from __future__ import annotations

import ctypes
import logging
import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QUrl, QTimer
from PyQt6.QtWidgets import QMainWindow, QLabel


log = logging.getLogger("aegis.shell.window")

WEB_DIR = Path(__file__).resolve().parent / "web"
INDEX_HTML = WEB_DIR / "index.html"


def _enable_mica(hwnd: int) -> bool:
    """Win11 22H2+ Mica. Defensive — Fehler frieren das Fenster nicht ein."""
    if sys.platform != "win32" or not hwnd:
        return False
    try:
        dwmapi = ctypes.windll.dwmapi
        dark = ctypes.c_int(1)
        dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(dark), ctypes.sizeof(dark))
        backdrop = ctypes.c_int(2)
        dwmapi.DwmSetWindowAttribute(hwnd, 38, ctypes.byref(backdrop),
                                     ctypes.sizeof(backdrop))
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("Mica setup skipped: %s", e)
        return False


class AegisWindow(QMainWindow):
    def __init__(self, bridge):
        super().__init__()
        self.bridge = bridge
        self._web_built = False
        self.view = None
        self.channel = None

        self.setWindowTitle("AEGIS")
        self.resize(1240, 800)
        self.setMinimumSize(960, 640)

        # Minimal-Initial-UI — nur ein gestyltes Label.
        # Nichts in __init__ darf länger als einige Millisekunden brauchen.
        self._fallback = QLabel(self)
        self._fallback.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._fallback.setStyleSheet(
            "background: #0b0f15;"
            "color: #cde;"
            "font-family: 'Segoe UI Variable', 'Segoe UI', sans-serif;"
            "padding: 24px;"
        )
        self._fallback.setText(
            "<h2 style='color:#5bb8ff;letter-spacing:3px;'>AEGIS</h2>"
            "<p>Initialisiere Cognition-Kern...</p>"
            "<p style='color:#67768d;font-size:11px'>"
            "Erster Start kann 10-60 Sekunden dauern (Defender scannt Chromium-DLLs).<br>"
            "Bei langerem Hangen: Log unter "
            "<code>%USERPROFILE%\\.aegis\\shell.log</code> pruefen."
            "</p>"
        )
        self.setCentralWidget(self._fallback)
        log.info("AegisWindow constructor done (web deferred)")

    def closeEvent(self, event):
        # "X" minimiert in den Tray statt zu beenden — der Schutz laeuft im
        # Background-Service weiter; die UI ist nur eine Ansicht.
        if getattr(self, "_force_quit", False):
            event.accept()
            return
        from PyQt6.QtWidgets import QApplication, QSystemTrayIcon
        tray = getattr(QApplication.instance(), "_aegis_tray", None)
        if tray is None:
            event.accept()
            return
        event.ignore()
        self.hide()
        if not getattr(self, "_tray_hint_shown", False):
            try:
                tray.showMessage(
                    "AEGIS l\u00e4uft weiter",
                    "Die \u00dcberwachung bleibt aktiv. \u00dcber das Tray-Icon wieder \u00f6ffnen.",
                    QSystemTrayIcon.MessageIcon.Information, 4000)
            except Exception:
                pass
            self._tray_hint_shown = True

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(50, lambda: _enable_mica(int(self.winId())))
        if not self._web_built:
            QTimer.singleShot(100, self._build_webengine)

    def _build_webengine(self):
        if self._web_built:
            return
        self._web_built = True
        try:
            log.info("Building QWebEngineView...")
            from PyQt6.QtWebEngineWidgets import QWebEngineView
            from PyQt6.QtWebChannel import QWebChannel

            self.view = QWebEngineView()
            # v2.0.6 diag: JS-Console -> shell.log
            try:
                from PyQt6.QtWebEngineCore import QWebEnginePage
                class _LogPage(QWebEnginePage):
                    def javaScriptConsoleMessage(self, lvl, m, ln, src):
                        log.debug("JS: %s", m)
                self.view.setPage(_LogPage(self.view))
            except Exception:
                log.exception("logpage failed")
            # v2.0.6: V8/HTTP-Cache deaktivieren — sonst laedt QtWebEngine altes
            # (truncated) sentinel.js aus dem Code-Cache -> Sentinel-Panel tot.
            try:
                from PyQt6.QtWebEngineCore import QWebEngineProfile
                _prof = self.view.page().profile()
                _prof.setHttpCacheType(QWebEngineProfile.HttpCacheType.NoCache)
                _prof.clearHttpCache()
            except Exception:
                log.exception("cache-disable failed (non-fatal)")
            # KRITISCH: QtWebEngine sperrt den Zwischenablage-Zugriff aus JavaScript
            # standardmaessig -> der Kopier-Button (clipboard-API UND execCommand("copy"))
            # tut sonst GAR NICHTS und gibt keine Rueckmeldung. Hier explizit erlauben.
            try:
                from PyQt6.QtWebEngineCore import QWebEngineSettings
                _st = self.view.page().settings()
                _st.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanAccessClipboard, True)
                _st.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanPaste, True)
            except Exception:
                log.exception("clipboard-settings failed (non-fatal)")
            self.channel = QWebChannel(self.view.page())
            self.channel.registerObject("aegis", self.bridge)
            self.view.page().setWebChannel(self.channel)
            self.view.loadFinished.connect(self._on_load_finished)

            if INDEX_HTML.exists():
                url = QUrl.fromLocalFile(str(INDEX_HTML))
                log.info("Loading: %s", url.toString())
                self.view.load(url)
            else:
                log.error("INDEX_HTML missing: %s", INDEX_HTML)
                self._fallback.setText(
                    "<div style='color:#f97373'>"
                    "<h2>UI-Files fehlen</h2>"
                    f"<p>{INDEX_HTML} nicht gefunden.</p></div>")
                return
            QTimer.singleShot(15000, self._timeout_check)
        except Exception as e:
            log.exception("WebEngine build failed")
            self._fallback.setText(
                "<div style='color:#f97373'>"
                f"<h2>WebEngine-Fehler</h2><p>{type(e).__name__}: {e}</p></div>")

    def _on_load_finished(self, ok):
        log.info("loadFinished ok=%s", ok)
        if ok and self.view is not None:
            self.setCentralWidget(self.view)
            log.info("Swapped fallback -> WebView")
        else:
            self._fallback.setText(
                "<div style='color:#f97373'>"
                "<h2>UI konnte nicht geladen werden</h2></div>")

    def _timeout_check(self):
        if self.centralWidget() is self._fallback:
            log.warning("WebEngine hat nach 15s nicht geladen")
            self._fallback.setText(
                "<div style='color:#facc15'>"
                "<h2>QtWebEngine startet langsam</h2>"
                "<p>Defender scannt vermutlich noch.</p></div>")
