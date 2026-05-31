"""Topmost CRITICAL-Alert-Overlay — kommt auch ueber Vollbild-Spiele.

Frameless, always-on-top, Tool-Window (nicht in Taskbar). Erscheint bei
CRITICAL-Events oben mittig, zeigt WAS passiert ist + den Status (blockiert/
gelöscht/quarantäniert) und schliesst nach Timeout oder Klick.

MUSS im GUI-Main-Thread aufgerufen werden -> via Bridge-Signal (Qt queued).
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (QWidget, QLabel, QVBoxLayout, QHBoxLayout,
                             QPushButton, QApplication)


_active = []   # haelt Referenzen, damit der GC die Fenster nicht killt


class AlertOverlay(QWidget):
    def __init__(self, category: str, message: str, status: str = "BLOCKIERT"):
        super().__init__(None)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setFixedWidth(420)

        wrap = QWidget(self)
        wrap.setObjectName("wrap")
        wrap.setStyleSheet("""
            #wrap { background:#1a0d0f; border:2px solid #f87171; border-radius:14px; }
            QLabel { color:#ffe9e9; }
            #title { font-size:16px; font-weight:800; letter-spacing:1px; color:#fca5a5; }
            #cat   { font-size:11px; color:#fbbf24; letter-spacing:1px; }
            #msg   { font-size:13px; color:#f3d6d6; }
            #status{ font-size:12px; font-weight:700; color:#34d399; }
            QPushButton { background:#3a1518; color:#ffd9d9; border:1px solid #f87171;
                          border-radius:8px; padding:6px 16px; font-weight:700; }
            QPushButton:hover { background:#52191e; }
        """)
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(18, 16, 18, 14)
        lay.setSpacing(7)

        t = QLabel("⚠  BEDROHUNG ERKANNT")
        t.setObjectName("title")
        lay.addWidget(t)

        c = QLabel((category or "SYSTEM").upper())
        c.setObjectName("cat")
        lay.addWidget(c)

        m = QLabel(message or "Verdächtige Aktivität")
        m.setObjectName("msg")
        m.setWordWrap(True)
        lay.addWidget(m)

        s = QLabel(f"AEGIS hat reagiert  •  Status: {status}")
        s.setObjectName("status")
        lay.addWidget(s)

        row = QHBoxLayout()
        row.addStretch(1)
        btn = QPushButton("Verstanden")
        btn.clicked.connect(self.close)
        row.addWidget(btn)
        lay.addLayout(row)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(wrap)
        self.adjustSize()

        # Position: oben mittig auf dem primaeren Bildschirm
        try:
            scr = QApplication.primaryScreen().availableGeometry()
            self.move(scr.center().x() - self.width() // 2, scr.top() + 40)
        except Exception:  # noqa: BLE001
            pass

        QTimer.singleShot(9000, self.close)   # auto-close

    def closeEvent(self, e):
        try:
            _active.remove(self)
        except ValueError:
            pass
        super().closeEvent(e)


def show_alert(category: str, message: str, status: str = "BLOCKIERT") -> None:
    """Zeigt das Overlay. No-op, wenn keine QApplication laeuft."""
    if QApplication.instance() is None:
        return
    try:
        w = AlertOverlay(category, message, status)
        _active.append(w)
        w.show()
        w.raise_()
    except Exception:  # noqa: BLE001
        pass
