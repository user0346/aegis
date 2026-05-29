"""QWebChannel-Bridge — exposes Python functions to JS in the embedded WebView.

JS calls:  await aegis.cmd('{"name":"stats"}')
Service push:  aegis.eventReceived.connect((json) => ...)
"""
from __future__ import annotations

import json
import logging
import secrets
from typing import Optional

from PyQt6.QtCore import QObject, QTimer, pyqtSignal, pyqtSlot

from .ipc_client import IpcClient


log = logging.getLogger("aegis.shell.bridge")


class AegisBridge(QObject):
    """Single QObject exposed to JS as `aegis`."""

    eventReceived = pyqtSignal(str)        # JSON-stringified event
    stateChanged = pyqtSignal(str)         # "connected" | "disconnected" | ...
    statsUpdated = pyqtSignal(str)         # JSON-stringified stats snapshot
    voiceState = pyqtSignal(str, str)      # (kind, payload) e.g. ("wake","detected")

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._last_state = "disconnected"
        self._ipc = IpcClient(on_frame=self._on_frame, on_state=self._on_state,
                              topics=["events", "stats"])
        self._pending: dict[str, list] = {}   # ref -> [resolve, reject]
        self._ipc.start()
        # IpcClient often connects in milliseconds, BEFORE the WebChannel is
        # set up. Re-emit current state at 1s/3s/6s so the JS-side listener
        # (which subscribes after WebView load) always gets the actual state.
        for delay_ms in (1000, 3000, 6000):
            QTimer.singleShot(delay_ms,
                              lambda: self.stateChanged.emit(self._last_state))

    # ---- JS-callable slots ----
    @pyqtSlot(str, result=str)
    def cmd(self, json_str: str) -> str:
        """Synchronous command — returns a ref the JS side awaits via response signal.

        For Phase-1 simplicity we use fire-and-forget + emit `cmdResult` event.
        Phase-2 may switch to a promise-style via QWebChannel transaction map.
        """
        try:
            data = json.loads(json_str) if json_str else {}
        except Exception:  # noqa: BLE001
            return json.dumps({"ok": False, "error": "bad JSON"})
        ref = secrets.token_hex(8)
        frame = {"t": "cmd", "name": data.get("name", ""),
                 "args": data.get("args", {}), "ref": ref}
        ok = self._ipc.send(frame)
        log.debug("cmd name=%s send_ok=%s", data.get("name"), ok)
        return json.dumps({"ok": ok, "ref": ref})

    @pyqtSlot(result=str)
    def state(self) -> str:
        return "connected" if self._ipc._handle is not None else "disconnected"

    # ---- internal ----
    def _on_frame(self, frame: dict) -> None:
        t = frame.get("t")
        if t == "event":
            self.eventReceived.emit(json.dumps(frame.get("ev", {}), ensure_ascii=False))
        elif t == "stats":
            self.statsUpdated.emit(json.dumps(frame.get("data", {}), ensure_ascii=False))
        elif t == "cmd_result":
            self.eventReceived.emit(json.dumps(frame, ensure_ascii=False))

    def _on_state(self, state: str) -> None:
        self._last_state = state
        self.stateChanged.emit(state)

    def push_voice(self, kind: str, payload: str) -> None:
        """Called from the voice subsystem (UI process) to surface wake/transcript."""
        self.voiceState.emit(kind, payload)

    def stop(self) -> None:
        self._ipc.stop()
