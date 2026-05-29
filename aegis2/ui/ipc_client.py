"""Named-Pipe IPC client (UI side).

Connects to the AegisCore service. Reconnects on disconnect.
Forwards inbound frames to a callback (typically the Qt bridge).

v2.0.6: single I/O thread with non-blocking PeekNamedPipe polling. Reads and
queued writes run sequentially in ONE thread, so a blocking ReadFile can no
longer deadlock a concurrent WriteFile on the same duplex handle (root cause of
the Sentinel commands never reaching the service).
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from pathlib import Path
from typing import Callable, Optional

try:
    import win32file  # type: ignore
    import win32pipe  # type: ignore
    import pywintypes  # type: ignore
    HAS_WIN = True
except ImportError:
    HAS_WIN = False

log = logging.getLogger("aegis.shell.ipc")

PIPE_NAME = r"\\.\pipe\aegis-v2-bus"
TOKEN_PATH = Path.home() / ".aegis" / "ipc_token"


class IpcClient:
    """Reconnecting JSON-Lines client (single I/O thread, poll-based)."""

    BACKOFFS = [1, 2, 5, 10, 30]

    def __init__(self,
                 on_frame: Callable[[dict], None],
                 on_state: Optional[Callable[[str], None]] = None,
                 topics: Optional[list[str]] = None):
        self.on_frame = on_frame
        self.on_state = on_state or (lambda s: None)
        self.topics = topics or ["events", "stats"]
        self._stop = threading.Event()
        self._handle = None
        self._send_q: "queue.Queue[dict]" = queue.Queue(maxsize=2000)
        self._thread = threading.Thread(target=self._loop, daemon=True, name="IpcClient")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._close()

    def send(self, frame: dict) -> bool:
        # Non-blocking: enqueue only. The single I/O thread drains the queue and
        # writes, so the Qt main thread (bridge.cmd) never blocks on the pipe.
        if not HAS_WIN:
            return False
        try:
            self._send_q.put_nowait(frame)
            return True
        except queue.Full:
            log.warning("send queue full - dropping frame")
            return False

    # ---- internals ----
    def _loop(self) -> None:
        attempt = 0
        log.info("IpcClient loop started (HAS_WIN=%s, pipe=%s)", HAS_WIN, PIPE_NAME)
        while not self._stop.is_set():
            try:
                if not HAS_WIN:
                    log.warning("pywin32 nicht verfuegbar - IPC disabled")
                    self.on_state("unsupported")
                    time.sleep(30)
                    continue
                self._connect_once()
                attempt = 0
                self._io_loop()
            except Exception as e:  # noqa: BLE001
                log.warning("connect/io exception: %s: %s", type(e).__name__, e)
            finally:
                self._close()
                self.on_state("disconnected")
            if self._stop.is_set():
                return
            backoff = self.BACKOFFS[min(attempt, len(self.BACKOFFS) - 1)]
            attempt += 1
            log.info("retry in %ss (attempt %d)", backoff, attempt)
            time.sleep(backoff)

    def _connect_once(self) -> None:
        log.info("Connecting to %s ...", PIPE_NAME)
        for i in range(5):
            try:
                win32pipe.WaitNamedPipe(PIPE_NAME, 1000)
                log.info("Pipe available after %d wait(s)", i)
                break
            except Exception as e:  # noqa: BLE001
                log.debug("WaitNamedPipe attempt %d failed: %s", i, e)
                time.sleep(0.5)
        else:
            log.error("Pipe not available after 5 attempts - server down?")
            raise RuntimeError("pipe unavailable")
        self._handle = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING, 0, None,
        )
        log.info("CreateFile OK, handle=%s", self._handle)
        # byte-mode (default) — we frame on newlines + poll via PeekNamedPipe.
        token = ""
        if TOKEN_PATH.exists():
            try:
                token = TOKEN_PATH.read_text(encoding="utf-8").strip()
                log.info("Token loaded (len=%d)", len(token))
            except Exception as e:  # noqa: BLE001
                log.warning("Token read failed: %s", e)
        else:
            log.warning("Token file missing: %s", TOKEN_PATH)
        self.send({"t": "hello", "client": "shell", "version": 2, "token": token})
        self.send({"t": "subscribe", "topics": self.topics})
        self.on_state("connected")
        log.info("on_state(connected) emitted; hello+subscribe queued")

    def _io_loop(self) -> None:
        log.info("Entering io_loop (poll mode)")
        buf = b""
        while not self._stop.is_set():
            h = self._handle
            if h is None:
                return
            # 1) READ — non-blocking peek, then read only what's available
            avail = 0
            try:
                _, avail, _ = win32pipe.PeekNamedPipe(h, 0)
            except Exception as e:  # noqa: BLE001
                log.info("peek failed (disconnect): %s", e)
                return
            if avail:
                try:
                    _, chunk = win32file.ReadFile(h, avail)
                except Exception as e:  # noqa: BLE001
                    log.info("ReadFile exited: %s", e)
                    return
                if not chunk:
                    log.info("EOF")
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        frame = json.loads(line.decode("utf-8"))
                    except Exception as e:  # noqa: BLE001
                        log.debug("bad JSON line: %s", e)
                        continue
                    try:
                        self.on_frame(frame)
                    except Exception as e:  # noqa: BLE001
                        log.debug("on_frame raised: %s", e)
            # 2) WRITE — drain the send queue
            wrote = False
            while True:
                try:
                    frame = self._send_q.get_nowait()
                except queue.Empty:
                    break
                try:
                    data = (json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8")
                    win32file.WriteFile(h, data)
                    wrote = True
                    log.debug("IO sent name=%s bytes=%d", frame.get("name") or frame.get("t"), len(data))
                except Exception as e:  # noqa: BLE001
                    log.warning("IO write except name=%s: %s", frame.get("name"), e)
                    return
            # 3) idle only when nothing happened
            if not avail and not wrote:
                time.sleep(0.03)

    def _close(self) -> None:
        if self._handle is None:
            return
        try:
            win32file.CloseHandle(self._handle)
        except Exception:  # noqa: BLE001
            pass
        self._handle = None
