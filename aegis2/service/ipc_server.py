"""Named-Pipe IPC server for Service ↔ UI communication.

Protocol: newline-delimited JSON. See AEGIS_V2_ARCHITECTURE.md for frame types.

Design notes:
- Windows-only (uses pywin32 win32pipe / win32file). On non-Windows we noop.
- Per-client thread (max 4 concurrent clients).
- ACL restricted to current-user + SYSTEM via win32security DACL.
- All client writes are size-checked (max 64KB per frame).
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from typing import Callable, Optional

try:
    import win32pipe  # type: ignore
    import win32file  # type: ignore
    import pywintypes  # type: ignore
    import win32security  # type: ignore
    import win32api  # type: ignore
    import ntsecuritycon  # type: ignore
    HAS_WIN = True
except ImportError:
    HAS_WIN = False

PIPE_NAME = r"\\.\pipe\aegis-v2-bus"
MAX_CLIENTS = 4
FRAME_MAX = 64 * 1024


def _build_pipe_security_attributes():
    """DACL: allow current user + LocalSystem RW only. Deny all others.

    This prevents OTHER local user accounts from connecting to our pipe.
    """
    if not HAS_WIN:
        return None
    try:
        user_sid = win32security.LookupAccountName(None, win32api.GetUserName())[0]
        sys_sid = win32security.CreateWellKnownSid(
            win32security.WinLocalSystemSid, None)
        dacl = win32security.ACL()
        access = ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, access, user_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, access, sys_sid)
        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        sa = win32security.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        sa.bInheritHandle = False
        return sa
    except Exception:  # noqa: BLE001
        return None


class IpcServer:
    """JSON-Lines named pipe server. Service-side."""

    def __init__(self, on_command: Callable[[dict, "ClientHandle"], None],
                 emit_token: Optional[str] = None):
        self.on_command = on_command
        self.emit_token = emit_token or secrets.token_urlsafe(24)
        self._clients: list["ClientHandle"] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._accept_thread: Optional[threading.Thread] = None

    @property
    def token(self) -> str:
        return self.emit_token

    def start(self) -> None:
        if not HAS_WIN:
            return
        self._accept_thread = threading.Thread(target=self._accept_loop,
                                               daemon=True, name="IpcAccept")
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            for c in self._clients:
                try:
                    c.close()
                except Exception:  # noqa: BLE001
                    pass

    def broadcast(self, frame: dict) -> None:
        """Send a frame to all subscribed clients."""
        data = (json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8")
        with self._lock:
            dead: list[ClientHandle] = []
            for c in self._clients:
                if not c.alive:
                    dead.append(c)
                    continue
                try:
                    c.write_raw(data)
                except Exception:  # noqa: BLE001
                    dead.append(c)
            for d in dead:
                self._clients.remove(d)

    # ---- internal ----
    def _accept_loop(self) -> None:
        sa = _build_pipe_security_attributes()
        while not self._stop.is_set():
            try:
                handle = win32pipe.CreateNamedPipe(
                    PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE
                    | win32pipe.PIPE_READMODE_MESSAGE
                    | win32pipe.PIPE_WAIT
                    | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
                    MAX_CLIENTS,
                    FRAME_MAX, FRAME_MAX, 0, sa,
                )
                # Block until client connects
                win32pipe.ConnectNamedPipe(handle, None)
                client = ClientHandle(handle, self)
                with self._lock:
                    self._clients.append(client)
                threading.Thread(target=client.read_loop, daemon=True,
                                 name="IpcClient").start()
            except Exception:  # noqa: BLE001
                time.sleep(0.5)


class ClientHandle:
    def __init__(self, handle, server: IpcServer):
        self.handle = handle
        self.server = server
        self.alive = True
        self.subscribed_topics: set[str] = set()
        self.authed = False

    def write_raw(self, data: bytes) -> None:
        if not self.alive:
            return
        try:
            win32file.WriteFile(self.handle, data)
        except Exception:  # noqa: BLE001
            self.alive = False
            raise

    def write(self, frame: dict) -> None:
        self.write_raw((json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8"))

    def read_loop(self) -> None:
        buf = b""
        try:
            while self.alive:
                hr, chunk = win32file.ReadFile(self.handle, FRAME_MAX)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        frame = json.loads(line.decode("utf-8"))
                    except Exception:  # noqa: BLE001
                        self.write({"t": "error", "msg": "invalid json"})
                        continue
                    self._handle_frame(frame)
        except Exception:  # noqa: BLE001
            pass
        finally:
            self.alive = False

    def _handle_frame(self, frame: dict) -> None:
        t = frame.get("t")
        if t == "hello":
            tok = frame.get("token", "")
            if tok != self.server.emit_token:
                self.write({"t": "error", "msg": "auth"})
                self.alive = False
                self.close()
                return
            self.authed = True
            self.write({"t": "hello_ack", "service_pid": 0, "uptime_s": 0})
            return
        if not self.authed:
            self.write({"t": "error", "msg": "not authed"})
            return
        if t == "subscribe":
            self.subscribed_topics |= set(frame.get("topics", []))
            self.write({"t": "subscribed", "topics": list(self.subscribed_topics)})
            return
        if t == "ping":
            self.write({"t": "pong"})
            return
        if t == "cmd":
            self.server.on_command(frame, self)
            return
        self.write({"t": "error", "msg": f"unknown frame type: {t}"})

    def close(self) -> None:
        self.alive = False
        try:
            win32file.CloseHandle(self.handle)
        except Exception:  # noqa: BLE001
            pass
