"""Named-Pipe IPC server for Service ↔ UI communication.

Protocol: newline-delimited JSON. See AEGIS_V2_ARCHITECTURE.md for frame types.

Design notes:
- Windows-only (uses pywin32 win32pipe / win32file). On non-Windows we noop.
- Per-client thread (max 4 concurrent clients).
- ACL restricted to current-user + SYSTEM via win32security DACL.
- All client writes are size-checked (max 64KB per frame).
"""
from __future__ import annotations

import hmac
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


def _own_user_sid():
    """SID aus dem eigenen Prozess-Token — robuster als LookupAccountName(GetUserName),
    das mehrdeutig ist und im Dienst-/SYSTEM-Kontext die falsche SID liefert."""
    try:
        th = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), ntsecuritycon.TOKEN_QUERY)
        return win32security.GetTokenInformation(th, ntsecuritycon.TokenUser)[0]
    except Exception:  # noqa: BLE001
        try:
            return win32security.LookupAccountName(None, win32api.GetUserName())[0]
        except Exception:  # noqa: BLE001
            return None


def _build_pipe_security_attributes():
    """DACL: allow current user + LocalSystem RW only. Deny all others.

    This prevents OTHER local user accounts from connecting to our pipe.
    Schlaegt die SID-Ermittlung fehl, wird KEINE offene Pipe gebaut (return None).
    """
    if not HAS_WIN:
        return None
    try:
        user_sid = _own_user_sid()
        if user_sid is None:
            return None
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
        """Send a frame to all subscribed clients.

        WICHTIG: Das blockierende WriteFile pro Client laeuft OHNE gehaltenem
        self._lock. Frueher wurde der Lock ueber die gesamte Schleife gehalten —
        ein einziger haengender Client (langsame/abgewuergte UI) blockierte dann
        die komplette Event-Auslieferung, den Accept-Loop (neue Clients) und
        stop(). Daher: Liste unter dem Lock schnappschiessen, Lock freigeben,
        Schreibvorgaenge ausserhalb erledigen, danach Lock nur kurz zum
        Aussortieren toter Clients erneut nehmen.
        Pro-Handle-Serialisierung uebernimmt weiterhin write_raw()._wlock.
        """
        data = (json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8")
        with self._lock:
            clients = list(self._clients)
        dead: list[ClientHandle] = []
        for c in clients:
            if not c.alive:
                dead.append(c)
                continue
            try:
                c.write_raw(data)
            except Exception:  # noqa: BLE001
                dead.append(c)
        if dead:
            with self._lock:
                for d in dead:
                    try:
                        self._clients.remove(d)
                    except ValueError:
                        pass  # bereits anderswo entfernt

    # ---- internal ----
    def _accept_loop(self) -> None:
        sa = _build_pipe_security_attributes()
        if sa is None:          # fail-CLOSED: ohne nutzerbeschraenkte DACL KEINE Pipe oeffnen
            import logging as _lg
            _lg.getLogger("aegis.ipc").critical(
                "IPC: konnte keine nutzerbeschraenkte DACL erzeugen — Pipe wird NICHT "
                "geoeffnet (fail-closed statt offener Default-ACL).")
            return
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
        self._wlock = threading.Lock()   # serialisiert WriteFile auf diesem Handle

    def write_raw(self, data: bytes) -> None:
        if not self.alive:
            return
        try:
            # Ein Handle, mehrere Schreiber (broadcast-Thread + read_loop-Thread):
            # ohne Lock koennen zwei WriteFile-Aufrufe ihre Bytes verschraenken
            # und zerrissenes JSON erzeugen.
            with self._wlock:
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
                if len(buf) > FRAME_MAX:     # Frame-Cap: kein unbegrenztes Puffer-Wachstum
                    self.write({"t": "error", "msg": "frame too large"})
                    break
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        frame = json.loads(line.decode("utf-8"))
                    except Exception:  # noqa: BLE001
                        self.write({"t": "error", "msg": "invalid json"})
                        continue
                    if not isinstance(frame, dict):
                        self.write({"t": "error", "msg": "frame must be object"})
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
            # konstante-Zeit-Vergleich (kein Timing-Orakel auf das Token)
            if not isinstance(tok, str) or not hmac.compare_digest(tok, self.server.emit_token):
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
            topics = frame.get("topics", [])
            if isinstance(topics, list):
                self.subscribed_topics |= {str(x) for x in topics}
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
