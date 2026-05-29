"""NetworkWatcher — neue TCP/UDP-Verbindungen + Portscan-/Flood-Detection.

Loopback wird ausgeklammert (False-Positive-Quelle für IPC zwischen lokalen
Apps wie Discord, Roblox, NordVPN). Private-IPs werden bei Outgoing-Logging
gefiltert um Spam zu reduzieren.
"""
from __future__ import annotations

import socket
import threading
import time
from collections import defaultdict, deque

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

from ..db import Database
from ..events import EventBus, Event, Severity, Category
from .base import Module


class PortScanState:
    PORT_THRESHOLD = 12
    PORT_WINDOW_SEC = 60
    FLOOD_THRESHOLD = 80
    FLOOD_WINDOW_SEC = 30

    def __init__(self):
        self.ports: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.port_set: dict[str, dict[int, float]] = defaultdict(dict)
        self.conn_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._lock = threading.Lock()

    def observe(self, src_ip: str, port: int) -> None:
        now = time.time()
        with self._lock:
            self.ports[src_ip].append(port)
            self.port_set[src_ip][port] = now
            self.conn_times[src_ip].append(now)
            cutoff = now - self.PORT_WINDOW_SEC
            self.port_set[src_ip] = {p: t for p, t in self.port_set[src_ip].items() if t > cutoff}

    def is_scanning(self, src_ip: str) -> bool:
        with self._lock:
            cutoff = time.time() - self.PORT_WINDOW_SEC
            recent = {p for p, t in self.port_set[src_ip].items() if t > cutoff}
            return len(recent) >= self.PORT_THRESHOLD

    def port_count(self, src_ip: str) -> int:
        with self._lock:
            cutoff = time.time() - self.PORT_WINDOW_SEC
            return len({p for p, t in self.port_set[src_ip].items() if t > cutoff})

    def is_flooding(self, src_ip: str) -> bool:
        with self._lock:
            cutoff = time.time() - self.FLOOD_WINDOW_SEC
            recent = [t for t in self.conn_times[src_ip] if t > cutoff]
            return len(recent) >= self.FLOOD_THRESHOLD


class NetworkWatcher(Module):
    name = "NetworkWatcher"

    def __init__(self, bus: EventBus, db: Database, interval: float = 2.0):
        super().__init__(bus)
        self.db = db
        self.interval = interval
        self._seen: set[str] = set()
        self._out_dedup: dict = {}
        self._portscan = PortScanState()

    def run(self) -> None:
        if not psutil:
            self.emit(Severity.WARN, Category.SYSTEM,
                      "psutil fehlt — NetworkWatcher inaktiv")
            return
        while not self._stop.is_set():
            try:
                conns = psutil.net_connections(kind="inet")
                pid_cache: dict[int, tuple] = {}
                for c in conns:
                    self._handle(c, pid_cache)
            except psutil.AccessDenied:
                self.emit(Severity.WARN, Category.SYSTEM,
                          "NetworkWatcher: Access denied — benötigt Admin für alle Connections")
                self._stop.wait(30)
                continue
            except psutil.Error as e:
                self.emit(Severity.WARN, Category.SYSTEM,
                          f"NetworkWatcher-Fehler: {e}")
            if len(self._seen) > 5000:
                self._seen = set(list(self._seen)[-2000:])
            self._stop.wait(self.interval)

    def _handle(self, conn, pid_cache: dict) -> None:
        try:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            if not raddr:
                return
            tup = f"{conn.pid}|{laddr}|{raddr}|{conn.status}"
            if tup in self._seen:
                return
            self._seen.add(tup)

            pname, pexe = "", ""
            if conn.pid:
                if conn.pid in pid_cache:
                    pname, pexe = pid_cache[conn.pid]
                else:
                    try:
                        p = psutil.Process(conn.pid)
                        pname = p.name()
                        try:
                            pexe = p.exe()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pexe = ""
                        pid_cache[conn.pid] = (pname, pexe)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pid_cache[conn.pid] = ("", "")

            direction = "out"
            if conn.status in ("SYN_RECV", "TIME_WAIT") or (
                conn.laddr and conn.laddr.port < 10000 and conn.raddr and conn.raddr.port > 30000
            ):
                if conn.status != "ESTABLISHED" or (conn.laddr.port < 1024):
                    direction = "in"

            protocol = "tcp" if conn.type == socket.SOCK_STREAM else "udp"

            self.db.log_connection(
                conn.pid or 0, pname, pexe, laddr, raddr,
                conn.raddr.port if conn.raddr else 0,
                direction, protocol, conn.status)

            if direction == "in" and conn.raddr and not self._is_loopback(conn.raddr.ip):
                self.db.touch_source(conn.raddr.ip)
                self._portscan.observe(conn.raddr.ip, conn.laddr.port if conn.laddr else 0)
                if self._portscan.is_scanning(conn.raddr.ip):
                    self.db.flag_source(conn.raddr.ip, "portscan")
                    self.emit(Severity.THREAT, Category.NETWORK,
                              f"PORTSCAN von {conn.raddr.ip} "
                              f"({self._portscan.port_count(conn.raddr.ip)} verschiedene Ports)",
                              {"source_ip": conn.raddr.ip})
                if self._portscan.is_flooding(conn.raddr.ip):
                    self.db.flag_source(conn.raddr.ip, "flood")
                    self.emit(Severity.THREAT, Category.NETWORK,
                              f"CONNECTION-FLOOD von {conn.raddr.ip}",
                              {"source_ip": conn.raddr.ip})
            elif direction == "out" and conn.raddr:
                if not self._is_private(conn.raddr.ip):
                    _dk = str(conn.pid) + "|" + conn.raddr.ip
                    if time.time() - self._out_dedup.get(_dk, 0) < 90:
                        return
                    self._out_dedup[_dk] = time.time()
                    try:
                        _bl = self.db.baseline_observe("conn", (pname or "?") + "|" + conn.raddr.ip)
                    except Exception:
                        _bl = {"status": "new"}
                    if _bl.get("status") == "known":
                        return
                    self.emit(Severity.INFO, Category.NETWORK,
                              f"OUT {pname}({conn.pid}) → {raddr}",
                              {"pid": conn.pid, "process": pname,
                               "raddr": conn.raddr.ip, "rport": conn.raddr.port,
                               "protocol": protocol, "state": conn.status})
        except (AttributeError, psutil.NoSuchProcess):
            pass

    def _is_loopback(self, ip: str) -> bool:
        if not ip:
            return True
        if ip.startswith("127.") or ip == "::1":
            return True
        return False

    def _is_private(self, ip: str) -> bool:
        if not ip:
            return True
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return ip.startswith(("fe80:", "::1", "fc", "fd"))
            a, b = int(parts[0]), int(parts[1])
            if a == 10: return True
            if a == 127: return True
            if a == 172 and 16 <= b <= 31: return True
            if a == 192 and b == 168: return True
            if a == 169 and b == 254: return True
            return False
        except (ValueError, IndexError):
            return False
