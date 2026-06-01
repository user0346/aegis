"""AEGIS Native-Messaging-Host — Bruecke Browser-Extension <-> Desktop-App.

Liefert die Blocklist an die Extension und meldet blockierte Browser-Ereignisse
an die AEGIS-Desktop-App:

  - Primaer: per IPC ueber die Named-Pipe in den laufenden Service injizieren
    (event.inject) -> erscheint SOFORT im Live-Stream der UI.
  - Fallback (Service laeuft nicht): direkt in die DB schreiben, damit nichts
    verloren geht.

Chrome/Brave/Edge Native-Messaging-Protokoll (stdin/stdout, 4-byte length + JSON).
"""
import sys, os, json, struct, time, threading
from pathlib import Path

# Konsolenfenster verstecken (windowless host)
try:
    import ctypes
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

PIPE_NAME = r"\\.\pipe\aegis-v2-bus"
TOKEN_PATH = Path.home() / ".aegis" / "ipc_token"

# ----- Browser-Control: datei-basierte Bruecke Desktop-App <-> Host <-> Extension -----
# Die Desktop-App SCHREIBT Steuer-Befehle in BROWSER_CMD_FILE; dieser Host POLLT die Datei
# und schiebt neue Befehle an die Extension. Ergebnisse der Extension schreibt der Host nach
# BROWSER_RESULT_FILE (die App liest sie dort). HEARTBEAT zeigt der App, dass die Bruecke lebt.
_AEGIS_DIR = Path.home() / ".aegis"
BROWSER_CMD_FILE = _AEGIS_DIR / "browser_cmd.jsonl"
BROWSER_RESULT_FILE = _AEGIS_DIR / "browser_result.jsonl"
HEARTBEAT_FILE = _AEGIS_DIR / "browser_bridge_alive"

_send_lock = threading.Lock()      # send_msg aus mehreren Threads serialisieren


# ----- Native-Messaging-Protokoll -----
def read_msg():
    raw = sys.stdin.buffer.read(4)
    if len(raw) < 4:
        return None
    n = struct.unpack("<I", raw)[0]
    return json.loads(sys.stdin.buffer.read(n).decode("utf-8"))


def send_msg(obj):
    data = json.dumps(obj).encode("utf-8")
    with _send_lock:                # zwei Threads (main + cmd-pump) schreiben sonst verschraenkt
        sys.stdout.buffer.write(struct.pack("<I", len(data)))
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


# ----- Browser-Control: Befehls-Queue der App pollen + an Extension weiterreichen -----
def _browser_cmd_pump(stop_evt):
    """Tail't BROWSER_CMD_FILE (append-only JSONL) und schickt neue Steuer-Befehle an die
    Extension. Aktualisiert die Heartbeat-Datei, damit die App weiss, dass die Bruecke lebt.
    Best-effort, schweigt bei Fehlern (der Host darf nie crashen)."""
    seek = 0
    try:
        if BROWSER_CMD_FILE.exists():
            seek = BROWSER_CMD_FILE.stat().st_size      # nur NEUE Befehle ab jetzt
    except Exception:
        seek = 0
    while not stop_evt.is_set():
        try:
            HEARTBEAT_FILE.write_text(str(int(time.time())), encoding="utf-8")
        except Exception:
            pass
        try:
            if BROWSER_CMD_FILE.exists():
                size = BROWSER_CMD_FILE.stat().st_size
                if size < seek:
                    seek = 0                            # Datei wurde rotiert/geleert
                if size > seek:
                    with open(BROWSER_CMD_FILE, "rb") as f:
                        f.seek(seek)
                        chunk = f.read()
                    nl = chunk.rfind(b"\n")
                    if nl != -1:
                        seek += nl + 1
                        for line in chunk[:nl + 1].split(b"\n"):
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                cmd = json.loads(line.decode("utf-8", "replace"))
                            except Exception:
                                continue
                            if isinstance(cmd, dict) and cmd.get("cmd"):
                                send_msg(cmd)            # -> Extension (handleBrowserCmd)
        except Exception:
            pass
        stop_evt.wait(0.4)                               # ~400 ms Poll-Intervall


def _write_browser_result(obj):
    """Ergebnis der Extension fuer die Desktop-App ablegen (append-only, von der App getailt)."""
    try:
        _AEGIS_DIR.mkdir(parents=True, exist_ok=True)
        with open(BROWSER_RESULT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception:
        pass


# ----- Event an den laufenden Service injizieren (Live-Stream) -----
def ipc_inject(args: dict) -> bool:
    try:
        import win32file, win32pipe  # type: ignore
    except Exception:
        return False
    try:
        token = TOKEN_PATH.read_text(encoding="utf-8").strip() if TOKEN_PATH.exists() else ""
        win32pipe.WaitNamedPipe(PIPE_NAME, 800)
        h = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING, 0, None)
        try:
            hello = json.dumps({"t": "hello", "client": "guard", "version": 2,
                                "token": token}, ensure_ascii=False) + "\n"
            cmd = json.dumps({"t": "cmd", "name": "event.inject", "args": args},
                             ensure_ascii=False) + "\n"
            win32file.WriteFile(h, (hello + cmd).encode("utf-8"))
            time.sleep(0.05)   # dem Server kurz Zeit zum Verarbeiten geben
            return True
        finally:
            try:
                win32file.CloseHandle(h)
            except Exception:
                pass
    except Exception:
        return False


# ----- Service erreichbar? (fuer Live-Status in der Extension) -----
def service_online() -> bool:
    try:
        import win32pipe  # type: ignore
        win32pipe.WaitNamedPipe(PIPE_NAME, 200)
        return True
    except Exception:
        return False


# ----- Fallback: direkt in die DB -----
def db_log(sev: str, cat: str, message: str, meta: dict) -> None:
    try:
        from aegis2.shared.db import get_db
        get_db().log_event(sev, cat, message, "AEGIS-Guard", meta)
    except Exception:
        pass


def report(sev: str, cat: str, message: str, meta: dict) -> None:
    args = {"severity": sev, "category": cat, "message": message,
            "source": "AEGIS-Guard", "metadata": meta}
    if not ipc_inject(args):
        db_log(sev, cat, message, meta)


def main():
    try:
        from aegis2.shared import threat_intel as ti
        blocklist = sorted(ti.IP_LOGGER_DOMAINS)
    except Exception:
        blocklist = []

    # Browser-Control: App->Extension-Befehls-Pump als Hintergrund-Thread starten.
    _stop = threading.Event()
    try:
        threading.Thread(target=_browser_cmd_pump, args=(_stop,), daemon=True).start()
    except Exception:
        pass

    while True:
        msg = read_msg()
        if msg is None:
            break
        t = (msg or {}).get("t")
        if t == "hello":
            send_msg({"blocklist": blocklist, "service_online": service_online()})
        elif t == "ping":
            send_msg({"t": "pong", "service_online": service_online()})
        elif t == "cmd_result":
            _write_browser_result(msg)               # Browser-Control-Ergebnis -> fuer die App
        elif t == "blocked_nav":
            host = msg.get("host", "?")
            report("WARN", "URL", f"Browser: Risiko-Navigation blockiert ({host})", msg)
        elif t == "blocked_download":
            host = msg.get("host", "?")
            report("THREAT", "FILE",
                   f"Browser: Risiko-Download gestoppt: {msg.get('file','?')} ({host})", msg)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
