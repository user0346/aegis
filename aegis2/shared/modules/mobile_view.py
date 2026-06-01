"""Handy-Live-Ansicht — kleiner, READ-ONLY HTTP-Server, damit der Nutzer vom
Smartphone (gleiches WLAN) live sieht, was AEGIS gerade macht.

SICHERHEIT (bewusst defensiv fuer ein Security-Tool):
  - OPT-IN: laeuft NUR, wenn Setting 'mobile_view_enabled' = True (Default AUS).
  - TOKEN-Pflicht: jede Anfrage braucht ?t=<token> (hmac.compare_digest) -> sonst 403.
  - READ-ONLY: zeigt ausschliesslich Status + letzte Ereignisse. KEINE Steuer-Endpunkte,
    kein POST -> vom Handy kann NICHTS ausgeloest werden.
  - LAN: bindet auf den lokalen Port; das Router-Firewall haelt das Internet (WAN) draussen.
  - Kein Verzeichnis-Listing, nur 3 feste Routen; nosniff-Header.
"""
from __future__ import annotations

import hmac
import json
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .base import Module
from ..events import Severity, Category


def _lan_ip() -> str:
    """Bevorzugt die echte Heim-WLAN/LAN-IP. WICHTIG: die Route zu 8.8.8.8 liefert bei
    aktivem VPN (z.B. NordVPN/NordLynx) die VPN-IP (10.x) zurueck — dorthin kommt das
    Handy NICHT. Daher ALLE IPv4 sammeln und 192.168.x > 172.16-31 > 10.x bevorzugen."""
    cands = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                cands.append(ip)
    except Exception:  # noqa: BLE001
        pass
    for pref in ("192.168.", "172.", "10."):
        for ip in cands:
            if ip.startswith(pref):
                return ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:  # noqa: BLE001
        return "127.0.0.1"


_PAGE = """<!doctype html><html lang=de><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name=theme-color content="#0a0e17"><title>AEGIS</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}
body{margin:0;font:15px/1.45 -apple-system,system-ui,Segoe UI,sans-serif;background:#0a0e17;color:#dbe4f0}
header{padding:16px;display:flex;align-items:center;gap:11px;position:sticky;top:0;z-index:5;
background:rgba(12,18,32,.92);backdrop-filter:blur(8px);border-bottom:1px solid #1b2640}
.dot{width:13px;height:13px;border-radius:50%;background:#37d39a;box-shadow:0 0 12px #37d39a;flex:none}
.dot.warn{background:#facc15;box-shadow:0 0 12px #facc15}.dot.crit{background:#f9737e;box-shadow:0 0 12px #f9737e}
h1{font-size:17px;margin:0;font-weight:650;letter-spacing:.02em}.sub{color:#8a93a6;font-size:12px}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:12px}
.card{background:#0f1626;border:1px solid #1b2640;border-radius:14px;padding:13px 14px}
.card .n{font-size:26px;font-weight:750;line-height:1}.card .l{color:#8a93a6;font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-top:6px}
.evts{padding:2px 12px 30px}.h2{color:#8a93a6;font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin:6px 4px 10px}
.evt{background:#0f1626;border:1px solid #1b2640;border-left:3px solid #2b3a5e;border-radius:10px;padding:10px 12px;margin-bottom:8px}
.evt.WARN{border-left-color:#facc15}.evt.CRITICAL,.evt.THREAT{border-left-color:#f9737e}
.evt .m{font-size:13.5px}.evt .meta{color:#8a93a6;font-size:11px;margin-top:4px}
.muted{color:#8a93a6;text-align:center;padding:24px;font-size:13px}
</style></head><body>
<header><span class=dot id=dot></span><div><h1>AEGIS</h1><div class=sub id=sub>verbinde…</div></div></header>
<div class=cards id=cards></div>
<div class=evts><div class=h2>Letzte Ereignisse</div><div id=evts></div></div>
<script>
var T=new URLSearchParams(location.search).get('t')||'';
function esc(s){return(s||'').replace(/[&<>]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}
function tile(n,l){return '<div class=card><div class=n>'+n+'</div><div class=l>'+l+'</div></div>'}
async function j(p){var r=await fetch(p+(p.indexOf('?')<0?'?':'&')+'t='+encodeURIComponent(T),{cache:'no-store'});return r.json()}
async function tick(){
 try{
  var s=await j('api/status');
  var crit=s.threats_24h>0,warn=s.quarantine_pending>0;
  document.getElementById('dot').className='dot'+(crit?' crit':warn?' warn':'');
  document.getElementById('sub').textContent=(crit?'Achtung — Bedrohung erkannt':warn?'Quarantäne wartet':'Alles ruhig')+' · '+new Date().toLocaleTimeString();
  document.getElementById('cards').innerHTML=tile(s.threats_24h,'Bedrohungen 24h')+tile(s.quarantine_pending,'in Quarantäne')+tile(s.events_24h,'Ereignisse 24h')+tile(s.programs_known,'bekannte Programme');
  var e=await j('api/events');
  document.getElementById('evts').innerHTML=(e.events||[]).map(function(x){return '<div class="evt '+esc(x.severity)+'"><div class=m>'+esc(x.message)+'</div><div class=meta>'+esc(x.source)+' · '+esc(x.category)+' · '+esc(x.ago)+'</div></div>'}).join('')||'<div class=muted>Noch keine Ereignisse.</div>';
 }catch(err){document.getElementById('sub').textContent='Verbindung verloren – neuer Versuch…'}
}
tick();setInterval(tick,3000);
</script></body></html>"""


class MobileView(Module):
    name = "MobileView"

    def __init__(self, bus, db, port: int = 8770):
        super().__init__(bus)
        self.db = db
        self.port = port
        self._httpd = None

    def _token(self) -> str:
        t = (self.db.get_setting("mobile_view_token", "") or "").strip()
        if not t:
            t = secrets.token_urlsafe(18)
            self.db.set_setting("mobile_view_token", t)
        return t

    def run(self) -> None:
        # Warten, bis der Nutzer die Ansicht einschaltet (kein Neustart noetig zum AN-schalten).
        while not self._stop.is_set():
            if bool(self.db.get_setting("mobile_view_enabled", False)):
                self._serve()       # blockiert bis Stop / Fehler
            self._stop.wait(5)

    def _serve(self) -> None:
        token = self._token()
        db = self.db
        try:
            port = int(self.db.get_setting("mobile_view_port", self.port) or self.port)
        except (TypeError, ValueError):
            port = self.port

        def _ago(ts):
            d = max(0, int(time.time() - (ts or 0)))
            if d < 60:
                return f"vor {d}s"
            if d < 3600:
                return f"vor {d // 60} min"
            if d < 86400:
                return f"vor {d // 3600} h"
            return f"vor {d // 86400} d"

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):   # kein Konsolen-/Stderr-Spam
                pass

            def _ok_token(self, q):
                got = (q.get("t", [""])[0] or "")
                return bool(got) and hmac.compare_digest(got, token)

            def _send(self, code, body, ctype="application/json; charset=utf-8"):
                b = body.encode("utf-8") if isinstance(body, str) else body
                try:
                    self.send_response(code)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(b)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Referrer-Policy", "no-referrer")
                    self.end_headers()
                    self.wfile.write(b)
                except Exception:  # noqa: BLE001
                    pass

            def do_GET(self):
                u = urlparse(self.path)
                q = parse_qs(u.query)
                path = (u.path or "/").rstrip("/") or "/"
                if not self._ok_token(q):
                    self._send(403, "<h2>AEGIS</h2><p>Zugriff verweigert — Token fehlt oder falsch.</p>",
                               "text/html; charset=utf-8")
                    return
                if path == "/":
                    self._send(200, _PAGE, "text/html; charset=utf-8")
                    return
                if path == "/api/status":
                    try:
                        st = db.stats() or {}
                    except Exception:  # noqa: BLE001
                        st = {}
                    try:
                        from ..knowledge import learned_summary
                        ls = learned_summary(db) or {}
                    except Exception:  # noqa: BLE001
                        ls = {}
                    self._send(200, json.dumps({
                        "threats_24h": int(st.get("threats_24h", 0) or 0),
                        "events_24h": int(st.get("events_24h", 0) or 0),
                        "quarantine_pending": int(st.get("quarantine_pending", 0) or 0),
                        "programs_known": int(ls.get("baseline_known", 0) or 0),
                    }))
                    return
                if path == "/api/events":
                    try:
                        rows = db.recent_events(limit=40)
                        evs = [{"severity": r["severity"], "category": r["category"],
                                "source": r["source"], "message": (r["message"] or "")[:220],
                                "ago": _ago(r["ts"])} for r in rows]
                    except Exception:  # noqa: BLE001
                        evs = []
                    self._send(200, json.dumps({"events": evs}))
                    return
                self._send(404, "{}")

        try:
            httpd = ThreadingHTTPServer(("0.0.0.0", port), H)
        except Exception as e:  # noqa: BLE001
            self.emit(Severity.WARN, Category.SYSTEM,
                      f"Handy-Ansicht: Port {port} nicht verfuegbar ({type(e).__name__}).")
            self._stop.wait(30)
            return
        self._httpd = httpd
        ip = _lan_ip()
        url = f"http://{ip}:{port}/?t={token}"
        try:
            self.db.set_setting("mobile_view_url", url)     # die UI zeigt sie an (QR/Link)
        except Exception:  # noqa: BLE001
            pass
        self.emit(Severity.INFO, Category.SYSTEM,
                  f"Handy-Ansicht aktiv unter {ip}:{port} (gleiches WLAN, Token-gesichert).")
        srv = threading.Thread(target=httpd.serve_forever,
                               kwargs={"poll_interval": 0.5}, daemon=True, name="MobileViewHTTP")
        srv.start()
        # laufen lassen, solange aktiviert UND nicht gestoppt
        while not self._stop.is_set() and bool(self.db.get_setting("mobile_view_enabled", False)):
            self._stop.wait(1.0)
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:  # noqa: BLE001
            pass
        self._httpd = None
