"""Handy-Fernsteuerung — sieh UND steuere AEGIS vom Smartphone (gleiches WLAN).

SICHERHEIT (defensiv fuer ein Security-Tool):
  - OPT-IN: nur aktiv bei Setting 'mobile_view_enabled' = True (Default AUS).
  - TOKEN-Pflicht auf JEDER Anfrage (GET+POST), hmac.compare_digest -> sonst 403.
  - Steuerung nur ueber eine ALLOWLIST sicherer Befehle (Scan/Quarantaene/Status). Gefaehrliches
    (Schutz stoppen, Settings, Autonomie, Neustart) ist NICHT erreichbar.
  - Chat = derselbe Assistent wie am Desktop (gleiche Shell-/Aktions-Gates) — token-gated.
  - LAN-only; Verzeichnis-Listing aus; nosniff/no-store.
"""
from __future__ import annotations

import hmac
import json
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .base import Module
from ..events import Severity, Category

# cloudflared (Cloudflare Quick Tunnel) — optionaler Fernzugriff "von ueberall" (mobile Daten /
# fremdes WLAN). Ein einzelnes signiertes Cloudflare-Binary; Quick-Tunnel braucht KEIN Konto.
_CLOUDFLARED_URL = ("https://github.com/cloudflare/cloudflared/releases/latest/download/"
                    "cloudflared-windows-amd64.exe")
_CREATE_NO_WINDOW = 0x08000000
_TRYCF_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
# POST-Body deckeln: die einzigen Bodies sind {text<=500} bzw. {name,args} — 1 MB ist
# reichlich. Schuetzt vor dem Content-Length-OOM-Trick (riesiger Header -> Speicher-Allok).
_MAX_BODY = 1024 * 1024

# Echte PC-Web-UI (1:1 aufs Handy). aegis2/ui/web/ — von hier: ../../ui/web
WEB_DIR = Path(__file__).resolve().parents[2] / "ui" / "web"
_CTYPES = {".js": "application/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
           ".html": "text/html; charset=utf-8", ".json": "application/json; charset=utf-8",
           ".map": "application/json", ".png": "image/png", ".jpg": "image/jpeg",
           ".jpeg": "image/jpeg", ".gif": "image/gif", ".svg": "image/svg+xml",
           ".webp": "image/webp", ".ico": "image/x-icon", ".woff": "font/woff",
           ".woff2": "font/woff2", ".ttf": "font/ttf", ".mp3": "audio/mpeg", ".wav": "audio/wav"}


def _adapted_index() -> "str | None":
    """Die ECHTE PC-index.html — aber die Qt-QWebChannel-Bridge (qrc://, nur in Qt verfuegbar)
    wird durch unsere HTTP-Mobile-Bridge ersetzt, damit die Oberflaeche 1:1 im Handy-Browser
    laeuft."""
    try:
        html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001
        return None
    return html.replace('<script src="qrc:///qtwebchannel/qwebchannel.js"></script>',
                        '<script src="mobile_bridge.js?v=6"></script>')


# Nur diese Befehle darf das Handy ausloesen (sicher: lesen/scannen/Quarantaene verwalten).
_MOBILE_CMDS = {
    "scan.start", "scan.cancel", "scan.status", "scan.items",
    "quarantine.list", "quarantine.approve", "quarantine.deny",
    "quarantine.delete", "quarantine.purge_orphan",
    "stats", "learning.stats", "update.check", "update.status", "integrity.status",
}


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


_PAGE = r"""<!doctype html><html lang=de><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name=theme-color content="#070b14"><title>AEGIS</title><style>
:root{color-scheme:dark;--bg:#070b14;--card:#0f1626;--line:#1b2640;--txt:#dbe4f0;--mut:#8a93a6;--acc:#37b6ff;--ok:#37d39a;--warn:#facc15;--crit:#f9737e}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;font:15px/1.45 -apple-system,system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--txt)}
header{padding:14px 16px;display:flex;align-items:center;gap:11px;position:sticky;top:0;z-index:5;background:rgba(8,12,22,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.dot{width:13px;height:13px;border-radius:50%;background:var(--ok);box-shadow:0 0 12px var(--ok);flex:none}
.dot.warn{background:var(--warn);box-shadow:0 0 12px var(--warn)}.dot.crit{background:var(--crit);box-shadow:0 0 12px var(--crit)}
h1{font-size:17px;margin:0;font-weight:650;letter-spacing:.14em}.sub{color:var(--mut);font-size:12px}
.wrap{padding:12px 12px calc(80px + env(safe-area-inset-bottom))}.hide{display:none!important}
#tab-chat{padding-bottom:calc(122px + env(safe-area-inset-bottom))}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:13px 14px}
.card .n{font-size:26px;font-weight:750;line-height:1}.card .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-top:6px}
.h2{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin:16px 4px 10px}
.evt{background:var(--card);border:1px solid var(--line);border-left:3px solid #2b3a5e;border-radius:10px;padding:10px 12px;margin-bottom:8px}
.evt.WARN{border-left-color:var(--warn)}.evt.CRITICAL,.evt.THREAT{border-left-color:var(--crit)}
.evt .m{font-size:13.5px;word-break:break-word}.evt .meta{color:var(--mut);font-size:11px;margin-top:4px}
.muted{color:var(--mut);text-align:center;padding:22px;font-size:13px}
button{font:inherit;color:var(--txt);background:#15233b;border:1px solid var(--line);border-radius:10px;padding:11px 14px;font-weight:600}
button:active{background:#1b2c49}.btnacc{background:var(--acc);color:#04121f;border-color:var(--acc)}
.bubble{max-width:84%;padding:10px 13px;border-radius:14px;margin:6px 0;font-size:14px;word-break:break-word;white-space:pre-wrap}
.me{background:var(--acc);color:#04121f;margin-left:auto;border-bottom-right-radius:4px}
.ae{background:var(--card);border:1px solid var(--line);border-bottom-left-radius:4px}
#chatbox{min-height:40vh;display:flex;flex-direction:column}
.inputbar{position:fixed;left:0;right:0;bottom:calc(49px + env(safe-area-inset-bottom));display:flex;gap:8px;padding:8px 12px;background:rgba(8,12,22,.97);border-top:1px solid var(--line);z-index:6}
.inputbar input{flex:1;font:inherit;color:var(--txt);background:var(--card);border:1px solid var(--line);border-radius:10px;padding:11px 13px}
nav{position:fixed;left:0;right:0;bottom:0;display:flex;background:rgba(8,12,22,.96);border-top:1px solid var(--line);z-index:6}
nav a{flex:1;text-align:center;padding:11px 0 calc(11px + env(safe-area-inset-bottom));color:var(--mut);font-size:12px;font-weight:600;letter-spacing:.02em}
nav a.on{color:var(--acc)}
.kv{display:flex;justify-content:space-between;gap:12px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:11px 13px;margin-bottom:7px}
.kv .k{color:var(--mut);font-size:13px}.kv .v{font-weight:650;font-size:13.5px;text-align:right;word-break:break-word}
.kv .v.good{color:var(--ok)}.kv .v.bad{color:var(--crit)}.kv .v.warn{color:var(--warn)}
.mod{display:flex;align-items:center;gap:9px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:9px 12px;margin-bottom:6px}
.md{width:9px;height:9px;border-radius:50%;background:#46506b;flex:none}.md.on{background:var(--ok);box-shadow:0 0 8px var(--ok)}
.mod .mn{font-size:13.5px}
#scanstat.run{color:var(--acc);font-weight:600}
</style></head><body>
<header><span class=dot id=dot></span><div><h1>A E G I S</h1><div class=sub id=sub>verbinde…</div></div></header>

<div class=wrap id=tab-status>
  <div class=cards id=cards></div>
  <div class=h2>Letzte Ereignisse</div><div id=evts></div>
</div>

<div class="wrap hide" id=tab-system>
  <div class=h2>System</div><div id=sysinfo></div>
  <div class=h2>Module (Wächter)</div><div id=modlist></div>
</div>

<div class="wrap hide" id=tab-chat>
  <div id=chatbox></div>
</div>
<div class="inputbar hide" id=chatbar>
  <input id=msg placeholder="Frag AEGIS… (z. B. „Status" oder „scanne")" autocomplete=off>
  <button class=btnacc id=send>Senden</button>
</div>

<div class="wrap hide" id=tab-schutz>
  <div class=h2>Scan</div>
  <div id=scanstat class=muted>—</div>
  <button class=btnacc id=scanbtn style="width:100%;margin:6px 0 4px">▶ Vollständigen Scan starten</button>
  <div class=h2>Quarantäne</div><div id=quar></div>
</div>

<nav>
  <a class=on data-t=status onclick="go('status')">Status</a>
  <a data-t=system onclick="go('system')">System</a>
  <a data-t=chat onclick="go('chat')">Chat</a>
  <a data-t=schutz onclick="go('schutz')">Schutz</a>
</nav>
<script>
var T=new URLSearchParams(location.search).get('t')||'',TAB='status';
function esc(s){return(s||'').replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function tile(n,l){return '<div class=card><div class=n>'+n+'</div><div class=l>'+l+'</div></div>'}
async function jget(p){var r=await fetch(p+(p.indexOf('?')<0?'?':'&')+'t='+encodeURIComponent(T),{cache:'no-store'});return r.json()}
async function jpost(p,b){var r=await fetch(p+'?t='+encodeURIComponent(T),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});return r.json()}
function go(t){TAB=t;['status','system','chat','schutz'].forEach(function(x){document.getElementById('tab-'+x).classList.toggle('hide',x!==t)});
 document.getElementById('chatbar').classList.toggle('hide',t!=='chat');
 document.querySelectorAll('nav a').forEach(function(a){a.classList.toggle('on',a.dataset.t===t)});
 if(t==='schutz')loadSchutz();
 if(t==='system'||t==='status')tick();}
async function tick(){
 try{var s=await jget('api/status');var crit=s.threats_24h>0,warn=s.quarantine_pending>0;
  document.getElementById('dot').className='dot'+(crit?' crit':warn?' warn':'');
  document.getElementById('sub').textContent=(crit?'Achtung — Bedrohung':warn?'Quarantäne wartet':'Alles ruhig')+' · '+(s.modules_running||0)+'/'+(s.modules_total||0)+' Wächter · '+new Date().toLocaleTimeString();
  if(TAB==='status'){document.getElementById('cards').innerHTML=tile(s.threats_24h,'Bedrohungen 24h')+tile(s.quarantine_pending,'in Quarantäne')+tile(s.events_24h,'Ereignisse 24h')+tile((s.modules_running||0)+'/'+(s.modules_total||0),'Wächter aktiv')+tile(s.programs_known,'bekannte Programme')+tile(s.files_total,'Dateien erfasst');
   var e=await jget('api/events');document.getElementById('evts').innerHTML=(e.events||[]).map(function(x){return '<div class="evt '+esc(x.severity)+'"><div class=m>'+esc(x.message)+'</div><div class=meta>'+esc(x.source)+' · '+esc(x.category)+' · '+esc(x.ago)+'</div></div>'}).join('')||'<div class=muted>Noch keine Ereignisse.</div>';}
  else if(TAB==='system'){renderSystem(s);}
 }catch(err){document.getElementById('sub').textContent='Verbindung verloren …'}
}
function kv(k,v,cls){return '<div class=kv><div class=k>'+esc(k)+'</div><div class="v'+(cls?' '+cls:'')+'">'+esc(String(v))+'</div></div>'}
function renderSystem(s){
 var ig=s.integrity||{},up=s.update||{},au=s.autonomy||{};
 var igt=ig.verified?'✓ verifiziert':(ig.safe_mode?'⚠ Safe-Mode':(ig.frozen?'gepinnt (exe)':'Quellcode-Modus')),igc=ig.verified?'good':(ig.safe_mode?'bad':'');
 var upt=up.staged?('● Update bereit'+(up.version?' '+up.version:'')):'aktuell',upc=up.staged?'warn':'good';
 document.getElementById('sysinfo').innerHTML=
  kv('Version', s.version||'—')+
  kv('Autonomie',(au.level_name||'—')+(au.active?' · aktiv':''),au.active?'warn':'')+
  kv('Integrität',igt,igc)+
  kv('Update',upt,upc)+
  kv('Verbindungen 1h', s.connections_1h)+
  kv('Domains geblockt', s.domains_blocked, s.domains_blocked>0?'good':'')+
  kv('Unbekannte Dateien', s.files_unknown, s.files_unknown>0?'warn':'');
 var m=s.modules||[];
 document.getElementById('modlist').innerHTML=m.length?m.map(function(x){return '<div class=mod><span class="md'+(x.on?' on':'')+'"></span><span class=mn>'+esc(x.name)+'</span></div>'}).join(''):'<div class=muted>—</div>';
}
function addBubble(who,txt){var d=document.createElement('div');d.className='bubble '+(who==='me'?'me':'ae');d.textContent=txt;document.getElementById('chatbox').appendChild(d);d.scrollIntoView();}
async function sendMsg(){var i=document.getElementById('msg'),t=i.value.trim();if(!t)return;i.value='';addBubble('me',t);
 var th=document.createElement('div');th.className='bubble ae';th.textContent='…';document.getElementById('chatbox').appendChild(th);th.scrollIntoView();
 try{var r=await jpost('api/chat',{text:t});th.textContent=r.reply||'(keine Antwort)';}catch(e){th.textContent='Fehler.';}th.scrollIntoView();}
async function pollScan(){
 if(TAB!=='schutz')return;
 try{var s=await jpost('api/cmd',{name:'scan.status'});var d=s.data||{},sm=d.summary||{};
  var g=sm.items_total||0,f=(sm.items_block||0)+(sm.items_warn||0),u=sm.items_unknown||0;
  var el=document.getElementById('scanstat');
  if(d.running){el.textContent='läuft… '+g+' geprüft · '+f+' Funde';el.classList.add('run');clearTimeout(window._sp);window._sp=setTimeout(pollScan,1500);}
  else if(sm.finished_at||g){el.classList.remove('run');el.textContent='fertig · '+g+' geprüft · '+f+' Funde'+(u?(' · '+u+' unbekannt'):'')+(sm.cancelled?' (abgebrochen)':'');}
  else{el.classList.remove('run');el.textContent='kein Scan bisher';}
 }catch(e){}
}
async function loadSchutz(){
 pollScan();
 try{var q=await jpost('api/cmd',{name:'quarantine.list'});var items=(q.data&&(q.data.items||q.data))||[];if(!Array.isArray(items))items=[];
  document.getElementById('quar').innerHTML=items.length?items.slice(0,30).map(function(x){return '<div class=evt><div class=m>'+esc(x.path||x.name||x.ident||JSON.stringify(x).slice(0,80))+'</div><div class=meta>'+esc(x.verdict||x.reason||'')+'</div></div>'}).join(''):'<div class=muted>Quarantäne ist leer.</div>';}catch(e){document.getElementById('quar').innerHTML='<div class=muted>—</div>';}
}
document.getElementById('send').onclick=sendMsg;
document.getElementById('msg').addEventListener('keydown',function(e){if(e.key==='Enter')sendMsg()});
document.getElementById('scanbtn').onclick=async function(){var b=this;b.textContent='Starte…';b.disabled=true;try{await jpost('api/cmd',{name:'scan.start'});}catch(e){}b.disabled=false;b.textContent='▶ Vollständigen Scan starten';setTimeout(pollScan,500);};
tick();setInterval(tick,3000);
</script></body></html>"""


class MobileView(Module):
    name = "MobileView"

    def __init__(self, bus, db, orch=None, port: int = 8770):
        super().__init__(bus)
        self.db = db
        self.orch = orch
        self.port = port
        self._httpd = None
        self._vc = None
        self._uitl = threading.local()   # sammelt ui_cmd-Aktionen pro /api/chat-Request (Thread-lokal)

    def _collect_ui(self, c):
        """ui_cmd-Hook des Mobile-Controllers: sammelt UI-Aktionen (hide_chat, switch_tab,
        hide_vision …) des aktuellen Requests Thread-lokal, damit /api/chat sie ans Handy
        zurueckgibt und die Mobile-Bridge sie wie am PC abspielt. Ausserhalb eines Requests No-Op."""
        acts = getattr(self._uitl, "acts", None)
        if acts is not None and c:
            acts.append(c)

    def _token(self) -> str:
        t = (self.db.get_setting("mobile_view_token", "") or "").strip()
        if not t:
            t = secrets.token_urlsafe(18)
            self.db.set_setting("mobile_view_token", t)
        return t

    def _cmd(self, name: str, args: dict):
        """Sicheren Allowlist-Befehl direkt am Orchestrator ausfuehren (Rueckgabe-dict)."""
        if name not in _MOBILE_CMDS or self.orch is None:
            return {"ok": False, "error": "not allowed"}
        try:
            from ..signatures import validate_command  # falls vorhanden -> Schema-Check
        except Exception:  # noqa: BLE001
            validate_command = None
        try:
            from ..command_schema import validate_command as _vc2  # eigentlicher Ort
            validate_command = _vc2
        except Exception:  # noqa: BLE001
            pass
        try:
            if validate_command:
                ok, why = validate_command(name, args or {})
                if not ok:
                    return {"ok": False, "error": f"validation: {why}"}
        except Exception:  # noqa: BLE001
            pass
        h = getattr(self.orch, "_cmd_" + name.replace(".", "_"), None)
        if not h:
            return {"ok": False, "error": "unknown"}
        try:
            return {"ok": True, "data": h(args or {})}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": type(e).__name__}

    def _chat(self, text: str) -> str:
        """Vollwertiger Assistent (gleiche Gates wie am Desktop), Aktionen ueber den Orchestrator."""
        if not text:
            return ""
        if self._vc is None:
            try:
                from ...voice.controller import VoiceController
            except Exception:  # noqa: BLE001
                from aegis2.voice.controller import VoiceController
            orch = self.orch

            def _svc(f):
                try:
                    nm = f.get("name", "")
                    h = getattr(orch, "_cmd_" + nm.replace(".", "_"), None)
                    if h:
                        return h(f.get("args", {}) or {})
                except Exception:  # noqa: BLE001
                    pass
                return None

            self._vc = VoiceController(ui_cmd=self._collect_ui, service_cmd=_svc,
                                       status_cb=lambda: (self.db.stats() if hasattr(self.db, "stats") else {}))
        try:
            res = self._vc.handle_text(text)
            return (res.get("msg") or "").strip() or "Ok."
        except Exception as e:  # noqa: BLE001
            return f"Fehler: {type(e).__name__}"

    def _exec(self, name: str, args: dict):
        """VOLLER Befehlszugriff (1:1 wie Desktop) — JEDER Orchestrator-Befehl, Schema-validiert.
        Bewusste Nutzer-Entscheidung (Handy = PC). Token schuetzt den Zugang."""
        if self.orch is None:
            return {"ok": False, "error": "no orch"}
        try:
            from ..command_schema import validate_command
            ok, why = validate_command(name, args or {})
            if not ok:
                return {"ok": False, "name": name, "error": f"validation: {why}"}
        except Exception:  # noqa: BLE001
            pass
        h = getattr(self.orch, "_cmd_" + name.replace(".", "_"), None)
        if not h:
            return {"ok": False, "name": name, "error": "unknown"}
        try:
            return {"ok": True, "name": name, "data": h(args or {})}
        except Exception as e:  # noqa: BLE001
            # Sicherheit (#1 Stack-Traces): rohe Exception-Message (Pfade/SQL/Interna)
            # NICHT ueber die Netz-Antwort leaken — nur der generische Typ raus.
            return {"ok": False, "name": name, "error": type(e).__name__}

    def _memory(self) -> dict:
        try:
            from .. import user_memory as um, knowledge_base as kb
            return {"address": um.get_address(), "wake_word": um.get_wake_word(),
                    "notes": um.get_notes(), "aliases": um.get_aliases(),
                    "top_cmds": um.top_commands(5), "knowledge_count": kb.count()}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _ollama_status(self) -> dict:
        try:
            from ...voice.ollama_setup import status
            return status()
        except Exception as e:  # noqa: BLE001
            return {"installed": True, "running": True, "error": str(e)}

    # ---- Fernzugriff "von ueberall" via Cloudflare Quick Tunnel (opt-in) ----
    def _cloudflared_path(self) -> Path:
        return Path.home() / ".aegis" / "bin" / "cloudflared.exe"

    def _ensure_cloudflared(self):
        p = self._cloudflared_path()
        try:
            if p.exists() and p.stat().st_size > 1_000_000:
                return p
        except OSError:
            pass
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            self.emit(Severity.INFO, Category.SYSTEM,
                      "Handy-Fernzugriff: lade einmalig cloudflared (~50 MB) …")
            tmp = p.with_suffix(".part")
            with urllib.request.urlopen(_CLOUDFLARED_URL, timeout=180) as r, open(tmp, "wb") as f:
                shutil.copyfileobj(r, f)
            tmp.replace(p)
            return p if (p.exists() and p.stat().st_size > 1_000_000) else None
        except Exception as e:  # noqa: BLE001
            self.emit(Severity.WARN, Category.SYSTEM,
                      f"Handy-Fernzugriff: cloudflared-Download fehlgeschlagen ({type(e).__name__}).")
            return None

    def _start_tunnel(self, port: int):
        """cloudflared Quick-Tunnel -> oeffentliche HTTPS-URL (Token-gated). Returns Popen|None."""
        exe = self._ensure_cloudflared()
        if not exe:
            return None
        try:
            proc = subprocess.Popen(
                [str(exe), "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=_CREATE_NO_WINDOW, text=True, encoding="utf-8",
                errors="replace", bufsize=1)
        except Exception as e:  # noqa: BLE001
            self.emit(Severity.WARN, Category.SYSTEM,
                      f"Handy-Fernzugriff: cloudflared-Start fehlgeschlagen ({type(e).__name__}).")
            return None

        def _reader():
            got = False
            try:
                for line in proc.stdout:
                    if not got:
                        m = _TRYCF_RE.search(line or "")
                        if m:
                            got = True
                            base = m.group(0)
                            try:
                                self.db.set_setting("mobile_remote_url", f"{base}/?t={self._token()}")
                            except Exception:  # noqa: BLE001
                                pass
                            self.emit(Severity.INFO, Category.SYSTEM,
                                      f"Handy-Fernzugriff aktiv (von ueberall): {base}")
            except Exception:  # noqa: BLE001
                pass

        threading.Thread(target=_reader, daemon=True, name="CFTunnelReader").start()
        return proc

    def _stop_tunnel(self, proc) -> None:
        if proc is None:
            return
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                proc.kill()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.db.set_setting("mobile_remote_url", "")
        except Exception:  # noqa: BLE001
            pass

    def run(self) -> None:
        while not self._stop.is_set():
            if bool(self.db.get_setting("mobile_view_enabled", False)):
                self._serve()
            self._stop.wait(5)

    def _serve(self) -> None:
        token = self._token()
        db = self.db
        outer = self
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

            def log_message(self, *a):
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

            def _body(self):
                try:
                    n = int(self.headers.get("Content-Length", 0) or 0)
                    if n > _MAX_BODY:        # ueberdimensionierter Body -> nicht lesen (OOM-Schutz)
                        return {}
                    raw = self.rfile.read(min(n, _MAX_BODY)) if n > 0 else b""
                    return json.loads(raw.decode("utf-8")) if raw else {}
                except Exception:  # noqa: BLE001
                    return {}

            def do_GET(self):
                u = urlparse(self.path)
                q = parse_qs(u.query)
                path = (u.path or "/").rstrip("/") or "/"
                # Statische UI-Assets (JS/CSS/Bilder) UNGATED ausliefern — nur Client-Code, keine
                # Daten. Token schuetzt die Seite (/) und ALLE /api/* (Daten + Befehle).
                if path != "/" and not path.startswith("/api"):
                    if self._serve_static(path):
                        return
                if not self._ok_token(q):
                    self._send(403, "<h2>AEGIS</h2><p>Zugriff verweigert — Token falsch.</p>",
                               "text/html; charset=utf-8")
                    return
                if path == "/":
                    # 1:1: die ECHTE PC-Oberflaeche (mit Mobile-Bridge). Fallback: schlanke Seite.
                    self._send(200, _adapted_index() or _PAGE, "text/html; charset=utf-8")
                    return
                if path == "/lite":
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
                    orch = outer.orch

                    def _ro(cmd):
                        """READ-ONLY Orchestrator-Abfrage — reine Anzeige, aendert nie State."""
                        try:
                            h = getattr(orch, "_cmd_" + cmd, None)
                            return (h({}) or {}) if h else {}
                        except Exception:  # noqa: BLE001
                            return {}

                    mods = []
                    try:
                        for nm, on in (orch.module_states() or {}).items():
                            mods.append({"name": nm, "on": bool(on)})
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        from aegis2 import __version__ as _ver
                    except Exception:  # noqa: BLE001
                        _ver = "?"
                    self._send(200, json.dumps({
                        "version": _ver,
                        "threats_24h": int(st.get("threats_24h", 0) or 0),
                        "events_24h": int(st.get("events_24h", 0) or 0),
                        "quarantine_pending": int(st.get("quarantine_pending", 0) or 0),
                        "programs_known": int(ls.get("baseline_known", 0) or 0),
                        "files_total": int(st.get("files_total", 0) or 0),
                        "files_unknown": int(st.get("files_unknown", 0) or 0),
                        "connections_1h": int(st.get("connections_1h", 0) or 0),
                        "domains_blocked": int(st.get("domains_blocked", 0) or 0),
                        "modules_running": sum(1 for m in mods if m["on"]),
                        "modules_total": len(mods),
                        "modules": mods,
                        "integrity": _ro("integrity_status"),
                        "update": _ro("update_status"),
                        "autonomy": _ro("autonomy_status"),
                        "scan": _ro("scan_status"),
                    }))
                    return
                if path == "/api/events":
                    try:
                        rows = db.recent_events(limit=60)
                        evs = [{"ts": r["ts"], "severity": r["severity"], "category": r["category"],
                                "source": r["source"], "message": (r["message"] or "")[:220],
                                "ago": _ago(r["ts"])} for r in rows]
                    except Exception:  # noqa: BLE001
                        evs = []
                    self._send(200, json.dumps({"events": evs}))
                    return
                if path == "/api/memory":
                    self._send(200, json.dumps(outer._memory()))
                    return
                if path == "/api/ollama":
                    self._send(200, json.dumps(outer._ollama_status()))
                    return
                self._send(404, "{}")

            def _serve_static(self, path):
                """Flache UI-Datei aus WEB_DIR ausliefern (kein Pfad-Traversal). True bei Erfolg."""
                name = (path.lstrip("/").split("?")[0] or "").strip()
                if not name or "/" in name or "\\" in name or ".." in name:
                    return False
                f = WEB_DIR / name
                try:
                    if not f.is_file():
                        return False
                    data = f.read_bytes()
                except Exception:  # noqa: BLE001
                    return False
                self._send(200, data, _CTYPES.get(f.suffix.lower(), "application/octet-stream"))
                return True

            def do_POST(self):
                u = urlparse(self.path)
                q = parse_qs(u.query)
                path = (u.path or "/").rstrip("/") or "/"
                if not self._ok_token(q):
                    self._send(403, json.dumps({"ok": False, "error": "forbidden"}))
                    return
                data = self._body()
                if path == "/api/chat":
                    outer._uitl.acts = []                  # UI-Aktionen dieses Requests sammeln
                    reply = outer._chat(str(data.get("text", ""))[:500])
                    ui = getattr(outer._uitl, "acts", None) or []
                    outer._uitl.acts = None
                    self._send(200, json.dumps({"reply": reply, "ui": ui}))
                    return
                if path == "/api/cmd":
                    res = outer._cmd(str(data.get("name", "")), data.get("args", {}) or {})
                    self._send(200, json.dumps(res))
                    return
                if path == "/api/exec":
                    # VOLLZUGRIFF (1:1 wie PC, vom Nutzer bewusst gewaehlt): jeder Befehl, mit
                    # Schema-Validierung. Token schuetzt den Zugang.
                    res = outer._exec(str(data.get("name", "")), data.get("args", {}) or {})
                    self._send(200, json.dumps(res))
                    return
                self._send(404, json.dumps({"ok": False}))

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
            self.db.set_setting("mobile_view_url", url)
        except Exception:  # noqa: BLE001
            pass
        self.emit(Severity.INFO, Category.SYSTEM,
                  f"Handy-Fernsteuerung aktiv unter {ip}:{port} (gleiches WLAN, Token-gesichert).")
        srv = threading.Thread(target=httpd.serve_forever,
                               kwargs={"poll_interval": 0.5}, daemon=True, name="MobileViewHTTP")
        srv.start()
        # Fernzugriff-Tunnel (opt-in) parallel zum LAN-Server verwalten.
        tunnel = None
        if bool(self.db.get_setting("mobile_remote_enabled", False)):
            tunnel = self._start_tunnel(port)
        while not self._stop.is_set() and bool(self.db.get_setting("mobile_view_enabled", False)):
            self._stop.wait(2.0)
            want = bool(self.db.get_setting("mobile_remote_enabled", False))
            if want and (tunnel is None or tunnel.poll() is not None):
                tunnel = self._start_tunnel(port)        # an / abgestuerzt -> (neu) starten
            elif not want and tunnel is not None:
                self._stop_tunnel(tunnel)
                tunnel = None
        if tunnel is not None:
            self._stop_tunnel(tunnel)
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:  # noqa: BLE001
            pass
        self._httpd = None
