"""
AEGIS Threat-Intelligence Layer.

- IP-Logger / URL-Shortener-Detection (Discord-Anti-Dox)
- VirusTotal-API-Lookup fuer Hashes (optional, mit API-Key)
- Suspicious-Process-Pattern-Matching
- Heuristik-Scoring fuer EXEs (Entropy, Pfad, Eltern-Prozess)
"""

import re
import math
import hashlib
import time
import urllib.parse
import urllib.request
import json
import threading
from pathlib import Path
from typing import Optional


# =============================================================================
#  IP-Logger / URL-Shortener-Blacklist
#  Wenn jemand dir sowas in Discord/Telegram schickt, ist es fast immer
#  ein Versuch deine IP zu pullen (3rd-party Service der den Klick loggt).
# =============================================================================

IP_LOGGER_DOMAINS = {
    # Direkte IP-Logger
    "grabify.link", "grabify.com", "iplogger.org", "iplogger.com",
    "iplogger.info", "iplogger.ru", "iplogger.co", "iplogger.cn",
    "blasze.com", "blasze.tk", "ipgrabber.ru",
    "yip.su", "2no.co", "iplis.ru",
    "ipgraber.com", "ipgraber.ru", "ipgraber.net",
    # Bekannte IP-Pull-as-a-Service
    "ip-logger.com", "ip-logger.net", "ip-logger.ru",
    "ip-track.ru", "iptrack.ru", "ip-tracker.org",
    # Discord-spezifisch verwendete URL-Shortener mit Logging
    "shorturl.at", "tinyurl.com", "bit.ly", "rebrand.ly",
    "cutt.ly", "rb.gy", "shrtco.de", "is.gd", "v.gd",
    # NEW: 2024-2025 emerging trackers
    "ipl.ws", "ip-api.cc", "geoiplookup.io",
    # Anonymous file hosts often used for malware delivery
    "anonfiles.com", "bayfiles.com", "wormhole.app",
}

# Domain-Whitelist (false-positive Pruefung) - vertrauenswuerdige Shortener
URL_SHORTENER_TRUSTED = {
    # Wir blocken nicht alle Shortener generell - manche sind legit
    # Diese sind die SAUBEREN (wenig phishing-Aufkommen):
    "youtu.be", "git.io", "amzn.to", "spoti.fi", "wp.me",
}

# Discord IP-puller obfuscation tricks
SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"\bgrabify[._]"),
    re.compile(r"\biplogger[._]"),
    re.compile(r"\bip[_-]?log(ger)?\b"),
    re.compile(r"\b2no\.co\b"),
    # Verdächtige Subdomain-Tricks: discord.com.suspicious.tld
    re.compile(r"discord(?:app)?\.com\.[a-z0-9-]+\.[a-z]{2,}", re.IGNORECASE),
    re.compile(r"steamcommunity\.com\.[a-z0-9-]+", re.IGNORECASE),
    # Punycode-Spoofing
    re.compile(r"xn--[a-z0-9-]+", re.IGNORECASE),
    # IP-Adressen als URL (selten legitim in Messages)
    re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)"),
]


def extract_urls(text: str) -> list[str]:
    """Findet alle URLs in einem Text-Blob."""
    url_re = re.compile(
        r"https?://[^\s<>\"'`{}|\\^]+",
        re.IGNORECASE
    )
    return [u.rstrip(".,;:!?)]}") for u in url_re.findall(text)]


def classify_url(url: str) -> dict:
    """
    Klassifiziert eine URL nach Bedrohungs-Wahrscheinlichkeit.

    Returns:
        {
            "verdict": "clean" | "suspicious" | "malicious",
            "reasons": [list of reason strings],
            "score": 0-100 (higher = more suspicious),
            "domain": extracted hostname
        }
    """
    reasons = []
    score = 0
    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
    except (ValueError, AttributeError):
        return {"verdict": "malicious", "reasons": ["unparseable URL"],
                "score": 100, "domain": ""}

    if not host:
        return {"verdict": "suspicious", "reasons": ["no hostname"],
                "score": 50, "domain": ""}

    # Direkter Treffer auf IP-Logger-Liste = sehr hoch
    if host in IP_LOGGER_DOMAINS:
        reasons.append(f"Bekannter IP-Logger / Tracker-Service ({host})")
        score = 95

    # Subdomain einer IP-Logger-Liste
    for bad in IP_LOGGER_DOMAINS:
        if host.endswith("." + bad):
            reasons.append(f"Subdomain eines bekannten IP-Loggers ({bad})")
            score = max(score, 85)
            break

    # Pattern-Match
    for pat in SUSPICIOUS_URL_PATTERNS:
        if pat.search(url):
            reasons.append(f"Verdaechtiges URL-Pattern: {pat.pattern[:50]}")
            score = max(score, 70)
            break

    # IP-Adresse als Host (kein DNS, oft Phishing)
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
        reasons.append("URL nutzt nackte IP statt Domain (oft Phishing)")
        score = max(score, 60)

    # Punycode
    if "xn--" in host:
        reasons.append("Punycode-Hostname (Homograph-Spoofing moeglich)")
        score = max(score, 65)

    # Sehr viele Subdomains (z.B. login.amazon.com.scam.tk)
    if host.count(".") >= 4:
        reasons.append(f"Auffaellig viele Subdomain-Ebenen ({host.count('.')+1})")
        score = max(score, 50)

    # Verdict
    if score >= 80:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    else:
        verdict = "clean"

    if not reasons:
        reasons = ["Keine bekannten Bedrohungsindikatoren"]

    return {
        "verdict": verdict,
        "reasons": reasons,
        "score": score,
        "domain": host
    }


# =============================================================================
#  File-Hash-Heuristik (vor VT-Lookup)
#  Schaut auf Entropy, Pfad, Dateiendung-Mismatch, etc.
# =============================================================================

SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"\\Temp\\", re.IGNORECASE),
    re.compile(r"\\AppData\\Local\\Temp\\", re.IGNORECASE),
    re.compile(r"\\Downloads\\.+\\(?:.+\.(?:scr|pif|cmd|bat|vbs|ps1)\b)", re.IGNORECASE),
    re.compile(r"\\Users\\Public\\", re.IGNORECASE),
]

SUSPICIOUS_DOUBLE_EXT = [
    ".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe", ".png.exe",
    ".mp4.exe", ".mp3.exe", ".zip.exe", ".rar.exe", ".txt.exe",
    ".pdf.scr", ".jpg.scr", ".doc.scr",
    ".pdf.bat", ".doc.bat", ".jpg.bat",
    ".pdf.vbs", ".doc.vbs",
    ".pdf.ps1", ".doc.ps1",
    ".pdf.pif", ".jpg.pif",
    ".pdf.com", ".jpg.com",
]

# Direkt ausfuehrbare Datei-Endungen.
# WICHTIG: .lnk (Windows-Shortcut) NICHT hier - eine .lnk ist nur ein Verweis,
# kann selbst nichts ausfuehren. Quarantaene von .lnk = False-Positive.
# .dll auch nicht - DLLs werden nicht direkt geklickt-gestartet (rundll32 etc.).
EXECUTABLE_EXTS = {
    ".exe", ".msi", ".scr", ".bat", ".cmd", ".com",
    ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".pif",
    ".cpl", ".reg", ".jar", ".wsf", ".msc", ".inf",
}


def file_sha256(path: Path, chunk: int = 65536) -> Optional[str]:
    """SHA-256 einer Datei. None wenn nicht lesbar."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                data = f.read(chunk)
                if not data:
                    break
                h.update(data)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def file_entropy(path: Path, sample: int = 8192) -> float:
    """Shannon-Entropy der ersten N Bytes. >7.9 = stark packed/encrypted."""
    try:
        with open(path, "rb") as f:
            data = f.read(sample)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        ent = 0.0
        for c in freq:
            if c > 0:
                p = c / length
                ent -= p * math.log2(p)
        return ent
    except (OSError, PermissionError):
        return 0.0


def classify_file(path: Path, sha256_hash: Optional[str] = None) -> dict:
    """
    Heuristische Klassifikation einer Datei.
    Returns ähnlich wie classify_url.
    """
    reasons = []
    score = 0
    p = Path(path)
    name = p.name.lower()
    ext = p.suffix.lower()

    if not p.exists():
        return {"verdict": "unknown", "reasons": ["file not found"],
                "score": 0, "is_executable": False}

    is_exec = ext in EXECUTABLE_EXTS

    # Pfad-Pattern
    for pat in SUSPICIOUS_PATH_PATTERNS:
        if pat.search(str(p)):
            reasons.append(f"Datei in verdaechtigem Pfad ({pat.pattern})")
            score = max(score, 50)
            break

    # Double extension
    for dx in SUSPICIOUS_DOUBLE_EXT:
        if name.endswith(dx):
            reasons.append(f"Double-Extension {dx} - klassischer Maskierungs-Trick")
            score = max(score, 90)
            break

    # Entropy (nur fuer kleinere Dateien, sonst sample-bias)
    try:
        size = p.stat().st_size
    except OSError:
        size = 0
    if is_exec and 1024 < size < 50 * 1024 * 1024:
        ent = file_entropy(p)
        if ent > 7.95:
            reasons.append(f"Sehr hohe Entropy {ent:.2f} (packed/encrypted)")
            score = max(score, 55)

    # Hash-basierte Bekanntheit (nur dann sinnvoll wenn DB-bekannt)
    if is_exec and not sha256_hash:
        sha256_hash = file_sha256(p)

    if score >= 80:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    elif is_exec:
        verdict = "unknown"  # executable but no flags -> unknown until validated
    else:
        verdict = "clean"

    if not reasons:
        reasons = ["Keine offensichtlichen Indikatoren"]

    return {
        "verdict": verdict,
        "reasons": reasons,
        "score": score,
        "is_executable": is_exec,
        "sha256": sha256_hash or "",
        "size": size,
    }


# =============================================================================
#  Process-Pattern-Heuristik
# =============================================================================

# Bekannte LEGITIME rundll32-Targets - werden NICHT geflagged.
# rundll32.exe shell32.dll,Control_RunDLL ist 100% normales Windows-Verhalten.
LEGIT_RUNDLL32_TARGETS = {
    "shell32.dll", "user32.dll", "advapi32.dll", "ntdll.dll", "kernel32.dll",
    "syssetup.dll", "setupapi.dll", "printui.dll", "mshtml.dll",
    "ieframe.dll", "iesetup.dll", "iernonce.dll", "iedkcs32.dll",
    "comctl32.dll", "ole32.dll", "url.dll", "shdocvw.dll",
    "wininet.dll", "wlanapi.dll", "winipsec.dll", "mscoree.dll",
    "msi.dll", "wbemupgd.dll", "themecpl.dll", "actioncenter.dll",
    "tabletinputservice.dll", "windowscodecsraw.dll", "imageres.dll",
    "fontext.dll", "dfshim.dll", "twinui.dll", "twinui.appcore.dll",
    "twinapi.dll", "wuapi.dll", "wuaueng.dll", "policymanager.dll",
    "input.dll", "duser.dll", "winhttp.dll", "winmm.dll",
    "shimgvw.dll", "appwiz.cpl", "main.cpl", "inetcpl.cpl",
    "ncpa.cpl", "sysdm.cpl", "desk.cpl", "powercfg.cpl",
    "mmsys.cpl", "intl.cpl", "timedate.cpl", "firewall.cpl",
    "bthprops.cpl", "hdwwiz.cpl", "wscui.cpl",
}


def _check_rundll32(cmdline: str) -> tuple[bool, str]:
    """
    Klassifiziert rundll32-Aufrufe getrennt - mit Whitelist.
    Returns (is_suspicious, reason_msg).

    Normal-Beispiele die NICHT triggern:
        rundll32.exe shell32.dll,Control_RunDLL
        rundll32.exe user32.dll,LockWorkStation
        rundll32.exe C:\\Windows\\System32\\imageres.dll,-5358
    Echte Bad-Patterns die triggern:
        rundll32.exe C:\\Users\\x\\AppData\\Local\\Temp\\evil.dll,RunMe
        rundll32.exe javascript:foo
    """
    cmd_lower = cmdline.lower()
    if "rundll32" not in cmd_lower:
        return False, ""

    # Script-protocol = sehr verdaechtig
    if re.search(r"rundll32(?:\.exe)?\s+(?:javascript:|vbscript:|data:)", cmd_lower):
        return True, "rundll32 mit Script-Protocol-Argument"

    # DLL-Pfad extrahieren
    m = re.search(r"rundll32(?:\.exe)?\s+\"?([^,\"]+?)(?:\"|,)", cmd_lower)
    if not m:
        return False, ""
    dll_path = m.group(1).strip().strip('"')

    # In verdaechtigem Pfad?
    for sus in ("\\appdata\\local\\temp\\", "\\appdata\\roaming\\temp\\",
                "\\windows\\temp\\", "\\users\\public\\",
                "\\programdata\\temp\\", "\\$recycle.bin\\"):
        if sus in dll_path:
            return True, f"rundll32 laedt DLL aus '{sus}'"

    # Whitelist-Check: System-Pfad ODER bekannter Name = clean
    dll_name = dll_path.split("\\")[-1] if "\\" in dll_path else dll_path
    in_system_path = any(dll_path.startswith(p) for p in (
        "c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
        "c:\\windows\\winsxs\\", "c:\\windows\\servicing\\",
        "c:\\windows\\immersivecontrolpanel\\",
        "c:\\program files\\", "c:\\program files (x86)\\",
    ))
    if in_system_path or dll_name in LEGIT_RUNDLL32_TARGETS:
        return False, ""

    # Unbekannte DLL aus User-Profile-Pfad ist mild verdaechtig
    if "\\users\\" in dll_path:
        return True, f"rundll32 mit DLL aus User-Profile ({dll_name})"

    return False, ""


SUSPICIOUS_CMD_PATTERNS = [
    # HINWEIS: bare -EncodedCommand wird NICHT mehr hier (=score 70/malicious) gefuehrt —
    # viele LEGITIME Tools (Entwickler-/Admin-Tools, Paketmanager) nutzen es voellig normal,
    # das fuehrte zu einer Fehlalarm-Flut. Stattdessen dekodiert _check_encoded_powershell()
    # den Befehl und stuft nur ECHTE Download/Exec-Cradles hoch ein (s. classify_process).
    # Hidden window UND bypass kombiniert = high confidence
    (re.compile(r"powershell.*-w(?:indowstyle)?\s+hidden.*-(?:exec|ep)(?:utionpolicy)?\s+bypass", re.IGNORECASE),
     "PowerShell hidden + ExecutionPolicy Bypass kombiniert"),
    (re.compile(r"powershell.*-(?:exec|ep)(?:utionpolicy)?\s+bypass.*-w(?:indowstyle)?\s+hidden", re.IGNORECASE),
     "PowerShell ExecutionPolicy Bypass + hidden kombiniert"),
    # Download-and-execute pattern
    (re.compile(r"(?:Invoke-WebRequest|iwr|wget|curl).+\|\s*(?:Invoke-Expression|iex|powershell)", re.IGNORECASE),
     "PowerShell Download+Execute-Pipe (drive-by)"),
    (re.compile(r"(?:Invoke-Expression|iex)\s*\(?\s*(?:\(?\s*)?(?:Invoke-WebRequest|iwr|new-object\s+net\.webclient).*download", re.IGNORECASE),
     "IEX downloader-pattern"),
    # CMD aus Temp
    (re.compile(r"cmd(?:\.exe)?\s+.*\\Temp\\.+\.(?:exe|bat|cmd|ps1|vbs)", re.IGNORECASE),
     "CMD startet executable aus Temp-Verzeichnis"),
    # WMIC process call create
    (re.compile(r"wmic\s+process\s+(?:call\s+)?create", re.IGNORECASE),
     "WMIC process call create (Living-off-the-land)"),
    # bitsadmin transfer
    (re.compile(r"bitsadmin\s+/?(?:transfer|create|addfile)", re.IGNORECASE),
     "bitsadmin transfer (Living-off-the-land)"),
    # certutil decode/urlcache
    (re.compile(r"certutil\s+(?:-decode|--decode|-urlcache|-f\s+-split)", re.IGNORECASE),
     "certutil decode/urlcache (Malware-Delivery-Pattern)"),
    # mshta with URL or script protocol
    (re.compile(r"mshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)", re.IGNORECASE),
     "mshta laedt remote-content (Living-off-the-land)"),
    # regsvr32 squiblydoo
    (re.compile(r"regsvr32\s+/s\s+/u\s+/i:https?://", re.IGNORECASE),
     "regsvr32 squiblydoo-pattern (Bypass-Technik)"),
    # InstallUtil als executor
    (re.compile(r"installutil(?:\.exe)?\s+.*\.exe\b", re.IGNORECASE),
     "InstallUtil als executor (Living-off-the-land)"),
]


_PS_ENC_RE = re.compile(r"-(?:enc\w*|ec)\b\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)
_PS_CRADLE_RE = re.compile(
    r"(?:iex|invoke-expression|downloadstring|downloadfile|invoke-webrequest|\biwr\b|"
    r"net\.webclient|frombase64string|start-process|reflection\.assembly|http://|https://)",
    re.IGNORECASE)


def _check_encoded_powershell(cmdline: str):
    """PowerShell -EncodedCommand bewerten OHNE pauschalen Fehlalarm. Legitime Tools
    (Entwickler-/Admin-Tools wie z.B. Code-Assistenten, Paketmanager) nutzen -EncodedCommand
    voellig normal -> nicht blind als Bedrohung werten. Erst DEKODIEREN und schauen, was der
    Befehl WIRKLICH tut:
      - dekodiert + Download/Exec-Cradle (iex, DownloadString, WebClient ...) -> echte
        Verschleierung (score 80 -> THREAT)
      - encoded, aber harmlos / nicht dekodierbar -> nur mild verdaechtig (score 45 -> WARN)
    Returns (score, reason) oder (0, '')."""
    if not cmdline or "powershell" not in cmdline.lower():
        return 0, ""
    if not re.search(r"-(?:enc\w*|ec)\b", cmdline, re.IGNORECASE):
        return 0, ""
    blob = ""
    bm = _PS_ENC_RE.search(cmdline)
    if bm:
        try:
            import base64
            blob = base64.b64decode(bm.group(1) + "===").decode("utf-16-le", errors="ignore")
        except Exception:  # noqa: BLE001
            blob = ""
    if blob and _PS_CRADLE_RE.search(blob):
        return 80, "PowerShell EncodedCommand mit Download/Exec-Cradle (dekodiert) — echte Verschleierung"
    return 45, "PowerShell EncodedCommand (verschleiert; oft auch legitime Entwickler-/Admin-Tools)"


def classify_process(name: str, cmdline: str, exe: str) -> dict:
    """Heuristische Klassifikation eines Prozesses."""
    reasons = []
    score = 0
    cmd_full = f"{name} {cmdline}"

    # rundll32 SEPARAT pruefen mit Whitelist (kein einfaches Regex)
    is_sus_rundll, sus_msg = _check_rundll32(cmd_full)
    if is_sus_rundll:
        reasons.append(sus_msg)
        score = max(score, 70)

    for pat, msg in SUSPICIOUS_CMD_PATTERNS:
        if pat.search(cmd_full):
            reasons.append(msg)
            score = max(score, 70)

    # PowerShell EncodedCommand: dekodieren + nur echte Download/Exec-Cradles hoch einstufen
    # (legitime Tools mit EncodedCommand bleiben mild verdaechtig statt THREAT -> kein Fehlalarm).
    enc_score, enc_reason = _check_encoded_powershell(cmd_full)
    if enc_reason:
        reasons.append(enc_reason)
        score = max(score, enc_score)

    # EXE aus AppData/Temp aber NICHT Windows-Update/Installer-Caches
    exe_lower = (exe or "").lower()
    for sus_path in ["\\appdata\\local\\temp\\", "\\windows\\temp\\",
                     "\\users\\public\\downloads\\",
                     "\\programdata\\temp\\"]:
        if sus_path in exe_lower:
            # Whitelist: bekannte legitime Installer-Pfade
            if any(legit in exe_lower for legit in (
                    "\\package cache\\", "\\edgewebview\\",
                    "\\setup\\setup.exe", "msiexec",
                    "windowsupdatebox", "windowssetupbox")):
                continue
            reasons.append(f"EXE laeuft aus {sus_path}")
            score = max(score, 55)
            break

    if score >= 70:
        verdict = "malicious"
    elif score >= 40:
        verdict = "suspicious"
    else:
        verdict = "clean"

    if not reasons:
        reasons = ["Keine Auffaelligkeiten"]

    return {"verdict": verdict, "reasons": reasons, "score": score}


# =============================================================================
#  VirusTotal API Integration (optional, mit API-Key)
# =============================================================================

VT_API_BASE = "https://www.virustotal.com/api/v3"

class VTRateLimiter:
    """4 requests / minute, 500 / day (Free-Tier Limit)."""
    def __init__(self):
        self.lock = threading.Lock()
        self.minute_window: list[float] = []
        self.day_window: list[float] = []

    def can_request(self) -> tuple[bool, str]:
        with self.lock:
            now = time.time()
            # cleanup
            self.minute_window = [t for t in self.minute_window if now - t < 60]
            self.day_window = [t for t in self.day_window if now - t < 86400]
            if len(self.minute_window) >= 4:
                return False, "VT-Minute-Limit (4/min)"
            if len(self.day_window) >= 500:
                return False, "VT-Daily-Limit (500/Tag)"
            return True, ""

    def record(self):
        with self.lock:
            now = time.time()
            self.minute_window.append(now)
            self.day_window.append(now)


_vt_limiter = VTRateLimiter()


def vt_lookup_hash(sha256: str, api_key: str, timeout: int = 15) -> dict:
    """
    Schlaegt einen Datei-Hash bei VirusTotal nach.
    Returns: {
        "found": bool,
        "malicious": int (count of AV-vendors flagging it),
        "suspicious": int,
        "total": int (number of vendors),
        "first_seen": str or None,
        "names": [list of known names],
        "error": str if any
    }
    """
    if not api_key:
        return {"found": False, "error": "no api key"}

    ok, reason = _vt_limiter.can_request()
    if not ok:
        return {"found": False, "error": f"rate-limited: {reason}"}

    url = f"{VT_API_BASE}/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Erst NACH erhaltener Antwort zaehlen: nur ein tatsaechlich an VT
            # gesendeter Request verbraucht das Limit. Transiente Netz-/DNS-
            # Fehler (Connection refused, Timeout, getaddrinfo) duerfen das
            # 4/min-Budget NICHT aufbrauchen.
            _vt_limiter.record()
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # Eine HTTP-Antwort (auch 404/4xx/5xx) bedeutet: der Request kam bei VT
        # an und zaehlt gegen das Limit.
        _vt_limiter.record()
        if e.code == 404:
            return {"found": False, "error": "not in VT database"}
        return {"found": False, "error": f"HTTP {e.code}"}
    except Exception as e:
        # Kein Response erhalten (URLError/Timeout/DNS) -> NICHT zaehlen.
        return {"found": False, "error": str(e)[:120]}

    try:
        attr = data["data"]["attributes"]
        stats = attr.get("last_analysis_stats", {})
        names = attr.get("names", [])[:5]
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total": sum(stats.values()) if stats else 0,
            "first_seen": attr.get("first_submission_date"),
            "names": names,
            "type": attr.get("type_description", ""),
            "reputation": attr.get("reputation", 0),
        }
    except (KeyError, TypeError) as e:
        return {"found": False, "error": f"unexpected response: {e}"}


def vt_verdict(vt_result: dict) -> str:
    """Mapping VT-Result -> AEGIS verdict."""
    if not vt_result.get("found"):
        return "unknown"
    mal = vt_result.get("malicious", 0)
    sus = vt_result.get("suspicious", 0)
    total = vt_result.get("total", 0) or 1
    ratio = (mal + sus) / total
    if mal >= 5 or ratio > 0.3:
        return "malicious"
    if mal >= 1 or sus >= 3:
        return "suspicious"
    return "clean"


# =============================================================================
#  Initial domain seeds - werden in die DB importiert beim ersten Start
# =============================================================================

INITIAL_DOMAIN_SEEDS = [
    # Bekannte IP-Logger - werden geblockt auf DNS-Ebene
    *[(d, "ip-logger") for d in IP_LOGGER_DOMAINS],
    # Tracker-Highlights (full list kommt aus StevenBlack hosts-Datei)
    ("google-analytics.com", "tracker"),
    ("googletagmanager.com", "tracker"),
    ("doubleclick.net", "tracker"),
    # facebook.com selbst blocken wir nicht (zerschiesst Login bei Drittseiten);
    # nur das tracking-CDN
    ("connect.facebook.net", "tracker"),
    ("scorecardresearch.com", "tracker"),
    ("quantserve.com", "tracker"),
    ("hotjar.com", "tracker"),
    ("mixpanel.com", "tracker"),
    ("segment.io", "tracker"),
    ("amplitude.com", "tracker"),
    # Discord-puller / phishing
    ("dlscord.com", "phishing"),
    ("dlscord.gift", "phishing"),
    ("dlscord-app.com", "phishing"),
    ("steamcommunlty.com", "phishing"),
    ("steamccmmunity.com", "phishing"),
]
