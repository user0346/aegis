"""Auto-Wissen — holt einen kompakten Fakten-Extrakt, wenn AEGIS etwas nicht aus
eigenem Wissen beantworten kann ("such selbst nach, merk es dir, wende es an").

SICHERHEIT (bewusst eng, da AEGIS ein Security-Tool ist):
  * NUR die offizielle Wikipedia-REST-API — vertrauenswuerdige, strukturierte Quelle,
    KEIN wildes Web-Scraping (das waere ein Prompt-Injection-Risiko).
  * Gated durch das «Web-Suche»-Toggle (allow_websearch).
  * Timeout + Laengenlimit; der Text wird vom Aufrufer als DATEN ans lokale LLM
    gegeben, niemals als Anweisung ausgefuehrt.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.parse
import urllib.request

_API = "https://de.wikipedia.org/api/rest_v1/page/summary/"
_UA = {"User-Agent": "AEGIS-Local-Assistant/1.0 (privacy-first endpoint guardian)"}

# Quellen, denen AEGIS ohne Rueckfrage vertraut (kuratiert; Subdomains inklusive).
# Unbekannte Domains werden NICHT automatisch gelernt -> Vorsichtsprinzip.
TRUSTED_DOMAINS = (
    "wikipedia.org", "wikimedia.org", "microsoft.com", "learn.microsoft.com",
    "cisa.gov", "nist.gov", "bsi.bund.de", "mitre.org", "owasp.org",
    "mozilla.org", "developer.mozilla.org", "python.org", "github.com",
    "stackoverflow.com", "kaspersky.com", "eset.com", "welivesecurity.com",
    "malwarebytes.com", "crowdstrike.com", "bitdefender.com", "sans.org",
    "europa.eu", "github.io", "readthedocs.io",
)


def lookup(term: str, timeout: float = 6.0) -> dict | None:
    """Wikipedia-Kurzfassung zu einem Begriff. Returns {title, extract, url} | None.

    None, wenn: leer/zu lang, Web-Suche deaktiviert, kein Treffer, Begriffsklaerung
    (mehrdeutig) oder Netzwerkfehler — der Aufrufer faellt dann auf das Modell zurueck.
    """
    term = (term or "").strip().strip("?!.,").strip()
    if not term or len(term) > 80:
        return None
    # Master-Toggle: Web-Zugriff muss in den Einstellungen erlaubt sein.
    try:
        from ..cognition.gate import capability_enabled
        if not capability_enabled("websearch"):
            return None
    except Exception:  # noqa: BLE001
        pass
    try:
        url = _API + urllib.parse.quote(term.replace(" ", "_"), safe="")
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(d, dict) or d.get("type") == "disambiguation":
        return None
    ex = (d.get("extract") or "").strip()
    if len(ex) < 20:                      # zu duenn -> lieber Modell-Wissen nutzen
        return None
    return {
        "title": (d.get("title") or term).strip(),
        "extract": ex[:600],
        "url": ((d.get("content_urls") or {}).get("desktop") or {}).get("page", ""),
    }


def _is_public_host(host: str) -> bool:
    """True, wenn der Host KEINE lokale/private/Loopback-Adresse ist (SSRF-Schutz).
    Verhindert, dass 'lerne von http://127.0.0.1/...' interne Dienste anzapft."""
    try:
        for *_rest, sockaddr in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(sockaddr[0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                return False
        return True
    except Exception:  # noqa: BLE001
        return False


def fetch_url(url: str, timeout: float = 8.0, max_bytes: int = 600_000,
              full: bool = False) -> dict | None:
    """Holt eine Webseite als bereinigten Text fuer das Lernen aus Links.
    Returns {title, text, domain, trusted, url, links} oder {error: ...} oder None.
    full=True: VOLLTEXT (statt 4000 Zeichen) + gleiche-Domain-Links sammeln (fuer fetch_site).

    SICHERHEIT: nur http(s); KEIN localhost/privates Netz (SSRF-Schutz); Groessen-
    limit + Timeout; gated durch das Web-Suche-Toggle. Der Text ist DATEN — der
    Aufrufer gibt ihn dem LLM in einem Sentinel-Block, nie als Anweisung."""
    url = (url or "").strip()
    if not url:
        return None
    try:
        from ..cognition.gate import capability_enabled
        if not capability_enabled("websearch"):
            return {"error": "websearch_off"}
    except Exception:  # noqa: BLE001
        pass
    try:
        p = urllib.parse.urlparse(url)
    except Exception:  # noqa: BLE001
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    host = p.hostname.lower()
    if not _is_public_host(host):
        return {"error": "blocked_host"}
    dom = host[4:] if host.startswith("www.") else host
    trusted = any(dom == d or dom.endswith("." + d) for d in TRUSTED_DOMAINS)
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "html" not in ctype and "text" not in ctype:
                return {"error": "not_text", "domain": dom, "trusted": trusted}
            raw = r.read(max(max_bytes, 2_000_000) if full else max_bytes)
    except Exception:  # noqa: BLE001
        return None
    html = raw.decode("utf-8", errors="ignore")
    mt = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    title = re.sub(r"\s+", " ", (mt.group(1) if mt else dom)).strip()[:120]
    # Fuer TIEFES Lernen: gleiche-Domain-Links sammeln (VOR dem Tag-Strippen). Nur derselbe Host
    # -> kein Abdriften auf fremde Domains; gedeckelt. fetch_site() crawlt damit die ganze Seite.
    links: list = []
    if full:
        for _m in re.finditer(r'<a\s[^>]*href=["\']([^"\'#]+)', html, re.I):
            try:
                _ab = urllib.parse.urljoin(url, _m.group(1).strip())
                _hp = urllib.parse.urlparse(_ab)
                if _hp.scheme in ("http", "https") and _hp.hostname:
                    _hh = _hp.hostname.lower()
                    _hh = _hh[4:] if _hh.startswith("www.") else _hh
                    if _hh == dom:
                        links.append(_ab.split("#")[0])
            except Exception:  # noqa: BLE001
                pass
        links = list(dict.fromkeys(links))[:80]
    html = re.sub(r"(?is)<(script|style|noscript|template|svg|head)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    for a, b in (("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                 ("&quot;", '"'), ("&#39;", "'")):
        text = text.replace(a, b)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) < 80:
        return {"error": "too_thin", "domain": dom, "trusted": trusted}
    return {"title": title, "text": (text if full else text[:4000]), "domain": dom,
            "trusted": trusted, "url": url, "links": links}


def fetch_site(start_url: str, max_pages: int = 10, timeout: float = 8.0) -> object:
    """Lernt eine GANZE Seite: folgt Links auf DERSELBEN Domain (Breitensuche), bis max_pages.
    Gibt eine Liste [{url, title, text}] zurueck — ODER ein {error:...}-dict, falls schon die
    Startseite scheitert. Alle Sicherheits-Gates aus fetch_url gelten pro Seite (SSRF, Toggle,
    Content-Type). Konservativ gedeckelt, damit es nicht entgleist."""
    first = fetch_url(start_url, timeout=timeout, full=True)
    if not isinstance(first, dict) or first.get("error") or not first.get("text"):
        return first if isinstance(first, dict) else None
    def _key(u: str) -> str:
        return (u or "").split("#")[0].rstrip("/")
    pages = [{"url": start_url, "title": first.get("title"), "text": first.get("text")}]
    visited = {_key(start_url)}
    queue = list(first.get("links", []))
    while queue and len(pages) < max_pages:
        u = queue.pop(0)
        if _key(u) in visited:
            continue
        visited.add(_key(u))
        r = fetch_url(u, timeout=timeout, full=True)
        if isinstance(r, dict) and not r.get("error") and r.get("text"):
            pages.append({"url": u, "title": r.get("title"), "text": r.get("text")})
            for l in r.get("links", []):
                if _key(l) not in visited:
                    queue.append(l)
    return pages
