"""Spotify OAuth 2.0 Authorization-Code-Flow mit PKCE (public client, KEIN Secret —
darum repo-safe). Erlaubt AEGIS, den laufenden Titel in die Spotify-Lieblingssongs
(„Liked Songs") zu speichern.

Tokens liegen ausschliesslich lokal in der DB (~/.aegis, gitignored) — nichts wird
ins Repo geschrieben. Der Nutzer braucht EINMALIG eine eigene, kostenlose Spotify-App
(developer.spotify.com) -> Client-ID + Redirect-URI. PKCE braucht KEIN Client-Secret.

Reiner Standard-lib-Code (urllib + http.server), keine Zusatz-Abhaengigkeit.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

AUTH_URL = "https://accounts.spotify.com/authorize"
TOKEN_URL = "https://accounts.spotify.com/api/token"
API = "https://api.spotify.com/v1"
# Nur was wir wirklich brauchen: Likes schreiben/lesen + laufenden Titel sehen.
SCOPES = "user-library-modify user-library-read user-read-currently-playing"
REDIRECT_PORT = 8888
REDIRECT_URI = f"http://127.0.0.1:{REDIRECT_PORT}/callback"


def _post_form(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def pkce_pair():
    """(code_verifier, code_challenge) nach RFC 7636 (S256)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def auth_url(client_id: str, state: str, challenge: str) -> str:
    return AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": client_id, "response_type": "code", "redirect_uri": REDIRECT_URI,
        "code_challenge_method": "S256", "code_challenge": challenge,
        "scope": SCOPES, "state": state,
    })


def exchange_code(client_id: str, code: str, verifier: str) -> dict:
    return _post_form(TOKEN_URL, {
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI,
        "client_id": client_id, "code_verifier": verifier,
    })


def refresh(client_id: str, refresh_token: str) -> dict:
    return _post_form(TOKEN_URL, {
        "grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id,
    })


def _api_get(token: str, path: str, params: dict | None = None) -> dict:
    url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def search_track_id(token: str, title: str, artist: str) -> str | None:
    """Beste Treffer-ID fuer Titel(+Interpret) — None, wenn nichts gefunden."""
    q = ("track:" + title) + ((" artist:" + artist) if artist else "")
    try:
        d = _api_get(token, "/search", {"q": q, "type": "track", "limit": 1})
        items = (d.get("tracks") or {}).get("items") or []
        return items[0].get("id") if items else None
    except Exception:  # noqa: BLE001
        return None


def like_track(token: str, track_id: str) -> bool:
    """Titel in „Liked Songs" speichern (PUT /me/tracks?ids=). True bei Erfolg."""
    req = urllib.request.Request(
        API + "/me/tracks?ids=" + urllib.parse.quote(track_id), method="PUT",
        headers={"Authorization": "Bearer " + token, "Content-Length": "0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return 200 <= r.status < 300
    except Exception:  # noqa: BLE001
        return False


def run_callback(expect_state: str, on_code, timeout: int = 300) -> None:
    """Kurzlebiger lokaler Server auf REDIRECT_PORT: faengt den OAuth-Redirect ab, prueft den
    state (CSRF), ruft on_code(code|None) und zeigt eine Erfolgs-/Fehlerseite. Blockiert bis
    Callback oder Timeout — IN EINEM DAEMON-THREAD aufrufen."""
    done = {"v": False}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # kein Log-Spam
            pass

        def do_GET(self):
            u = urlparse(self.path)
            if u.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return
            q = parse_qs(u.query)
            code = (q.get("code") or [None])[0]
            state = (q.get("state") or [None])[0]
            ok = bool(code) and state == expect_state
            html = ("<!doctype html><meta charset=utf-8><body style='font-family:Segoe UI;"
                    "background:#0b0f15;color:#cde;text-align:center;padding:60px'>"
                    "<h2 style='color:#1DB954'>AEGIS &times; Spotify</h2><p>" +
                    ("Verbunden! Du kannst dieses Fenster schlie&szlig;en."
                     if ok else "Autorisierung fehlgeschlagen oder abgebrochen.") +
                    "</p></body>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            done["v"] = True
            try:
                on_code(code if ok else None)
            except Exception:  # noqa: BLE001
                pass

    try:
        srv = ThreadingHTTPServer(("127.0.0.1", REDIRECT_PORT), H)
    except Exception:  # noqa: BLE001
        try:
            on_code(None)
        except Exception:  # noqa: BLE001
            pass
        return
    srv.timeout = 1
    start = time.time()
    while not done["v"] and time.time() - start < timeout:
        srv.handle_request()
    try:
        srv.server_close()
    except Exception:  # noqa: BLE001
        pass
