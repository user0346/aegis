"""Sichere Datei-Suche im Nutzer-Profil — nur Namen/Pfade, KEINE Inhalte.

Sucht ausschliesslich in den ueblichen Nutzer-Ordnern (Desktop, Downloads,
Dokumente, Bilder, Videos, Musik). Kein System, kein Program Files, kein
AppData, keine Datei-Inhalte — nur Name + Pfad + Groesse. Erfordert vorher die
explizite Bestaetigung des Nutzers (Dialog in der UI).
"""
from __future__ import annotations

import os
from pathlib import Path

_KIND_EXT = {
    "image": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic", ".svg", ".tiff"},
    "video": {".mp4", ".mov", ".mkv", ".avi", ".webm", ".flv"},
    "audio": {".mp3", ".wav", ".flac", ".m4a", ".ogg"},
    "doc":   {".pdf", ".docx", ".doc", ".txt", ".md", ".xlsx", ".pptx", ".odt"},
}

_USER_FOLDERS = ("Desktop", "Downloads", "Documents", "Dokumente",
                 "Pictures", "Bilder", "Videos", "Music", "Musik")


def _user_dirs():
    home = Path.home()
    seen, out = set(), []
    for n in _USER_FOLDERS:
        p = home / n
        try:
            if p.exists() and p.resolve() not in seen:
                seen.add(p.resolve())
                out.append(p)
        except OSError:
            pass
    return out


def search(query: str, kind: str = "", limit: int = 25, max_depth: int = 4) -> list:
    """Sucht Dateien deren Name `query` enthaelt. kind: image|video|audio|doc|''."""
    q = (query or "").strip().lower()
    if len(q) < 2:
        return []
    exts = _KIND_EXT.get(kind, set())
    hits = []
    for base in _user_dirs():
        base_s = str(base)
        try:
            for root, dirs, files in os.walk(base):
                # nicht zu tief; versteckte Ordner ueberspringen
                if root[len(base_s):].count(os.sep) > max_depth:
                    dirs[:] = []
                    continue
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for f in files:
                    fl = f.lower()
                    if q in fl and (not exts or os.path.splitext(fl)[1] in exts):
                        fp = os.path.join(root, f)
                        try:
                            sz = os.path.getsize(fp)
                        except OSError:
                            sz = 0
                        hits.append({"name": f, "path": fp, "size": sz})
                        if len(hits) >= limit:
                            return hits
        except Exception:  # noqa: BLE001
            continue
    return hits


def summarize(query: str, hits: list) -> str:
    """Kurze, sprechbare Zusammenfassung der Treffer."""
    if not hits:
        return f"Ich habe nichts gefunden, das «{query}» enthaelt."
    n = len(hits)
    first = hits[0]
    loc = os.path.dirname(first["path"])
    if n == 1:
        return f"Ein Treffer: {first['name']} in {loc}."
    return (f"{n} Treffer für «{query}». Erster: {first['name']} in {loc}. "
            f"Die ganze Liste steht im Fenster.")
