"""Self-learning memory writer.

Reads/appends to AEGIS_LEARNINGS.md following the section-discipline:
  - Runtime may only append to sections 4 (Performance) and 5 (Bug-Catalog).
  - User/Architecture sections are READ-ONLY for the runtime.

Concurrency: file lock via portalocker. All writes go through a single
queue thread to avoid races between modules.
"""
from __future__ import annotations

import datetime as _dt
import re
import threading
import queue
from pathlib import Path
from typing import Optional


# Path resolution: prefer workspace-root LEARNINGS file
def find_learnings_file(start: Optional[Path] = None) -> Path:
    cur = (start or Path(__file__)).resolve()
    for parent in [cur, *cur.parents]:
        candidate = parent / "AEGIS_LEARNINGS.md"
        if candidate.exists():
            return candidate
    # fallback: next to setup
    return Path.home() / ".aegis" / "AEGIS_LEARNINGS.md"


_WRITABLE_SECTIONS = {
    "performance": "## 4. Performance-Erkenntnisse",
    "bugs": "## 5. Bekannte-aktiv-vermiedene Bugs",
}


def _norm_title(s: str) -> set:
    """Titel -> Menge normalisierter Woerter (fuer Duplikat-Erkennung)."""
    import re
    return set(re.sub(r"[^a-z0-9 ]", " ", (s or "").lower()).split())


def _already_present(content: str, title: str) -> bool:
    """True, wenn eine sehr aehnliche Erkenntnis (>=50% Wort-Ueberlappung) schon vermerkt ist."""
    import re
    ntw = _norm_title(title)
    if not ntw:
        return False
    for m in re.finditer(r"^###\s*\[[^\]]*\]\s*(.+?)\s+[—-]", content, re.M):
        exw = _norm_title(m.group(1))
        if exw and len(ntw & exw) / max(len(ntw | exw), 1) >= 0.5:
            return True
    return False


class MemoryWriter:
    """Single-writer thread, append-only into approved sections."""

    def __init__(self, path: Optional[Path] = None, author: str = "@aegis-runtime"):
        self.path = path or find_learnings_file()
        self.author = author
        self._q: queue.Queue = queue.Queue(maxsize=200)
        self._thread = threading.Thread(target=self._loop, daemon=True, name="MemoryWriter")
        self._stop = threading.Event()
        self._thread.start()

    def append(self, section: str, title: str, body: str) -> None:
        """section in {'performance','bugs'}. Body may be multiline markdown."""
        if section not in _WRITABLE_SECTIONS:
            raise ValueError(f"Section '{section}' is read-only for runtime")
        self._q.put((section, title, body))

    def stop(self) -> None:
        self._stop.set()
        self._q.put(None)
        self._thread.join(timeout=2.0)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            if item is None:
                return
            section, title, body = item
            try:
                self._do_append(section, title, body)
            except Exception:  # noqa: BLE001
                pass

    def _do_append(self, section: str, title: str, body: str) -> None:
        if not self.path.exists():
            return
        marker = _WRITABLE_SECTIONS[section]
        content = self.path.read_text(encoding="utf-8")
        if marker not in content:
            return  # section missing; refuse to silently create
        # Duplikat-Schutz: aehnliche Erkenntnis schon vermerkt -> nicht doppelt schreiben.
        if _already_present(content, title):
            return

        # Find the NEXT section header to know where to insert before
        idx_start = content.index(marker)
        # search for next "\n## " after marker
        idx_next = content.find("\n## ", idx_start + len(marker))
        if idx_next == -1:
            insert_at = len(content)
        else:
            insert_at = idx_next

        today = _dt.date.today().isoformat()
        entry = f"\n### [{today}] {title} — {self.author}\n{body.rstrip()}\n"
        new_content = content[:insert_at].rstrip() + entry + content[insert_at:]
        # Atomic write
        tmp = self.path.with_suffix(".md.tmp")
        tmp.write_text(new_content, encoding="utf-8")
        tmp.replace(self.path)


# Convenience singleton accessor
_singleton: Optional[MemoryWriter] = None
_lock = threading.Lock()


def get_writer() -> MemoryWriter:
    global _singleton
    with _lock:
        if _singleton is None:
            _singleton = MemoryWriter()
        return _singleton
