"""Encrypted Persistent Memory für gelernte Patterns + Signaturen.

Speichert namespaced Blobs unter %USERPROFILE%\\.aegis\\memory\\<ns>.bin
DPAPI-verschlüsselt (gleicher Mechanismus wie secrets_store, aber für
größere Daten und mit Versioning).

Schema pro Blob:
    {
        "version": int,        # inkrementiert pro write
        "schema_v": int,       # wenn wir das Format brechen
        "created":  ts,
        "updated":  ts,
        "data":     dict       # eigentliche Nutzdaten
    }

Anti-Duplication: bevor write, hash der serialisierten Daten. Wenn gleich
wie letzter Hash → kein write (verhindert Schreiblast und Audit-Spam).

Compaction: alle 30 Tage automatischer Rewrite (komprimiert Versionsketten).
"""
from __future__ import annotations

import hashlib
import json
import logging
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Any

from ..cognition.secrets_store import _dpapi_encrypt, _dpapi_decrypt  # type: ignore


MEMORY_DIR = Path.home() / ".aegis" / "memory"
_LOCK = threading.Lock()
_log = logging.getLogger("aegis2.encrypted_memory")


def _ns_path(namespace: str) -> Path:
    safe = "".join(c for c in namespace if c.isalnum() or c in "._-")[:64]
    return MEMORY_DIR / f"{safe}.bin"


def _now() -> float:
    return time.time()


def _hash_blob(data: dict) -> str:
    s = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(s).hexdigest()


def save(namespace: str, data: dict, schema_v: int = 1) -> bool:
    """Schreibt namespaced Daten. Returns True bei effektivem Write."""
    if not isinstance(data, dict):
        return False
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    path = _ns_path(namespace)
    with _LOCK:
        existing = _load_raw(path)
        if existing and existing.get("hash") == _hash_blob(data):
            return False    # nothing changed
        version = (existing.get("version", 0) if existing else 0) + 1
        record = {
            "version": version,
            "schema_v": schema_v,
            "created": existing.get("created", _now()) if existing else _now(),
            "updated": _now(),
            "hash": _hash_blob(data),
            "data": data,
        }
        raw = json.dumps(record, ensure_ascii=False).encode("utf-8")
        if sys.platform == "win32":
            try:
                blob = _dpapi_encrypt(raw)
            except Exception as e:  # noqa: BLE001
                # Sichtbar machen: DPAPI fehlgeschlagen -> Blob liegt UNVERSCHLUESSELT.
                # Kein stilles Degradieren mehr (Entropie/HMAC-Haertung ist separat dokumentiert).
                _log.critical("DPAPI-Verschluesselung fehlgeschlagen fuer %s — Daten werden "
                              "UNVERSCHLUESSELT gespeichert: %s", path.name, e)
                blob = b"PLAIN1\n" + raw    # marker für fallback
        else:
            blob = b"PLAIN1\n" + raw
        tmp = path.with_suffix(".bin.tmp")
        tmp.write_bytes(blob)
        tmp.replace(path)
        try:
            path.chmod(0o600)
        except Exception:  # noqa: BLE001
            pass
        return True


def _load_raw(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        blob = path.read_bytes()
    except OSError:
        return None
    if blob.startswith(b"PLAIN1\n"):
        try:
            return json.loads(blob[7:].decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None
    if sys.platform == "win32":
        try:
            raw = _dpapi_decrypt(blob)
            return json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None
    return None


def load(namespace: str) -> Optional[dict]:
    """Returns the data-dict (innerhalb des record) oder None."""
    with _LOCK:
        rec = _load_raw(_ns_path(namespace))
        if not rec:
            return None
        return rec.get("data")


def metadata(namespace: str) -> dict:
    with _LOCK:
        rec = _load_raw(_ns_path(namespace))
        if not rec:
            return {}
        return {
            "version": rec.get("version", 0),
            "schema_v": rec.get("schema_v", 0),
            "created": rec.get("created"),
            "updated": rec.get("updated"),
            "hash": rec.get("hash"),
        }


def list_namespaces() -> list[str]:
    if not MEMORY_DIR.exists():
        return []
    return sorted(p.stem for p in MEMORY_DIR.glob("*.bin"))


def delete(namespace: str) -> bool:
    with _LOCK:
        p = _ns_path(namespace)
        if not p.exists():
            return False
        try:
            p.unlink()
            return True
        except OSError:
            return False


def compact() -> int:
    """Re-write alle Namespaces. Nur wenn updated_at >= 30 Tage alt."""
    cutoff = _now() - 30 * 86400
    written = 0
    with _LOCK:
        for ns in list_namespaces():
            rec = _load_raw(_ns_path(ns))
            if not rec:
                continue
            if rec.get("updated", 0) > cutoff:
                continue
            if save(ns, rec.get("data", {}), rec.get("schema_v", 1)):
                written += 1
    return written


# ============================================================
#  Convenience: persistente Signature-DB-Sync
# ============================================================
SIGNATURE_NS = "signatures_v1"
PATTERN_LEARNING_NS = "pattern_learning_v1"
DECISION_HISTORY_NS = "decision_history_v1"


def save_signatures(signatures_data: dict) -> bool:
    return save(SIGNATURE_NS, signatures_data)


def load_signatures() -> Optional[dict]:
    return load(SIGNATURE_NS)


def append_decision(subject_type: str, subject_value: str, decision: str,
                    rationale: str = "") -> None:
    """Append-only Entscheidungshistorie für Lern-Replay."""
    existing = load(DECISION_HISTORY_NS) or {"entries": []}
    entries = existing.get("entries", [])
    entries.append({
        "ts": _now(),
        "subject_type": subject_type,
        "subject_value": subject_value[:200],
        "decision": decision,
        "rationale": rationale[:200],
    })
    # Cap bei 5000 Einträgen
    if len(entries) > 5000:
        entries = entries[-5000:]
    save(DECISION_HISTORY_NS, {"entries": entries})


def get_decisions(limit: int = 100) -> list[dict]:
    data = load(DECISION_HISTORY_NS) or {}
    entries = data.get("entries", [])
    return entries[-limit:]
