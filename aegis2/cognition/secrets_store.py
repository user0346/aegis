"""Secrets store — DPAPI-encrypted at rest, never logged, never sent over IPC.

Uses Windows DPAPI (CryptProtectData) keyed to the current user. Secrets are
unreadable to other user accounts on the same machine. Falls back to an
in-memory store on non-Windows (dev only).

API:
    set_secret(key, value)
    get_secret(key) -> value | None
    delete_secret(key)
    list_keys() -> list of key names (NEVER the values)
"""
from __future__ import annotations

import base64
import json
import os
import sys
import threading
from pathlib import Path
from typing import Optional


SECRETS_PATH = Path.home() / ".aegis" / "secrets.bin"
_LOCK = threading.Lock()
_MEM_FALLBACK: dict[str, str] = {}


# ---------------- Windows DPAPI ----------------
def _dpapi_encrypt(plaintext: bytes) -> bytes:
    """Wrap CryptProtectData(CRYPTPROTECT_LOCAL_MACHINE=0 -> user-scope)."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_blob = DATA_BLOB(len(plaintext), ctypes.cast(
        ctypes.c_char_p(plaintext), ctypes.POINTER(ctypes.c_char)))
    out_blob = DATA_BLOB()

    # CRYPTPROTECT_UI_FORBIDDEN=0x1, no description, no entropy
    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob), None, None, None, None, 0x1, ctypes.byref(out_blob)
    ):
        raise OSError("CryptProtectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_decrypt(blob: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_blob = DATA_BLOB(len(blob), ctypes.cast(
        ctypes.c_char_p(blob), ctypes.POINTER(ctypes.c_char)))
    out_blob = DATA_BLOB()

    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), None, None, None, None, 0x1, ctypes.byref(out_blob)
    ):
        raise OSError("CryptUnprotectData failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


# ---------------- file format ----------------
def _load_store() -> dict:
    if sys.platform != "win32":
        return dict(_MEM_FALLBACK)
    if not SECRETS_PATH.exists():
        return {}
    try:
        ct = SECRETS_PATH.read_bytes()
        if len(ct) < 16:
            return {}
        pt = _dpapi_decrypt(ct)
        return json.loads(pt.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _save_store(d: dict) -> None:
    if sys.platform != "win32":
        _MEM_FALLBACK.clear()
        _MEM_FALLBACK.update(d)
        return
    SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(d, ensure_ascii=False).encode("utf-8")
    ct = _dpapi_encrypt(raw)
    tmp = SECRETS_PATH.with_suffix(".bin.tmp")
    tmp.write_bytes(ct)
    tmp.replace(SECRETS_PATH)
    try:
        # restrict ACL to current user
        os.chmod(SECRETS_PATH, 0o600)
    except Exception:  # noqa: BLE001
        pass


# ---------------- public API ----------------
def set_secret(key: str, value: str) -> None:
    if not key or value is None:
        return
    with _LOCK:
        d = _load_store()
        if value == "":
            d.pop(key, None)
        else:
            d[key] = value
        _save_store(d)


def get_secret(key: str) -> Optional[str]:
    with _LOCK:
        return _load_store().get(key)


def delete_secret(key: str) -> None:
    with _LOCK:
        d = _load_store()
        if key in d:
            d.pop(key)
            _save_store(d)


def list_keys() -> list[str]:
    """Return ONLY key names — never values, ever."""
    with _LOCK:
        return sorted(_load_store().keys())
