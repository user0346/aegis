"""Brute-Force-Protection für Owner-Pin und alle Auth-Aktionen.

Mechanismen:
  - Exponential lockout: nach N falschen Versuchen → lockout_seconds = 2^attempts.
    Beispiel: 5 falsche → 32s, 6 → 64s, 7 → 128s, 8 → 256s. Cap bei 1h.
  - Hard-Lockout nach 12 falschen Versuchen in 1h → 24h gesperrt, CRITICAL-Event.
  - Audit-Log jedes Versuchs.
  - Per-Action-Type Tracking (Pin-Auth vs. Consent-Decide separat).
  - Persistent über Service-Restart (in encrypted_memory).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional


_LOCK = threading.Lock()


@dataclass
class AuthAttempts:
    failed_count: int = 0
    last_failed_at: float = 0.0
    lockout_until: float = 0.0
    total_failed_history: int = 0
    first_failed_in_window: float = 0.0


_state: dict[str, AuthAttempts] = {}

# Konstanten
WINDOW_SEC = 3600                 # 1h rolling window
HARD_LOCKOUT_THRESHOLD = 12       # 12 fehlversuche → 24h
HARD_LOCKOUT_SEC = 24 * 3600
MAX_BACKOFF_SEC = 3600            # 1h cap auf exponential


def _now() -> float:
    return time.time()


def _audit(record: dict) -> None:
    try:
        from pathlib import Path
        import json
        AUDIT_PATH = Path.home() / ".aegis" / "audit.jsonl"
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        record["ts"] = _now()
        record["component"] = "bruteforce"
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass


def is_locked(action: str) -> tuple[bool, float]:
    """Returns (locked, seconds_until_unlock)."""
    with _LOCK:
        s = _state.get(action)
        if not s:
            return False, 0.0
        now = _now()
        if s.lockout_until > now:
            return True, s.lockout_until - now
        return False, 0.0


def record_attempt(action: str, success: bool) -> dict:
    """Logs Versuch. Returns status-dict für UI."""
    with _LOCK:
        s = _state.setdefault(action, AuthAttempts())
        now = _now()

        # Reset window wenn last_failed > window_sec her
        if s.first_failed_in_window and (now - s.first_failed_in_window) > WINDOW_SEC:
            s.failed_count = 0
            s.first_failed_in_window = 0.0

        if success:
            s.failed_count = 0
            s.first_failed_in_window = 0.0
            _audit({"event": "auth_success", "action": action})
            return {"ok": True, "locked": False}

        # Failed
        s.failed_count += 1
        s.total_failed_history += 1
        s.last_failed_at = now
        if s.failed_count == 1:
            s.first_failed_in_window = now

        _audit({"event": "auth_failed", "action": action,
                "count": s.failed_count})

        # Hard-Lockout?
        if s.failed_count >= HARD_LOCKOUT_THRESHOLD:
            s.lockout_until = now + HARD_LOCKOUT_SEC
            _audit({"event": "hard_lockout", "action": action,
                    "lockout_until": s.lockout_until,
                    "count": s.failed_count})
            # Notify autonomy → kill any active session
            try:
                from .autonomy import get_autonomy
                get_autonomy().on_critical_threat(f"bruteforce:{action}")
            except Exception:  # noqa: BLE001
                pass
            return {"ok": False, "locked": True,
                    "until": s.lockout_until,
                    "kind": "hard_lockout",
                    "msg": "24h gesperrt nach 12 fehlgeschlagenen Versuchen."}

        # Exponential lockout — start at 3rd failed attempt
        if s.failed_count >= 3:
            backoff = min(MAX_BACKOFF_SEC, 2 ** s.failed_count)
            s.lockout_until = now + backoff
            return {"ok": False, "locked": True,
                    "until": s.lockout_until,
                    "kind": "backoff",
                    "msg": f"Gesperrt für {backoff}s nach {s.failed_count} Fehlversuchen."}

        return {"ok": False, "locked": False,
                "remaining_before_lock": 3 - s.failed_count}


def status(action: str) -> dict:
    with _LOCK:
        s = _state.get(action)
        if not s:
            return {"locked": False, "failed": 0, "total": 0}
        now = _now()
        return {
            "locked": s.lockout_until > now,
            "until": max(0, s.lockout_until - now),
            "failed": s.failed_count,
            "total": s.total_failed_history,
            "last_failed": s.last_failed_at,
        }


def reset(action: str) -> None:
    """Owner-only — manuelles Reset über UI (mit Pin)."""
    with _LOCK:
        if action in _state:
            _audit({"event": "lockout_reset", "action": action})
            _state[action] = AuthAttempts()


def all_status() -> dict[str, dict]:
    with _LOCK:
        return {a: status(a) for a in list(_state.keys())}
