"""Consent framework — every elevated action goes through here.

Design:
  - The runtime (service-core, cognition layer, voice intent) REQUESTS an action.
  - The action sits in a pending queue with TTL.
  - The UI shows pending requests. User clicks Approve / Deny.
  - On approve, the runtime is given a one-shot signed token to execute the action.
  - On TTL expiry without decision, request is auto-denied.

What needs consent (defaults; configurable in settings):
  - web_search:<query>
  - shell_exec:<command>             (always urgent)
  - file_write:<path>
  - learning_write:<section,title>
  - claude_call:<model>              (off by default if user wants strict privacy)

What does NOT need consent (always allowed):
  - Reading observed events
  - Internal DB updates by watchers
  - Quarantine actions (already gated by classifier rules + auto-quarantine setting)
  - Tab switches in UI

Tokens:
  Approval issues a 32-byte token bound to (action_id, expires_at). The token
  is HMAC-signed with a per-install secret stored in the secrets store. The
  caller MUST present the token to execute. After one execution, the token
  is burned.
"""
from __future__ import annotations

import hmac
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from .secrets_store import get_secret, set_secret


AUDIT_PATH = Path.home() / ".aegis" / "audit.jsonl"
DEFAULT_TTL_SEC = 600           # 10 minutes
URGENT_TTL_SEC = 120

_INSTALL_SECRET_KEY = "consent_install_secret"


def _install_secret() -> bytes:
    s = get_secret(_INSTALL_SECRET_KEY)
    if not s:
        s = secrets.token_urlsafe(48)
        set_secret(_INSTALL_SECRET_KEY, s)
    return s.encode("utf-8")


def _audit(record: dict) -> None:
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass


@dataclass
class ConsentRequest:
    id: str
    action: str                    # e.g. "web_search"
    title: str                     # short user-facing title
    detail: str                    # human-readable description
    requested_by: str              # who asked: "voice", "claude", "watcher:X"
    scope: str                     # parameters; sanitised
    severity: str = "normal"       # normal | high | critical
    created_at: float = field(default_factory=time.time)
    ttl_sec: int = DEFAULT_TTL_SEC
    decision: Optional[str] = None    # approve | deny | expired
    decided_at: Optional[float] = None
    token: Optional[str] = None    # set on approve

    def expires_at(self) -> float:
        return self.created_at + self.ttl_sec

    def expires_in(self) -> float:
        return max(0.0, self.expires_at() - time.time())

    def is_expired(self) -> bool:
        return time.time() > self.expires_at()


class ConsentManager:
    """Thread-safe approval registry. Singleton per process."""

    def __init__(self):
        self._lock = threading.Lock()
        self._items: dict[str, ConsentRequest] = {}
        self._tokens: dict[str, str] = {}    # token -> action_id (one-shot)

    # ---- request side ----
    def request(self, action: str, *, title: str, detail: str = "",
                requested_by: str = "?", scope: str = "",
                severity: str = "normal", ttl_sec: Optional[int] = None) -> str:
        if severity in ("high", "critical") and ttl_sec is None:
            ttl_sec = URGENT_TTL_SEC
        cr = ConsentRequest(
            id=secrets.token_hex(8),
            action=action, title=title, detail=detail,
            requested_by=requested_by, scope=scope,
            severity=severity,
            ttl_sec=ttl_sec or DEFAULT_TTL_SEC,
        )
        with self._lock:
            self._items[cr.id] = cr
        _audit({"event": "request", "ts": cr.created_at, "id": cr.id,
                "action": cr.action, "by": cr.requested_by, "scope": cr.scope})

        # ---- Autonomy: auto-approve wenn Owner-Toggle das erlaubt ----
        try:
            from .autonomy import get_autonomy
            from .gate import action_allowed
            ok, reason = get_autonomy().can_auto_approve(action)
            # Master-Toggle UND-verknuepfen: ist die Capability vom Owner abgeschaltet,
            # NIE auto-approven (der Request bleibt manuell entscheidbar).
            if ok and not action_allowed(action):
                ok, reason = False, "capability_disabled"
            if ok:
                token = self.decide(cr.id, "approve")
                _audit({"event": "auto_approved", "id": cr.id,
                        "action": action, "by": "autonomy", "reason": reason})
        except Exception:  # noqa: BLE001
            pass

        return cr.id

    # ---- decision side ----
    def decide(self, action_id: str, decision: str) -> Optional[str]:
        """User-facing approve/deny. Returns issued token on approve, else None."""
        with self._lock:
            cr = self._items.get(action_id)
            if not cr or cr.decision:
                return None
            if cr.is_expired():
                cr.decision = "expired"
                cr.decided_at = time.time()
                _audit({"event": "expire", "ts": cr.decided_at, "id": cr.id})
                return None
            cr.decision = decision
            cr.decided_at = time.time()
            if decision == "approve":
                token = secrets.token_urlsafe(32)
                cr.token = token
                self._tokens[token] = action_id
                _audit({"event": "approve", "ts": cr.decided_at,
                        "id": cr.id, "action": cr.action, "scope": cr.scope})
                return self._sign(token)
            _audit({"event": "deny", "ts": cr.decided_at,
                    "id": cr.id, "action": cr.action})
            return None

    # ---- execution side ----
    def consume(self, signed_token: str, expected_action: str) -> bool:
        """Caller proves they were approved by presenting the signed token.

        Returns True exactly once per approved request. Burns the token.
        """
        raw = self._verify(signed_token)
        if not raw:
            return False
        with self._lock:
            action_id = self._tokens.pop(raw, None)
            if not action_id:
                return False
            cr = self._items.get(action_id)
            if not cr or cr.decision != "approve" or cr.action != expected_action:
                return False
            # burn token: remove the request from active queue
            del self._items[action_id]
        _audit({"event": "consume", "ts": time.time(), "id": action_id,
                "action": expected_action})
        return True

    # ---- listing for UI ----
    def list_pending(self) -> list[dict]:
        out = []
        with self._lock:
            for cr in list(self._items.values()):
                if cr.decision:
                    continue
                if cr.is_expired():
                    cr.decision = "expired"
                    cr.decided_at = time.time()
                    _audit({"event": "expire", "ts": cr.decided_at, "id": cr.id})
                    continue
                d = asdict(cr)
                d["expires_in_s"] = cr.expires_in()
                d.pop("token", None)     # never expose tokens
                out.append(d)
        return out

    def gc(self) -> None:
        cutoff = time.time() - 24 * 3600
        with self._lock:
            stale = [cid for cid, cr in self._items.items()
                     if (cr.decided_at or cr.created_at) < cutoff]
            for cid in stale:
                self._items.pop(cid, None)

    # ---- HMAC helpers ----
    def _sign(self, raw: str) -> str:
        sig = hmac.new(_install_secret(), raw.encode("utf-8"),
                       hashlib.sha256).hexdigest()
        return f"{raw}.{sig}"

    def _verify(self, signed: str) -> Optional[str]:
        if not signed or "." not in signed:
            return None
        raw, sig = signed.rsplit(".", 1)
        expect = hmac.new(_install_secret(), raw.encode("utf-8"),
                          hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            return None
        return raw


_singleton: Optional[ConsentManager] = None
_singleton_lock = threading.Lock()


def get_manager() -> ConsentManager:
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ConsentManager()
        return _singleton
