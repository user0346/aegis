"""Autonomy-Framework — Owner-controlled levels of self-direction.

Hard safety rails:
  - Owner-Pin (4-6 digit) wird beim ersten Toggle gesetzt. Jeder Level-Change
    danach verlangt den Pin (DPAPI-verschluesselt im secrets-store).
  - Auto/Full geht IMMER mit Session-TTL. Default 60min, max 8h.
  - Per-Action-Type Kill-Switches (z.B. shell aus, web on).
  - Blacklist HARD (nie autonom): registry edit, format/delete C:, password change,
    network config, user account changes, anti-AEGIS actions.
  - Jede autonome Aktion erzeugt Audit-Eintrag mit reason + result.
  - Wenn AEGIS einen Threat-Event mit severity >= CRITICAL sieht, faellt Autonomy
    automatisch zurueck auf SUGGEST (defensive: System koennte kompromittiert sein).
  - Notfall-Kill: Ctrl+Alt+Shift+A toggle (geplant Phase B).

Levels:
  OFF (0):     keine Aktionen, kein Lernen, nur passives Beobachten.
  OBSERVE (1): Beobachtet + analysiert + sammelt Stats. Keine Side-Effects.
  SUGGEST (2): Schlaegt Aktionen in Consent-Queue vor. User muss approven.
  AUTO (3):    Approved automatisch *whitelisted* Aktionen (siehe AUTO_ALLOWED).
               Alles andere geht in Consent.
  FULL (4):    Approved automatisch ALLES *ausser Blacklist*. Maximum-Risiko-Level.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from .secrets_store import get_secret, set_secret


# ---------- Levels ----------
LEVEL_OFF, LEVEL_OBSERVE, LEVEL_SUGGEST, LEVEL_AUTO, LEVEL_FULL = 0, 1, 2, 3, 4
LEVEL_NAMES = {0: "OFF", 1: "OBSERVE", 2: "SUGGEST", 3: "AUTO", 4: "FULL"}


# Was AUTO-Level autonom erlaubt — relativ risikoarm, reversibel, lokal.
AUTO_ALLOWED_ACTIONS = {
    "web_search",            # browser-Tab oeffnen
    "learning_write",        # MemoryWriter (mit Sektion-Discipline)
    "notification",          # Toast
    "system_info_read",      # disk, battery, uptime
    "file_organize_suggest", # nur "wuerde X tun" output
    "claude_call",           # LLM-Query
}

# Hard-Blacklist — nie auch nicht mit FULL.
NEVER_AUTONOMOUS = {
    "registry_write",
    "user_account_modify",
    "service_disable",          # darf nicht eigenen Service abschalten
    "defender_modify",          # darf nicht Defender-Settings aendern
    "firewall_disable",
    "file_delete_system",       # Files in C:\Windows, %ProgramFiles%
    "password_change",
    "network_config",
    "aegis_self_modify",        # keine Code-Aenderung an sich selbst
    "audit_log_delete",         # Audit-Log unantastbar
    "consent_bypass",
    "send_credentials",
    "launch_app",               # beliebige Programm-Ausfuehrung — nie unbeaufsichtigt auto-approven
}


AUDIT_PATH = Path.home() / ".aegis" / "audit.jsonl"
MAX_SESSION_HOURS = 8


def _audit(record: dict) -> None:
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        record["ts"] = time.time()
        record["component"] = "autonomy"
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001
        pass


# ---------- Owner-Pin ----------
def _pin_hash(pin: str) -> str:
    salt = b"aegis-autonomy-v1"
    return hashlib.sha256(salt + pin.encode("utf-8")).hexdigest()


def has_owner_pin() -> bool:
    return bool(get_secret("autonomy_pin_hash"))


def _valid_pin(pin: str) -> bool:
    """Owner-Pin/-Passwort: 4-64 druckbare Zeichen (Buchstaben, Zahlen, Symbole)."""
    return bool(pin) and 4 <= len(pin) <= 64 and pin.isprintable()


def set_owner_pin(pin: str) -> bool:
    """Setzt erstmaliges Pin/Passwort. Fail wenn schon eins da ist (use change_owner_pin)."""
    if has_owner_pin():
        return False
    if not _valid_pin(pin):
        return False
    set_secret("autonomy_pin_hash", _pin_hash(pin))
    _audit({"event": "owner_pin_set"})
    return True


def verify_owner_pin(pin: str) -> bool:
    stored = get_secret("autonomy_pin_hash")
    if not stored or not pin:
        return False
    return hmac.compare_digest(stored, _pin_hash(pin))


def change_owner_pin(old_pin: str, new_pin: str) -> bool:
    if not verify_owner_pin(old_pin):
        _audit({"event": "owner_pin_change_failed", "reason": "wrong_old_pin"})
        return False
    if not _valid_pin(new_pin):
        return False
    set_secret("autonomy_pin_hash", _pin_hash(new_pin))
    _audit({"event": "owner_pin_changed"})
    return True


# ---------- Session ----------
@dataclass
class AutonomySession:
    level: int = LEVEL_OFF
    started_at: float = 0.0
    expires_at: float = 0.0
    disabled_actions: set = field(default_factory=set)     # vom Owner deaktiviert
    enabled_actions: set = field(default_factory=set)      # zusaetzlich erlaubt
    triggered_actions: int = 0
    auto_demoted: bool = False           # True wenn Critical-Threat zurueckschaltete

    def is_active(self) -> bool:
        return self.level > LEVEL_SUGGEST and time.time() < self.expires_at

    def remaining_sec(self) -> int:
        return max(0, int(self.expires_at - time.time()))


# ---------- Manager ----------
class AutonomyManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.session = AutonomySession()
        # Lesen letzte Settings
        with self._lock:
            disabled = get_secret("autonomy_disabled_actions")
            enabled = get_secret("autonomy_enabled_actions")
            if disabled:
                try:
                    self.session.disabled_actions = set(json.loads(disabled))
                except Exception:  # noqa: BLE001
                    pass
            if enabled:
                try:
                    self.session.enabled_actions = set(json.loads(enabled))
                except Exception:  # noqa: BLE001
                    pass
            # Persistierte NIEDRIGE Stufe (OFF/OBSERVE/SUGGEST) wiederherstellen.
            # AUTO/FULL werden NIE persistiert (laufen mit TTL, Reset nach Neustart).
            try:
                pl = get_secret("autonomy_persisted_level")
                if pl not in (None, ""):
                    lv = int(pl)
                    if LEVEL_OFF <= lv <= LEVEL_SUGGEST:
                        self.session.level = lv
                else:
                    # Default beim ersten Start: SUGGEST (vorschlagen) statt OFF —
                    # damit AEGIS von sich aus reagiert und Vorschlaege in die Consent-Queue legt.
                    self.session.level = LEVEL_SUGGEST
            except Exception:  # noqa: BLE001
                pass

    def current_level(self) -> int:
        with self._lock:
            if self.session.level > LEVEL_SUGGEST and time.time() > self.session.expires_at:
                self._end_session("ttl_expired")
            return self.session.level

    def level_name(self) -> str:
        return LEVEL_NAMES.get(self.current_level(), "?")

    def status(self) -> dict:
        with self._lock:
            now = time.time()
            return {
                "level": self.session.level,
                "level_name": LEVEL_NAMES.get(self.session.level, "?"),
                "active": self.session.level > LEVEL_SUGGEST and now < self.session.expires_at,
                "remaining_sec": max(0, int(self.session.expires_at - now)),
                "triggered_actions": self.session.triggered_actions,
                "auto_demoted": self.session.auto_demoted,
                "disabled_actions": sorted(self.session.disabled_actions),
                "enabled_actions": sorted(self.session.enabled_actions),
                "has_owner_pin": has_owner_pin(),
            }

    def set_level(self, new_level: int, pin: str,
                  ttl_minutes: int = 60) -> tuple[bool, str]:
        if new_level not in LEVEL_NAMES:
            return False, "invalid level"
        if not has_owner_pin():
            return False, "owner pin not set"
        # Brute-Force-Lockout check
        from . import bruteforce
        locked, until_s = bruteforce.is_locked("autonomy_pin")
        if locked:
            return False, f"gesperrt für {int(until_s)}s (Brute-Force-Schutz)"
        if not verify_owner_pin(pin):
            r = bruteforce.record_attempt("autonomy_pin", success=False)
            _audit({"event": "set_level_denied", "reason": "wrong_pin",
                    "wanted_level": new_level, "bf": r})
            return False, r.get("msg", "wrong pin")
        bruteforce.record_attempt("autonomy_pin", success=True)
        if new_level >= LEVEL_AUTO:
            ttl_minutes = min(max(1, ttl_minutes), MAX_SESSION_HOURS * 60)
        with self._lock:
            old_level = self.session.level
            now = time.time()
            self.session.level = new_level
            self.session.started_at = now
            self.session.expires_at = now + ttl_minutes * 60 if new_level >= LEVEL_AUTO else 0
            self.session.triggered_actions = 0
            self.session.auto_demoted = False
        # Niedrige Stufen ueber Neustarts halten (UX). AUTO/FULL nie (Sicherheit/TTL).
        if new_level <= LEVEL_SUGGEST:
            try:
                set_secret("autonomy_persisted_level", str(new_level))
            except Exception:  # noqa: BLE001
                pass
        _audit({"event": "level_changed",
                "old_level": old_level, "new_level": new_level,
                "ttl_minutes": ttl_minutes})
        return True, "ok"

    def end_session(self, reason: str = "owner_stop") -> None:
        with self._lock:
            self._end_session(reason)

    def _end_session(self, reason: str) -> None:
        if self.session.level > LEVEL_SUGGEST:
            _audit({"event": "session_ended", "reason": reason,
                    "old_level": self.session.level,
                    "triggered_actions": self.session.triggered_actions})
        self.session.level = LEVEL_SUGGEST if reason == "auto_demoted" else LEVEL_OFF
        self.session.expires_at = 0
        if reason == "auto_demoted":
            self.session.auto_demoted = True

    def on_critical_threat(self, event_summary: str) -> None:
        """Bei Critical-Severity: Autonomy degraded auf SUGGEST.
        Verhindert dass kompromittiertes System AEGIS gegen den User benutzt.
        """
        with self._lock:
            if self.session.level >= LEVEL_AUTO:
                _audit({"event": "auto_demote_on_threat",
                        "old_level": self.session.level,
                        "trigger": event_summary[:160]})
                self._end_session("auto_demoted")

    def disable_action(self, action: str, pin: str) -> bool:
        if not verify_owner_pin(pin):
            return False
        with self._lock:
            self.session.disabled_actions.add(action)
            set_secret("autonomy_disabled_actions",
                       json.dumps(sorted(self.session.disabled_actions)))
        _audit({"event": "action_disabled", "action": action})
        return True

    def enable_action(self, action: str, pin: str) -> bool:
        if not verify_owner_pin(pin):
            return False
        with self._lock:
            self.session.disabled_actions.discard(action)
            self.session.enabled_actions.add(action)
            set_secret("autonomy_disabled_actions",
                       json.dumps(sorted(self.session.disabled_actions)))
            set_secret("autonomy_enabled_actions",
                       json.dumps(sorted(self.session.enabled_actions)))
        _audit({"event": "action_enabled", "action": action})
        return True

    def can_auto_approve(self, action: str) -> tuple[bool, str]:
        """Wird vom Consent-Manager beim request() aufgerufen.

        Returns (auto_approve, reason).
        """
        if action in NEVER_AUTONOMOUS:
            return False, "blacklisted"
        with self._lock:
            now = time.time()
            if self.session.level <= LEVEL_SUGGEST:
                return False, "level_suggest_or_below"
            if now >= self.session.expires_at:
                self._end_session("ttl_expired")
                return False, "session_expired"
            if action in self.session.disabled_actions:
                return False, "action_disabled_by_owner"
            if self.session.level == LEVEL_AUTO:
                if action in AUTO_ALLOWED_ACTIONS or action in self.session.enabled_actions:
                    self.session.triggered_actions += 1
                    return True, "auto_whitelist"
                return False, "not_in_auto_whitelist"
            if self.session.level == LEVEL_FULL:
                self.session.triggered_actions += 1
                return True, "full_autonomy"
        return False, "?"


_inst = None
_inst_lock = threading.Lock()

def get_autonomy():
    global _inst
    with _inst_lock:
        if _inst is None:
            _inst = AutonomyManager()
        return _inst
