"""Capability-Gate — Master-Schalter fuer elevated/autonome Aktionen.

Der Nutzer entscheidet in den Einstellungen, WELCHE Faehigkeiten das System
ueberhaupt besitzen darf. Dieses Modul ist die EINE Stelle, die das prueft,
bevor eine elevated Aktion ausgefuehrt wird ODER ein Consent-Request entsteht.

  Toggle aus -> Faehigkeit existiert nicht. Aktion wird hart abgelehnt.
  Toggle an  -> Faehigkeit erlaubt; autonome Nutzung laeuft zusaetzlich
                durch Consent-Queue + Autonomy-Level.

Direkte Nutzer-Befehle (z.B. Voice "suche X") brauchen KEIN Consent (der Nutzer
hat ja gerade befohlen) — aber das Master-Toggle gilt trotzdem.
Autonome Aktionen (Brain/Reflektor) brauchen Toggle AN *und* Consent/Autonomy.
"""
from __future__ import annotations


# capability -> (settings-key, default)
_CAP = {
    "websearch": ("allow_websearch", False),
    "shell":     ("allow_shell", False),
    "learning":  ("allow_learning", True),
}

# consent-action -> capability
_ACTION_CAP = {
    "web_search":     "websearch",
    "open_url":       "websearch",
    "shell_exec":     "shell",
    "learning_write": "learning",
}

_CAP_NAMES = {
    "websearch": "Web-Suche",
    "shell": "Shell-Befehle",
    "learning": "Self-Learning",
}


def _get_setting(key: str, default):
    try:
        from ..shared.db import get_db
        return get_db().get_setting(key, default)
    except Exception:  # noqa: BLE001
        return default


def capability_enabled(capability: str) -> bool:
    """True, wenn der Nutzer diese Faehigkeit in den Einstellungen erlaubt hat."""
    key, default = _CAP.get(capability, (None, False))
    if key is None:
        return False
    return bool(_get_setting(key, default))


def action_allowed(action: str) -> bool:
    """True, wenn die konkrete consent-action erlaubt ist (Master-Toggle an).

    Nicht-gated Aktionen (notification, system_info_read, ...) sind immer frei.
    """
    cap = _ACTION_CAP.get(action)
    if cap is None:
        return True
    return capability_enabled(cap)


def reason_blocked(action_or_cap: str) -> str:
    """Menschlich lesbarer Hinweis, warum eine Aktion blockiert ist."""
    cap = _ACTION_CAP.get(action_or_cap, action_or_cap)
    name = _CAP_NAMES.get(cap)
    if name:
        return f"{name} ist in den Einstellungen deaktiviert. Du kannst sie unter Einstellungen → Autonome Aktionen freischalten."
    return "Diese Aktion ist in den Einstellungen deaktiviert."
