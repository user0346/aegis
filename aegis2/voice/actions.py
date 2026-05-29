"""Action router — dispatches classified intents onto actual side-effects."""
from __future__ import annotations

import subprocess
import urllib.parse
import webbrowser
from typing import Callable, Optional


# Known UI-target aliases (translated to tab names)
TAB_ALIASES = {
    "dashboard": "dashboard", "übersicht": "dashboard",
    "threats": "threats", "bedrohungen": "threats", "events": "threats",
    "quarantine": "quarantine", "quarantäne": "quarantine",
    "network": "network", "netzwerk": "network",
    "voice": "voice", "sprache": "voice",
    "settings": "settings", "einstellungen": "settings",
}


class ActionRouter:
    """Routes intent dicts to actions. UI-callback receives display-feedback."""

    def __init__(self, ui_cmd: Optional[Callable[[dict], None]] = None,
                 service_cmd: Optional[Callable[[dict], None]] = None):
        self.ui_cmd = ui_cmd or (lambda _: None)
        self.service_cmd = service_cmd or (lambda _: None)

    def dispatch(self, intent: dict) -> dict:
        name = intent.get("intent", "unknown")
        args = intent.get("args", {})
        handler = getattr(self, f"_do_{name}", self._do_unknown)
        try:
            return handler(args)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "msg": f"{type(e).__name__}: {e}"}

    def _do_status(self, args) -> dict:
        self.service_cmd({"name": "stats"})
        return {"ok": True, "msg": "Status angefragt"}

    def _do_pause(self, args) -> dict:
        minutes = 5
        self.service_cmd({"name": "monitor.pause", "args": {"minutes": minutes}})
        return {"ok": True, "msg": f"Pause für {minutes} Minuten"}

    def _do_open(self, args) -> dict:
        target = (args.get("target") or "").lower()
        tab = TAB_ALIASES.get(target)
        if tab:
            self.ui_cmd({"action": "switch_tab", "tab": tab})
            return {"ok": True, "msg": f"Öffne {tab}"}
        # Try to open as application
        try:
            subprocess.Popen(["cmd", "/c", "start", "", target], shell=False)
            return {"ok": True, "msg": f"Starte {target}"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "msg": f"Konnte nicht öffnen: {e}"}

    def _do_search(self, args) -> dict:
        q = (args.get("query") or "").strip()
        if not q:
            return {"ok": False, "msg": "Was soll ich suchen?"}
        url = "https://www.google.com/search?q=" + urllib.parse.quote(q)
        webbrowser.open(url, new=2)
        return {"ok": True, "msg": f"Suche: {q}"}

    def _do_threats(self, args) -> dict:
        self.ui_cmd({"action": "switch_tab", "tab": "threats"})
        return {"ok": True, "msg": "Threats-Tab geöffnet"}

    def _do_close(self, args) -> dict:
        self.ui_cmd({"action": "hide_window"})
        return {"ok": True, "msg": "Fenster versteckt"}

    def _do_query(self, args) -> dict:
        # Phase-3.5: forward to Claude API for natural-language answer.
        # For now: feedback echo.
        return {"ok": True, "msg": "Anfrage erkannt (LLM-Answer kommt in Phase 3.5)",
                "echo": args.get("text", "")}

    def _do_unknown(self, args) -> dict:
        return {"ok": False, "msg": "Nicht verstanden."}
