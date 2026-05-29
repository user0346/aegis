"""Action executors that REQUIRE a valid consent token.

Every function takes a `consent_token` (HMAC-signed) and verifies it
via consent.consume() BEFORE executing the side effect. No bypass.
"""
from __future__ import annotations

import shutil
import subprocess
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Optional

from .consent import get_manager


# ---------- Web search (low risk) ----------
def execute_web_search(consent_token: str, query: str) -> dict:
    if not get_manager().consume(consent_token, "web_search"):
        return {"ok": False, "error": "consent missing or expired"}
    if not query or len(query) > 500:
        return {"ok": False, "error": "invalid query"}
    url = "https://duckduckgo.com/?q=" + urllib.parse.quote(query)
    try:
        webbrowser.open(url, new=2)
        return {"ok": True, "msg": f"opened search: {query}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ---------- Shell exec (HIGH risk — needs critical-severity request) ----------
# Hard whitelist: only specific binaries we ship with the project, no arbitrary commands.
_SHELL_WHITELIST = {
    "ipconfig", "netstat", "tasklist", "systeminfo", "powercfg",
    "wmic", "sc",         # status query only — handled below
}


def execute_shell(consent_token: str, command: str, args: list[str]) -> dict:
    """Whitelisted system-introspection commands only. NO arbitrary shell."""
    if not get_manager().consume(consent_token, "shell_exec"):
        return {"ok": False, "error": "consent missing or expired"}
    cmd = (command or "").lower().strip()
    if cmd not in _SHELL_WHITELIST:
        return {"ok": False, "error": f"command not in whitelist: {cmd}"}
    if cmd in {"sc"}:
        # sc only allowed read-ops: query, qc
        if not args or args[0].lower() not in {"query", "qc"}:
            return {"ok": False, "error": "sc: only query/qc allowed"}
    if cmd == "wmic":
        # wmic only allowed get-statements
        joined = " ".join(args).lower()
        if " call " in joined or " create" in joined or " delete" in joined:
            return {"ok": False, "error": "wmic: only read-ops allowed"}
    # arg sanity: short, no shell-metacharacters
    safe_args = []
    for a in args[:10]:
        if not a or len(a) > 80:
            return {"ok": False, "error": "arg invalid"}
        if any(ch in a for ch in '&|;`$<>"\\\n'):
            return {"ok": False, "error": "arg contains shell metachar"}
        safe_args.append(a)
    try:
        r = subprocess.run([cmd, *safe_args], capture_output=True, text=True,
                           timeout=10, shell=False)
        return {"ok": True, "rc": r.returncode,
                "stdout": r.stdout[:8000], "stderr": r.stderr[:2000]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ---------- Learning write ----------
def execute_learning_write(consent_token: str, section: str, title: str,
                           body: str) -> dict:
    if not get_manager().consume(consent_token, "learning_write"):
        return {"ok": False, "error": "consent missing or expired"}
    if section not in ("performance", "bugs"):
        return {"ok": False, "error": "section restricted"}
    if not title or len(title) > 120:
        return {"ok": False, "error": "title invalid"}
    if len(body) > 4000:
        return {"ok": False, "error": "body too long"}
    try:
        from ..shared.memory import get_writer
        get_writer().append(section, title, body)
        return {"ok": True, "msg": "queued for write"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
