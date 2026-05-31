"""Strict allow-list of IPC commands + JSON schema validation.

The orchestrator rejects ANY command name not in COMMAND_SPECS. Each spec
declares the args it accepts plus type validators. Anything else returns
{"ok": false, "error": "validation"}.
"""
from __future__ import annotations

from typing import Any, Callable


def _is_str(v, max_len=4000): return isinstance(v, str) and len(v) <= max_len
def _is_int(v, lo=-1, hi=1_000_000_000): return isinstance(v, int) and lo <= v <= hi
def _is_bool(v): return isinstance(v, bool)
def _is_dict(v): return isinstance(v, dict)
def _is_str_short(v): return isinstance(v, str) and 0 < len(v) <= 200


# spec = {arg_name: validator(value) -> bool, required: bool}
COMMAND_SPECS: dict[str, dict[str, tuple[Callable[[Any], bool], bool]]] = {
    "ping": {},
    "stats": {},
    "module_status": {},

    "event.inject": {
        "severity": (lambda v: v in ("INFO","WARN","THREAT","CRITICAL","QUARANTINE"), True),
        "category": (lambda v: v in ("FILE","PROCESS","NETWORK","URL","DNS","SYSTEM","QUARANTINE","VOICE","TAMPER"), True),
        "message":  (lambda v: isinstance(v, str) and 0 < len(v) <= 2000, True),
        "source":   (_is_str_short, False),
        "metadata": (_is_dict, False),
    },

    "settings.save": {
        "vt_api_key":      (_is_str, False),
        "claude_api_key":  (_is_str, False),
        "pv_access_key":   (_is_str, False),
        "auto_quarantine": (_is_bool, False),
        "wake_active":     (_is_bool, False),
        "cloud_stt":       (_is_bool, False),
        "allow_websearch": (_is_bool, False),
        "allow_shell":     (_is_bool, False),
        "allow_learning":  (_is_bool, False),
        "enable_active_response": (_is_bool, False),
        "adaptive_autoblock": (_is_bool, False),
        "consent_ttl_min": (lambda v: _is_int(v, 1, 1440), False),
        "tts_voice": (lambda v: _is_str(v, 80), False),
        "tts_enabled": (_is_bool, False),
    },
    "settings.get": {},
    "vt.status": {"vt_api_key": (_is_str, False)},

    "system.autostart": {"enable": (_is_bool, False)},
    "system.repin":     {},
    "system.setup":     {},
    "system.restart":   {},

    "consent.list":   {},
    "consent.decide": {
        "id":       (_is_str_short, True),
        "decision": (lambda v: v in ("approve", "deny"), True),
    },

    "voice.text": {
        "text": (lambda v: _is_str(v, 4000) and len(v) > 0, True),
    },

    "claude.ask": {
        "prompt": (lambda v: _is_str(v, 4000) and len(v) > 0, True),
        "heavy":  (_is_bool, False),
    },

    "claude.analyze_recent": {
        "limit":    (lambda v: _is_int(v, 1, 200), False),
        "question": (_is_str, False),
    },

    "quarantine.list":    {},
    "quarantine.approve": {"id": (lambda v: _is_int(v, 1), True)},
    "quarantine.deny":    {"id": (lambda v: _is_int(v, 1), True)},
    "quarantine.delete":  {"id": (lambda v: _is_int(v, 1), True)},
    "quarantine.purge_orphan": {"name": (lambda v: _is_str(v, 260) and len(v) > 0, True)},

    # Autonomy
    "autonomy.status":  {},
    "autonomy.set_pin": {
        "pin":     (lambda v: _is_str(v, 64) and len(v) >= 4, True),
        "old_pin": (_is_str, False),
    },
    "autonomy.set_level": {
        "level":       (lambda v: _is_int(v, 0, 4), True),
        "pin":         (_is_str_short, True),
        "ttl_minutes": (lambda v: _is_int(v, 1, 480), False),
    },
    "autonomy.disable_action": {
        "action": (_is_str_short, True),
        "pin":    (_is_str_short, True),
    },
    "autonomy.enable_action": {
        "action": (_is_str_short, True),
        "pin":    (_is_str_short, True),
    },
    "autonomy.end_session": {},
    "integrations.system_info":   {},
    "integrations.recent_files":  {"limit": (lambda v: _is_int(v, 1, 100), False)},
    "integrations.installed_apps":{},
    "integrations.processes":     {"limit": (lambda v: _is_int(v, 1, 200), False)},
    "integrations.browser_brief": {},
    "calibration.all":  {"limit": (lambda v: _is_int(v, 1, 500), False)},
    "metrics.all":      {},

    # Full-System-Scan
    "scan.start":   {},
    "scan.cancel":  {},
    "scan.status":  {},
    "scan.items":   {"limit": (lambda v: _is_int(v, 1, 2000), False)},
    "scan.quarantine_item": {"index": (lambda v: _is_int(v, 0, 9999), True)},

    # Action-Routing (Sir-Mode)
    "routing.all":   {},
    "routing.set":   {
        "category": (_is_str_short, True),
        "severity": (_is_str_short, True),
        "mode":     (_is_str_short, True),
    },
    "routing.reset": {},

    # Voice
    "voice.speak":   {"text": (lambda v: _is_str(v, 500) and len(v) > 0, True)},
    "boot.status":   {},
    "boot.repin":    {"pin": (_is_str_short, True)},

    # Update flow (Phase 7)
    "update.status":  {},
    "update.check":   {},
    "update.install": {
        "version": (lambda v: _is_str(v, 64), False),
    },
    "update.skip": {
        "version": (lambda v: _is_str(v, 64), True),
    },
    "update.remind": {
        "version": (lambda v: _is_str(v, 64), False),
    },

    # Phase 5 — Driver/USB/Keylog (UI control + queries)
    "driver.list":    {"limit": (lambda v: _is_int(v, 1, 500), False)},
    "driver.rescan":  {},
    "driver.trust":   {"thumb": (_is_str_short, True)},
    "usb.list":       {},
    "usb.block_vid_pid":   {"vid": (_is_str_short, True),
                            "pid": (_is_str_short, True)},
    "usb.unblock_vid_pid": {"vid": (_is_str_short, True),
                            "pid": (_is_str_short, True)},

    "keylog.add_name":      {"name": (_is_str_short, True)},
    "keylog.remove_name":   {"name": (_is_str_short, True)},
    "keylog.suspects":      {},
}


def validate(name, args):
    spec = COMMAND_SPECS.get(name)
    if spec is None:
        return False, f"unknown command: {name}"
    if not isinstance(args, dict):
        return False, "args must be object"
    for k, (_v, req) in spec.items():
        if req and k not in args:
            return False, f"missing required arg: {k}"
    for k, v in args.items():
        if k not in spec:
            return False, f"unknown arg: {k}"
        validator, _req = spec[k]
        if not validator(v):
            return False, f"invalid value for {k}"
    return True, ""
