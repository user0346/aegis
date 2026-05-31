"""Orchestrator — owns all watcher modules + dispatches IPC commands.

V2 keeps V1 module classes intact but rebases them onto aegis2.shared.modules.base.
For Phase-1 skeleton we import the V1 modules as adapters; Phase-1.5 migration
moves them into shared/modules/ proper.
"""
from __future__ import annotations

import json
import logging
from typing import Optional, TYPE_CHECKING

from ..shared.events import EventBus, Event, Severity, Category
from ..shared.db import get_db
from ..shared.modules.quarantine import QuarantineManager
from ..shared.modules.filewatch import FileWatcher, WATCH_FOLDERS_DEFAULT
from ..shared.modules.procwatch import ProcessWatcher
from ..shared.modules.netwatch import NetworkWatcher
from ..shared.modules.self_protect import SelfProtect
from ..shared.modules.driver_scan import DriverScanner
from ..shared.modules.usb_watch import UsbWatcher
from ..shared.modules.keylog_watch import KeylogWatcher
from ..shared.learner import SelfReflector
from ..shared.updater import UpdateChecker
from .command_schema import validate as validate_command

if TYPE_CHECKING:
    from .ipc_server import ClientHandle

log = logging.getLogger("aegis2.orchestrator")


class Orchestrator:
    """Holds modules + handles IPC commands.

    Phase-1 minimum: empty module list. Phase-1.5 adds actual watchers.
    """

    def __init__(self, bus: EventBus):
        self.bus = bus
        self.db = get_db()
        self.quarantine = QuarantineManager(bus, self.db)
        self.modules: list = []
        self._build_modules()

    def _build_modules(self) -> None:
        """Phase 1: real watchers. Subset of V1 modules, rest follows in Phase 1.6."""
        # FileWatcher — Downloads/Desktop/Documents, auto-quarantine new EXEs
        watch_setting = self.db.get_setting("watch_folders") or [str(p) for p in WATCH_FOLDERS_DEFAULT]
        from pathlib import Path as _P
        folders = [_P(p) for p in watch_setting if _P(p).exists()]
        auto_q = bool(self.db.get_setting("auto_quarantine", True))
        self.modules.append(FileWatcher(self.bus, self.db, self.quarantine, folders, auto_q))

        # ProcessWatcher — new processes via psutil-poll
        if self.db.get_setting("enable_process_watch", True):
            self.modules.append(ProcessWatcher(self.bus))

        # NetworkWatcher — TCP/UDP + portscan/flood detection
        if self.db.get_setting("enable_network_watch", True):
            self.modules.append(NetworkWatcher(self.bus, self.db))

        # SelfReflector — Phase 1.5: real self-learning loop
        if self.db.get_setting("enable_self_reflect", True):
            interval_h = float(self.db.get_setting("reflect_interval_h", 6.0))
            self.modules.append(SelfReflector(self.bus, self.db, interval_h=interval_h))

        # CognitionReasoner — bindet lokales Ollama ans Lernen: bewertet unklare
        # Events und fuettert das Ergebnis gewichtet in die Reputation (schneller schlau).
        if self.db.get_setting("enable_cognition_reason", True):
            try:
                from ..shared.reasoner import CognitionReasoner
                self.modules.append(CognitionReasoner(self.bus, self.db))
            except Exception:  # noqa: BLE001
                log.exception("CognitionReasoner konnte nicht geladen werden")

        # BehaviorAnomaly — statistische Ausreisser-Erkennung (Vorfilter fuer Reasoner)
        if self.db.get_setting("enable_anomaly", True):
            try:
                from ..shared.anomaly import BehaviorAnomaly
                self.modules.append(BehaviorAnomaly(self.bus))
            except Exception:  # noqa: BLE001
                log.exception("BehaviorAnomaly konnte nicht geladen werden")

        # SelfProtect — Phase 3: Integrity + Defender-Watchdog + Hosts-Watchdog
        if self.db.get_setting("enable_self_protect", True):
            root = _P(__file__).resolve().parents[2]
            self.modules.append(SelfProtect(self.bus, self.db, project_root=root))

        # UpdateChecker — Phase 3: passive Update-Notification
        if self.db.get_setting("enable_update_check", True):
            self.modules.append(UpdateChecker(self.bus, self.db))

        # ============================================================
        #  Phase 5 — Driver/USB/Keylog detection
        # ============================================================
        if self.db.get_setting("enable_driver_scan", True):
            self.modules.append(DriverScanner(self.bus, self.db))

        if self.db.get_setting("enable_usb_watch", True):
            self.modules.append(UsbWatcher(self.bus, self.db))

        if self.db.get_setting("enable_keylog_watch", True):
            self.modules.append(KeylogWatcher(self.bus, self.db))

        # Persistente Signaturen laden (encrypted memory -> in-memory DB)
        try:
            from ..shared.encrypted_memory import load_signatures
            from ..shared.signatures import get_signatures
            persisted = load_signatures()
            if persisted:
                get_signatures().restore_from(persisted)
        except Exception:  # noqa: BLE001
            pass

    def start_all(self) -> None:
        for m in self.modules:
            try:
                m.start()
            except Exception:  # noqa: BLE001
                log.exception("Module start failed: %s", getattr(m, "name", "?"))

    def stop_all(self) -> None:
        for m in self.modules:
            try:
                m.stop()
            except Exception:  # noqa: BLE001
                log.exception("Module stop failed: %s", getattr(m, "name", "?"))

    def module_states(self) -> dict[str, bool]:
        return {m.name: m.is_running() for m in self.modules}

    # ---- IPC command dispatch ----
    def handle_command(self, frame: dict, client: "ClientHandle") -> None:
        name = frame.get("name", "")
        args = frame.get("args", {}) or {}
        ref = frame.get("ref")

        # 1) Strict schema validation
        ok, why = validate_command(name, args)
        if not ok:
            client.write({"t": "cmd_result", "ref": ref, "name": name, "ok": False,
                          "error": f"validation: {why}"})
            return

        # 2) Audit every command (without secret payloads)
        try:
            safe_args = {k: ("***" if k in {"vt_api_key","claude_api_key","pv_access_key"}
                             else v)
                         for k, v in args.items()}
            log.info("cmd: %s args=%s", name, safe_args)
        except Exception:  # noqa: BLE001
            pass

        try:
            handler = getattr(self, f"_cmd_{name.replace('.', '_')}", None)
            if not handler:
                client.write({"t": "cmd_result", "ref": ref, "name": name, "ok": False,
                              "error": f"unknown command: {name}"})
                return
            result = handler(args)
            client.write({"t": "cmd_result", "ref": ref, "name": name, "ok": True, "data": result})
        except Exception as e:  # noqa: BLE001
            client.write({"t": "cmd_result", "ref": ref, "name": name, "ok": False,
                          "error": f"{type(e).__name__}: {e}"})

    # ---- command implementations ----
    def _cmd_ping(self, args: dict) -> dict:
        return {"ok": True}

    # ---- System-Steuerung aus der App (ersetzt die .bat; alles ohne Admin: HKCU/DB) ----
    def _cmd_system_autostart(self, args: dict) -> dict:
        on = bool(args.get("enable", False))
        from ..setup import install_autostart
        (install_autostart.install if on else install_autostart.uninstall)()
        return {"enabled": on}

    def _cmd_system_repin(self, args: dict) -> dict:
        import subprocess, sys as _s
        from pathlib import Path as _P
        rp = _P(__file__).resolve().parents[1] / "setup" / "repin_integrity.py"
        subprocess.Popen([_s.executable, str(rp)], creationflags=0x08000000)
        return {"started": True}

    def _cmd_system_setup(self, args: dict) -> dict:
        import subprocess, sys as _s
        from pathlib import Path as _P
        base = _P(__file__).resolve().parents[1] / "setup"
        for scr in ("install_native_host.py", "install_autostart.py", "repin_integrity.py"):
            try:
                subprocess.run([_s.executable, str(base / scr)], capture_output=True,
                               timeout=60, creationflags=0x08000000)
            except Exception:  # noqa: BLE001
                pass
        return {"done": True}

    def _cmd_system_restart(self, args: dict) -> dict:
        import subprocess, sys as _s
        from pathlib import Path as _P
        rs = _P(__file__).resolve().parents[2] / "bin" / "aegis_restart.py"
        subprocess.Popen([_s.executable, str(rs)],
                         creationflags=0x00000008 | 0x08000000, close_fds=True)
        return {"restarting": True}

    def _cmd_event_inject(self, args: dict) -> dict:
        """Externer Client (Browser-Guard Native-Host) injiziert ein Event in den
        Live-Bus -> erscheint sofort im Stream.

        SICHERHEIT: Ein extern injiziertes Event darf NICHT die hoechsten
        Alarmstufen (THREAT/CRITICAL) tragen — sonst kann jeder authentifizierte
        IPC-Client Fehlalarme/Alarm-Fatigue ausloesen (Alert-Spoofing) und so die
        echten Erkennungen verschleiern. Daher werden THREAT/CRITICAL auf WARN
        herabgestuft, ausser ein bewusst gesetztes Server-Flag erlaubt es.
        Der legitime Browser-Guard nutzt INFO/WARN/QUARANTINE — die bleiben
        unveraendert und funktionieren weiter."""
        sev = args.get("severity", "INFO")
        clamped = False
        if sev in ("THREAT", "CRITICAL"):
            try:
                allow_high = bool(self.db.get_setting("allow_external_critical", False))
            except Exception:  # noqa: BLE001
                allow_high = False  # fail-closed: im Zweifel herabstufen
            if not allow_high:
                sev = Severity.WARN
                clamped = True
        self.bus.emit(Event(
            severity=sev,
            category=args.get("category", "SYSTEM"),
            message=args.get("message", ""),
            source=args.get("source", "AEGIS-Guard"),
            metadata=args.get("metadata", {}) or {},
        ))
        return {"injected": True, "severity": sev, "clamped": clamped}

    def _cmd_stats(self, args: dict) -> dict:
        try:
            s = self.db.stats()
        except Exception:  # noqa: BLE001
            s = {}
        try:
            bk = self.db.baseline_counts().get("known", 0)
        except Exception:  # noqa: BLE001
            bk = 0
        return {
            "events_24h":         s.get("events_24h", 0),
            "threats_24h":        s.get("threats_24h", 0),
            "files_total":        s.get("files_total", 0),
            "files_unknown":      s.get("files_unknown", 0),
            "quarantine_pending": s.get("quarantine_pending", 0),
            "connections_1h":     s.get("connections_1h", 0),
            "domains_blocked":    s.get("domains_blocked", 0),
            "modules_running":    sum(1 for m in self.modules if m.is_running()),
            "modules_total":      len(self.modules),
            "baseline_known":     bk,
        }

    def _cmd_module_status(self, args: dict) -> dict:
        return self.module_states()

    def _cmd_quarantine_list(self, args: dict) -> dict:
        from pathlib import Path as _QP
        items = []
        pending_vaults = set()
        for r in self.db.pending_quarantine():
            d = dict(r)
            vp = d.get("vault_path", "") or ""
            if vp and not _QP(vp).exists():
                try:
                    self.db.decide_quarantine(d["id"], "deleted", "vault missing (manuell entfernt)")
                except Exception:
                    pass
                continue
            if vp:
                pending_vaults.add(_QP(vp).name)
            items.append({
                "id": d.get("id"), "file": d.get("original_path", ""),
                "sha256": d.get("sha256", ""), "reason": d.get("reason", ""),
                "quarantined_at": d.get("quarantined_at", 0),
                "size": d.get("size", 0), "orphan": False,
            })
        try:
            vault = self.quarantine.vault
            if vault.exists():
                for f in vault.iterdir():
                    if (not f.is_file()) or (f.name in pending_vaults):
                        continue
                    try:
                        st = f.stat(); sz = st.st_size; mt = st.st_mtime
                    except OSError:
                        sz = 0; mt = 0
                    items.append({
                        "id": None, "file": f.name, "sha256": "",
                        "reason": "lose Datei im Vault (kein DB-Eintrag)",
                        "quarantined_at": mt, "size": sz,
                        "orphan": True, "vault_name": f.name,
                    })
        except Exception:
            pass
        return {"items": items}

    def _cmd_quarantine_purge_orphan(self, args: dict) -> dict:
        name = (args.get("name") or "").strip()
        if (not name) or ("/" in name) or ("\\" in name) or (".." in name):
            return {"ok": False, "error": "invalid name"}
        try:
            target = self.quarantine.vault / name
            if target.exists() and target.is_file():
                target.unlink()
                return {"ok": True}
            return {"ok": False, "error": "not found"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _cmd_quarantine_approve(self, args: dict) -> dict:
        return {"ok": self.quarantine.approve(int(args["id"]))}

    def _cmd_quarantine_deny(self, args: dict) -> dict:
        return {"ok": self.quarantine.deny(int(args["id"]))}

    def _cmd_quarantine_delete(self, args: dict) -> dict:
        return {"ok": self.quarantine.delete_forever(int(args["id"]))}

    def _cmd_settings_save(self, args: dict) -> dict:
        from ..cognition.secrets_store import set_secret
        secret_map = {
            "vt_api_key": "vt_api_key",
            "claude_api_key": "anthropic_api_key",
            "pv_access_key": "picovoice_access_key",
        }
        saved = []
        for ui_key, sec_key in secret_map.items():
            if ui_key in args and args[ui_key]:
                set_secret(sec_key, args[ui_key])
                saved.append(sec_key)
        for _tk in ("auto_quarantine", "wake_active", "cloud_stt",
                    "allow_websearch", "allow_shell", "allow_learning",
                    "enable_active_response", "tts_enabled"):
            if _tk in args:
                self.db.set_setting(_tk, bool(args[_tk]))
        if "consent_ttl_min" in args:
            self.db.set_setting("consent_ttl_min", int(args["consent_ttl_min"]))
        if "tts_voice" in args:
            self.db.set_setting("tts_voice", str(args["tts_voice"])[:80])
        return {"saved_secrets": saved, "ok": True}

    def _cmd_settings_get(self, args: dict) -> dict:
        from ..cognition.secrets_store import get_secret
        def _has(k):
            try:
                return bool(get_secret(k))
            except Exception:
                return False
        return {
            "auto_quarantine": bool(self.db.get_setting("auto_quarantine", True)),
            "tts_enabled": bool(self.db.get_setting("tts_enabled", True)),
            "tts_voice": self.db.get_setting("tts_voice", "de-DE-ConradNeural"),
            "enable_active_response": bool(self.db.get_setting("enable_active_response", True)),
            "adaptive_autoblock": bool(self.db.get_setting("adaptive_autoblock", True)),
            "wake_active": bool(self.db.get_setting("wake_active", True)),
            "cloud_stt": bool(self.db.get_setting("cloud_stt", False)),
            "allow_websearch": bool(self.db.get_setting("allow_websearch", False)),
            "allow_shell": bool(self.db.get_setting("allow_shell", False)),
            "allow_learning": bool(self.db.get_setting("allow_learning", True)),
            "consent_ttl_min": int(self.db.get_setting("consent_ttl_min", 10)),
            "vt_key_set": _has("vt_api_key"),
            "claude_key_set": _has("anthropic_api_key"),
            "pv_key_set": _has("picovoice_access_key"),
        }

    def _cmd_vt_status(self, args: dict) -> dict:
        """Testet den VirusTotal-Key (read-only Lookup des EICAR-Test-Hash) und
        meldet, wie viele Dateien bisher per VT geprueft wurden. Key bleibt DPAPI."""
        from ..cognition.secrets_store import get_secret
        # Test bevorzugt den GERADE EINGETIPPTEN Key (args) -> man kann vor dem Speichern
        # testen. Sonst den gespeicherten. Beides leer -> klare Meldung statt Stille.
        key = (args.get("vt_api_key") or "").strip() or get_secret("vt_api_key")
        if not key:
            return {"configured": False, "valid": False,
                    "detail": "Kein Key eingegeben oder gespeichert."}
        try:
            lookups_done = self.db.count_vt_checked()
        except Exception:
            lookups_done = 0
        # EICAR-Antivirus-Test-Hash — garantiert in der VT-Datenbank vorhanden.
        eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        try:
            from ..shared.threat_intel import vt_lookup_hash
            res = vt_lookup_hash(eicar, key)
        except Exception as e:  # noqa: BLE001
            return {"configured": True, "valid": False,
                    "lookups_done": lookups_done, "detail": f"Fehler: {type(e).__name__}"}
        err = str(res.get("error") or "")
        if res.get("found"):
            valid, detail = True, "Key gueltig (VT erreichbar)"
        elif err.startswith("HTTP 401") or err.startswith("HTTP 403"):
            valid, detail = False, "Ungueltig — " + err
        elif "rate-limited" in err:
            # Kontakt zu VT klappte ueber das Limit hinaus — Key ist nicht ungueltig.
            valid, detail = True, "Key gesetzt — Rate-Limit aktiv, kurz warten"
        elif "not in VT" in err:
            # HTTP 200/404: Key wurde akzeptiert -> gueltig.
            valid, detail = True, "Key gueltig (VT erreichbar)"
        else:
            valid, detail = False, (err or "unbekannte Antwort")
        return {"configured": True, "valid": valid,
                "lookups_done": lookups_done, "detail": detail}

    def _cmd_consent_list(self, args: dict) -> dict:
        from ..cognition.consent import get_manager
        return {"consent_items": get_manager().list_pending()}

    def _cmd_consent_decide(self, args: dict) -> dict:
        from ..cognition.consent import get_manager
        from ..cognition.actions import execute_learning_write
        from ..shared.learner import get_pending_proposal, consume_pending_proposal
        cid = args["id"]
        decision = args["decision"]
        proposal = get_pending_proposal(cid)
        token = get_manager().decide(cid, decision)
        if token and decision == "approve" and proposal:
            r = execute_learning_write(
                consent_token=token,
                section=proposal["section"],
                title=proposal["title"],
                body=proposal["body"],
            )
            consume_pending_proposal(cid)
            if r.get("ok"):
                self.bus.emit(Event(Severity.INFO, Category.SYSTEM,
                    f"Lern-Vorschlag «{proposal['title']}» nach LEARNINGS geschrieben",
                    "orchestrator", {"section": proposal["section"]}))
            else:
                self.bus.emit(Event(Severity.WARN, Category.SYSTEM,
                    f"Lern-Vorschlag-Write fehlgeschlagen: {r.get('error','?')}",
                    "orchestrator"))
        elif decision == "deny" and proposal:
            consume_pending_proposal(cid)
        return {"granted": bool(token)}

    def _cmd_voice_text(self, args: dict) -> dict:
        from ..cognition.claude_client import ask
        r = ask(args["text"], max_tokens=400)
        return {"voice_reply": r.get("text") or r.get("error", "(no reply)")}

    def _cmd_claude_ask(self, args: dict) -> dict:
        from ..cognition.claude_client import ask
        r = ask(args["prompt"], heavy=args.get("heavy", False))
        return r

    # ---- Autonomy ----
    def _cmd_autonomy_status(self, args: dict) -> dict:
        from ..cognition.autonomy import get_autonomy
        return get_autonomy().status()

    def _cmd_autonomy_set_pin(self, args: dict) -> dict:
        from ..cognition.autonomy import (
            set_owner_pin, change_owner_pin, has_owner_pin,
        )
        if not has_owner_pin():
            ok = set_owner_pin(args["pin"])
            return {"ok": ok, "msg": "pin set" if ok else "invalid pin"}
        ok = change_owner_pin(args.get("old_pin", ""), args["pin"])
        return {"ok": ok, "msg": "pin changed" if ok else "old pin wrong or invalid"}

    def _cmd_autonomy_set_level(self, args):
        from ..cognition.autonomy import get_autonomy
        ok, msg = get_autonomy().set_level(
            args["level"], args["pin"], ttl_minutes=args.get("ttl_minutes", 60))
        return {"ok": ok, "msg": msg, "status": get_autonomy().status()}

    def _cmd_autonomy_disable_action(self, args):
        from ..cognition.autonomy import get_autonomy
        return {"ok": get_autonomy().disable_action(args["action"], args["pin"])}

    def _cmd_autonomy_enable_action(self, args):
        from ..cognition.autonomy import get_autonomy
        return {"ok": get_autonomy().enable_action(args["action"], args["pin"])}

    def _cmd_autonomy_end_session(self, args):
        from ..cognition.autonomy import get_autonomy
        get_autonomy().end_session("owner_stop")
        return {"ok": True}

    def _cmd_integrations_system_info(self, args):
        from ..cognition.integrations import system_info
        return system_info()

    def _cmd_integrations_recent_files(self, args):
        from ..cognition.integrations import recent_files
        return {"items": recent_files(args.get("limit", 20))}

    def _cmd_integrations_installed_apps(self, args):
        from ..cognition.integrations import installed_apps_quick
        return {"apps": installed_apps_quick()}

    def _cmd_integrations_processes(self, args):
        from ..cognition.integrations import running_processes
        return {"processes": running_processes(args.get("limit", 50))}

    def _cmd_integrations_browser_brief(self, args):
        from ..cognition.integrations import browser_data_brief
        return browser_data_brief()

    def _cmd_calibration_all(self, args):
        rows = self.db.calibration_all(args.get("limit", 100))
        return {"items": [dict(r) for r in rows]}

    def _cmd_metrics_all(self, args):
        return self.db.all_metrics()

    # ---- Full-System-Scan ----
    def _ensure_scanner(self):
        if not hasattr(self, "_scanner") or self._scanner is None or not self._scanner.is_running():
            return None
        return self._scanner

    def _cmd_scan_start(self, args):
        from ..shared.full_scan import FullSystemScanner
        if hasattr(self, "_scanner") and self._scanner and self._scanner.is_running():
            return {"ok": False, "error": "scan already running"}

        def on_progress(p):
            try:
                self.bus.emit(Event(Severity.INFO, Category.SYSTEM,
                    f"Scan {p.get('phase','?')}: {p.get('location','')}",
                    "FullScan", p))
            except Exception:
                pass

        def on_item(it):
            try:
                self.bus.emit(Event(Severity.INFO, Category.SYSTEM,
                    f"Scan-Item: [{it.verdict}] {it.location_kind}: {it.name}",
                    "FullScan", it.to_dict()))
                # Auto-Quarantaene NUR bei verdict=block (hoechste Stufe) + echte Datei
                if it.verdict == "block" and bool(self.db.get_setting("auto_quarantine", True)):
                    from pathlib import Path as _QP
                    p = _QP(it.value) if getattr(it, "value", "") else None
                    if p and p.exists() and p.is_file():
                        qid = self.quarantine.quarantine(p, f"scan-block:{it.layer}", it.sha256)
                        if qid:
                            self.bus.emit(Event(Severity.QUARANTINE, Category.QUARANTINE,
                                f"AUTO-QUARANTAENE (Scan-BLOCK): {it.name}", "FullScan",
                                {"path": it.value, "quarantine_id": qid}))
            except Exception:
                pass

        self._scanner = FullSystemScanner(on_progress=on_progress, on_item=on_item)
        self._scanner.start()
        return {"ok": True, "started_at": self._scanner.report.started_at}

    def _cmd_scan_cancel(self, args):
        if hasattr(self, "_scanner") and self._scanner:
            self._scanner.cancel()
            return {"ok": True}
        return {"ok": False, "error": "no scan running"}

    def _cmd_scan_status(self, args):
        if not hasattr(self, "_scanner") or self._scanner is None:
            return {"running": False}
        return {"running": self._scanner.is_running(),
                "summary": self._scanner.report.summary()}

    def _cmd_scan_items(self, args):
        if not hasattr(self, "_scanner") or self._scanner is None:
            return {"items": []}
        limit = args.get("limit", 500)
        items = self._scanner.report.items[:limit]
        return {"items": [it.to_dict() for it in items]}

    def _cmd_scan_quarantine_item(self, args):
        if not hasattr(self, "_scanner") or self._scanner is None:
            return {"ok": False, "error": "no scan"}
        idx = args["index"]
        if idx >= len(self._scanner.report.items):
            return {"ok": False, "error": "index out of range"}
        from pathlib import Path as _P
        it = self._scanner.report.items[idx]
        if not it.value or not _P(it.value).exists():
            return {"ok": False, "error": "file not found"}
        qid = self.quarantine.quarantine(_P(it.value), f"scan:{it.layer}", it.sha256)
        return {"ok": bool(qid), "quarantine_id": qid}

    def _cmd_routing_all(self, args):
        from ..cognition.action_router import all_modes
        return all_modes(self.db)

    def _cmd_routing_set(self, args):
        from ..cognition.action_router import set_mode
        ok = set_mode(self.db, args["category"], args["severity"], args["mode"])
        return {"ok": ok}

    def _cmd_routing_reset(self, args):
        from ..cognition.action_router import reset_to_defaults
        reset_to_defaults(self.db)
        return {"ok": True}

    # ---- Boot-Integrity ----
    def _cmd_boot_status(self, args):
        try:
            from ..shared.boot_integrity import capture_state, compare_to_pin
            import json as _json
            from pathlib import Path as _P
            state = capture_state()
            pin_path = _P.home() / ".aegis" / "boot_pin.json"
            pinned = {}
            mismatches = []
            if pin_path.exists():
                try:
                    pinned = _json.loads(pin_path.read_text(encoding="utf-8"))
                    mismatches = compare_to_pin(state, pinned)
                except Exception:
                    pass
            return {
                "state": state.to_dict(),
                "trust": state.trust_summary(),
                "pinned": bool(pinned),
                "mismatches": mismatches,
            }
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    def _cmd_boot_repin(self, args):
        try:
            from ..cognition.autonomy import verify_owner_pin
            if not verify_owner_pin(args["pin"]):
                return {"ok": False, "error": "wrong pin"}
            from ..shared.boot_integrity import capture_state
            import json as _json
            from pathlib import Path as _P
            state = capture_state()
            pin_path = _P.home() / ".aegis" / "boot_pin.json"
            pin_path.parent.mkdir(parents=True, exist_ok=True)
            pin_path.write_text(_json.dumps(state.to_dict(), indent=2), encoding="utf-8")
            return {"ok": True, "trust": state.trust_summary()}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def _cmd_voice_speak(self, args):
        import json as _json
        from pathlib import Path as _P
        import time as _t
        sentinel = _P.home() / ".aegis" / "notifications.jsonl"
        sentinel.parent.mkdir(parents=True, exist_ok=True)
        with open(sentinel, "a", encoding="utf-8") as f:
            f.write(_json.dumps({"ts": _t.time(), "kind": "sir",
                                 "tts_text": args["text"][:500]},
                                ensure_ascii=False) + "\n")
        return {"ok": True}

    def _cmd_claude_analyze_recent(self, args):
        try:
            limit = int(args.get("limit", 30))
            rows = self.db.recent_events(limit=limit)
            events = [dict(r) for r in rows]
            from ..cognition.claude_client import analyze_events
            return analyze_events(events, args.get("question", ""))
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    # ============================================================
    #  Phase 7 — Update flow
    # ============================================================
    def _cmd_update_status(self, args):
        """Returns staged-update metadata if anything is downloaded."""
        from pathlib import Path
        import json as _json
        meta_path = Path.home() / ".aegis" / "updates" / "staged.json"
        if not meta_path.exists():
            return {"staged": False}
        try:
            data = _json.loads(meta_path.read_text(encoding="utf-8"))
            data["staged"] = True
            return data
        except Exception as e:
            return {"staged": False, "error": str(e)}

    def _cmd_update_check(self, args):
        """Force an immediate update-check (normally runs every 24h)."""
        try:
            for m in self.modules:
                if type(m).__name__ == "GitHubUpdateChecker":
                    if hasattr(m, "_check_now"):
                        m._check_now()
                    return {"ok": True, "triggered": True}
            return {"ok": False, "error": "GitHubUpdateChecker not loaded"}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def _cmd_update_install(self, args):
        """Trigger atomic-swap install of the staged update."""
        from pathlib import Path
        import json as _json, subprocess, sys
        meta_path = Path.home() / ".aegis" / "updates" / "staged.json"
        zip_path  = Path.home() / ".aegis" / "updates" / "staged.zip"
        if not (meta_path.exists() and zip_path.exists()):
            return {"ok": False, "error": "no staged update"}
        try:
            meta = _json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as e:
            return {"ok": False, "error": f"meta parse: {e}"}

        if meta.get("signature_verified") is not True:
            return {"ok": False,
                    "error": "refusing: signature not verified ("
                             + str(meta.get("signature_reason", "no info")) + ")"}

        want_ver = (args.get("version") or "").lstrip("v")
        have_ver = (meta.get("version") or "").lstrip("v")
        if want_ver and have_ver and want_ver != have_ver:
            return {"ok": False,
                    "error": f"version mismatch: ui={want_ver} staged={have_ver}"}

        try:
            from ..shared.events import Event, Severity, Category
            import time as _t
            self.bus.emit(Event(
                severity=Severity.WARN,
                category=Category.SYSTEM,
                message=f"Auto-update applying {have_ver}",
                source="update",
                metadata={"version": have_ver, "sha256": meta.get("sha256", "")},
                ts=_t.time(),
            ))
        except Exception:
            pass

        try:
            install_path = Path(__file__).resolve().parents[2]
            script = install_path / "aegis2" / "setup" / "auto_update.py"
            pyw = Path(sys.executable).with_name("pythonw.exe")
            if not pyw.exists():
                pyw = Path(sys.executable)
            CREATE_NEW = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            DETACHED   = getattr(subprocess, "DETACHED_PROCESS", 0)
            subprocess.Popen(
                [str(pyw), str(script), "--install-path", str(install_path)],
                creationflags=CREATE_NEW | DETACHED,
                close_fds=True,
            )
            return {"ok": True, "step": "started",
                    "detail": "auto_update.py spawned — service will restart"}
        except Exception as e:
            return {"ok": False, "error": f"spawn failed: {type(e).__name__}: {e}"}

    def _cmd_update_skip(self, args):
        version = args.get("version", "").lstrip("v")
        if not version:
            return {"ok": False, "error": "version required"}
        try:
            skipped = self.db.get_setting("update_skipped_versions", "") or ""
            tags = set(t.strip() for t in skipped.split(",") if t.strip())
            tags.add(version)
            self.db.set_setting("update_skipped_versions", ",".join(sorted(tags)))
            return {"ok": True, "skipped": version}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def _cmd_update_remind(self, args):
        import time as _t
        version = (args.get("version") or "").lstrip("v")
        try:
            self.db.set_setting("update_remind_after_ts", str(int(_t.time()) + 86400))
            if version:
                self.db.set_setting("update_remind_version", version)
            return {"ok": True, "remind_after_ts": int(_t.time()) + 86400}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    # ============================================================
    #  Phase 5 — Driver / USB / Keylog control + queries
    # ============================================================
    def _cmd_driver_list(self, args):
        """Recent driver events from DB (already emitted by DriverScanner)."""
        try:
            limit = int(args.get("limit", 100))
            rows = self.db.recent_events_by_source("DriverScanner", limit=limit) \
                   if hasattr(self.db, "recent_events_by_source") else []
            return {"ok": True, "items": [dict(r) for r in rows]}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def _cmd_driver_rescan(self, args):
        for m in self.modules:
            if type(m).__name__ == "DriverScanner":
                try:
                    m._scan_once()
                    return {"ok": True}
                except Exception as e:
                    return {"ok": False, "error": str(e)}
        return {"ok": False, "error": "DriverScanner not loaded"}

    def _cmd_driver_trust(self, args):
        thumb = (args.get("thumb") or "").strip().upper()
        if not thumb:
            return {"ok": False, "error": "thumb required"}
        try:
            cur = self.db.get_setting("driver_trusted_thumbprints", "") or ""
            tags = set(t.strip() for t in cur.split(",") if t.strip())
            tags.add(thumb)
            self.db.set_setting("driver_trusted_thumbprints", ",".join(sorted(tags)))
            return {"ok": True, "trusted": thumb}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def _cmd_usb_list(self, args):
        for m in self.modules:
            if type(m).__name__ == "UsbWatcher":
                return {"ok": True, "devices": list(m._known.values())[:200]}
        return {"ok": False, "error": "UsbWatcher not loaded"}

    def _cmd_usb_block_vid_pid(self, args):
        vid = (args.get("vid") or "").strip().upper()
        pid = (args.get("pid") or "").strip().upper()
        if not (vid and pid):
            return {"ok": False, "error": "vid+pid required"}
        try:
            cur = self.db.get_setting("usb_vid_pid_blocklist", "") or ""
            tags = set(t.strip() for t in cur.split(",") if t.strip())
            tags.add(f"{vid}:{pid}")
            self.db.set_setting("usb_vid_pid_blocklist", ",".join(sorted(tags)))
            return {"ok": True, "blocked": f"{vid}:{pid}"}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def _cmd_usb_unblock_vid_pid(self, args):
        vid = (args.get("vid") or "").strip().upper()
        pid = (args.get("pid") or "").strip().upper()
        target = f"{vid}:{pid}"
        try:
            cur = self.db.get_setting("usb_vid_pid_blocklist", "") or ""
            tags = set(t.strip() for t in cur.split(",") if t.strip())
            tags.discard(target)
            self.db.set_setting("usb_vid_pid_blocklist", ",".join(sorted(tags)))
            return {"ok": True, "unblocked": target}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def _cmd_keylog_add_name(self, args):
        n = (args.get("name") or "").strip().lower()
        if not n:
            return {"ok": False, "error": "name required"}
        try:
            cur = self.db.get_setting("keylog_blocklist_names", "") or ""
            tags = set(t.strip() for t in cur.split(",") if t.strip())
            tags.add(n)
            self.db.set_setting("keylog_blocklist_names", ",".join(sorted(tags)))
            return {"ok": True, "added": n}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def _cmd_keylog_remove_name(self, args):
        n = (args.get("name") or "").strip().lower()
        try:
            cur = self.db.get_setting("keylog_blocklist_names", "") or ""
            tags = set(t.strip() for t in cur.split(",") if t.strip())
            tags.discard(n)
            self.db.set_setting("keylog_blocklist_names", ",".join(sorted(tags)))
            return {"ok": True, "removed": n}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    def _cmd_keylog_suspects(self, args):
        for m in self.modules:
            if type(m).__name__ == "KeylogWatcher":
                return {"ok": True, "suspects": list(m._reported)[:200]}
        return {"ok": False, "error": "KeylogWatcher not loaded"}
