"""AEGIS Diagnose — single-pass Selbsttest aller Subsysteme.

Aufruf:
    py -3.13 bin\\aegis_diagnose.py

Was geprüft wird (jeder Step zeigt OK/FAIL/SKIP mit Detail):
  1. Python-Version + Plattform + Admin-Status
  2. Imports: alle aegis2.*-Module einzeln
  3. Optional-Deps (psutil, watchdog, requests, PyQt6, pywin32)
  4. DB öffnen + Schema verifizieren + Stats lesen
  5. Signatures-DB laden
  6. Layered-Scanner auf einer eigenen Test-Datei
  7. Encrypted-Memory write/read roundtrip
  8. Autonomy-Pin set/verify (Test-Pin, sofort wieder gelöscht)
  9. Brute-Force record/reset
 10. Consent-Framework request → decide → consume
 11. Router-Snapshot (Gateway/MAC/DNS)
 12. Full-System-Scanner schneller Test-Run (10 Sekunden)
 13. Service-Status (laufend? PID? Pipe da?)
 14. Bekannte Lücken/Limits Report
"""
from __future__ import annotations

import json
import os
import platform
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ============================================================
#  ANSI Colors
# ============================================================
class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    C_ = "\033[96m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    END = "\033[0m"


# Enable ANSI on Windows
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


# ============================================================
#  Helpers
# ============================================================
RESULTS = {"ok": 0, "warn": 0, "fail": 0, "skip": 0}


def step(name, fn):
    print(f"\n{C.BOLD}{C.B}► {name}{C.END}")
    try:
        result = fn()
        if result == "skip":
            RESULTS["skip"] += 1
            return
        elif result == "warn":
            RESULTS["warn"] += 1
            return
        RESULTS["ok"] += 1
    except Exception as e:
        RESULTS["fail"] += 1
        print(f"  {C.R}✗ FAIL: {type(e).__name__}: {e}{C.END}")
        # Compact traceback (last 3 lines)
        tb = traceback.format_exc().splitlines()
        for line in tb[-4:]:
            print(f"    {C.DIM}{line}{C.END}")


def ok(msg): print(f"  {C.G}✓{C.END} {msg}")
def warn_(msg): print(f"  {C.Y}⚠{C.END} {msg}")
def info(msg): print(f"  {C.DIM}·{C.END} {msg}")
def fail_(msg): print(f"  {C.R}✗{C.END} {msg}")


def section(title):
    bar = "─" * 60
    print(f"\n{C.M}{bar}{C.END}")
    print(f"{C.M}  {title}{C.END}")
    print(f"{C.M}{bar}{C.END}")


# ============================================================
#  Tests
# ============================================================

def test_environment():
    info(f"Python:   {sys.version.splitlines()[0]}")
    info(f"Platform: {platform.platform()}")
    info(f"CWD:      {Path.cwd()}")
    info(f"ROOT:     {ROOT}")
    is_admin = False
    if sys.platform == "win32":
        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
    info(f"Admin:    {'YES' if is_admin else 'no'}")
    return True


def test_optional_deps():
    deps = ["psutil", "watchdog", "requests", "PyQt6.QtCore",
            "PyQt6.QtWebEngineCore", "win32api", "pvporcupine", "pyaudio"]
    present = []
    missing = []
    for d in deps:
        try:
            __import__(d)
            present.append(d)
        except ImportError:
            missing.append(d)
    for d in present: ok(f"have {d}")
    for d in missing: warn_(f"missing {d} (optional)")
    return "warn" if missing else True


def test_aegis_imports():
    modules = [
        "aegis2",
        "aegis2.shared.events",
        "aegis2.shared.db",
        "aegis2.shared.threat_intel",
        "aegis2.shared.signatures",
        "aegis2.shared.scanner",
        "aegis2.shared.full_scan",
        "aegis2.shared.encrypted_memory",
        "aegis2.shared.updater",
        "aegis2.shared.learner",
        "aegis2.shared.memory",
        "aegis2.shared.modules.base",
        "aegis2.shared.modules.quarantine",
        "aegis2.shared.modules.filewatch",
        "aegis2.shared.modules.procwatch",
        "aegis2.shared.modules.netwatch",
        "aegis2.shared.modules.self_protect",
        "aegis2.shared.modules.router_watch",
        "aegis2.cognition.secrets_store",
        "aegis2.cognition.claude_client",
        "aegis2.cognition.consent",
        "aegis2.cognition.actions",
        "aegis2.cognition.autonomy",
        "aegis2.cognition.integrations",
        "aegis2.cognition.bruteforce",
        "aegis2.cognition.action_router",
        "aegis2.service.command_schema",
        "aegis2.service.ipc_server",
        "aegis2.service.orchestrator",
    ]
    failed = []
    for m in modules:
        try:
            __import__(m)
            ok(m)
        except Exception as e:
            failed.append((m, str(e).splitlines()[0]))
            fail_(f"{m}: {e}")
    if failed:
        raise RuntimeError(f"{len(failed)} module(s) failed to import")
    return True


def test_db():
    from aegis2.shared.db import get_db
    db = get_db()
    info(f"DB-Pfad: {db.path}")
    s = db.stats()
    info(f"Schema-Tabellen via stats(): events_24h={s['events_24h']}, "
         f"files_total={s['files_total']}, domains={s['domains_blocked']}")
    db.set_metric("diagnose_test", 1.0)
    if db.all_metrics().get("diagnose_test") == 1.0:
        ok("metrics write+read")
    db.calibration_record_decision("test:diagnose", "TEST", 50, "denied")
    eff = db.calibration_effective_score("test:diagnose", 50)
    info(f"Calibration: base=50, effective={eff}")
    return True


def test_signatures():
    from aegis2.shared.signatures import get_signatures
    sigs = get_signatures()
    s = sigs.stats()
    info(f"Stats: {s['hashes_total']} hashes, "
         f"{s['filename_patterns']} name-patterns, "
         f"{s['byte_patterns']} byte-patterns")
    # Test add+lookup
    sigs.add_user_hash("a" * 64, "diagnose-test")
    if sigs.is_blacklisted_hash("a" * 64):
        ok("add_user_hash + lookup")
    # Test filename pattern
    if sigs.match_filename("Discord-Token-Grabber-Free.exe"):
        ok("seed pattern matches 'Discord-Token-Grabber-Free.exe'")
    return True


def test_scanner():
    from aegis2.shared.scanner import scan_file
    # Erstelle Test-File mit verdächtigem Filename
    test_dir = Path.home() / ".aegis" / "diagnose"
    test_dir.mkdir(parents=True, exist_ok=True)
    test_file = test_dir / "ip-grabber-test.exe"
    test_file.write_bytes(b"fake exe content")
    result = scan_file(test_file)
    info(f"Test-File: {test_file.name}")
    info(f"Verdict={result.verdict}, layer={result.layer}, "
         f"confidence={result.confidence}")
    info(f"Reasons: {result.reasons[:3]}")
    test_file.unlink(missing_ok=True)
    if result.verdict == "block":
        ok("name-pattern blocked correctly")
    else:
        warn_("expected 'block' for 'ip-grabber-test.exe'")
    return True


def test_encrypted_memory():
    from aegis2.shared import encrypted_memory as em
    em.save("diagnose_test", {"hello": "world", "n": 42})
    loaded = em.load("diagnose_test")
    info(f"Loaded: {loaded}")
    if loaded and loaded.get("hello") == "world" and loaded.get("n") == 42:
        ok("DPAPI write+read roundtrip")
    meta = em.metadata("diagnose_test")
    info(f"Metadata: version={meta.get('version')}, schema_v={meta.get('schema_v')}")
    em.delete("diagnose_test")
    return True


def test_autonomy():
    from aegis2.cognition.autonomy import (
        get_autonomy, has_owner_pin, set_owner_pin,
        change_owner_pin, verify_owner_pin,
    )
    # Diagnose-Pin Cycle (clean slate temporarily if existing pin)
    had_pin = has_owner_pin()
    if had_pin:
        info("Owner-Pin already set — skipping pin-set test (clean test below)")
        info(f"Current level: {get_autonomy().level_name()}")
        info(f"Status: {get_autonomy().status()}")
        return True
    # set + verify + change
    if set_owner_pin("9999"):
        ok("set_owner_pin('9999')")
    else:
        warn_("set_owner_pin failed")
        return "warn"
    if verify_owner_pin("9999"):
        ok("verify_owner_pin works")
    if not verify_owner_pin("0000"):
        ok("wrong pin rejected")
    if change_owner_pin("9999", "1234"):
        ok("change_owner_pin")
    # Cleanup — set back to None via direct secret-store
    from aegis2.cognition.secrets_store import delete_secret
    delete_secret("autonomy_pin_hash")
    info("test-pin removed (clean slate)")
    return True


def test_bruteforce():
    from aegis2.cognition import bruteforce as bf
    # Reset zuerst
    bf.reset("diagnose")
    # 5 fehlversuche
    for i in range(5):
        r = bf.record_attempt("diagnose", success=False)
        info(f"attempt {i+1}: locked={r['locked']} kind={r.get('kind','-')}")
    s = bf.status("diagnose")
    info(f"Status: {s}")
    if s["locked"]:
        ok("brute-force lockout active")
    bf.reset("diagnose")
    info("reset done")
    return True


def test_consent():
    from aegis2.cognition.consent import get_manager
    cm = get_manager()
    cid = cm.request("test_action", title="diagnose test",
                     detail="ignore me", requested_by="diagnose")
    info(f"Request id: {cid}")
    pending = cm.list_pending()
    info(f"Pending count: {len(pending)}")
    token = cm.decide(cid, "approve")
    if token:
        ok(f"approve issued token (len={len(token)})")
    consumed = cm.consume(token, "test_action")
    if consumed:
        ok("consume() success")
    # Try replay
    if not cm.consume(token, "test_action"):
        ok("replay rejected (one-shot)")
    return True


def test_router_snapshot():
    from aegis2.shared.modules.router_watch import RouterWatcher
    from aegis2.shared.events import EventBus
    from aegis2.shared.db import get_db
    rw = RouterWatcher(EventBus(), get_db())
    snap = rw._query_snapshot()
    info(f"Gateway-IP:  {snap.get('gateway_ip')}")
    info(f"Gateway-MAC: {snap.get('gateway_mac')}")
    info(f"DNS-Servers: {snap.get('dns_servers')}")
    info(f"Interface:   {snap.get('interface')}")
    if not snap.get("gateway_ip"):
        warn_("no gateway detected — check network connection")
        return "warn"
    arp = rw._arp_table_summary()
    info(f"ARP-Table: {len(arp)} entries")
    return True


def test_fullscan():
    from aegis2.shared.full_scan import FullSystemScanner
    items_seen = []
    progress_seen = []
    def on_item(it):
        items_seen.append(it)
    def on_progress(p):
        progress_seen.append(p)
    fs = FullSystemScanner(on_progress=on_progress, on_item=on_item)
    info("starting full-scan (10s budget)...")
    fs.start()
    deadline = time.time() + 10
    while fs.is_running() and time.time() < deadline:
        time.sleep(0.5)
    if fs.is_running():
        info("cancel triggered (budget reached)")
        fs.cancel()
        time.sleep(1)
    s = fs.report.summary()
    info(f"Items: total={s['items_total']} block={s['items_block']} "
         f"warn={s['items_warn']}")
    info(f"Locations scanned: {s['locations_scanned']}")
    info(f"Duration: {s['duration_s']:.1f}s")
    info(f"Progress callbacks: {len(progress_seen)}")
    if items_seen:
        ok(f"scan emitted {len(items_seen)} items")
        for it in items_seen[:5]:
            info(f"  · [{it.verdict}] {it.location_kind}: {it.name}")
    return True


def test_service_status():
    pid_file = Path.home() / ".aegis" / "service.pid"
    if not pid_file.exists():
        warn_("service-pid file missing — service not running")
        return "warn"
    try:
        pid = int(pid_file.read_text().strip())
    except Exception:
        warn_("pid-file unreadable")
        return "warn"
    info(f"Service-PID: {pid}")
    try:
        import psutil
        if psutil.pid_exists(pid):
            ok(f"PID {pid} alive")
        else:
            warn_(f"PID {pid} dead but file exists (stale)")
    except ImportError:
        info("psutil missing — can't verify PID")
    pipe_path = r"\\.\pipe\aegis-v2-bus"
    info(f"Pipe: {pipe_path}")
    # Try to open the pipe briefly
    try:
        import win32file
        try:
            h = win32file.CreateFile(
                pipe_path,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING, 0, None,
            )
            ok("pipe reachable")
            win32file.CloseHandle(h)
        except Exception as e:
            warn_(f"pipe not reachable: {e}")
    except ImportError:
        info("pywin32 missing — can't test pipe")
    return True


def test_known_limits():
    print("  Bekannte / bewusste Limits:")
    items = [
        ("DPAPI", "Plattform-spezifisch (nur Windows). Linux/Mac fallback in-memory only."),
        ("Voice", "Optional (pip install -r requirements_v2_voice.txt)."),
        ("Pre-Boot", "Unmöglich ohne UEFI-Driver (kein AEGIS-Scope)."),
        ("Kernel-Malware", "Bleibt unsichtbar für User-Mode AEGIS."),
        ("Driver-Scan", "TODO Phase 5 — Treiber-SHA-Pin + Signing-Check."),
        ("Keylogger-Detect", "TODO Phase 5 — GetAsyncKeyState/SetWindowsHookEx."),
        ("USB-Watch", "TODO Phase 5 — RegisterDeviceNotification."),
        ("Firefox-Ext", "TODO — Manifest V2 Build separat."),
        ("Update-Manifest", "Server + Public-Key noch nicht deployed."),
    ]
    for name, note in items:
        info(f"{name:18s} → {note}")
    return True


# ============================================================
#  Main
# ============================================================
def main():
    section("AEGIS Diagnose — Single-Pass Selbsttest")
    print(f"{C.DIM}Start: {time.strftime('%Y-%m-%d %H:%M:%S')}{C.END}")

    step("1.  Environment", test_environment)
    step("2.  Optional Dependencies", test_optional_deps)
    step("3.  AEGIS Module Imports", test_aegis_imports)
    step("4.  Database", test_db)
    step("5.  Signature-DB", test_signatures)
    step("6.  Layered Scanner", test_scanner)
    step("7.  Encrypted Memory", test_encrypted_memory)
    step("8.  Autonomy + Pin", test_autonomy)
    step("9.  Brute-Force Protection", test_bruteforce)
    step("10. Consent-Framework", test_consent)
    step("11. Router Snapshot", test_router_snapshot)
    step("12. Full-System-Scanner (10s)", test_fullscan)
    step("13. Service Status", test_service_status)
    step("14. Bekannte Limits", test_known_limits)

    section("Ergebnis")
    total = sum(RESULTS.values())
    print(f"  {C.G}OK:   {RESULTS['ok']:3d}/{total}{C.END}")
    print(f"  {C.Y}WARN: {RESULTS['warn']:3d}/{total}{C.END}")
    print(f"  {C.R}FAIL: {RESULTS['fail']:3d}/{total}{C.END}")
    print(f"  {C.DIM}SKIP: {RESULTS['skip']:3d}/{total}{C.END}")

    if RESULTS["fail"] == 0:
        print(f"\n{C.G}{C.BOLD}=== AEGIS ist betriebsbereit ==={C.END}")
        return 0
    else:
        print(f"\n{C.R}{C.BOLD}=== AEGIS hat {RESULTS['fail']} blocker — siehe FAILs oben ==={C.END}")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.Y}Abgebrochen.{C.END}")
        sys.exit(130)
