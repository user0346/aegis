"""AEGIS Ollama-Diagnose — zeigt, warum der Status (nicht) 'aktiv' ist."""
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

print("=" * 60)
print(" AEGIS  ·  Ollama-Diagnose")
print("=" * 60)

print("\n[1] Installation / Pfad:")
try:
    from aegis2.voice import ollama_setup as o
    print("    _OLLAMA_EXE :", o._OLLAMA_EXE)
    print("    exists      :", o._OLLAMA_EXE.exists())
    print("    is_installed:", o.is_installed())
    print("    best_model  :", o.best_model())
except Exception as e:  # noqa: BLE001
    print("    FEHLER:", type(e).__name__, e)

print("\n[2] Server erreichbar? (http://127.0.0.1:11434/api/tags)")
t0 = time.time()
try:
    with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as r:
        dt = time.time() - t0
        data = json.loads(r.read().decode("utf-8"))
        models = [m.get("name") for m in data.get("models", [])]
        print("    HTTP %s in %.2fs" % (getattr(r, "status", 200), dt))
        print("    Modelle:", models or "(keine installiert)")
except Exception as e:  # noqa: BLE001
    print("    NICHT erreichbar (%.2fs): %s %s" % (time.time() - t0, type(e).__name__, e))

print("\n[3] llm.available() (so prueft AEGIS):")
try:
    from aegis2.voice import llm
    t0 = time.time()
    print("    ->", llm.available(), "(%.2fs)" % (time.time() - t0))
except Exception as e:  # noqa: BLE001
    print("    FEHLER:", type(e).__name__, e)

print("\n[4] ollama list (CLI):")
try:
    from aegis2.voice import ollama_setup as o
    r = subprocess.run([o._exe(), "list"], capture_output=True, text=True, timeout=12)
    print(r.stdout or "    (leer)")
    if (r.stderr or "").strip():
        print("    stderr:", r.stderr[:300])
except Exception as e:  # noqa: BLE001
    print("    FEHLER:", type(e).__name__, e)

print("\n[5] Deutung:")
print("    - [2] erreichbar + [3] False -> Timeout/Check-Bug (sag mir die Sekunden).")
print("    - [2] NICHT erreichbar, obwohl Ollama-Tray laeuft -> Server nicht auf 11434")
print("      (Ollama-App-Modus ohne 'serve'). [Lokale KI aktivieren] startet 'ollama serve'.")
print("    - [1] is_installed False, obwohl Tray da -> anderer Installationspfad.")
print("=" * 60)
try:
    input("\nEnter zum Schliessen ...")
except EOFError:
    pass
