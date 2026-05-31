"""Ollama-Auto-Installer — lokale KI ohne manuellen Download.

Laedt + installiert Ollama silent (kein Admin, nach %LOCALAPPDATA%), zieht das
Sprachmodell und meldet ECHTEN Fortschritt (MB + %) ueber einen Callback.
Muss in einem Hintergrund-Thread laufen (dauert Minuten).

Robust: Download chunk-weise mit Timeout (kein ewiges Haengen), Modell-Pull
ueber die Ollama-REST-API (streamt completed/total Bytes). CLI-Fallback.

Privacy-USP bleibt: alles lokal, kein Cloud-Key, keine Daten verlassen den PC.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Callable, Optional

OLLAMA_URL = "https://ollama.com/download/OllamaSetup.exe"
API = "http://127.0.0.1:11434"
MODEL = "llama3.2:3b"          # Fallback (schlank, ~2 GB)


def _gpu_vram_gb() -> float:
    """NVIDIA-VRAM (GB) via nvidia-smi — die verlaessliche Quelle, da Ollama auf der GPU
    rechnet. 0.0, wenn keine NVIDIA-GPU/nicht ermittelbar (-> CPU/RAM-Pfad)."""
    try:
        import subprocess
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=6,
            creationflags=(0x08000000 if sys.platform == "win32" else 0))
        if out.returncode == 0:
            vals = [int(x) for x in out.stdout.split() if x.strip().isdigit()]
            if vals:
                return max(vals) / 1024.0
    except Exception:  # noqa: BLE001
        pass
    return 0.0


def best_model() -> str:
    """Bestes lokales Modell je nach Hardware (Qwen3-Generation). GPU-VRAM zuerst
    (Ollama rechnet auf der GPU), sonst RAM. Hoechste Qualitaet, die der PC FLUESSIG
    packt — kein Modell, das ins langsame CPU-Offloading kippt."""
    try:
        import psutil
        ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    except Exception:  # noqa: BLE001
        ram_gb = 8.0
    vram = _gpu_vram_gb()
    if vram >= 22 or (vram == 0 and ram_gb >= 48):
        return "qwen3:30b-a3b-instruct-2507"   # MoE: 30B-Qualitaet, nur ~3B aktiv -> schnell
    if vram >= 10:                             # z.B. RTX 3060 12GB / 3080 / 4070
        return "qwen3:14b"
    if vram >= 6:                              # 6-8 GB Karten
        return "qwen3:8b"
    if vram >= 4 or ram_gb >= 12:              # kleine GPU oder reiner CPU-Betrieb mit gutem RAM
        return "qwen3:4b-instruct"
    return MODEL                               # ganz schwach -> schlanker Fallback (llama3.2:3b)


def best_embed_model() -> str:
    """Bestes lokales Embedding-Modell fuer die Wissens-Suche, je nach Hardware — AEGIS
    waehlt es AUTONOM (analog best_model() fuers Chat-Modell). Das Embedding-Modell teilt
    sich den VRAM mit dem geladenen Chat-Modell, daher bewusst SCHLANK:
    qwen3-embedding:0.6b (~640 MB, neueste Generation, gleiche Familie wie das Chat-Modell,
    mehrsprachig inkl. Deutsch) passt neben JEDES Chat-Modell. Die staerkere 4B-Variante
    lohnt nur bei viel freiem VRAM (>=20 GB) — sonst wuerde sie das Chat-Modell verdraengen."""
    vram = _gpu_vram_gb()
    try:
        import psutil
        ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    except Exception:  # noqa: BLE001
        ram_gb = 8.0
    if vram >= 20 or (vram == 0 and ram_gb >= 32):
        return "qwen3-embedding:4b"            # ~2.5 GB — nur mit reichlich Headroom
    return "qwen3-embedding:0.6b"              # ~640 MB — neueste Gen, passt ueberall
_OLLAMA_EXE = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe"
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
_MB = 1024 * 1024

# Live-Fortschritt eines laufenden Modell-Downloads (von der UI gepollt via status()).
_PULL = {"model": "", "pct": 0, "active": False, "stage": ""}


def pull_state() -> dict:
    return dict(_PULL)


def _exe() -> str:
    return str(_OLLAMA_EXE) if _OLLAMA_EXE.exists() else "ollama"


def is_installed() -> bool:
    if _OLLAMA_EXE.exists():
        return True
    try:
        subprocess.run([_exe(), "--version"], capture_output=True,
                       timeout=5, creationflags=_NO_WINDOW)
        return True
    except Exception:  # noqa: BLE001
        return False


def has_model() -> bool:
    """True, wenn IRGENDEIN Modell vorhanden ist (egal welches) — robuster Status."""
    try:
        r = subprocess.run([_exe(), "list"], capture_output=True, text=True,
                           timeout=12, creationflags=_NO_WINDOW)
        lines = [l for l in (r.stdout or "").splitlines() if l.strip()]
        return len(lines) >= 2      # Kopfzeile + mindestens 1 Modell
    except Exception:  # noqa: BLE001
        return False


def status() -> dict:
    """UI-Status — schnell via HTTP, kein blockierendes subprocess bei laufendem Server.

    'active_model' = das tatsaechlich genutzte Modell (fuer die UI-Anzeige
    'aktiv ✓ · qwen2.5:7b' statt nur 'aktiv ✓')."""
    running = False
    model = False
    active = ""
    try:
        from . import llm
        running = llm.available(timeout=1.5)
        if running:
            active = llm.active_model() or ""          # echtes aktives Modell, per HTTP
            model = bool(active)
    except Exception:  # noqa: BLE001
        pass
    inst = is_installed()
    if inst and not running and not model:
        try:
            model = has_model()                        # Server aus -> lokal pruefen (subprocess)
        except Exception:  # noqa: BLE001
            model = False
    return {"installed": inst, "running": running, "model": model,
            "model_name": active or MODEL, "active_model": active,
            "pull_active": bool(_PULL.get("active")), "pull_pct": int(_PULL.get("pct", 0)),
            "pull_model": _PULL.get("model", ""), "pull_stage": _PULL.get("stage", "")}


def ensure_running(timeout: int = 10) -> bool:
    """Startet den Ollama-Server, falls installiert aber nicht erreichbar.

    Kein Re-Download/Re-Install — nur 'ollama serve' im Hintergrund hochfahren.
    """
    try:
        from . import llm
        if llm.available():
            return True
    except Exception:  # noqa: BLE001
        pass
    if not is_installed():
        return False
    try:
        subprocess.Popen([_exe(), "serve"], creationflags=_NO_WINDOW,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001
        return False
    try:
        from . import llm
        for _ in range(timeout):
            time.sleep(1)
            if llm.available():
                return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _download(url: str, dest: Path, progress, base: int, span: int) -> None:
    """Chunk-Download mit echtem MB/%-Fortschritt + Timeout auf die Verbindung."""
    req = urllib.request.Request(url, headers={"User-Agent": "AEGIS-Installer"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        got = 0
        last_pct = -1
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(262144)        # 256 KB
                if not chunk:
                    break
                f.write(chunk)
                got += len(chunk)
                if total:
                    pct = base + int(span * got / total)
                    if pct != last_pct:
                        last_pct = pct
                        progress(f"Lade Ollama … {got // _MB}/{total // _MB} MB", pct)
                else:
                    progress(f"Lade Ollama … {got // _MB} MB", base)


def _pull_via_api(progress, model: str) -> bool:
    """Modell ueber die Ollama-REST-API ziehen — streamt echten Fortschritt."""
    body = json.dumps({"name": model, "stream": True}).encode("utf-8")
    req = urllib.request.Request(API + "/api/pull", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        for raw in resp:                          # eine JSON-Zeile pro Update
            line = raw.decode("utf-8").strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            st = d.get("status", "")
            tot = d.get("total") or 0
            comp = d.get("completed") or 0
            if tot:
                pct = 55 + int(40 * comp / tot)
                progress(f"Modell: {st} {comp // _MB}/{tot // _MB} MB", min(95, pct))
            elif st:
                progress("Modell: " + st[:50], 58)
            if st == "success":
                return True
    return has_model()


def pull_with_progress(model: str) -> bool:
    """Modell ziehen mit LIVE-Fortschritt (REST-API-Stream) -> aktualisiert _PULL
    fuer die UI-Anzeige ('lädt qwen2.5:7b · 45%'). Returns True bei Erfolg.
    Blockierend -> nur im Hintergrund-Thread aufrufen."""
    global _PULL
    _PULL = {"model": model, "pct": 0, "active": True, "stage": "Start"}
    ok = False
    try:
        ensure_running(timeout=10)
        body = json.dumps({"name": model, "stream": True}).encode("utf-8")
        req = urllib.request.Request(API + "/api/pull", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as resp:
            for raw in resp:
                line = raw.decode("utf-8").strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                st = d.get("status", "")
                tot = d.get("total") or 0
                comp = d.get("completed") or 0
                if tot:
                    _PULL["pct"] = max(0, min(99, int(100 * comp / tot)))
                if st:
                    _PULL["stage"] = st[:40]
                if st == "success":
                    ok = True
    except Exception:  # noqa: BLE001
        ok = False
    if not ok:
        try:
            ok = has_model()
        except Exception:  # noqa: BLE001
            ok = False
    _PULL = {"model": model, "pct": 100 if ok else int(_PULL.get("pct", 0)),
             "active": False, "stage": "fertig" if ok else "fehlgeschlagen"}
    return ok


def install(progress: Optional[Callable[[str, int], None]] = None) -> dict:
    """Installiert Ollama + Modell. progress(stage, pct). Returns {ok, msg}."""
    def _p(stage, pct):
        if progress:
            try:
                progress(stage, pct)
            except Exception:  # noqa: BLE001
                pass

    if sys.platform != "win32":
        return {"ok": False, "msg": "Auto-Install nur unter Windows"}

    # 1) Ollama installieren (falls noetig)
    if not is_installed():
        _p("Lade Ollama-Installer …", 5)
        tmp = Path(os.environ.get("TEMP", "")) / "OllamaSetup.exe"
        try:
            _download(OLLAMA_URL, tmp, _p, 5, 25)        # 5..30 %
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "msg": f"Download fehlgeschlagen: {type(e).__name__}"}
        _p("Installiere Ollama …", 32)
        try:
            subprocess.run([str(tmp), "/VERYSILENT", "/NORESTART"],
                           timeout=300, creationflags=_NO_WINDOW)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "msg": f"Installation fehlgeschlagen: {type(e).__name__}"}
        for _ in range(40):
            if is_installed():
                break
            time.sleep(1)
        try:
            tmp.unlink()
        except OSError:
            pass
        if not is_installed():
            return {"ok": False, "msg": "Ollama nach Installation nicht gefunden"}

    # 2) Server sicherstellen: starten, falls installiert aber nicht erreichbar
    _p("Starte Ollama-Dienst …", 48)
    server_up = ensure_running(timeout=15)

    # 3) Modell ziehen (falls noetig) — bestes Modell je nach Hardware
    model = best_model()
    if not has_model():
        _p(f"Lade Sprachmodell {model} (einmalig) …", 52)
        ok = False
        if server_up:
            try:
                ok = _pull_via_api(_p, model)
            except Exception:  # noqa: BLE001
                ok = False
        if not ok and not has_model():
            try:                                        # CLI-Fallback ohne feinen Fortschritt
                subprocess.run([_exe(), "pull", model], timeout=3600,
                               creationflags=_NO_WINDOW)
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "msg": f"Modell-Download fehlgeschlagen: {type(e).__name__}"}
        if not has_model():
            return {"ok": False, "msg": "Modell nach Download nicht gefunden"}

    _p("Fertig — lokale KI aktiv.", 100)
    return {"ok": True, "msg": f"Lokale KI (Ollama, {model}) installiert + bereit."}
