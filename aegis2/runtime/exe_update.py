"""Frozen-Update-Applier fuer die gefrorene AEGIS.exe (onedir-Bundle).

Eine laufende .exe kann ihre eigenen Dateien nicht ersetzen (Windows sperrt sie),
und ein Applier, der AUS dem Install-Ordner laeuft, wuerde sich selbst sperren.
Deshalb extrahieren wir das verifizierte Bundle in ein Staging-Verzeichnis und
starten einen kleinen, fensterlosen PowerShell-Helfer (KEINE .bat) AUSSERHALB des
Install-Ordners, der:
  1. wartet, bis alle AEGIS.exe-Prozesse beendet sind (Watchdog respawnt nicht —
     .stop ist gesetzt) und Reste hart beendet,
  2. den Install-Ordner per robocopy /MIR durch das Staging ersetzt,
  3. die Stop-Sperre loest und die aktualisierte AEGIS.exe neu startet,
  4. sich selbst loescht.

SICHERHEIT: Vor dem Anwenden wird die Integritaet ERNEUT geprueft (SHA-256 +
Sigstore/cosign gegen den gepinnten release.yml-Workflow) — niemals nur dem
faelschbaren signature_verified-Flag in staged.json vertrauen. Die Extraktion
nutzt denselben kanonischen Zip-Slip-Schutz wie der Quellcode-Applier.

Die Install-/Staging-Pfade werden FEST in den generierten Helfer eingebacken
(keine PowerShell-Parameter) — Mandatory-Parameter wuerden in einem
fensterlosen, detached PowerShell einen Eingabe-Prompt ausloesen und haengen.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

_CREATE_NO_WINDOW = 0x08000000


def _update_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    d = Path(base) / "AEGIS" / "update"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _staging_dir() -> Path:
    return _update_dir() / "staged_bundle"


def _extract_bundle(zip_path: Path, dest: Path) -> None:
    """Extrahiert das exe-Bundle (Praefix 'AEGIS/') zip-slip-sicher nach dest.

    Spiegelt den kanonischen Containment-Check des Quellcode-Appliers: fuer JEDEN
    Member wird das aufgeloeste Ziel berechnet und muss real innerhalb von dest
    liegen; absolute/Drive-/UNC-Pfade werden hart abgelehnt (fail-closed)."""
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            if not member.startswith("AEGIS/"):
                continue
            rel = member[len("AEGIS/"):]
            if not rel:
                continue
            rel_norm = rel.replace("\\", "/")
            if (rel_norm.startswith("/") or rel_norm.startswith("//")
                    or (len(rel_norm) >= 2 and rel_norm[1] == ":")):
                raise ValueError(f"unsafe zip member (absolute/drive): {member}")
            target = dest / rel
            resolved = target.resolve()
            if resolved != dest_root and dest_root not in resolved.parents:
                raise ValueError(f"unsafe zip member (escapes staging): {member}")
            if member.endswith("/"):
                resolved.mkdir(parents=True, exist_ok=True)
            else:
                resolved.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(resolved, "wb") as dst:
                    shutil.copyfileobj(src, dst)


# Out-of-Process-Swap. Laeuft als eigener, fensterloser PowerShell-Prozess
# ausserhalb des Install-Ordners. @@INSTALL@@/@@STAGING@@ werden beim Generieren
# durch die echten Pfade ersetzt (fest eingebacken — keine Parameter, kein Prompt).
_HELPER_TEMPLATE = r"""$ErrorActionPreference = 'SilentlyContinue'
$Install = '@@INSTALL@@'
$Staging = '@@STAGING@@'
$stop  = Join-Path $env:USERPROFILE '.aegis\.stop'
$updir = Join-Path $env:USERPROFILE '.aegis\updates'

function Get-AegisProcs {
  Get-CimInstance Win32_Process | Where-Object {
    ($_.Name -eq 'AEGIS.exe' -or $_.Name -eq 'QtWebEngineProcess.exe') -and
    ($_.CommandLine -like ('*' + $Install + '*'))
  }
}

# 1) der App kurz Zeit geben, die IPC-Antwort zu senden
Start-Sleep -Seconds 2
# 2) auf sauberes Ende warten (Core/Watchdog beenden sich via .stop in ~3s; die
#    UI beachtet .stop nicht und wird danach hart beendet)
for ($i = 0; $i -lt 12; $i++) {
  if (-not (Get-AegisProcs)) { break }
  Start-Sleep -Milliseconds 700
}
# 3) Reste hart beenden
Get-AegisProcs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 1
# 4) Inhalte tauschen (App gestoppt -> Dateien frei). robocopy: Exit <8 = Erfolg.
$rc = 16
for ($t = 0; $t -lt 3 -and $rc -ge 8; $t++) {
  robocopy "$Staging" "$Install" /MIR /NFL /NDL /NJH /NJS /NP /R:3 /W:1 | Out-Null
  $rc = $LASTEXITCODE
}
# 5) nur bei Erfolg aufraeumen (sonst staged behalten fuer Retry)
if ($rc -lt 8) {
  Remove-Item "$Staging" -Recurse -Force
  Remove-Item (Join-Path $updir 'staged.json') -Force
  Remove-Item (Join-Path $updir 'staged.zip*') -Force
}
# 6) Stop-Sperre loesen, damit der frische Core laeuft, dann neu starten
Remove-Item $stop -Force
Start-Process -FilePath (Join-Path $Install 'AEGIS.exe') -WorkingDirectory $Install
# 7) Selbstzerstoerung
Start-Sleep -Seconds 1
Remove-Item $PSCommandPath -Force
"""


def _write_helper(install_dir: Path, staging: Path) -> Path:
    content = (_HELPER_TEMPLATE
               .replace("@@INSTALL@@", str(install_dir).replace("'", "''"))
               .replace("@@STAGING@@", str(staging).replace("'", "''")))
    p = _update_dir() / "apply_update.ps1"
    p.write_text(content, encoding="utf-8")
    return p


def _launch_helper(helper: Path) -> None:
    # -NonInteractive: niemals auf eine Eingabe warten (kein Hang). Fensterlos.
    subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
         "-File", str(helper)],
        creationflags=_CREATE_NO_WINDOW, close_fds=True)


def apply_frozen_update(meta: dict | None = None) -> dict:
    """Wendet das gestagte exe-Bundle an (nur gefroren). Returns IPC-Result-Dict."""
    from aegis2.shared import launcher
    if not launcher.is_frozen():
        return {"ok": False, "error": "not a frozen build"}

    # 1) Integritaet RE-verifizieren (SHA + Sigstore) — niemals dem Flag trauen.
    try:
        from aegis2.setup.auto_update import _verify_staged_integrity, STAGED_ZIP
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"verifier unavailable: {e}"}
    ok, reason = _verify_staged_integrity()
    if not ok:
        return {"ok": False, "error": f"integrity check failed: {reason}"}

    # 2) Bundle ins Staging extrahieren (zip-slip-sicher).
    install_dir = Path(sys.executable).resolve().parent
    staging = _staging_dir()
    try:
        _extract_bundle(STAGED_ZIP, staging)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"extract failed: {type(e).__name__}: {e}"}
    if not (staging / "AEGIS.exe").exists():
        return {"ok": False, "error": "staged bundle missing AEGIS.exe"}

    # 3) Helfer (mit eingebackenen Pfaden) schreiben, Stop-Sperre setzen
    #    (Watchdog respawnt nicht), Helfer starten.
    helper = _write_helper(install_dir, staging)
    try:
        (Path.home() / ".aegis" / ".stop").write_text("update", encoding="utf-8")
    except OSError:
        pass
    _launch_helper(helper)
    return {"ok": True, "step": "applying",
            "detail": "AEGIS wird ersetzt und automatisch neu gestartet"}
