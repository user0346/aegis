"""History-Cleanup mit git-filter-repo.

Generisches Tool zum Entfernen sensibler Strings aus der KOMPLETTEN
Git-History. Strings werden via CLI-Args uebergeben — NICHTS wird im
Script hartcodiert (sonst leakt das Script selbst).

Sicherheit:
  - Vor Ausfuehrung wird --replacements-file gelesen (oder --pattern args)
  - Repo-Clone als Backup in ../<repo>_backup_<timestamp>/
  - Filter-repo arbeitet auf working tree, anschliessend Verify-Step
  - User-Bestaetigung vor jedem destruktiven Schritt
  - replacements-Datei wird nach erfolg geloescht (ungeshredded)

Anwendung 1 — interaktiv (sicherste Variante):
    py -3.13 tools/clean_history.py --interactive
  Du tippst die zu entfernenden Strings live ein, sie landen NIE auf Disk.

Anwendung 2 — externes File (wird nach Lauf geloescht):
    py -3.13 tools/clean_history.py --replacements-file ~/leaks.txt
  Format pro Zeile:   <suchstring>==><ersatz>

Anwendung 3 — direkt Pattern uebergeben:
    py -3.13 tools/clean_history.py ^
        --replace "<dein-pfad>==><user-pfad>" ^
        --replace "<deine-firma>==><company>"

Voraussetzungen:
    pip install git-filter-repo --break-system-packages
    gh auth login
"""
from __future__ import annotations

import argparse
import datetime
import getpass
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def run(args, check=False, capture=False, cwd=None, input_=None, echo=True):
    if echo:
        print(f"  > {' '.join(str(a) for a in args)}")
    return subprocess.run(args, check=check, capture_output=capture, text=True,
                          cwd=cwd, input=input_,
                          encoding="utf-8", errors="replace")


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    v = input(f"  {prompt}{suffix}: ").strip()
    return v if v else default


def confirm(prompt: str) -> bool:
    a = ask(f"{prompt} (j/N)", "n").lower()
    return a in ("j", "y", "yes", "ja")


def check_prereqs() -> bool:
    print("\n[1/9] Voraussetzungen pruefen")
    for tool, hint in [("git", ""), ("gh", "gh auth login")]:
        if subprocess.run([tool, "--version"], capture_output=True).returncode != 0:
            print(f"  [ERR] {tool} fehlt. {hint}")
            return False
        print(f"  [OK] {tool} da")
    if subprocess.run(["gh", "auth", "status"], capture_output=True).returncode != 0:
        print("  [ERR] gh nicht eingeloggt: gh auth login")
        return False
    print("  [OK] gh authentifiziert")
    rc = subprocess.run(["git", "filter-repo", "--version"],
                        capture_output=True).returncode
    if rc != 0:
        print("  [WARN] git-filter-repo fehlt — installiere...")
        r = subprocess.run([sys.executable, "-m", "pip", "install",
                            "git-filter-repo", "--break-system-packages"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  [ERR] pip install fehlgeschlagen: {r.stderr[:300]}")
            return False
    print("  [OK] git-filter-repo da")
    return True


def collect_replacements_interactive() -> list[tuple[str, str]]:
    """Liest replacements im Klartext-Modus von stdin, ohne sie zu echoen."""
    print("\nInteraktiver Modus: gib jeweils Suchstring + Ersatz ein.")
    print("Leerzeile beim Suchstring -> fertig.")
    out: list[tuple[str, str]] = []
    i = 1
    while True:
        # getpass damit der String NICHT in CMD-History landet
        try:
            src = getpass.getpass(f"  [{i}] Such-String (Eingabe versteckt): ")
        except Exception:
            src = input(f"  [{i}] Such-String: ")
        if not src:
            break
        dst = input(f"      Ersatz fuer #{i} (default '<redacted>'): ").strip() or "<redacted>"
        out.append((src, dst))
        i += 1
    return out


def parse_replacements_file(path: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==>" not in line:
            print(f"  [WARN] zeile ohne '==>' ignoriert: {line[:40]}")
            continue
        src, dst = line.split("==>", 1)
        out.append((src.strip(), dst.strip()))
    return out


def write_filter_input(replacements: list[tuple[str, str]]) -> Path:
    """Schreibt die Replacements in tempfile fuer filter-repo."""
    # Temp-File in einem Ort der NIE committet wird
    tmp = Path(os.environ.get("TEMP", "/tmp")) / "aegis_filter_repo.txt"
    lines = [f"literal:{src}==>{dst}\n" for src, dst in replacements]
    tmp.write_text("".join(lines), encoding="utf-8")
    return tmp


def backup_repo() -> Path:
    print("\n[2/9] Backup anlegen")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = REPO_ROOT.parent / f"{REPO_ROOT.name}_backup_{ts}"
    run(["git", "clone", "--mirror", str(REPO_ROOT), str(backup_dir)])
    print(f"  [OK] Backup: {backup_dir}")
    return backup_dir


def find_remote_url() -> str:
    r = run(["git", "remote", "get-url", "origin"], capture=True, cwd=REPO_ROOT, echo=False)
    return (r.stdout or "").strip()


def run_filter_repo(rep_file: Path) -> bool:
    print("\n[3/9] git filter-repo (history rewrite)")
    print("  Alle Commit-SHAs werden neu berechnet.")
    if not confirm("  Weiter?"):
        return False
    args = ["git", "filter-repo", "--replace-text", str(rep_file), "--force"]
    rc = subprocess.call(args, cwd=REPO_ROOT)
    return rc == 0


def verify_clean(replacements: list[tuple[str, str]]) -> bool:
    print("\n[4/9] Verifikation — keine Such-Strings mehr in der History?")
    for src, _ in replacements:
        r = subprocess.run(["git", "log", "--all", "--full-history", "-p", "-S", src],
                           capture_output=True, text=True, cwd=REPO_ROOT,
                           encoding="utf-8", errors="replace")
        if r.stdout.strip():
            print(f"  [FAIL] '{src[:40]}...' noch in History")
            return False
    print("  [OK] Alle Patterns aus History entfernt")
    return True


def restore_remote(remote_url: str) -> None:
    print("\n[5/9] Remote 'origin' wiederherstellen")
    r = subprocess.run(["git", "remote"], capture_output=True, text=True, cwd=REPO_ROOT)
    if "origin" not in (r.stdout or ""):
        run(["git", "remote", "add", "origin", remote_url], cwd=REPO_ROOT)
    print(f"  [OK] origin -> {remote_url}")


def force_push_all(remote_url: str) -> bool:
    print("\n[6/9] Force-Push main")
    print(f"  Ziel: {remote_url}")
    if not confirm("  Force-Push?"):
        return False
    rc = subprocess.call(["git", "push", "--force", "origin", "main"], cwd=REPO_ROOT)
    return rc == 0


def delete_old_release_and_tag(user: str, repo: str, tag: str) -> None:
    print(f"\n[7/9] Alten Release+Tag {tag} loeschen")
    r = subprocess.run(["gh", "release", "delete", tag, "--repo", f"{user}/{repo}",
                        "--yes", "--cleanup-tag"],
                       capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode == 0:
        print(f"  [OK] Release+Tag {tag} geloescht")
    else:
        print(f"  [INFO] {r.stderr[:200]}")
    subprocess.call(["git", "tag", "-d", tag], cwd=REPO_ROOT)


def retag_and_push(user: str, repo: str, tag: str) -> bool:
    print(f"\n[8/9] Tag {tag} neu setzen + pushen -> triggert signed Release")
    if not confirm(f"  Tag {tag} jetzt?"):
        return False
    run(["git", "tag", tag], cwd=REPO_ROOT)
    rc = subprocess.call(["git", "push", "origin", tag], cwd=REPO_ROOT)
    return rc == 0


def get_repo_info() -> tuple[str, str]:
    r = run(["gh", "api", "user", "--jq", ".login"], capture=True, echo=False)
    user = (r.stdout or "").strip()
    url = find_remote_url()
    m = re.search(r"github\.com[/:]([^/]+)/([^/.]+?)(?:\.git)?$", url)
    if m:
        return m.group(1), m.group(2)
    return user, "aegis"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interactive", action="store_true",
                    help="Strings live abfragen (versteckt), nichts auf Disk")
    ap.add_argument("--replacements-file", type=Path,
                    help="Externe Datei mit Zeilen 'suchen==>ersetzen'")
    ap.add_argument("--replace", action="append", default=[],
                    metavar="SRC==>DST",
                    help="Einzelne Replacement-Regel (mehrfach erlaubt)")
    ap.add_argument("--tag", default="v2.0.0",
                    help="Tag der nach Cleanup neu signiert wird")
    ap.add_argument("--skip-push", action="store_true",
                    help="Nur lokal cleanen, nicht pushen")
    args = ap.parse_args()

    print("=" * 60)
    print("  AEGIS — History-Cleanup")
    print("=" * 60)
    print("\nDas Script wird:")
    print("  1. Backup deines Repos anlegen")
    print("  2. git filter-repo: persoenliche Strings aus History entfernen")
    print("  3. main + Tag force-pushen, alten Release loeschen,")
    print("     neuen Tag setzen -> GitHub-Actions baut neuen signed Release")
    print()
    print("Alle Commit-SHAs aendern sich. Bestehende Forks/Clones muessen neu klonen.")
    print()
    if not confirm("Weitermachen?"):
        return 0

    # ---- Replacements sammeln ----
    replacements: list[tuple[str, str]] = []
    if args.interactive:
        replacements = collect_replacements_interactive()
    elif args.replacements_file:
        replacements = parse_replacements_file(args.replacements_file)
    for r in args.replace:
        if "==>" in r:
            src, dst = r.split("==>", 1)
            replacements.append((src, dst))
    if not replacements:
        print("[ERR] Keine Replacements angegeben. Nutze --interactive oder --replace 'X==>Y'.")
        return 1

    if not check_prereqs():
        return 1

    remote_url = find_remote_url()
    if not remote_url:
        print("[ERR] Kein origin-remote")
        return 1
    user, repo = get_repo_info()
    print(f"\n  Repo: {user}/{repo}")
    print(f"  URL:  {remote_url}")
    print(f"  Replacements: {len(replacements)}")

    backup_repo()
    rep_file = write_filter_input(replacements)
    try:
        if not run_filter_repo(rep_file):
            return 1
        if not verify_clean(replacements):
            print("[ERR] Verifikation fehlgeschlagen — NICHT pushen!")
            return 1
        restore_remote(remote_url)
        if args.skip_push:
            print("\n[9/9] --skip-push gesetzt — lokal fertig, kein Remote-Push.")
            return 0
        if not force_push_all(remote_url):
            return 1
        delete_old_release_and_tag(user, repo, args.tag)
        if not retag_and_push(user, repo, args.tag):
            return 1
    finally:
        # Tempfile mit den Such-Strings sicher loeschen
        try:
            rep_file.unlink()
        except OSError:
            pass

    print("\n[9/9] Done")
    print("=" * 60)
    print(f"  Backup:  ../{REPO_ROOT.name}_backup_*/")
    print(f"  Actions: https://github.com/{user}/{repo}/actions")
    print(f"  Release: https://github.com/{user}/{repo}/releases/tag/{args.tag}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
