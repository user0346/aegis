"""Nuke & Redeploy — kompletter Clean-Slate Re-Setup.

Loescht das GitHub-Repo (mit aller Leak-History) und legt es neu an mit
EINEM einzigen Commit aus dem aktuellen (geleak-bereinigten) Working-Tree.

Vorteile vs. git filter-repo:
  * Kein lokales Backup mit alter Leak-History noetig
  * Kein History-Rewrite + force-push noetig
  * Pristine 1-Commit-Repo, garantiert leak-frei
  * Einfacher und schneller

Nachteile:
  * Commit-History geht verloren (hier: nur 2 Commits, kein Problem)
  * Stars/Forks/Issues falls vorhanden: weg (frisches Repo: keine Daten)
  * Repo-Creation-Date wird neu gesetzt

Aufruf:
    py -3.13 tools/nuke_and_redeploy.py

Voraussetzungen:
    gh auth login
    Token muss `delete_repo` Scope haben:
        gh auth refresh -h github.com -s delete_repo
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def run(args, capture=False, cwd=None, check=False, echo=True):
    if echo:
        print(f"  > {' '.join(str(a) for a in args)}")
    return subprocess.run(args, capture_output=capture, text=True,
                          cwd=cwd, check=check,
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
    for tool in ("git", "gh"):
        if subprocess.run([tool, "--version"], capture_output=True).returncode != 0:
            print(f"  [ERR] {tool} fehlt")
            return False
    print("  [OK] git + gh da")
    if subprocess.run(["gh", "auth", "status"], capture_output=True).returncode != 0:
        print("  [ERR] gh nicht eingeloggt — gh auth login")
        return False
    print("  [OK] gh authentifiziert")
    # delete_repo scope pruefen
    r = run(["gh", "auth", "status"], capture=True, echo=False)
    auth_text = (r.stdout or "") + (r.stderr or "")
    if "delete_repo" not in auth_text:
        print("  [WARN] delete_repo Scope fehlt.")
        print("         Fuehre aus:  gh auth refresh -h github.com -s delete_repo")
        if not confirm("  Trotzdem versuchen?"):
            return False
    else:
        print("  [OK] delete_repo Scope vorhanden")
    return True


def get_repo_info() -> tuple[str, str]:
    r = run(["gh", "api", "user", "--jq", ".login"], capture=True, echo=False)
    user = (r.stdout or "").strip()
    # remote URL
    r = run(["git", "remote", "get-url", "origin"],
            capture=True, cwd=REPO_ROOT, echo=False)
    url = (r.stdout or "").strip()
    m = re.search(r"github\.com[/:]([^/]+)/([^/.]+?)(?:\.git)?$", url)
    if m:
        return m.group(1), m.group(2)
    return user, "aegis"


def delete_remote_repo(user: str, repo: str) -> bool:
    print(f"\n[2/9] Remote-Repo {user}/{repo} loeschen")
    print("  Das loescht: Code, History, Issues, Releases, Tags, Settings.")
    print("  Stars/Forks (falls vorhanden) gehen verloren — bei neuem Repo egal.")
    if not confirm(f"  {user}/{repo} jetzt LOESCHEN?"):
        return False
    r = run(["gh", "repo", "delete", f"{user}/{repo}", "--yes"])
    if r.returncode != 0:
        print(f"  [ERR] gh repo delete fehlgeschlagen (Token ohne delete_repo?)")
        return False
    print("  [OK] Remote-Repo geloescht")
    time.sleep(2)   # GitHub braucht kurz bis das Cache-mässig flushed
    return True


def nuke_local_git() -> bool:
    print("\n[3/9] Lokales .git-Verzeichnis loeschen (frischer init)")
    git_dir = REPO_ROOT / ".git"
    if not git_dir.exists():
        print("  [INFO] Kein lokales .git vorhanden")
        return True
    print(f"  Loesche: {git_dir}")
    if not confirm("  Lokale History komplett verwerfen?"):
        return False
    try:
        # Windows-friendly removal mit retry
        for attempt in range(3):
            try:
                shutil.rmtree(git_dir)
                break
            except PermissionError:
                if attempt == 2:
                    raise
                time.sleep(1)
    except Exception as e:
        print(f"  [ERR] Konnte .git nicht loeschen: {e}")
        print("  Schliesse alle Editoren/IDEs die auf das Repo zugreifen und retry.")
        return False
    print("  [OK] Lokales .git weg")
    return True


def fresh_git_init() -> bool:
    print("\n[4/9] Frischer git init + clean commit")
    r = run(["git", "init"], cwd=REPO_ROOT)
    if r.returncode != 0:
        return False
    run(["git", "branch", "-M", "main"], cwd=REPO_ROOT)
    # gitignore muss da sein (sollte schon, aber defensive)
    gi = REPO_ROOT / ".gitignore"
    if not gi.exists():
        gi.write_text(
            "__pycache__/\n*.pyc\n.venv/\n.env\n.aegis/\nAEGIS.zip\n*.sig\n*.crt\n",
            encoding="utf-8")
    run(["git", "add", "."], cwd=REPO_ROOT)
    r = run(["git", "commit", "-m",
             "AEGIS V2 — clean slate (signed Sigstore release pipeline)"],
            cwd=REPO_ROOT)
    if r.returncode != 0:
        print("  [ERR] commit fehlgeschlagen — git user.name/email gesetzt?")
        return False
    print("  [OK] EIN sauberer Commit")
    return True


def recreate_remote(user: str, repo: str) -> bool:
    print(f"\n[5/9] Remote {user}/{repo} neu anlegen (public)")
    cmd = ["gh", "repo", "create", f"{user}/{repo}", "--public",
           "--description", "AEGIS — Autonomous Endpoint Guardian Intelligence System"]
    r = run(cmd)
    if r.returncode != 0:
        print("  [ERR] Repo-Create fehlgeschlagen")
        return False
    run(["git", "remote", "add", "origin",
         f"https://github.com/{user}/{repo}.git"], cwd=REPO_ROOT)
    print(f"  [OK] {user}/{repo} angelegt")
    return True


def push_main(user: str, repo: str) -> bool:
    print("\n[6/9] Push main")
    r = run(["git", "push", "-u", "origin", "main"], cwd=REPO_ROOT)
    if r.returncode != 0:
        return False
    print("  [OK] main gepusht")
    return True


def setup_pages_and_perms(user: str, repo: str) -> None:
    print("\n[7/9] Pages + Workflow-Permissions setzen")
    # Pages (Workflow-Source)
    r = run(["gh", "api", "--method", "POST",
             f"/repos/{user}/{repo}/pages",
             "-f", "build_type=workflow"], capture=True)
    if r.returncode == 0:
        print("  [OK] Pages aktiviert")
    else:
        out = (r.stdout or "") + (r.stderr or "")
        if "already" in out.lower():
            print("  [INFO] Pages schon aktiv")
        else:
            print(f"  [WARN] Pages-Setup: {out[:200]}")
    # Workflow-Permissions
    r = run(["gh", "api", "--method", "PUT",
             f"/repos/{user}/{repo}/actions/permissions/workflow",
             "-f", "default_workflow_permissions=write",
             "-F", "can_approve_pull_request_reviews=true"], capture=True)
    if r.returncode == 0:
        print("  [OK] Workflow-Permissions: write")
    else:
        print(f"  [WARN] Perms: {(r.stderr or r.stdout)[:200]}")


def tag_v2(user: str, repo: str, tag: str = "v2.0.0") -> bool:
    print(f"\n[8/9] Tag {tag} setzen + pushen -> triggert signed Release")
    if not confirm(f"  Tag {tag} jetzt?"):
        return False
    run(["git", "tag", tag], cwd=REPO_ROOT)
    r = run(["git", "push", "origin", tag], cwd=REPO_ROOT)
    if r.returncode != 0:
        return False
    print(f"  [OK] Tag {tag} gepusht")
    print(f"  Status:  https://github.com/{user}/{repo}/actions")
    print(f"  Release: https://github.com/{user}/{repo}/releases/tag/{tag}")
    return True


def enable_security_features(user: str, repo: str) -> None:
    print("\n[9/9] Security-Features aktivieren")
    enable_script = REPO_ROOT / "tools" / "enable_repo_security.py"
    if not enable_script.exists():
        print(f"  [INFO] {enable_script} fehlt — manuell ausfuehren")
        return
    if confirm("  enable_repo_security.py jetzt?"):
        subprocess.call([sys.executable, str(enable_script)], cwd=REPO_ROOT)


def main() -> int:
    print("=" * 60)
    print("  AEGIS — NUKE & REDEPLOY")
    print("=" * 60)
    print()
    print("Das Script wird:")
    print("  1. Das GitHub-Repo komplett LOESCHEN (Code+History+Releases)")
    print("  2. Lokale .git-History LOESCHEN")
    print("  3. Repo neu anlegen, EIN einziger sauberer Commit")
    print("  4. Pages + Workflow-Perms setzen")
    print("  5. Tag v2.0.0 -> signed Release per GitHub-Actions")
    print("  6. Security-Features (Secret-Scanning, Dependabot, Branch-Protection)")
    print()
    print("ERGEBNIS: Pristine Repo. Null Leak-History. Anywhere.")
    print()
    if not confirm("Wirklich? Das ist destruktiv."):
        return 0

    if not check_prereqs():
        return 1
    user, repo = get_repo_info()
    print(f"\n  Repo: {user}/{repo}")

    if not delete_remote_repo(user, repo):
        return 1
    if not nuke_local_git():
        return 1
    if not fresh_git_init():
        return 1
    if not recreate_remote(user, repo):
        return 1
    if not push_main(user, repo):
        return 1
    setup_pages_and_perms(user, repo)
    if not tag_v2(user, repo):
        return 1
    enable_security_features(user, repo)

    print("\n" + "=" * 60)
    print("  Done. Pristine Repo.")
    print(f"  Code:    https://github.com/{user}/{repo}")
    print(f"  Actions: https://github.com/{user}/{repo}/actions")
    print(f"  Release: https://github.com/{user}/{repo}/releases")
    print("=" * 60)
    print()
    print("Verifiziere danach:")
    print(f'  git log --all -p -S "<dein-username>"   <- muss EMPTY sein')
    return 0


if __name__ == "__main__":
    sys.exit(main())
