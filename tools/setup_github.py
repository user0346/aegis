"""One-Click GitHub-Setup für AEGIS.

Macht in einem Run:
  1. Prüft ob gh-CLI installiert + authentifiziert ist
  2. Prüft ob git installiert ist
  3. Legt Repo an (public oder private nach Wahl)
  4. git init + commit + push
  5. Aktiviert GitHub Pages (gh-pages branch)
  6. Setzt Workflow-Permissions (read+write)
  7. Setzt aegis2.shared.db default 'update_github_repo' auf neuen Repo
  8. Optional: erstes Tag v2.0.0 setzen → triggert Release-Workflow

Aufruf:
    cd /d "<dein-AEGIS_V2-Pfad>"
    py -3.13 tools\\setup_github.py
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


# ============================================================
#  Helpers
# ============================================================
def run(cmd, check=False, capture=False, cwd=None, shell=False):
    """Run subprocess with utf-8 + clear logging."""
    if isinstance(cmd, list):
        print(f"  > {' '.join(cmd)}")
    else:
        print(f"  > {cmd}")
    try:
        return subprocess.run(
            cmd, check=check, capture_output=capture, text=True,
            cwd=cwd or REPO_ROOT, shell=shell,
            encoding="utf-8", errors="replace"
        )
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Exit {e.returncode}")
        if e.stderr:
            print(f"    stderr: {e.stderr.strip()}")
        raise


def cmd_exists(name: str) -> bool:
    try:
        r = subprocess.run(["where", name] if sys.platform == "win32" else ["which", name],
                           capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    v = input(f"  {prompt}{suffix}: ").strip()
    return v if v else default


# ============================================================
#  Steps
# ============================================================
def check_prerequisites() -> bool:
    print("\n[1/8] Voraussetzungen prüfen")
    if not cmd_exists("git"):
        print("  ✗ git fehlt → installieren von https://git-scm.com/")
        return False
    print("  ✓ git da")
    if not cmd_exists("gh"):
        print("  ✗ gh-CLI fehlt → installieren von https://cli.github.com/")
        print("    Nach Install:  gh auth login")
        return False
    print("  ✓ gh da")
    # Check gh auth
    r = run(["gh", "auth", "status"], capture=True)
    if r.returncode != 0:
        print("  ✗ Nicht eingeloggt → führe aus:  gh auth login")
        return False
    print("  ✓ gh authentifiziert")
    return True


def get_repo_config():
    print("\n[2/8] Repo-Config")
    user = ""
    r = run(["gh", "api", "user", "--jq", ".login"], capture=True)
    if r.returncode == 0:
        user = (r.stdout or "").strip()
        print(f"  → GitHub-User: {user}")
    repo_name = ask("Repo-Name", "aegis")
    visibility = ask("Visibility (public/private)", "public").lower()
    if visibility not in ("public", "private"):
        visibility = "public"
    return user, repo_name, visibility


def create_repo(user: str, repo_name: str, visibility: str) -> bool:
    print(f"\n[3/8] Repo {user}/{repo_name} ({visibility}) anlegen")
    # Check ob schon existiert
    r = run(["gh", "repo", "view", f"{user}/{repo_name}"], capture=True)
    if r.returncode == 0:
        print(f"  → Repo existiert bereits, überspringe Create")
        return True
    cmd = ["gh", "repo", "create", f"{user}/{repo_name}",
           f"--{visibility}",
           "--description", "AEGIS - Autonomous Endpoint Guardian Intelligence System"]
    r = run(cmd)
    if r.returncode != 0:
        print("  ✗ Repo-Create fehlgeschlagen")
        return False
    print(f"  ✓ Repo angelegt: https://github.com/{user}/{repo_name}")
    return True


def _pre_commit_secret_scan() -> bool:
    """Ruft secret_scan.py --all VOR dem ersten Commit auf — verhindert
    dass Initial-Commit Leaks enthaelt (pre-commit Hook ist da noch nicht aktiv)."""
    print("\n  Vor-Commit Secret-Scan...")
    scan = REPO_ROOT / "tools" / "secret_scan.py"
    if not scan.exists():
        print("  [WARN] secret_scan.py fehlt — Skip")
        return True
    r = subprocess.run([sys.executable, str(scan), "--all"],
                       cwd=REPO_ROOT, capture_output=False)
    if r.returncode != 0:
        print("  [BLOCK] Secret-Scan hat Findings — Initial-Commit ABGEBROCHEN.")
        print("  Fixe die oben gemeldeten Findings und ruf das Script erneut auf.")
        return False
    return True


def init_and_push(user: str, repo_name: str) -> bool:
    print("\n[4/8] git init + commit + push")
    git_dir = REPO_ROOT / ".git"
    if not git_dir.exists():
        run(["git", "init"])
        run(["git", "branch", "-M", "main"])
    # gitignore wenn nicht da
    gi = REPO_ROOT / ".gitignore"
    if not gi.exists():
        gi.write_text("__pycache__/\n*.pyc\n.venv/\n.env\nAEGIS.zip\nAEGIS.zip.sig\nAEGIS.zip.crt\n.aegis/\n", encoding="utf-8")
    # WICHTIG: Pre-commit Hook installieren BEVOR der erste Commit kommt
    hook_installer = REPO_ROOT / "tools" / "install_hooks.py"
    if hook_installer.exists():
        print("  Installiere pre-commit Hook (vor Initial-Commit)...")
        subprocess.run([sys.executable, str(hook_installer)],
                       cwd=REPO_ROOT, capture_output=False)
    # ZUSAETZLICH: Secret-Scan VOR git add (catches alles, auch wenn Hook erst
    # bei nicht-initial Commits zaehlt)
    if not _pre_commit_secret_scan():
        return False
    run(["git", "add", "."])
    # commit
    r = run(["git", "commit", "-m", "AEGIS V2 — initial commit with Phase 1-6"], capture=True)
    if r.returncode != 0 and "nothing to commit" not in (r.stdout or "") + (r.stderr or ""):
        print(f"  → commit: {r.stdout or r.stderr}")
    remote_url = f"https://github.com/{user}/{repo_name}.git"
    r = run(["git", "remote"], capture=True)
    if "origin" not in (r.stdout or ""):
        run(["git", "remote", "add", "origin", remote_url])
    else:
        run(["git", "remote", "set-url", "origin", remote_url])
    r = run(["git", "push", "-u", "origin", "main"])
    if r.returncode != 0:
        print("  ✗ Push fehlgeschlagen")
        return False
    print(f"  ✓ Code gepushed")
    return True


def enable_pages(user: str, repo_name: str) -> bool:
    print("\n[5/8] GitHub Pages aktivieren")
    # Wir aktivieren Pages erst NACHDEM gh-pages Branch existiert (kommt mit erstem Release)
    # Aber wir setzen die Quelle vor.
    cmd = ["gh", "api", "--method", "POST",
           f"/repos/{user}/{repo_name}/pages",
           "-f", "build_type=workflow"]
    r = run(cmd, capture=True)
    if r.returncode == 0:
        print("  ✓ Pages aktiviert (Workflow-Source)")
    else:
        out = (r.stdout or "") + (r.stderr or "")
        if "already exists" in out.lower():
            print("  → Pages schon aktiv")
        else:
            print(f"  ⚠ Pages-Setup-Hinweis: {out[:200]}")
            print("    Manuell: Settings → Pages → Source: 'GitHub Actions'")
    return True


def set_workflow_permissions(user: str, repo_name: str) -> bool:
    print("\n[6/8] Workflow-Permissions (read+write)")
    cmd = ["gh", "api", "--method", "PUT",
           f"/repos/{user}/{repo_name}/actions/permissions/workflow",
           "-f", "default_workflow_permissions=write",
           "-F", "can_approve_pull_request_reviews=true"]
    r = run(cmd, capture=True)
    if r.returncode == 0:
        print("  ✓ Workflows dürfen Releases erstellen")
        return True
    print(f"  ⚠ {r.stderr or r.stdout}")
    print("    Manuell: Settings → Actions → General → 'Read and write permissions'")
    return False


def patch_default_repo(user: str, repo_name: str) -> bool:
    print(f"\n[7/8] Default-Repo in db.py setzen: {user}/{repo_name}")
    db_py = REPO_ROOT / "aegis2" / "shared" / "db.py"
    if not db_py.exists():
        print(f"  ⚠ db.py nicht gefunden: {db_py}")
        return False
    txt = db_py.read_text(encoding="utf-8")
    marker = f'_DEFAULT_UPDATE_REPO = "{user}/{repo_name}"'
    if marker in txt:
        print("  → Default schon gesetzt")
        return True
    # Insert at top of class Database body? Simpler: append a module-level constant
    if "_DEFAULT_UPDATE_REPO" in txt:
        # Replace any existing default
        import re
        txt = re.sub(r'_DEFAULT_UPDATE_REPO\s*=\s*".*"', marker, txt)
    else:
        # Add as module constant after imports
        lines = txt.splitlines()
        insert_at = 0
        for i, line in enumerate(lines):
            if line.startswith("from ") or line.startswith("import "):
                insert_at = i + 1
        lines.insert(insert_at + 1, "")
        lines.insert(insert_at + 2, "# Default GitHub repo for auto-updates (patched by setup_github.py)")
        lines.insert(insert_at + 3, marker)
        txt = "\n".join(lines)
    db_py.write_text(txt, encoding="utf-8")
    print(f"  ✓ {marker} gesetzt in db.py")

    # Commit + push
    run(["git", "add", "aegis2/shared/db.py"])
    run(["git", "commit", "-m", f"chore: pin default update_github_repo to {user}/{repo_name}"], capture=True)
    run(["git", "push"])
    return True


def first_release(user: str, repo_name: str, version: str = "v2.0.0") -> bool:
    print(f"\n[8/8] Erstes Release {version} (triggert Sigstore-Workflow)")
    ans = ask(f"Jetzt {version} taggen? (j/N)", "n").lower()
    if ans not in ("j", "y", "yes", "ja"):
        print("  → übersprungen. Später manuell:  git tag v2.0.0 && git push --tags")
        return True
    run(["git", "tag", version])
    r = run(["git", "push", "origin", version])
    if r.returncode != 0:
        print("  ✗ Tag-Push fehlgeschlagen")
        return False
    print(f"  ✓ Tag {version} gepushed → GitHub-Actions startet jetzt")
    print(f"  → Status:  https://github.com/{user}/{repo_name}/actions")
    print(f"  → Release: https://github.com/{user}/{repo_name}/releases/tag/{version}")
    return True


def main() -> int:
    print("=" * 60)
    print("  AEGIS — One-Click GitHub-Setup")
    print("=" * 60)

    if not check_prerequisites():
        print("\n❌ Voraussetzungen nicht erfüllt. Erst gh + git installieren.")
        return 1

    user, repo_name, vis = get_repo_config()
    if not user or not repo_name:
        print("\n❌ User oder Repo-Name leer.")
        return 1

    if not create_repo(user, repo_name, vis):
        return 1
    if not init_and_push(user, repo_name):
        return 1
    enable_pages(user, repo_name)
    set_workflow_permissions(user, repo_name)
    patch_default_repo(user, repo_name)
    first_release(user, repo_name)

    print("\n" + "=" * 60)
    print(f"  ✓ Setup fertig")
    print(f"  Repo:    https://github.com/{user}/{repo_name}")
    print(f"  Pages:   https://{user}.github.io/{repo_name}/")
    print(f"  Actions: https://github.com/{user}/{repo_name}/actions")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
