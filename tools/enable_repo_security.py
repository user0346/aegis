"""Aktiviert alle GitHub-Repo-Security-Features via gh CLI.

Aufruf:
    py -3.13 tools/enable_repo_security.py

Aktiviert (idempotent):
  * Secret Scanning           - GitHub scannt automatisch nach bekannten Secret-Patterns
  * Push Protection           - Push wird abgelehnt wenn Secret im Diff
  * Dependabot Alerts         - bei vulnerable Dependencies
  * Dependabot Security Updates - automatische Fix-PRs
  * Private Vulnerability Reports - Security-Advisories
  * Vulnerability Alerts      - allgemeine Alerts
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def run(args: list[str], capture: bool = True) -> tuple[int, str, str]:
    r = subprocess.run(args, capture_output=capture, text=True,
                       encoding="utf-8", errors="replace")
    return r.returncode, r.stdout or "", r.stderr or ""


def get_repo() -> tuple[str, str]:
    rc, out, _ = run(["gh", "api", "user", "--jq", ".login"])
    if rc != 0:
        print("[ERR] gh nicht eingeloggt: gh auth login")
        sys.exit(1)
    user = out.strip()
    # Get repo name from current dir
    cwd = Path.cwd()
    if (cwd / "aegis2").exists():
        repo = "aegis"   # default
    else:
        repo = cwd.name
    return user, repo


def patch(repo_full: str, fields: dict[str, bool]) -> bool:
    args = ["gh", "api", "--method", "PATCH", f"/repos/{repo_full}"]
    for k, v in fields.items():
        args += ["-F", f"{k}={str(v).lower()}"]
    rc, out, err = run(args)
    if rc != 0:
        print(f"  [WARN] PATCH /repos/{repo_full} fehlgeschlagen")
        print(f"         {err[:300]}")
        return False
    return True


def main() -> int:
    user, repo_name = get_repo()
    repo_full = f"{user}/{repo_name}"
    print(f"Hardening: {repo_full}\n")

    # ---- 1) Security & Analysis Features ----
    print("[1/4] Security-Features (Secret-Scanning, Push-Protection, Dependabot)")
    args = ["gh", "api", "--method", "PATCH", f"/repos/{repo_full}",
            "-H", "Accept: application/vnd.github+json",
            "--input", "-"]
    payload = {
        "security_and_analysis": {
            "secret_scanning":                  {"status": "enabled"},
            "secret_scanning_push_protection":  {"status": "enabled"},
            "dependabot_security_updates":      {"status": "enabled"},
            "private_vulnerability_reporting":  {"status": "enabled"},
        }
    }
    proc = subprocess.run(args, input=json.dumps(payload), capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    if proc.returncode == 0:
        print("  [OK] Secret-Scanning + Push-Protection + Dependabot aktiviert")
    else:
        print(f"  [WARN] {proc.stderr[:500]}")
        print("  Hinweis: Secret-Scanning ist bei Public-Repos automatisch an.")
        print("  Push-Protection kann manuell im Settings -> Code security aktiviert werden.")

    # ---- 2) Vulnerability Alerts ----
    print("\n[2/4] Vulnerability Alerts")
    rc, _, err = run(["gh", "api", "--method", "PUT",
                      f"/repos/{repo_full}/vulnerability-alerts"])
    if rc == 0:
        print("  [OK] Vulnerability-Alerts aktiviert")
    else:
        print(f"  [WARN] {err[:200]}")

    # ---- 3) Automated Security Fixes (Dependabot) ----
    print("\n[3/4] Automated Security Fixes (Dependabot Auto-PRs)")
    rc, _, err = run(["gh", "api", "--method", "PUT",
                      f"/repos/{repo_full}/automated-security-fixes"])
    if rc == 0:
        print("  [OK] Auto-Fix PRs aktiviert")
    else:
        print(f"  [WARN] {err[:200]}")

    # ---- 4) Branch Protection main ----
    print("\n[4/4] Branch-Protection main (require status checks + admins blocked)")
    bp_payload = {
        "required_status_checks": {
            "strict": True,
            "contexts": ["analyze (python)", "analyze (javascript)", "scan"]
        },
        "enforce_admins": False,   # bei Solo-Maintainer auf False, sonst lockst du dich aus
        "required_pull_request_reviews": None,  # auf None bei Solo
        "restrictions": None,
        "required_linear_history": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "required_conversation_resolution": True,
        "block_creations": False
    }
    args = ["gh", "api", "--method", "PUT",
            f"/repos/{repo_full}/branches/main/protection",
            "-H", "Accept: application/vnd.github+json",
            "--input", "-"]
    proc = subprocess.run(args, input=json.dumps(bp_payload), capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    if proc.returncode == 0:
        print("  [OK] Branch-Protection auf main aktiviert")
    else:
        print(f"  [WARN] {proc.stderr[:500]}")
        print("  Branch-Protection braucht ggf. erst die ersten CI-Runs.")

    print("\n" + "=" * 60)
    print(f"  Done. Pruefe: https://github.com/{repo_full}/settings/security_analysis")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
