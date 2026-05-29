"""AEGIS Secret-Scanner.

Wird vom pre-commit Hook aufgerufen. Scannt alle staged Files auf:
  - API-Keys (Anthropic, OpenAI, GitHub, AWS, Slack, Google)
  - JWT / Bearer-Tokens
  - Hartcodierte Passwoerter / Secrets
  - Persoenliche Pfade (C:\\Users\\<name>\\... ausser <placeholder>)
  - Email-Adressen (ausser .noreply.github.com)
  - HMAC / Crypto-Keys ohne klare Generierung

Exit-Code 0 = sauber.  Exit-Code 1 = Leak gefunden, Commit wird geblockt.

Aufruf:
    py -3.13 tools\\secret_scan.py             # scant alle staged Files
    py -3.13 tools\\secret_scan.py --all       # scant das ganze Repo
    py -3.13 tools\\secret_scan.py --file X    # scant nur ein File
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# ============================================================
#  Patterns
# ============================================================
# Jeder Eintrag: (Name, Regex, Severity)
# Severity: BLOCK = Commit abbrechen, WARN = nur warnen
PATTERNS: list[tuple[str, str, str]] = [
    # Anthropic
    ("Anthropic API key",            r"sk-ant-[A-Za-z0-9_-]{20,}",          "BLOCK"),
    # OpenAI
    ("OpenAI API key",               r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}", "BLOCK"),
    ("OpenAI project key",           r"sk-proj-[A-Za-z0-9_-]{20,}",         "BLOCK"),
    # GitHub
    ("GitHub PAT (classic)",         r"ghp_[A-Za-z0-9]{36,}",               "BLOCK"),
    ("GitHub OAuth",                 r"gho_[A-Za-z0-9]{36,}",               "BLOCK"),
    ("GitHub user-to-server",        r"ghu_[A-Za-z0-9]{36,}",               "BLOCK"),
    ("GitHub server-to-server",      r"ghs_[A-Za-z0-9]{36,}",               "BLOCK"),
    ("GitHub fine-grained",          r"github_pat_[A-Za-z0-9_]{82,}",       "BLOCK"),
    # AWS
    ("AWS Access Key",               r"AKIA[0-9A-Z]{16}",                   "BLOCK"),
    ("AWS Secret",                   r"(?i)aws.{0,10}secret.{0,5}=.{0,5}['\"][A-Za-z0-9/+=]{40}['\"]", "BLOCK"),
    # Slack
    ("Slack Bot Token",              r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]{24,}", "BLOCK"),
    ("Slack User Token",             r"xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]{24,}", "BLOCK"),
    # Google
    ("Google API Key",               r"AIza[0-9A-Za-z_-]{35}",              "BLOCK"),
    # Generic
    ("Hardcoded password",           r"(?i)password\s*=\s*['\"][^'\"]{6,}['\"]", "WARN"),
    ("Hardcoded secret",             r"(?i)secret\s*=\s*['\"][A-Za-z0-9]{20,}['\"]", "WARN"),
    ("Bearer token",                 r"(?i)bearer\s+[A-Za-z0-9_-]{30,}",    "WARN"),
    # JWT
    ("JWT token",                    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "BLOCK"),
    # Private keys
    ("RSA private key",              r"-----BEGIN RSA PRIVATE KEY-----",    "BLOCK"),
    ("OpenSSH private key",          r"-----BEGIN OPENSSH PRIVATE KEY-----", "BLOCK"),
    ("EC private key",               r"-----BEGIN EC PRIVATE KEY-----",     "BLOCK"),
    ("PGP private key",              r"-----BEGIN PGP PRIVATE KEY-----",    "BLOCK"),
    # Personal paths — BLOCK weil konkrete Usernamen verraten
    ("Windows-User-Path",            r"[Cc]:[\\/]+[Uu]sers[\\/]+(?!<|public|Public|Default|All Users|runneradmin)[A-Za-z0-9_.-]{2,}", "BLOCK"),
    # Linux/Mac home — BLOCK
    ("Unix home path",               r"/home/(?!<|root|ubuntu|runner|user)[a-z][a-z0-9_-]{2,}/", "BLOCK"),
    ("macOS home path",              r"/Users/(?!<|Shared|Public|runner)[A-Za-z][A-Za-z0-9_-]{2,}/", "BLOCK"),
    # Picovoice
    ("Picovoice Access Key",         r"(?i)pv_access_key[\"']?\s*[:=]\s*['\"][A-Za-z0-9+/=]{40,}['\"]", "BLOCK"),
    # VirusTotal
    ("VirusTotal API Key",           r"(?i)vt[_-]?api[_-]?key[\"']?\s*[:=]\s*['\"][0-9a-f]{64}['\"]", "BLOCK"),
]

# Allowlist: bekannte False-Positives (Substring oder Regex)
ALLOWLIST = [
    "sk-ant-…",                      # placeholder in input field
    "sk-ant-XXX",
    "sk-ant-PLACEHOLDER",
    "ghp_PLACEHOLDER",
    "<dein-",
    "<your-",
    "<placeholder>",
    "users.noreply.github.com",
    "runner.actions",                # GitHub Actions runner path
    "C:\\Users\\runneradmin",        # GHA runner
    "actions/runner",
    # AEGIS-eigene Patterns die wie Secrets aussehen
    "_install_secret",
    "test_secret",
    "PATTERNS",                      # this file
    "secret_scan",
]

# Files die NIE gescannt werden (Binary / known-clean)
SKIP_FILES = {
    ".gitignore", ".gitattributes",
    "LICENSE", "LICENSE.md", "LICENSE.txt",
}
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf",
                 ".zip", ".tar", ".gz", ".7z", ".exe", ".dll", ".so",
                 ".sqlite", ".db", ".bin")
SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules",
             "dist", "build", "public", ".pytest_cache"}

# Verzeichnisse die NIEMALS commiteet werden duerfen — wenn entdeckt:
# BLOCK weil sie git-Internals oder andere History enthalten koennen
FORBIDDEN_DIRS_AT_ROOT = {
    ".git_old", ".git_old_locked", ".git_backup", ".git-backup",
    ".gitOLD", ".git-old", ".git.bak", ".git.orig",
}


# ============================================================
#  Scanner
# ============================================================
def is_allowlisted(line: str) -> bool:
    return any(a in line for a in ALLOWLIST)


_GITIGNORE_CACHE: dict[str, bool] = {}


def is_gitignored(path: Path, repo_root: Path) -> bool:
    """Pruefe ob file von .gitignore ausgeschlossen ist.

    Wenn ja, kann es nicht committed werden -> kein Leak-Risiko ->
    Scan kann es ueberspringen. Spart False-Positives in zB .git_old_locked
    wenn dieses bereits in .gitignore steht.
    """
    try:
        rel = str(path.relative_to(repo_root)).replace("\\", "/")
    except ValueError:
        return False
    if rel in _GITIGNORE_CACHE:
        return _GITIGNORE_CACHE[rel]
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_root), "check-ignore", "-q", rel],
            capture_output=True, timeout=5,
        )
        ignored = (r.returncode == 0)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        ignored = False
    _GITIGNORE_CACHE[rel] = ignored
    return ignored


def scan_file(path: Path, repo_root: Path) -> list[tuple[str, int, str, str, str]]:
    """Returns list of (rel_path, line_no, pattern_name, severity, snippet)."""
    findings: list[tuple[str, int, str, str, str]] = []
    # Falls Datei via .gitignore ausgeschlossen ist -> kein Leak-Risiko
    if is_gitignored(path, repo_root):
        return findings
    # BLOCK: forbidden top-level dirs (.git_old etc — contain leaked binary git objects)
    # Diese Pruefung greift NUR wenn die Files NICHT via .gitignore ausgeschlossen sind
    try:
        rel_check = path.relative_to(repo_root)
        top = rel_check.parts[0] if rel_check.parts else ""
        for forbidden in FORBIDDEN_DIRS_AT_ROOT:
            if top.startswith(forbidden):
                rel = str(rel_check).replace("\\", "/")
                findings.append((rel, 0, f"Forbidden top-level dir: {top}",
                                 "BLOCK", "Move or delete this directory before commit."))
                return findings
    except ValueError:
        pass
    # Suspicious filename: unusual chars at end (accidental shell redirect, etc.)
    if path.name.endswith((":", "|", ">", "<", "\\", "?", "*")):
        try:
            rel = str(path.relative_to(repo_root)).replace("\\", "/")
        except ValueError:
            rel = path.name
        findings.append((rel, 0, "Suspicious filename (likely shell-accident)",
                         "BLOCK", path.name[:120]))
        return findings
    # Files ohne Extension am Repo-Root sind verdaechtig (oft Shell-Outputs)
    try:
        rel_check = path.relative_to(repo_root)
        if len(rel_check.parts) == 1 and not path.suffix and not path.name.startswith("."):
            # Erlaubte extensions-less files (Makefile, LICENSE, etc.)
            ALLOWED_NOEXT = {"Makefile", "Dockerfile", "LICENSE", "AUTHORS",
                             "CODEOWNERS", "MANIFEST", "VERSION", "NOTICE",
                             "CHANGELOG", "CONTRIBUTING", "PATENTS"}
            if path.name not in ALLOWED_NOEXT:
                rel = str(rel_check).replace("\\", "/")
                findings.append((rel, 0, "Extension-less root file (review needed)",
                                 "BLOCK", f"{path.name} ({path.stat().st_size} bytes)"))
                return findings
    except (ValueError, OSError):
        pass
    if path.name in SKIP_FILES:
        return findings
    if any(path.name.endswith(s) for s in SKIP_SUFFIXES):
        return findings
    if any(p in SKIP_DIRS for p in path.parts):
        return findings
    # secret_scan.py itself contains patterns — skip it
    if path.name == "secret_scan.py":
        return findings

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    rel = str(path.relative_to(repo_root)).replace("\\", "/")
    for lineno, line in enumerate(text.splitlines(), 1):
        if is_allowlisted(line):
            continue
        for name, regex, sev in PATTERNS:
            if re.search(regex, line):
                snippet = line.strip()[:120]
                findings.append((rel, lineno, name, sev, snippet))
    return findings


def get_staged_files(repo_root: Path) -> list[Path]:
    try:
        r = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, cwd=repo_root, check=True,
            encoding="utf-8", errors="replace",
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    files = []
    for line in r.stdout.splitlines():
        p = repo_root / line.strip()
        if p.is_file():
            files.append(p)
    return files


def all_files(repo_root: Path) -> list[Path]:
    out = []
    for p in repo_root.rglob("*"):
        if p.is_file() and not any(d in SKIP_DIRS for d in p.parts):
            out.append(p)
    return out


# ============================================================
#  Main
# ============================================================
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true",
                    help="Scan whole repo instead of just staged files")
    ap.add_argument("--file", type=Path, help="Scan a single file")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]

    if args.file:
        files = [args.file]
    elif args.all:
        files = all_files(repo_root)
    else:
        files = get_staged_files(repo_root)
        if not files:
            print("[secret-scan] No staged files. (use --all to scan whole repo)")
            return 0

    all_findings: list[tuple[str, int, str, str, str]] = []
    for f in files:
        all_findings.extend(scan_file(f, repo_root))

    block = [f for f in all_findings if f[3] == "BLOCK"]
    warn = [f for f in all_findings if f[3] == "WARN"]

    if not all_findings:
        print(f"[secret-scan] OK — {len(files)} files scanned, 0 findings.")
        return 0

    print(f"[secret-scan] {len(files)} files scanned, {len(all_findings)} findings "
          f"({len(block)} BLOCK, {len(warn)} WARN)\n")
    for rel, ln, name, sev, snip in all_findings:
        marker = "[BLOCK]" if sev == "BLOCK" else "[WARN ]"
        print(f"  {marker} {rel}:{ln}  {name}")
        print(f"          {snip}")

    if block:
        print("\n[secret-scan] COMMIT BLOCKED — entferne die Secrets oder fuege "
              "die Zeile in ALLOWLIST hinzu, wenn es ein False-Positive ist.")
        return 1
    print("\n[secret-scan] Nur WARN-Findings, Commit erlaubt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
