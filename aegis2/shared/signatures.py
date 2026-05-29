"""Signature-Datenbank für bekannte Malware und Pattern.

Drei Indikator-Typen:
  - SHA-256 Hash (exact match, höchste Confidence)
  - Filename-Pattern (z.B. "Discord-Token-Grabber-*.exe")
  - Byte-Pattern (Magic-Bytes / String-Marker im File-Header)

Die Initial-Liste ist klein. Sie wächst durch:
  1. Cloud-Sync von kuratierten Listen (MalwareBazaar, abuse.ch URLhaus)
  2. User-Quarantäne-Decisions (Deny → Hash wird in local-bad-Liste übernommen)
  3. Claude-Vorschläge nach Self-Reflection (mit Owner-Consent)

Speicherung verschlüsselt in encrypted_memory unter Key "signatures_v1".
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from pathlib import Path
from typing import Optional


# ============================================================
#  Seed-Indikatoren — verbreitete IP-Logger/Grabber/Dox-Tools/DoS-Patterns
# ============================================================
SEED_FILENAME_PATTERNS = [
    # Discord-Token-Grabber
    re.compile(r"(?i)discord.{0,8}(token).{0,8}grab"),
    re.compile(r"(?i)token.{0,8}stealer"),
    re.compile(r"(?i)discord.{0,8}nitro.{0,8}gen"),
    # IP-Grabber / Doxing
    re.compile(r"(?i)ip.{0,4}grabber"),
    re.compile(r"(?i)ip.{0,4}logger"),
    re.compile(r"(?i)ip.{0,4}pull(er)?"),
    re.compile(r"(?i)doxx?(ing)?.{0,4}(tool|kit)"),
    re.compile(r"(?i)osint.{0,4}(tool|grabber)"),
    # DoS / Booters / Stressers
    re.compile(r"(?i)booter"),
    re.compile(r"(?i)stresser"),
    re.compile(r"(?i)ddos.{0,4}(tool|kit|attack)"),
    re.compile(r"(?i)slowloris"),
    re.compile(r"(?i)loic"),
    re.compile(r"(?i)hoic"),
    # RATs
    re.compile(r"(?i)njrat"),
    re.compile(r"(?i)quasar.{0,4}rat"),
    re.compile(r"(?i)remcos"),
    re.compile(r"(?i)asyncrat"),
    # Crypto-Stealer
    re.compile(r"(?i)wallet.{0,4}stealer"),
    re.compile(r"(?i)metamask.{0,4}grabber"),
    re.compile(r"(?i)redline.{0,4}stealer"),
    # Crypto-Miner ohne Consent
    re.compile(r"(?i)xmrig"),
    re.compile(r"(?i)crypto.{0,4}miner.{0,4}silent"),
    # Generic "hack-pack"
    re.compile(r"(?i)hack.{0,4}pack"),
    re.compile(r"(?i)cracked\..*(loader|injector)"),
]

# Byte-Pattern im Header (ersten ~4 KB)
SEED_BYTE_PATTERNS = [
    # Discord Token Stealer typischer String
    (rb"discord.com/api/v9/users/@me", "discord-api-call"),
    (rb"discordtokenprotector", "token-grabber-marker"),
    # Common credential-grabber strings
    (rb"Local\\Google\\Chrome\\User Data\\Default\\Login Data", "chrome-cred-access"),
    (rb"Local\\Microsoft\\Edge\\User Data\\Default\\Login Data", "edge-cred-access"),
    # Stresser-IDs in Code
    (rb"layer4_attack", "ddos-tool"),
    (rb"layer7_flood", "ddos-tool"),
    # Powershell-Encoded-Command via WebClient (typisch Drive-By)
    (rb"System.Net.WebClient).DownloadString", "ps-downloadstring-pattern"),
    # PyInstaller mit GUI-Hack-Tools
    (rb"PyInstaller bootloader", "py-frozen-binary"),    # nur Marker - nicht alleine bösartig
]

# Hash-Blocklist (SHA-256). Default leer; befüllt aus Cloud + Decisions.
# Beispiel: ein paar bekannte Test-Hashes von Eicar etc würde man hier listen.
SEED_HASH_BLACKLIST: set[str] = set()


# ============================================================
#  Signature-DB Klasse — thread-safe, in-memory + persistent
# ============================================================

class SignatureDB:
    def __init__(self):
        self._lock = threading.RLock()
        self.hash_blacklist: set[str] = set(SEED_HASH_BLACKLIST)
        self.filename_patterns = list(SEED_FILENAME_PATTERNS)
        self.byte_patterns = list(SEED_BYTE_PATTERNS)
        self.user_added_hashes: set[str] = set()
        self.user_added_patterns: list[tuple[str, str]] = []   # (pattern_str, reason)
        self.last_updated = time.time()

    # ---- Lookups ----
    def is_blacklisted_hash(self, sha256: str) -> bool:
        with self._lock:
            return sha256.lower() in self.hash_blacklist

    def match_filename(self, name: str) -> Optional[str]:
        """Returns matched pattern source or None."""
        with self._lock:
            for pat in self.filename_patterns:
                if pat.search(name):
                    return pat.pattern[:60]
        return None

    def match_bytes(self, header_bytes: bytes) -> list[str]:
        """Returns list of matched pattern-tags."""
        hits = []
        with self._lock:
            for byte_pat, tag in self.byte_patterns:
                if byte_pat in header_bytes:
                    hits.append(tag)
        return hits

    # ---- Mutations ----
    def add_user_hash(self, sha256: str, reason: str = "user-deny") -> None:
        with self._lock:
            sha = sha256.lower()
            self.hash_blacklist.add(sha)
            self.user_added_hashes.add(sha)
            self.last_updated = time.time()

    def add_user_filename_pattern(self, regex_str: str, reason: str = "user-rule") -> bool:
        try:
            pat = re.compile(regex_str)
        except re.error:
            return False
        with self._lock:
            self.filename_patterns.append(pat)
            self.user_added_patterns.append((regex_str, reason))
            self.last_updated = time.time()
        return True

    def stats(self) -> dict:
        with self._lock:
            return {
                "hashes_total":        len(self.hash_blacklist),
                "hashes_user":         len(self.user_added_hashes),
                "filename_patterns":   len(self.filename_patterns),
                "byte_patterns":       len(self.byte_patterns),
                "user_patterns":       len(self.user_added_patterns),
                "last_updated":        self.last_updated,
            }

    # ---- Persistence ----
    def serialize(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "user_hashes": sorted(self.user_added_hashes),
                "user_patterns": [{"regex": p, "reason": r}
                                  for p, r in self.user_added_patterns],
                "last_updated": self.last_updated,
            }

    def restore_from(self, data: dict) -> None:
        if not isinstance(data, dict):
            return
        with self._lock:
            for h in data.get("user_hashes", []):
                if isinstance(h, str) and re.fullmatch(r"[0-9a-f]{64}", h.lower()):
                    self.hash_blacklist.add(h.lower())
                    self.user_added_hashes.add(h.lower())
            for entry in data.get("user_patterns", []):
                try:
                    pat = re.compile(entry["regex"])
                    self.filename_patterns.append(pat)
                    self.user_added_patterns.append((entry["regex"],
                                                     entry.get("reason", "")))
                except (re.error, KeyError, TypeError):
                    pass
            self.last_updated = data.get("last_updated", time.time())


# Singleton
_inst: Optional[SignatureDB] = None
_inst_lock = threading.Lock()


def get_signatures() -> SignatureDB:
    global _inst
    with _inst_lock:
        if _inst is None:
            _inst = SignatureDB()
        return _inst


def quick_hash(file_path: Path, chunk: int = 65536) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                d = f.read(chunk)
                if not d:
                    break
                h.update(d)
        return h.hexdigest().lower()
    except (OSError, PermissionError):
        return None
