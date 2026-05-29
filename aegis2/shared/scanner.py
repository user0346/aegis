"""Layered Scan-Pipeline.

Stufen, jede mit early-exit auf BLOCK:
  L1  Hash-Blacklist           (Signature-DB, O(1) lookup)
  L2  Filename-Pattern         (Regex auf Name)
  L3  Byte-Pattern             (Header-Read 4KB, In-Memory-Compare)
  L4  Heuristik (Pfad/Ext/Entropy)  - bestehende threat_intel.classify_file
  L5  VirusTotal-Cloud         (optional, mit Key)

Returns ScanResult mit:
  verdict:    "block" | "warn" | "clean" | "unknown"
  confidence: 0-100
  layer:      welche Stufe entschieden
  reasons:    Liste Begründungen
  recommend:  "quarantine" | "monitor" | "allow"
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import threat_intel as ti
from .signatures import get_signatures, quick_hash


@dataclass
class ScanResult:
    verdict: str = "clean"          # block | warn | clean | unknown
    confidence: int = 0             # 0-100
    layer: str = ""
    reasons: list = field(default_factory=list)
    recommend: str = "allow"
    sha256: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict, "confidence": self.confidence,
            "layer": self.layer, "reasons": self.reasons,
            "recommend": self.recommend, "sha256": self.sha256,
            "metadata": self.metadata,
        }


def scan_file(path: Path, vt_lookup_cb=None, max_header_bytes: int = 8192,
              skip_layers: Optional[set] = None) -> ScanResult:
    """Voller Scan einer Datei. vt_lookup_cb(sha256) -> dict|None ist optional."""
    skip = skip_layers or set()
    result = ScanResult()
    sigs = get_signatures()

    if not path.exists() or not path.is_file():
        result.verdict = "unknown"
        result.layer = "L0"
        result.reasons = ["file not found"]
        return result

    # L0: Hash
    sha = quick_hash(path)
    result.sha256 = sha

    # L1: Hash-Blacklist
    if "L1" not in skip and sha and sigs.is_blacklisted_hash(sha):
        result.verdict = "block"
        result.confidence = 100
        result.layer = "L1-hash"
        result.reasons = ["Hash in lokaler Blacklist"]
        result.recommend = "quarantine"
        return result

    # L2: Filename-Pattern
    if "L2" not in skip:
        m = sigs.match_filename(path.name)
        if m:
            result.verdict = "block"
            result.confidence = 85
            result.layer = "L2-name"
            result.reasons = [f"Filename matches pattern: {m}"]
            result.recommend = "quarantine"
            return result

    # L3: Byte-Pattern im Header
    if "L3" not in skip:
        try:
            with open(path, "rb") as f:
                header = f.read(max_header_bytes)
        except (OSError, PermissionError):
            header = b""
        if header:
            hits = sigs.match_bytes(header)
            # mehrere bösartige Marker = harter Block
            hard_hits = [h for h in hits if h not in {"py-frozen-binary"}]
            if len(hard_hits) >= 2:
                result.verdict = "block"
                result.confidence = 90
                result.layer = "L3-bytes"
                result.reasons = [f"Byte-Pattern matches: {', '.join(hard_hits[:5])}"]
                result.recommend = "quarantine"
                return result
            elif hard_hits:
                result.metadata["L3_hits"] = hard_hits

    # L4: Heuristik (Pfad/Ext/Entropy)
    if "L4" not in skip:
        cls = ti.classify_file(path, sha)
        verdict_l4 = cls.get("verdict", "unknown")
        result.metadata["L4_score"] = cls.get("score", 0)
        result.metadata["L4_reasons"] = cls.get("reasons", [])
        if verdict_l4 == "malicious":
            result.verdict = "block"
            result.confidence = max(result.confidence, 75)
            result.layer = "L4-heuristic"
            result.reasons = cls.get("reasons", [])[:5]
            result.recommend = "quarantine"
            return result
        elif verdict_l4 == "suspicious":
            result.verdict = "warn"
            result.confidence = max(result.confidence, 50)
            result.layer = "L4-heuristic"
            result.reasons = cls.get("reasons", [])[:5]
            result.recommend = "monitor"
            # weiterscannen mit VT

    # L5: VT-Cloud (nur wenn callback + Hash da)
    if "L5" not in skip and vt_lookup_cb and sha:
        try:
            vt = vt_lookup_cb(sha)
        except Exception:  # noqa: BLE001
            vt = None
        if vt and vt.get("found"):
            mal = vt.get("malicious", 0)
            sus = vt.get("suspicious", 0)
            total = max(1, vt.get("total", 0))
            ratio = (mal + sus) / total
            result.metadata["L5_vt"] = {"malicious": mal, "suspicious": sus,
                                        "total": total}
            if mal >= 5 or ratio > 0.3:
                result.verdict = "block"
                result.confidence = 95
                result.layer = "L5-vt"
                result.reasons.append(f"VT: {mal}/{total} engines flag this")
                result.recommend = "quarantine"
                return result
            elif mal >= 1 or sus >= 3:
                result.verdict = "warn"
                result.confidence = max(result.confidence, 60)
                result.layer = "L5-vt"
                result.reasons.append(f"VT: {mal} malicious + {sus} suspicious")
                result.recommend = "monitor"

    # Default if nothing decided
    if result.verdict == "clean":
        result.layer = "L0-baseline"
    return result


def scan_url(url: str) -> ScanResult:
    """URL-Scanner (IP-Logger, Phishing, etc.) via threat_intel.classify_url."""
    cls = ti.classify_url(url)
    result = ScanResult()
    result.metadata["domain"] = cls.get("domain", "")
    result.metadata["score"] = cls.get("score", 0)
    verdict = cls.get("verdict", "clean")
    reasons = cls.get("reasons", [])
    if verdict == "malicious":
        result.verdict = "block"
        result.confidence = cls.get("score", 80)
        result.layer = "URL-blocklist"
        result.reasons = reasons
        result.recommend = "block"
    elif verdict == "suspicious":
        result.verdict = "warn"
        result.confidence = cls.get("score", 50)
        result.layer = "URL-pattern"
        result.reasons = reasons
        result.recommend = "monitor"
    else:
        result.verdict = "clean"
        result.layer = "URL-clean"
        result.reasons = reasons
    return result
