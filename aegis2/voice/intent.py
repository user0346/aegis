"""Intent classifier — fast local regex first, LLM-fallback for complex queries.

Returns:
  {"intent": "status"|"pause"|"open"|"search"|"query"|"unknown",
   "args": {...},
   "confidence": 0..1}
"""
from __future__ import annotations

import re
from typing import Optional


_PATTERNS = [
    ("status",  re.compile(r"^\s*(status|wie\s+steht|wie\s+geht|lage|bericht)", re.I)),
    ("pause",   re.compile(r"^\s*(pausi[er]+e|pause)\b", re.I)),
    ("open",    re.compile(r"^\s*(öffne|zeig(e)?|wechsle\s+(zu|in))\s+([a-zäöü ]+?)\b", re.I)),
    ("search",  re.compile(r"^\s*(suche|google|recherchier(e)?)\s+(.+)$", re.I)),
    ("close",   re.compile(r"^\s*(schließe|beende|stop)\b", re.I)),
    ("threats", re.compile(r"^\s*(welche|wieviel|wie\s+viele)\s+(threats?|bedrohungen)", re.I)),
]


def classify(text: str) -> dict:
    if not text:
        return {"intent": "unknown", "args": {}, "confidence": 0.0}

    t = text.strip()
    for name, pat in _PATTERNS:
        m = pat.match(t)
        if m:
            args: dict[str, str] = {}
            if name == "open":
                args["target"] = m.group(4).strip().lower()
            elif name == "search":
                args["query"] = m.group(3).strip()
            return {"intent": name, "args": args, "confidence": 0.9}

    # Fall through: treat as freeform query for LLM-handler
    return {"intent": "query", "args": {"text": t}, "confidence": 0.5}
