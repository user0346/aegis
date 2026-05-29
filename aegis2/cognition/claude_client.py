"""Claude (Anthropic) client — used for analysis, Q&A, and self-learning proposals.

Hard rules:
  - API key never logged, never sent over IPC, never put in events.
  - All Claude calls are short-context. Recent events are summarized, not raw-dumped.
  - Every Claude response that asks for an *action* must go through consent.py.
  - Output sanitized before display: HTML/markdown allowed, no <script>, no iframe.

Models:
  - Default: claude-haiku-4-5  (fast, cheap, good enough for triage)
  - Heavy:   claude-sonnet-4-6 (deep analysis on user request)
"""
from __future__ import annotations

import json
import re
import time
from typing import Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore

from .secrets_store import get_secret


API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-haiku-4-5-20251001"
HEAVY_MODEL = "claude-sonnet-4-6"

# Output sanitization — strip any markup that could XSS the WebView
_TAG_BLOCKLIST = re.compile(r"<\s*(script|iframe|object|embed|link|meta)\b[^>]*>",
                            re.IGNORECASE)


def _sanitize(text: str) -> str:
    if not text:
        return ""
    return _TAG_BLOCKLIST.sub("[blocked-tag]", text)


def ask(prompt: str, *, system: Optional[str] = None, heavy: bool = False,
        max_tokens: int = 600, timeout: int = 25) -> dict:
    """Send a single prompt. Returns {"ok": bool, "text": str, "error": str}."""
    if requests is None:
        return {"ok": False, "error": "requests not available"}
    key = get_secret("anthropic_api_key")
    if not key:
        return {"ok": False, "error": "no anthropic key set"}

    body: dict = {
        "model": HEAVY_MODEL if heavy else DEFAULT_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system

    headers = {
        "x-api-key": key,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    try:
        r = requests.post(API_URL, headers=headers, data=json.dumps(body),
                          timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"network: {type(e).__name__}"}
    if r.status_code != 200:
        return {"ok": False, "error": f"http {r.status_code}"}
    try:
        data = r.json()
        for blk in data.get("content", []):
            if blk.get("type") == "text":
                return {"ok": True, "text": _sanitize(blk.get("text", "").strip())}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"parse: {e}"}
    return {"ok": False, "error": "no text in response"}


SYSTEM_TRIAGE = (
    "You are AEGIS, a personal endpoint-security assistant. "
    "You're allowed to be technical but stay concise. "
    "If a user asks about a threat, analyse the supplied event list and give "
    "(1) a 1-sentence verdict, (2) up to 3 concrete next-actions, "
    "(3) any flags that warrant investigation. "
    "Never invent file paths or hashes that aren't in the input. "
    "If you propose system-modifying actions, prefix each with [REQUEST-CONSENT:scope] "
    "so the controller can route it through the approval queue."
)


def analyze_events(events: list[dict], question: str = "") -> dict:
    """Summarize+analyze recent events. Caller has already filtered to relevant ones."""
    if not events:
        return {"ok": False, "error": "no events provided"}
    # Trim each event to a compact line
    lines = []
    for ev in events[-30:]:
        line = (f"{ev.get('ts',0):.0f} {ev.get('severity','?')} "
                f"{ev.get('category','?')} {ev.get('source','?')}: "
                f"{(ev.get('message') or '')[:160]}")
        lines.append(line)
    body = "Recent events:\n" + "\n".join(lines)
    if question:
        body += f"\n\nUser-Frage: {question}"
    return ask(body, system=SYSTEM_TRIAGE, max_tokens=600)


SYSTEM_LEARNING = (
    "You are AEGIS's self-reflection process. Your job: look at the recent events "
    "and identify ONE non-obvious pattern that future-AEGIS should remember. "
    "Output strictly in this format:\n\n"
    "TITLE: <short title>\n"
    "SECTION: performance | bugs\n"
    "BODY:\n<two paragraphs max>\n\n"
    "If you have nothing valuable to add, respond with 'NO-PROPOSAL'. "
    "Never invent observations not present in the input."
)


def propose_learning(events: list[dict]) -> dict:
    """Returns a proposal for AEGIS_LEARNINGS.md. Caller routes through consent."""
    lines = []
    for ev in events[-50:]:
        lines.append(f"{ev.get('severity','?')} {ev.get('source','?')}: "
                     f"{(ev.get('message') or '')[:120]}")
    body = "Events:\n" + "\n".join(lines)
    r = ask(body, system=SYSTEM_LEARNING, max_tokens=400)
    if not r.get("ok"):
        return r
    text = r["text"]
    if "NO-PROPOSAL" in text.upper():
        return {"ok": True, "proposal": None}
    m_title = re.search(r"TITLE:\s*(.+)", text)
    m_sec = re.search(r"SECTION:\s*(performance|bugs)", text, re.I)
    m_body = re.search(r"BODY:\s*(.+)", text, re.S)
    if not (m_title and m_sec and m_body):
        return {"ok": False, "error": "malformed proposal"}
    return {"ok": True, "proposal": {
        "title": m_title.group(1).strip()[:120],
        "section": m_sec.group(1).lower(),
        "body": m_body.group(1).strip(),
    }}
