"""
AEGIS SQLite database layer.

Speichert:
- events: alle Beobachtungen mit Severity + Source + Kategorie + Detail-JSON
- files: jede gesehene Datei mit Hash, First-Seen, Status
- connections: Netzwerk-Verbindungen mit Prozess-Attribution
- quarantine: in Vault verschobene Dateien, warten auf Approve/Deny
- domains: bekannte Tracker/Phishing-Domains, geblockt-am
- decisions: User-Entscheidungen ueber Files/Domains/Prozesse (zur Wiederverwendung)
"""

import sqlite3
import json
import time
import threading
from pathlib import Path
from typing import Any, Optional


# Default GitHub repo for auto-updates (patched by setup_github.py)
_DEFAULT_UPDATE_REPO = "user0346/aegis"

# Default DB-Pfad - im User-AppData damit nicht admin-rechte-pflichtig
DB_DIR = Path.home() / ".aegis"
DB_PATH = DB_DIR / "aegis.sqlite"


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    severity      TEXT NOT NULL,        -- INFO, WARN, THREAT, CRITICAL, QUARANTINE
    category      TEXT NOT NULL,        -- FILE, PROCESS, NETWORK, DNS, URL, SYSTEM
    source        TEXT,                 -- module name that emitted
    message       TEXT NOT NULL,
    metadata      TEXT,                 -- JSON blob with details
    acknowledged  INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);

CREATE TABLE IF NOT EXISTS files (
    sha256        TEXT PRIMARY KEY,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    size          INTEGER,
    path          TEXT,                 -- last known path
    source_url    TEXT,                 -- if from download with source
    status        TEXT NOT NULL,        -- unknown, clean, quarantined, blocked, allowed
    vt_result     TEXT,                 -- JSON from VirusTotal lookup
    vt_checked_at REAL,
    notes         TEXT
);

CREATE TABLE IF NOT EXISTS connections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    pid           INTEGER,
    process_name  TEXT,
    process_exe   TEXT,
    laddr         TEXT,
    raddr         TEXT,
    rport         INTEGER,
    direction     TEXT,                 -- in / out
    protocol      TEXT,                 -- tcp / udp
    state         TEXT
);
CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(ts DESC);
CREATE INDEX IF NOT EXISTS idx_conn_pid ON connections(pid);
CREATE INDEX IF NOT EXISTS idx_conn_raddr ON connections(raddr);

CREATE TABLE IF NOT EXISTS quarantine (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT NOT NULL,
    original_path   TEXT NOT NULL,
    vault_path      TEXT NOT NULL,
    quarantined_at  REAL NOT NULL,
    reason          TEXT,
    status          TEXT NOT NULL,      -- pending, approved, denied, deleted
    decided_at      REAL,
    decided_by      TEXT,
    decision_notes  TEXT
);

CREATE TABLE IF NOT EXISTS domains (
    domain          TEXT PRIMARY KEY,
    category        TEXT NOT NULL,      -- tracker, ad, phishing, ip-logger, malware
    source          TEXT,               -- which feed contributed
    blocked         INTEGER DEFAULT 1,
    added_at        REAL NOT NULL,
    hit_count       INTEGER DEFAULT 0,
    last_hit        REAL
);
CREATE INDEX IF NOT EXISTS idx_domains_cat ON domains(category);

CREATE TABLE IF NOT EXISTS decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_type    TEXT NOT NULL,      -- file_hash, domain, process_path, url
    subject_value   TEXT NOT NULL,
    decision        TEXT NOT NULL,      -- allow, deny
    rationale       TEXT,
    created_at      REAL NOT NULL,
    expires_at      REAL                -- NULL = forever
);
CREATE INDEX IF NOT EXISTS idx_dec_subj ON decisions(subject_type, subject_value);

CREATE TABLE IF NOT EXISTS sources (
    source_ip       TEXT PRIMARY KEY,
    first_seen      REAL NOT NULL,
    last_seen       REAL NOT NULL,
    hit_count       INTEGER DEFAULT 1,
    flag            TEXT,               -- portscan, flood, normal
    blocked         INTEGER DEFAULT 0,
    blocked_at      REAL
);

CREATE TABLE IF NOT EXISTS settings (
    key             TEXT PRIMARY KEY,
    value           TEXT
);

-- Pattern-Calibration: angepasste Scores fuer Heuristik-Pattern basierend
-- auf User-Entscheidungen (Approve/Deny aus der Quarantine-UI).
CREATE TABLE IF NOT EXISTS pattern_calibration (
    pattern_key     TEXT PRIMARY KEY,
    category        TEXT NOT NULL,
    base_score      INTEGER NOT NULL,
    adjust          INTEGER DEFAULT 0,
    n_approved      INTEGER DEFAULT 0,
    n_denied        INTEGER DEFAULT 0,
    last_updated    REAL NOT NULL
);

-- Learning-Metriken: zeigt dem User wieviel das System gelernt hat.
CREATE TABLE IF NOT EXISTS learning_metrics (
    metric_key      TEXT PRIMARY KEY,
    value           REAL NOT NULL,
    updated_at      REAL NOT NULL
);

-- Persistente Baseline / Pattern-Memory: was ist auf DIESEM PC normal?
-- status: learning (neu/lernend) -> known (>=3 Sichtungen oder >=24h)
CREATE TABLE IF NOT EXISTS baseline (
    kind        TEXT NOT NULL,
    ident       TEXT NOT NULL,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    seen_count  INTEGER NOT NULL DEFAULT 1,
    status      TEXT NOT NULL DEFAULT 'learning',
    PRIMARY KEY (kind, ident)
);
"""


class Database:
    """
    Thread-sicherer SQLite-Wrapper. Eine connection pro Thread via thread-local.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.path = db_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            c = sqlite3.connect(str(self.path), timeout=10, isolation_level=None,
                                check_same_thread=False)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.row_factory = sqlite3.Row
            self._local.conn = c
        return self._local.conn

    def _init_schema(self):
        with self._init_lock:
            c = self._conn()
            c.executescript(SCHEMA)

    # ------------ Events ------------
    def log_event(self, severity: str, category: str, message: str,
                  source: str = "", metadata: Optional[dict] = None) -> int:
        ts = time.time()
        md = json.dumps(metadata) if metadata else None
        cur = self._conn().execute(
            "INSERT INTO events (ts, severity, category, source, message, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, severity, category, source, message, md)
        )
        return cur.lastrowid or 0

    def recent_events(self, limit: int = 500,
                      severity: Optional[str] = None,
                      category: Optional[str] = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM events"
        params: list = []
        clauses = []
        if severity and severity != "ALL":
            clauses.append("severity = ?")
            params.append(severity)
        if category and category != "ALL":
            clauses.append("category = ?")
            params.append(category)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        return list(self._conn().execute(q, params).fetchall())

    def count_events_last(self, seconds: int = 3600,
                          severity: Optional[str] = None) -> int:
        since = time.time() - seconds
        if severity:
            r = self._conn().execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ? AND severity = ?",
                (since, severity)
            ).fetchone()
        else:
            r = self._conn().execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ?", (since,)
            ).fetchone()
        return r[0] if r else 0

    # ------------ Files ------------
    def upsert_file(self, sha256: str, path: str, size: int,
                    source_url: str = "", status: str = "unknown") -> bool:
        """
        Returns True if file is NEW (first-seen), False if already known.
        """
        now = time.time()
        existing = self._conn().execute(
            "SELECT sha256 FROM files WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if existing:
            self._conn().execute(
                "UPDATE files SET last_seen = ?, path = ? WHERE sha256 = ?",
                (now, path, sha256)
            )
            return False
        self._conn().execute(
            "INSERT INTO files (sha256, first_seen, last_seen, size, path, "
            "source_url, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sha256, now, now, size, path, source_url, status)
        )
        return True

    def set_file_status(self, sha256: str, status: str, notes: str = ""):
        self._conn().execute(
            "UPDATE files SET status = ?, notes = ? WHERE sha256 = ?",
            (status, notes, sha256)
        )

    def get_file(self, sha256: str) -> Optional[sqlite3.Row]:
        return self._conn().execute(
            "SELECT * FROM files WHERE sha256 = ?", (sha256,)
        ).fetchone()

    def files_by_status(self, status: str, limit: int = 200) -> list[sqlite3.Row]:
        return list(self._conn().execute(
            "SELECT * FROM files WHERE status = ? ORDER BY first_seen DESC LIMIT ?",
            (status, limit)
        ).fetchall())

    def set_vt_result(self, sha256: str, vt_data: dict):
        self._conn().execute(
            "UPDATE files SET vt_result = ?, vt_checked_at = ? WHERE sha256 = ?",
            (json.dumps(vt_data), time.time(), sha256)
        )

    # ------------ Connections ------------
    def log_connection(self, pid: int, process_name: str, process_exe: str,
                       laddr: str, raddr: str, rport: int,
                       direction: str, protocol: str, state: str):
        self._conn().execute(
            "INSERT INTO connections (ts, pid, process_name, process_exe, "
            "laddr, raddr, rport, direction, protocol, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), pid, process_name, process_exe,
             laddr, raddr, rport, direction, protocol, state)
        )

    def recent_connections(self, limit: int = 200) -> list[sqlite3.Row]:
        return list(self._conn().execute(
            "SELECT * FROM connections ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall())

    def prune_connections(self, keep_days: int = 7):
        cutoff = time.time() - (keep_days * 86400)
        self._conn().execute(
            "DELETE FROM connections WHERE ts < ?", (cutoff,)
        )

    # ------------ Quarantine ------------
    def add_quarantine(self, sha256: str, original_path: str,
                       vault_path: str, reason: str) -> int:
        cur = self._conn().execute(
            "INSERT INTO quarantine (sha256, original_path, vault_path, "
            "quarantined_at, reason, status) VALUES (?, ?, ?, ?, ?, 'pending')",
            (sha256, original_path, vault_path, time.time(), reason)
        )
        return cur.lastrowid or 0

    def pending_quarantine(self) -> list[sqlite3.Row]:
        return list(self._conn().execute(
            "SELECT q.*, f.size, f.source_url, f.vt_result FROM quarantine q "
            "LEFT JOIN files f ON f.sha256 = q.sha256 "
            "WHERE q.status = 'pending' ORDER BY q.quarantined_at DESC"
        ).fetchall())

    def all_quarantine(self, limit: int = 200) -> list[sqlite3.Row]:
        return list(self._conn().execute(
            "SELECT q.*, f.size, f.source_url FROM quarantine q "
            "LEFT JOIN files f ON f.sha256 = q.sha256 "
            "ORDER BY q.quarantined_at DESC LIMIT ?", (limit,)
        ).fetchall())

    def decide_quarantine(self, qid: int, decision: str, notes: str = ""):
        """decision: approved | denied | deleted"""
        self._conn().execute(
            "UPDATE quarantine SET status = ?, decided_at = ?, "
            "decision_notes = ? WHERE id = ?",
            (decision, time.time(), notes, qid)
        )

    # ------------ Domains / Sinkhole ------------
    def add_domain(self, domain: str, category: str, source: str = ""):
        try:
            self._conn().execute(
                "INSERT INTO domains (domain, category, source, added_at) "
                "VALUES (?, ?, ?, ?)",
                (domain.lower(), category, source, time.time())
            )
        except sqlite3.IntegrityError:
            pass  # already exists

    def is_blocked_domain(self, domain: str) -> Optional[sqlite3.Row]:
        return self._conn().execute(
            "SELECT * FROM domains WHERE domain = ? AND blocked = 1",
            (domain.lower(),)
        ).fetchone()

    def domains_by_category(self, category: str, limit: int = 500) -> list[sqlite3.Row]:
        return list(self._conn().execute(
            "SELECT * FROM domains WHERE category = ? ORDER BY domain LIMIT ?",
            (category, limit)
        ).fetchall())

    def all_blocked_domains(self) -> list[sqlite3.Row]:
        return list(self._conn().execute(
            "SELECT * FROM domains WHERE blocked = 1 ORDER BY category, domain"
        ).fetchall())

    def domain_count_by_category(self) -> dict[str, int]:
        rows = self._conn().execute(
            "SELECT category, COUNT(*) as c FROM domains WHERE blocked = 1 GROUP BY category"
        ).fetchall()
        return {r["category"]: r["c"] for r in rows}

    # ------------ Decisions ------------
    def record_decision(self, subject_type: str, subject_value: str,
                        decision: str, rationale: str = ""):
        self._conn().execute(
            "INSERT INTO decisions (subject_type, subject_value, decision, "
            "rationale, created_at) VALUES (?, ?, ?, ?, ?)",
            (subject_type, subject_value, decision, rationale, time.time())
        )

    def get_decision(self, subject_type: str, subject_value: str) -> Optional[str]:
        r = self._conn().execute(
            "SELECT decision FROM decisions WHERE subject_type = ? "
            "AND subject_value = ? ORDER BY created_at DESC LIMIT 1",
            (subject_type, subject_value)
        ).fetchone()
        return r["decision"] if r else None

    # ------------ Source IPs (for portscan/flood) ------------
    def touch_source(self, source_ip: str) -> int:
        """Increment hit count for a source IP. Returns new count."""
        now = time.time()
        r = self._conn().execute(
            "SELECT hit_count FROM sources WHERE source_ip = ?", (source_ip,)
        ).fetchone()
        if r:
            new_count = r["hit_count"] + 1
            self._conn().execute(
                "UPDATE sources SET hit_count = ?, last_seen = ? WHERE source_ip = ?",
                (new_count, now, source_ip)
            )
            return new_count
        self._conn().execute(
            "INSERT INTO sources (source_ip, first_seen, last_seen) VALUES (?, ?, ?)",
            (source_ip, now, now)
        )
        return 1

    def flag_source(self, source_ip: str, flag: str):
        self._conn().execute(
            "UPDATE sources SET flag = ? WHERE source_ip = ?",
            (flag, source_ip)
        )

    # ------------ Settings ------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        r = self._conn().execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        if not r:
            return default
        try:
            return json.loads(r["value"])
        except (json.JSONDecodeError, TypeError):
            return r["value"]

    def set_setting(self, key: str, value: Any):
        v = json.dumps(value) if not isinstance(value, str) else value
        self._conn().execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, v)
        )

    # ------------ Baseline / Pattern-Memory ------------
    def baseline_observe(self, kind: str, ident: str) -> dict:
        """Sichtung erfassen. learning -> known nach >=3 Sichtungen oder >=24h."""
        now = time.time()
        c = self._conn()
        r = c.execute("SELECT first_seen, seen_count, status FROM baseline "
                      "WHERE kind=? AND ident=?", (kind, ident)).fetchone()
        if r is None:
            c.execute("INSERT INTO baseline (kind, ident, first_seen, last_seen, seen_count, status) "
                      "VALUES (?, ?, ?, ?, 1, 'learning')", (kind, ident, now, now))
            return {"status": "learning", "seen_count": 1, "age_s": 0.0, "is_new": True}
        fs = r["first_seen"]; cnt = r["seen_count"] + 1; st = r["status"]
        if st == "learning" and (cnt >= 3 or (now - fs) >= 86400):
            st = "known"
        c.execute("UPDATE baseline SET last_seen=?, seen_count=?, status=? "
                  "WHERE kind=? AND ident=?", (now, cnt, st, kind, ident))
        return {"status": st, "seen_count": cnt, "age_s": now - fs, "is_new": False}

    def baseline_counts(self) -> dict:
        rows = self._conn().execute(
            "SELECT status, COUNT(*) AS c FROM baseline GROUP BY status").fetchall()
        m = {row["status"]: row["c"] for row in rows}
        return {"known": m.get("known", 0), "learning": m.get("learning", 0),
                "total": sum(m.values())}

    # ------------ Stats ------------
    def stats(self) -> dict:
        c = self._conn()
        return {
            "events_24h":     c.execute("SELECT COUNT(*) FROM events WHERE ts >= ?",
                                        (time.time() - 86400,)).fetchone()[0],
            "threats_24h":    c.execute("SELECT COUNT(*) FROM events WHERE ts >= ? "
                                        "AND severity IN ('THREAT', 'CRITICAL')",
                                        (time.time() - 86400,)).fetchone()[0],
            "files_total":    c.execute("SELECT COUNT(*) FROM files").fetchone()[0],
            "files_unknown":  c.execute("SELECT COUNT(*) FROM files WHERE status = 'unknown'").fetchone()[0],
            "quarantine_pending": c.execute("SELECT COUNT(*) FROM quarantine WHERE status = 'pending'").fetchone()[0],
            "connections_1h": c.execute("SELECT COUNT(*) FROM connections WHERE ts >= ?",
                                        (time.time() - 3600,)).fetchone()[0],
            "domains_blocked":c.execute("SELECT COUNT(*) FROM domains WHERE blocked = 1").fetchone()[0],
        }

    def calibration_get(self, pattern_key):
        return self._conn().execute(
            "SELECT * FROM pattern_calibration WHERE pattern_key = ?", (pattern_key,)
        ).fetchone()

    def calibration_record_decision(self, pattern_key, category, base_score, decision):
        now = time.time()
        delta_adj = -5 if decision == "approved" else 3
        d_app = 1 if decision == "approved" else 0
        d_den = 0 if decision == "approved" else 1
        self._conn().execute(
            "INSERT INTO pattern_calibration "
            "(pattern_key, category, base_score, adjust, n_approved, n_denied, last_updated) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(pattern_key) DO UPDATE SET "
            "  adjust = adjust + ?, n_approved = n_approved + ?, "
            "  n_denied = n_denied + ?, last_updated = ?",
            (pattern_key, category, base_score, delta_adj, d_app, d_den, now,
             delta_adj, d_app, d_den, now))

    def calibration_effective_score(self, pattern_key, base_score):
        row = self.calibration_get(pattern_key)
        if not row:
            return base_score
        adj = max(-30, min(30, row["adjust"]))
        return max(0, min(100, base_score + adj))

    def calibration_all(self, limit=100):
        return list(self._conn().execute(
            "SELECT * FROM pattern_calibration ORDER BY ABS(adjust) DESC LIMIT ?",
            (limit,)).fetchall())

    def set_metric(self, key, value):
        self._conn().execute(
            "INSERT INTO learning_metrics (metric_key, value, updated_at) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(metric_key) DO UPDATE SET "
            "  value = excluded.value, updated_at = excluded.updated_at",
            (key, value, time.time()))

    def inc_metric(self, key, by=1.0):
        self._conn().execute(
            "INSERT INTO learning_metrics (metric_key, value, updated_at) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(metric_key) DO UPDATE SET "
            "  value = value + ?, updated_at = ?",
            (key, by, time.time(), by, time.time()))

    def all_metrics(self):
        rows = self._conn().execute(
            "SELECT metric_key, value FROM learning_metrics").fetchall()
        return {r["metric_key"]: r["value"] for r in rows}


_db_instance = None

def get_db():
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance