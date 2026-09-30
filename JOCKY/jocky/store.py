"""GUI-only tables (alerts, cases, audit) in the same evidence/jocky.db. The original `evidence` table is untouched."""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB = Path("evidence/jocky.db")
SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, host TEXT, rule TEXT, severity TEXT, target TEXT,
    reason TEXT, timestamp TEXT, status TEXT DEFAULT 'New');
CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, title TEXT, severity TEXT, status TEXT, investigator TEXT,
    created TEXT, report_file TEXT);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, action TEXT, detail TEXT);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rows(sql, args=()):
    with sqlite3.connect(DB, timeout=10) as c:
        c.row_factory = sqlite3.Row
        return [dict(r) for r in c.execute(sql, args).fetchall()]


def _run(sql, args=()):
    with sqlite3.connect(DB, timeout=10) as c:
        return c.execute(sql, args).rowcount


def init():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB) as c:
        c.executescript(SCHEMA)


def add_alert(f):     # INSERT OR IGNORE on a stable id: the same finding is never duplicated
    return _run("INSERT OR IGNORE INTO alerts (id,host,rule,severity,target,reason,timestamp) VALUES (?,?,?,?,?,?,?)",
                (f["id"], f["host"], f["rule"], f["severity"], f["target"], f["reason"], now())) > 0


def get_alerts():
    return _rows("SELECT * FROM alerts ORDER BY timestamp DESC, id")


def set_alert_status(i, status):
    _run("UPDATE alerts SET status=? WHERE id=?", (status, i))


def add_case(title, severity, user):
    cid = f"CASE-{datetime.now().year}-{len(_rows('SELECT id FROM cases')) + 1:03d}"
    _run("INSERT INTO cases (id,title,severity,status,investigator,created) VALUES (?,?,?,?,?,?)", (cid, title, severity, "Open", user, now()))
    return cid


def get_cases():
    return _rows("SELECT * FROM cases ORDER BY created DESC")


def set_case_report(cid, path):
    _run("UPDATE cases SET report_file=? WHERE id=?", (path, cid))


def add_audit(action, detail=""):
    _run("INSERT INTO audit (timestamp,action,detail) VALUES (?,?,?)", (now(), action, detail))


def get_audit():
    return _rows("SELECT * FROM audit ORDER BY id DESC LIMIT 1000")
