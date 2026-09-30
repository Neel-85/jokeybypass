"""GUI facade over the ORIGINAL JOCKY backend.

Every action calls the same functions the `jocky` CLI uses (jocky/cli/main.py) and captures their console output,
so the GUI covers all backend features without re-implementing them. Results are read back from evidence/*.json.
"""
import contextlib
import getpass
import io
import json
import os
import platform
import tempfile
import threading
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)                                  # original modules use cwd-relative evidence/ and reports/ paths
os.environ.setdefault("COLUMNS", "170")         # wide rich tables in the captured console output

import psutil
import typer

from jocky import store
from jocky.cli import main as cli
from jocky.detection import rules
from jocky.evidence import database as evdb
from jocky.evidence.hash_utils import calculate_sha256
from jocky.evidence.network_collector import collect_network_connections
from jocky.evidence.process_collector import collect_processes
from jocky.evidence.user_collector import collect_users

EVIDENCE = Path("evidence")
REPORTS = Path("reports")
DB = EVIDENCE / "jocky.db"
# data key -> (evidence file, key inside the JSON)
FILES = {"processes": ("processes.json", "processes"), "connections": ("network_connections.json", "connections"),
         "persistence": ("persistence.json", "entries"), "files": ("file_hashes.json", "files")}
IDE_COMMANDS = {"parse": cli.parse, "compile": cli.compile, "run": cli.run, "investigate": cli.investigate}


class Core:
    def __init__(self):
        EVIDENCE.mkdir(exist_ok=True)
        REPORTS.mkdir(exist_ok=True)
        evdb.initialize_database(DB)
        store.init()
        self.user, self.host = getpass.getuser(), platform.node()
        self.lock = threading.Lock()
        self.data = {"system": {}, "processes": [], "connections": [], "persistence": [], "files": [], "findings": [],
                     "files_dir": "", "cpu": 0.0, "mem": 0.0, "updated": None}
        self.load()
        self.detect()

    # ---------------------------------------------------------------- evidence files -> memory
    def _read(self, name):
        try:
            return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))
        except Exception:
            return {}

    def load(self):
        d = self.data
        d["system"] = {k: v for k, v in self._read("system_info.json").items() if k != "evidence_type"}
        for k, (f, key) in FILES.items():
            d[k] = self._read(f).get(key, [])
        d["files_dir"] = self._read("file_hashes.json").get("directory", "")
        self._name_connections()

    def _name_connections(self):
        names = {p["pid"]: p["name"] for p in self.data["processes"]}
        for c in self.data["connections"]:
            c["process"] = names.get(c.get("pid"), "")

    def evidence_info(self, evfile):
        p = EVIDENCE / evfile
        if not p.exists():
            return None
        return {"path": str(p), "sha256": calculate_sha256(p), "saved": datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")}

    # ---------------------------------------------------------------- running backend (CLI) commands
    def call(self, label, fn, *args):
        """Run an original CLI function, capture its output, then refresh data/evidence DB/alerts. -> (output, ok)."""
        buf, ok = io.StringIO(), True
        with self.lock, contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                fn(*args)
            except typer.Exit as e:
                ok = e.exit_code in (0, None)
            except Exception as e:
                buf.write(f"[!] {type(e).__name__}: {e}\n")
                ok = False
        store.add_audit("COMMAND" if ok else "COMMAND_FAILED", label)
        self.after_command()
        return buf.getvalue(), ok

    def after_command(self):
        self.load()
        self.register_evidence()
        self.detect()

    def register_evidence(self):
        """Every evidence/report file gets a chain-of-custody record (id, type, path, SHA-256) when new or changed.
        (The original CLI only recorded system_info during `scan`.)"""
        last = {}
        for r in evdb.get_evidence(DB):
            last[r[2].replace("\\", "/")] = r[3]
        files = [(EVIDENCE / f) for f in ("system_info.json", "processes.json", "network_connections.json", "persistence.json",
                                        "file_hashes.json", "findings.json")] + sorted(REPORTS.glob("*.txt"))
        for p in files:
            if not p.exists():
                continue
            digest, key = calculate_sha256(p), str(p)
            if last.get(key.replace("\\", "/")) != digest:
                etype = "report" if p.parent == REPORTS else self._read(p.name).get("evidence_type", p.stem)
                evdb.add_evidence(DB, etype, key, digest, datetime.now().astimezone().isoformat(timespec="seconds"))

    def verify_evidence(self):
        """Re-hash each file and compare with the hash recorded at collection time. Files are overwritten by every new
        scan, so only the newest record per file can match; older records are marked SUPERSEDED (history, not tampering)."""
        rows = evdb.get_evidence(DB)
        newest = {}
        for i, etype, path, sha, at in rows:
            k = path.replace("\\", "/")
            newest[k] = max(newest.get(k, 0), i)
        out = []
        for i, etype, path, sha, at in rows:
            p = Path(path.replace("\\", "/"))
            if newest[path.replace("\\", "/")] != i:
                state = "SUPERSEDED"
            else:
                state = "MISSING" if not p.exists() else ("OK" if calculate_sha256(p) == sha else "MODIFIED")
            out.append({"id": i, "evidence_type": etype, "file_path": path, "sha256": sha, "collected_at": at, "integrity": state})
        store.add_audit("EVIDENCE_VERIFY", f"{len(out)} records")
        return sorted(out, key=lambda r: -r["id"])

    def evidence_rows(self):
        return [{"id": i, "evidence_type": t, "file_path": p, "sha256": s, "collected_at": a, "integrity": ""}
                for i, t, p, s, a in evdb.get_evidence(DB)][::-1]

    # ---------------------------------------------------------------- live monitor
    def live(self):
        d = self.data
        d["processes"], d["connections"] = collect_processes(), collect_network_connections()
        self._name_connections()
        d["cpu"], d["mem"] = psutil.cpu_percent(None), psutil.virtual_memory().percent
        d["updated"] = datetime.now().strftime("%H:%M:%S")
        return self.detect()

    def detect(self):
        self.data["findings"] = rules.run_all(self.data, self.host)
        return sum(store.add_alert(f) for f in self.data["findings"])

    def risk(self):
        return rules.score(self.data["findings"])

    def users(self):
        return collect_users()

    # ---------------------------------------------------------------- IDE (uses original parse/compile/run/investigate)
    def ide(self, mode, source):
        fd, tmp = tempfile.mkstemp(suffix=".jky")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(source)
        try:
            return self.call(f"jocky {mode} <IDE script>", IDE_COMMANDS[mode], Path(tmp))
        finally:
            os.remove(tmp)

    # ---------------------------------------------------------------- alerts / cases / reports
    def set_alert_status(self, alert_id, status):
        store.set_alert_status(alert_id, status)
        store.add_audit("ALERT_STATUS", f"{alert_id} -> {status}")

    def create_case(self, title, severity):
        cid = store.add_case(title, severity, self.user)
        store.add_audit("CASE_CREATE", f"{cid} {title}")
        return cid

    def make_report(self, case=None):
        """Original `jocky report` (needs system_info/processes/findings evidence: runs `jocky scan` first if missing)."""
        need = [EVIDENCE / f for f in ("system_info.json", "processes.json", "findings.json")]
        out = ""
        if not all(p.exists() for p in need):
            out += self.call("jocky scan", cli.scan)[0]
        out += self.call("jocky report", cli.report)[0]
        text = (REPORTS / "forensic_report.txt").read_text(encoding="utf-8")
        path = str(REPORTS / "forensic_report.txt")
        if case:
            head = f"CASE {case['id']} - {case['title']}  |  severity: {case['severity']}  |  investigator: {case['investigator']}\n\n"
            text = head + text
            path = str(REPORTS / f"{case['id']}_{datetime.now():%Y%m%d_%H%M%S}.txt")
            Path(path).write_text(text, encoding="utf-8")
            store.set_case_report(case["id"], path)
            self.register_evidence()
        store.add_audit("REPORT_GENERATE", path)
        return text, path, out
