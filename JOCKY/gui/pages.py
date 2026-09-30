from collections import deque
from pathlib import Path

from PySide6.QtCharts import (QBarCategoryAxis, QBarSeries, QBarSet, QChart, QChartView, QLineSeries, QPieSeries,
                              QValueAxis)
from PySide6.QtCore import QRegularExpression, Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QFont, QPainter, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QPlainTextEdit, QPushButton, QSplitter, QTabWidget, QVBoxLayout, QWidget)

from gui.common import SEV_COLOR, DataTable, Worker
from jocky import store
from jocky.core import REPORTS, ROOT

MONO = QFont("Consolas", 10)
MONO.setStyleHint(QFont.Monospace)


def title(text):
    l = QLabel(text)
    l.setObjectName("h2")
    return l


def button(text, slot):
    b = QPushButton(text)
    b.clicked.connect(lambda _=False: slot())
    return b


def make_chart(t):
    c = QChart()
    c.setTitle(t)
    c.setTheme(QChart.ChartThemeDark)
    c.setBackgroundBrush(QColor("#111c33"))
    c.legend().setLabelColor(QColor("#d6deeb"))
    v = QChartView(c)
    v.setRenderHint(QPainter.Antialiasing)
    v.setMinimumHeight(220)
    return c, v


class Card(QFrame):
    def __init__(self, label):
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(label))
        self.val = QLabel("-")
        self.val.setObjectName("big")
        lay.addWidget(self.val)


# ------------------------------------------------------------------ Dashboard
class Dashboard(QWidget):
    def __init__(self, core):
        super().__init__()
        self.core, self.hist = core, deque(maxlen=60)
        lay = QVBoxLayout(self)
        lay.addWidget(title("Dashboard"))
        row = QHBoxLayout()
        self.cards = {k: Card(k) for k in ("Processes", "Connections", "Persistence", "Files hashed", "Open alerts", "Risk")}
        for c in self.cards.values():
            row.addWidget(c)
        lay.addLayout(row)
        charts = QHBoxLayout()
        self.pie, pv = make_chart("Open alerts by severity")
        self.line, lv = make_chart("CPU / Memory % (live)")
        self.bar, bv = make_chart("Top processes by memory (MB)")
        for v in (pv, lv, bv):
            charts.addWidget(v)
        lay.addLayout(charts)
        lay.addWidget(QLabel("Latest alerts"))
        self.table = DataTable(["timestamp", "severity", "status", "rule", "reason"], "severity")
        lay.addWidget(self.table)

    def refresh(self, live=False):
        d, alerts = self.core.data, store.get_alerts()
        openal = [a for a in alerts if a["status"] != "Resolved"]
        r = self.core.risk()
        vals = {"Processes": len(d["processes"]), "Connections": len(d["connections"]), "Persistence": len(d["persistence"]),
                "Files hashed": len(d["files"]), "Open alerts": len(openal), "Risk": f"{r['score']} {r['level']}"}
        for k, v in vals.items():
            self.cards[k].val.setText(str(v))
        self.pie.removeAllSeries()
        s = QPieSeries()
        for sev in ("critical", "high", "medium", "low"):
            n = sum(a["severity"] == sev for a in openal)
            if n:
                sl = s.append(f"{sev} ({n})", n)
                sl.setColor(QColor(SEV_COLOR[sev]))
                sl.setLabelVisible(True)
                sl.setLabelColor(QColor("white"))
        self.pie.addSeries(s)
        if live:
            self.hist.append((d["cpu"], d["mem"]))
        self.line.removeAllSeries()
        for ax in self.line.axes():
            self.line.removeAxis(ax)
        cpu, mem = QLineSeries(), QLineSeries()
        cpu.setName("CPU")
        mem.setName("Memory")
        for i, (c, m) in enumerate(self.hist):
            cpu.append(i, c)
            mem.append(i, m)
        self.line.addSeries(cpu)
        self.line.addSeries(mem)
        self.line.createDefaultAxes()
        self.line.axes(Qt.Vertical)[0].setRange(0, 100)
        self.bar.removeAllSeries()
        for ax in self.bar.axes():
            self.bar.removeAxis(ax)
        top = sorted(d["processes"], key=lambda p: -p.get("memory_mb", 0))[:6]
        bs, bset = QBarSeries(), QBarSet("MB")
        bset.setColor(QColor("#38bdf8"))
        for p in top:
            bset.append(p.get("memory_mb", 0))
        bs.append(bset)
        self.bar.addSeries(bs)
        ax, ay = QBarCategoryAxis(), QValueAxis()
        ax.append([(p.get("name") or "?")[:10] for p in top])
        ay.setRange(0, max([p.get("memory_mb", 0) for p in top] + [10]) * 1.1)
        self.bar.addAxis(ax, Qt.AlignBottom)
        self.bar.addAxis(ay, Qt.AlignLeft)
        bs.attachAxis(ax)
        bs.attachAxis(ay)
        self.table.set(alerts[:8])


# ------------------------------------------------------------------ evidence pages (one per backend collector)
class CollectPage(QWidget):
    """Generic page: 'Collect' button runs the original CLI command, table shows the saved evidence file."""

    def __init__(self, core, run_cmd, name, cmd, fn, key, evfile, cols, dir_input=False):
        super().__init__()
        self.core, self.run_cmd, self.cmd, self.fn, self.key, self.evfile, self.dir_input = core, run_cmd, cmd, fn, key, evfile, dir_input
        lay = QVBoxLayout(self)
        lay.addWidget(title(name))
        bar = QHBoxLayout()
        if dir_input:
            self.dir = QLineEdit(core.data["files_dir"] or "scripts")
            bar.addWidget(QLabel("Directory:"))
            bar.addWidget(self.dir)
            bar.addWidget(button("Browse...", self.browse))
        bar.addWidget(button(f"Collect  (jocky {cmd})", self.collect))
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter...")
        self.search.textChanged.connect(self.refresh)
        bar.addWidget(self.search)
        lay.addLayout(bar)
        self.info = QLabel()
        lay.addWidget(self.info)
        self.table = DataTable(cols)
        lay.addWidget(self.table)

    def browse(self):
        p = QFileDialog.getExistingDirectory(self, "Choose directory", self.dir.text())
        if p:
            self.dir.setText(p)

    def collect(self):
        if self.dir_input:
            d = self.dir.text().strip()
            self.run_cmd(f'jocky files "{d}"', self.fn, Path(d))
        else:
            self.run_cmd(f"jocky {self.cmd}", self.fn)

    def refresh(self):
        rows = self.core.data[self.key]
        self.table.set(rows, self.search.text())
        i = self.core.evidence_info(self.evfile)
        self.info.setText(f"{len(rows)} records  ·  evidence: {i['path']}  ·  saved {i['saved']}  ·  SHA-256 {i['sha256']}" if i
                          else f"{len(rows)} records (live)  ·  no evidence file yet - click Collect to save one")


class SystemPage(QWidget):
    def __init__(self, core, run_cmd, fn):
        super().__init__()
        self.core = core
        lay = QVBoxLayout(self)
        lay.addWidget(title("System"))
        bar = QHBoxLayout()
        bar.addWidget(button("Collect  (jocky system-info)", lambda: run_cmd("jocky system-info", fn)))
        bar.addWidget(button("Load local users", self.load_users))
        bar.addStretch()
        lay.addLayout(bar)
        self.info = QLabel()
        lay.addWidget(self.info)
        self.tabs = QTabWidget()
        self.sys = DataTable(["key", "value"])
        self.usr = DataTable(["username", "enabled", "last_logon", "sid", "user_id", "group_id", "home_directory", "shell", "is_current_user"])
        self.tabs.addTab(self.sys, "System information")
        self.tabs.addTab(self.usr, "Local users")
        lay.addWidget(self.tabs)

    def load_users(self):
        self.usr.set(self.core.users())
        self.tabs.setCurrentIndex(1)

    def refresh(self):
        self.sys.set([{"key": k, "value": v} for k, v in self.core.data["system"].items()])
        i = self.core.evidence_info("system_info.json")
        self.info.setText(f"evidence: {i['path']}  ·  saved {i['saved']}  ·  SHA-256 {i['sha256']}" if i else "no system_info evidence yet - click Collect")


# ------------------------------------------------------------------ IDE
class Highlighter(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)

        def fmt(color, bold=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Bold)
            return f
        self.rules = [(QRegularExpression(r"\b(scan|report)\b"), fmt("#38bdf8", True)),
                      (QRegularExpression(r"\b(system|processes|network|files|persistence)\b"), fmt("#a78bfa")),
                      (QRegularExpression(r'"[^"]*"'), fmt("#facc15")),
                      (QRegularExpression(r"#[^\n]*"), fmt("#64748b"))]

    def highlightBlock(self, text):
        for rx, f in self.rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), f)


class IDE(QWidget):
    def __init__(self, core, on_change):
        super().__init__()
        self.core, self.on_change, self.worker = core, on_change, None
        lay = QVBoxLayout(self)
        lay.addWidget(title("JOCKY IDE"))
        bar = QHBoxLayout()
        self.examples = QComboBox()
        for p in sorted((ROOT / "scripts").glob("*.jky")):
            self.examples.addItem(p.name, str(p))
        self.examples.activated.connect(lambda _: self.load(self.examples.currentData()))
        bar.addWidget(QLabel("Script:"))
        bar.addWidget(self.examples)
        for t, s in (("Open...", self.open), ("Save...", self.save)):
            bar.addWidget(button(t, s))
        for t, m in (("Parse (AST)", "parse"), ("Compile (IR)", "compile"), ("▶ Run", "run"), ("Investigate", "investigate")):
            bar.addWidget(button(t, lambda m=m: self.go(m)))
        bar.addStretch()
        lay.addLayout(bar)
        self.editor = QPlainTextEdit()
        self.editor.setFont(MONO)
        Highlighter(self.editor.document())
        self.out = QPlainTextEdit()
        self.out.setFont(MONO)
        self.out.setReadOnly(True)
        sp = QSplitter(Qt.Vertical)
        sp.addWidget(self.editor)
        sp.addWidget(self.out)
        lay.addWidget(sp)
        if self.examples.count():
            self.load(self.examples.itemData(0))

    def load(self, path):
        self.editor.setPlainText(Path(path).read_text(encoding="utf-8"))

    def open(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open script", str(ROOT / "scripts"), "JOCKY (*.jky);;All (*)")
        if p:
            self.load(p)

    def save(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save script", str(ROOT / "scripts"), "JOCKY (*.jky)")
        if p:
            Path(p).write_text(self.editor.toPlainText(), encoding="utf-8")

    def go(self, mode):
        if self.worker and self.worker.isRunning():
            return
        self.out.setPlainText(f"$ jocky {mode} <script>\n")
        src = self.editor.toPlainText()
        self.worker = Worker(lambda log: self.core.ide(mode, src))
        self.worker.done.connect(lambda r: (self.out.appendPlainText(r[0]), self.on_change()))
        self.worker.failed.connect(lambda e: self.out.appendPlainText("ERROR: " + e))
        self.worker.start()


# ------------------------------------------------------------------ Alerts
class Alerts(QWidget):
    def __init__(self, core, on_change):
        super().__init__()
        self.core, self.on_change = core, on_change
        lay = QVBoxLayout(self)
        lay.addWidget(title("Alerts (detection findings)"))
        bar = QHBoxLayout()
        self.status = QComboBox()
        self.status.addItems(["All", "New", "Investigating", "Resolved"])
        self.status.currentIndexChanged.connect(self.refresh)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search...")
        self.search.textChanged.connect(self.refresh)
        bar.addWidget(self.status)
        bar.addWidget(self.search)
        for s in ("New", "Investigating", "Resolved"):
            bar.addWidget(button(f"Mark {s}", lambda s=s: self.mark(s)))
        lay.addLayout(bar)
        self.table = DataTable(["id", "timestamp", "host", "severity", "rule", "reason", "status"], "severity")
        lay.addWidget(self.table)

    def refresh(self):
        rows = store.get_alerts()
        if self.status.currentText() != "All":
            rows = [r for r in rows if r["status"] == self.status.currentText()]
        self.table.set(rows, self.search.text())

    def mark(self, status):
        aid = self.table.selected(0)
        if aid:
            self.core.set_alert_status(aid, status)
            self.on_change()


# ------------------------------------------------------------------ Evidence
class Evidence(QWidget):
    def __init__(self, core):
        super().__init__()
        self.core = core
        lay = QVBoxLayout(self)
        lay.addWidget(title("Evidence (chain of custody)"))
        bar = QHBoxLayout()
        bar.addWidget(button("Verify integrity (re-hash SHA-256)", self.verify))
        bar.addWidget(button("Open evidence folder", lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(ROOT / "evidence")))))
        bar.addStretch()
        lay.addLayout(bar)
        self.table = DataTable(["id", "evidence_type", "integrity", "sha256", "collected_at", "file_path"], "integrity")
        lay.addWidget(self.table)

    def refresh(self):
        self.table.set(self.core.evidence_rows())

    def verify(self):
        self.table.set(self.core.verify_evidence())


# ------------------------------------------------------------------ Cases / Reports
class Cases(QWidget):
    def __init__(self, core, log):
        super().__init__()
        self.core, self.log, self.worker = core, log, None
        lay = QVBoxLayout(self)
        lay.addWidget(title("Cases / Reports"))
        bar = QHBoxLayout()
        self.title_in = QLineEdit()
        self.title_in.setPlaceholderText("New case title...")
        self.sev = QComboBox()
        self.sev.addItems(["medium", "low", "high", "critical"])
        bar.addWidget(self.title_in)
        bar.addWidget(self.sev)
        for t, s in (("Create case", self.create), ("Generate report  (jocky report)", self.report), ("Export report...", self.export),
                     ("Open reports folder", lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(ROOT / "reports"))))):
            bar.addWidget(button(t, s))
        lay.addLayout(bar)
        sp = QSplitter(Qt.Vertical)
        self.cases = DataTable(["id", "title", "severity", "status", "investigator", "created", "report_file"], "severity")
        self.viewer = QPlainTextEdit()
        self.viewer.setFont(MONO)
        self.viewer.setReadOnly(True)
        last = REPORTS / "forensic_report.txt"
        if last.exists():
            self.viewer.setPlainText(last.read_text(encoding="utf-8"))
        sp.addWidget(self.cases)
        sp.addWidget(self.viewer)
        lay.addWidget(sp)

    def refresh(self):
        self.cases.set(store.get_cases())

    def create(self):
        t = self.title_in.text().strip()
        if t:
            self.core.create_case(t, self.sev.currentText())
            self.title_in.clear()
            self.refresh()

    def report(self):
        if self.worker and self.worker.isRunning():
            return
        cid = self.cases.selected(0)
        case = next((c for c in store.get_cases() if c["id"] == cid), None)
        self.log("$ jocky report" + (f"   (case {cid})" if case else ""))
        self.worker = Worker(lambda log: self.core.make_report(case))
        self.worker.done.connect(self.done)
        self.worker.failed.connect(lambda e: self.log("ERROR: " + e))
        self.worker.start()

    def done(self, r):
        text, path, _ = r
        self.viewer.setPlainText(text)
        self.log(f"[+] report saved: {path}")
        self.refresh()

    def export(self):
        text = self.viewer.toPlainText()
        if not text:
            return QMessageBox.information(self, "Export", "Generate a report first.")
        p, _ = QFileDialog.getSaveFileName(self, "Export report", "jocky_report.txt", "Text (*.txt)")
        if p:
            Path(p).write_text(text, encoding="utf-8")


# ------------------------------------------------------------------ Audit
class Audit(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addWidget(title("Audit Logs"))
        self.table = DataTable(["timestamp", "action", "detail"])
        lay.addWidget(self.table)

    def refresh(self):
        self.table.set(store.get_audit())
