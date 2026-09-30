from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDockWidget, QHBoxLayout, QLabel, QListWidget, QMainWindow,
                               QPlainTextEdit, QPushButton, QSpinBox, QStackedWidget, QVBoxLayout, QWidget)

from gui import pages
from gui.common import Worker
from jocky.cli import main as cli

STYLE = """
QWidget{background:#0b1220;color:#d6deeb;font-size:13px}
QListWidget{background:#0f1a2e;border:0;font-size:14px}QListWidget::item{padding:10px}
QListWidget::item:selected{background:#1e2d4a;color:#38bdf8}
#h2{font-size:20px;font-weight:bold;color:#e2e8f0}#big{font-size:24px;font-weight:bold;color:#38bdf8}
#card{background:#111c33;border:1px solid #1e2d4a;border-radius:8px}#card QLabel{background:transparent}
QTableWidget{background:#111c33;alternate-background-color:#0f1a2e;gridline-color:#1e2d4a;border:1px solid #1e2d4a}
QHeaderView::section{background:#1e2d4a;padding:5px;border:0}
QPushButton{background:#2563eb;color:white;border:0;padding:7px 14px;border-radius:6px}QPushButton:hover{background:#1d4ed8}
QLineEdit,QComboBox,QSpinBox{background:#020617;border:1px solid #1e2d4a;border-radius:6px;padding:5px}
QPlainTextEdit{background:#020617;color:#7dd3fc;border:1px solid #1e2d4a;border-radius:6px}
QTabWidget::pane{border:1px solid #1e2d4a}QTabBar::tab{background:#0f1a2e;padding:7px 14px}QTabBar::tab:selected{background:#1e2d4a;color:#38bdf8}
QSplitter::handle{background:#1e2d4a}QDockWidget{font-weight:bold}
"""
PROC_COLS = ["pid", "name", "username", "cpu_percent", "memory_percent", "memory_mb", "executable"]
NET_COLS = ["status", "process", "pid", "local_address", "remote_address", "family", "type"]
PERS_COLS = ["type", "location", "name", "data"]
FILE_COLS = ["name", "extension", "size", "sha256", "modified_at", "path"]


def INVESTIGATE():
    cli.investigate(Path("scripts/basic.jky"))


CONSOLE_COMMANDS = {"version": cli.version, "status": cli.status, "system-info": cli.system_info, "processes": cli.processes,
                    "network": cli.network, "persistence": cli.persistence, "scan": cli.scan, "report": cli.report,
                    "evidence": cli.evidence, "investigate (scripts/basic.jky)": INVESTIGATE}


class MainWindow(QMainWindow):
    def __init__(self, core):
        super().__init__()
        self.core, self.live_worker, self.cmd = core, None, None
        self.setWindowTitle("JOCKY v0.1.0 - Digital Forensics Framework")
        self.resize(1400, 860)
        self.setStyleSheet(STYLE)
        rc = self.run_cmd
        self.dash = pages.Dashboard(core)
        self.alerts = pages.Alerts(core, self.refresh_all)
        self.pages = {
            "Dashboard": self.dash,
            "System": pages.SystemPage(core, rc, cli.system_info),
            "Processes": pages.CollectPage(core, rc, "Processes", "processes", cli.processes, "processes", "processes.json", PROC_COLS),
            "Network": pages.CollectPage(core, rc, "Network connections", "network", cli.network, "connections", "network_connections.json", NET_COLS),
            "Persistence": pages.CollectPage(core, rc, "Persistence", "persistence", cli.persistence, "persistence", "persistence.json", PERS_COLS),
            "Files": pages.CollectPage(core, rc, "File evidence (SHA-256)", "files", cli.files, "files", "file_hashes.json", FILE_COLS, dir_input=True),
            "Alerts": self.alerts,
            "JOCKY IDE": pages.IDE(core, self.refresh_all),
            "Evidence": pages.Evidence(core),
            "Cases / Reports": pages.Cases(core, self.log),
            "Audit Logs": pages.Audit(),
        }
        self.stack = QStackedWidget()
        side = QListWidget()
        for name, w in self.pages.items():
            side.addItem(name)
            self.stack.addWidget(w)
        side.setFixedWidth(170)
        side.currentRowChanged.connect(self.switch)
        # top bar
        self.live = QCheckBox("Live monitor")
        self.live.setChecked(True)
        self.secs = QSpinBox()
        self.secs.setRange(3, 300)
        self.secs.setValue(10)
        self.secs.setSuffix(" s")
        self.secs.valueChanged.connect(lambda v: self.timer.setInterval(v * 1000))
        self.status = QLabel("starting...")
        top = QHBoxLayout()
        for w in (self.live, self.secs):
            top.addWidget(w)
        for t, s in (("Refresh now", self.tick), ("Scan  (jocky scan)", lambda: rc("jocky scan", cli.scan)),
                     ("Investigate  (basic.jky)", lambda: rc("jocky investigate scripts/basic.jky", INVESTIGATE))):
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, s=s: s())
            top.addWidget(b)
        top.addWidget(self.status)
        top.addStretch()
        right = QVBoxLayout()
        right.addLayout(top)
        right.addWidget(self.stack)
        root = QWidget()
        lay = QHBoxLayout(root)
        lay.addWidget(side)
        lay.addLayout(right)
        self.setCentralWidget(root)
        # console dock: raw output of the backend CLI commands + a command runner
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(5000)
        cbar = QHBoxLayout()
        self.cmdbox = QComboBox()
        self.cmdbox.addItems(CONSOLE_COMMANDS)
        cbar.addWidget(self.cmdbox)
        for t, s in (("Run command", self.run_selected), ("Clear", self.console.clear)):
            b = QPushButton(t)
            b.clicked.connect(lambda _=False, s=s: s())
            cbar.addWidget(b)
        cbar.addStretch()
        box = QWidget()
        bl = QVBoxLayout(box)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addLayout(cbar)
        bl.addWidget(self.console)
        dock = QDockWidget("Console (backend output)", self)
        dock.setWidget(box)
        self.addDockWidget(Qt.BottomDockWidgetArea, dock)
        self.resizeDocks([dock], [190], Qt.Vertical)
        side.setCurrentRow(0)
        self.timer = QTimer(self)
        self.timer.timeout.connect(lambda: self.live.isChecked() and self.tick())
        self.timer.start(10000)
        self.log("JOCKY ready. Evidence folder: evidence/   Reports: reports/")
        QTimer.singleShot(200, self.tick)

    # ---- backend commands
    def log(self, text):
        self.console.appendPlainText(text.rstrip())

    def run_selected(self):
        n = self.cmdbox.currentText()
        self.run_cmd(f"jocky {n.split()[0]}", CONSOLE_COMMANDS[n])

    def run_cmd(self, label, fn, *args):
        if self.cmd and self.cmd.isRunning():
            self.status.setText("a command is still running...")
            return
        self.log(f"\n$ {label}")
        self.status.setText(f"running: {label}")
        self.cmd = Worker(lambda log: self.core.call(label, fn, *args))
        self.cmd.done.connect(self.cmd_done)
        self.cmd.failed.connect(lambda e: self.log("ERROR: " + e))
        self.cmd.start()

    def cmd_done(self, r):
        out, ok = r
        self.log(out + ("" if ok else "\n[command failed]"))
        self.status.setText("done" if ok else "command failed (see console)")
        self.refresh_all()

    # ---- live monitor
    def tick(self):
        if self.live_worker and self.live_worker.isRunning():
            return
        self.live_worker = Worker(lambda log: self.core.live())
        self.live_worker.done.connect(self.on_live)
        self.live_worker.failed.connect(lambda e: self.status.setText("error: " + e))
        self.live_worker.start()

    def on_live(self, new):
        self.status.setText(f"live update {self.core.data['updated']}" + (f"  •  {new} new alert(s)" if new else ""))
        self.refresh_all(live=True)

    # ---- refresh
    def switch(self, i):
        self.stack.setCurrentIndex(i)
        self.refresh_current()

    def refresh_current(self):
        w = self.stack.currentWidget()
        if hasattr(w, "refresh"):
            w.refresh()

    def refresh_all(self, live=False):
        self.dash.refresh(live)
        if self.stack.currentWidget() is not self.dash:
            self.refresh_current()
