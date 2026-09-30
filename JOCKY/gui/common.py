from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QTableWidget, QTableWidgetItem

SEV_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#15803d",
             "CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#a16207", "LOW": "#15803d",
             "OK": "#15803d", "MODIFIED": "#b91c1c", "MISSING": "#c2410c", "SUPERSEDED": "#475569"}


class Worker(QThread):
    """Runs fn(log) in a background thread so the window never freezes."""
    done, failed, log = Signal(object), Signal(str), Signal(str)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn(self.log.emit))
        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")


class DataTable(QTableWidget):
    """Read-only sortable table filled from a list of dicts; keeps scroll position on refresh."""

    def __init__(self, cols, color_col=None):
        super().__init__(0, len(cols))
        self.cols, self.color_col = cols, color_col
        self.setHorizontalHeaderLabels(cols)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setDefaultSectionSize(150)
        self.setSortingEnabled(True)

    def set(self, rows, flt=""):
        f = flt.lower()
        vis = [r for r in rows if not f or f in " ".join(str(r.get(c, "")) for c in self.cols).lower()]
        pos = self.verticalScrollBar().value()
        self.setUpdatesEnabled(False)
        self.setSortingEnabled(False)
        self.setRowCount(len(vis))
        for i, r in enumerate(vis):
            for j, c in enumerate(self.cols):
                v, it = r.get(c), QTableWidgetItem()
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    it.setData(Qt.DisplayRole, v)
                else:
                    it.setText("" if v is None else str(v))
                if c == self.color_col and str(v) in SEV_COLOR:
                    it.setBackground(QColor(SEV_COLOR[str(v)]))
                    it.setForeground(QColor("white"))
                self.setItem(i, j, it)
        self.setSortingEnabled(True)
        self.setUpdatesEnabled(True)
        self.verticalScrollBar().setValue(pos)

    def selected(self, col=0):
        r = self.currentRow()
        return self.item(r, col).text() if r >= 0 else None
