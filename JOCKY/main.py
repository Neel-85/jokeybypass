import sys

from PySide6.QtWidgets import QApplication

from jocky.core import Core          # first: switches cwd to the project folder (original backend uses relative paths)
from gui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    win = MainWindow(Core())
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
