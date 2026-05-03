import sys
from PyQt6.QtWidgets import QApplication

from app.ui.main_window import AsphylaxUI


def main():
    app = QApplication(sys.argv)
    window = AsphylaxUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()