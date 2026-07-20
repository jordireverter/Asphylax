import sys
from pathlib import Path

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

from app.ui.main_window import AsphylaxUI

BASE_DIR = Path(__file__).resolve().parent
LOGO_ICON_PATH = BASE_DIR / "gui" / "icons" / "logo.ico"


def set_windows_app_id():
    if sys.platform != "win32":
        return
    import ctypes

    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Asphylax.Antivirus")
    except (AttributeError, OSError):
        pass


def main():
    set_windows_app_id()
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(str(LOGO_ICON_PATH)))
    window = AsphylaxUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()