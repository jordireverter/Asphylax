from PyQt6.QtCore import QThread, pyqtSignal

from app.controllers.scan_controller import ScanController


class ScanWorker(QThread):
    progress_changed = pyqtSignal(int)
    scan_finished = pyqtSignal(dict)

    def __init__(self, path: str):
        super().__init__()
        self.path = path
        self.controller = ScanController()

    def run(self):
        response = self.controller.scan_stream(
            self.path,
            on_progress=self.progress_changed.emit,
        )

        self.scan_finished.emit(response)