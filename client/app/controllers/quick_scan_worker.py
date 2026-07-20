from PyQt6.QtCore import QThread, pyqtSignal

from app.controllers.scan_controller import ScanController


class QuickScanWorker(QThread):
    scan_finished = pyqtSignal(dict)

    def run(self):
        controller = ScanController()
        response = controller.quick_scan()
        self.scan_finished.emit(response)