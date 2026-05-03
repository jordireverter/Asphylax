from pathlib import Path

from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QMainWindow,
)
from PyQt6.QtGui import QIcon, QFont, QPixmap
from PyQt6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve

from app.controllers.scan_controller import ScanController
from app.controllers.scan_worker import ScanWorker

BASE_DIR = Path(__file__).resolve().parents[2]
GUI_DIR = BASE_DIR / "gui"


class AsphylaxUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.scan_controller = ScanController()

        self.setWindowTitle("Asphylax Antivirus")
        self.setGeometry(200, 200, 1100, 650)
        self.setWindowIcon(QIcon(str(GUI_DIR / "icons" / "logo.svg")))

        self.current_mode = "light"
        self.apply_style(self.current_mode)

        main_layout = QVBoxLayout()
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        header_layout = QHBoxLayout()

        logo_label = QLabel()
        pixmap = QPixmap(str(GUI_DIR / "icons" / "logo.svg")).scaled(
            40,
            40,
            Qt.AspectRatioMode.KeepAspectRatio,
        )
        logo_label.setPixmap(pixmap)
        header_layout.addWidget(logo_label)

        name_label = QLabel("Asphylax")
        name_label.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        name_label.setStyleSheet("color: #0078D7; margin-left: 10px;")
        header_layout.addWidget(name_label)

        header_layout.addStretch()

        mode_selector = QComboBox()
        mode_selector.addItems(["Clar", "Fosc"])
        mode_selector.currentIndexChanged.connect(self.change_mode)
        header_layout.addWidget(mode_selector)

        main_layout.addLayout(header_layout)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_scan_tab(), QIcon(str(GUI_DIR / "icons" / "scan.svg")), "Escaneig")
        self.tabs.addTab(self.create_heuristic_tab(), QIcon(str(GUI_DIR / "icons" / "heuristic.svg")), "Heurística")
        self.tabs.addTab(self.create_monitor_tab(), QIcon(str(GUI_DIR / "icons" / "monitor.svg")), "Monitorització")
        self.tabs.addTab(self.create_quarantine_tab(), QIcon(str(GUI_DIR / "icons" / "quarantine.svg")), "Quarantena")
        self.tabs.addTab(self.create_history_tab(), QIcon(str(GUI_DIR / "icons" / "history.svg")), "Historial")
        self.tabs.addTab(self.create_settings_tab(), QIcon(str(GUI_DIR / "icons" / "settings.svg")), "Configuració")

        main_layout.addWidget(self.tabs)

    def apply_style(self, mode):
        style_file = GUI_DIR / ("style_dark.qss" if mode == "dark" else "style_light.qss")

        with style_file.open("r", encoding="utf-8") as f:
            self.setStyleSheet(f.read())

    def change_mode(self, index):
        self.current_mode = "dark" if index == 1 else "light"
        self.apply_style(self.current_mode)

    def create_scan_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("Escaneig Antivirus")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.selected_path_label = QLabel("Cap ruta seleccionada")
        self.selected_path_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.selected_path_label)

        select_path_button = QPushButton("Seleccionar carpeta o fitxer")
        select_path_button.clicked.connect(self.select_scan_path)
        layout.addWidget(select_path_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.start_button = QPushButton("ESCANEJAR")
        self.start_button.setFixedSize(150, 150)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #FF0000;
                color: white;
                border-radius: 75px;
                font-size: 18px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #8B0000;
            }
        """)
        self.start_button.clicked.connect(self.start_scan)
        layout.addWidget(self.start_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.scan_type = QComboBox()
        self.scan_type.addItems(["Escaneig focalitzat"])
        layout.addWidget(self.scan_type, alignment=Qt.AlignmentFlag.AlignCenter)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.result_list = QListWidget()
        layout.addWidget(self.result_list)

        self.selected_scan_path = None

        widget.setLayout(layout)
        return widget

    def select_scan_path(self):
        path = QFileDialog.getExistingDirectory(
            self,
            "Selecciona una carpeta per escanejar",
        )

        if path:
            self.selected_scan_path = path
            self.selected_path_label.setText(path)

    def start_scan(self):
        if not self.selected_scan_path:
            QMessageBox.warning(
                self,
                "Ruta no seleccionada",
                "Selecciona una carpeta abans d'iniciar l'escaneig.",
            )
            return

        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.result_list.clear()

        self.start_button.setEnabled(False)
        self.start_button.setText("ESCANEJANT")

        self.scan_worker = ScanWorker(self.selected_scan_path)
        self.scan_worker.progress_changed.connect(self.update_scan_progress)
        self.scan_worker.scan_finished.connect(self.finish_scan)
        self.scan_worker.start()

    def update_scan_progress(self, percent: int):
        self.progress.setValue(percent)

    def finish_scan(self, response: dict):
        self.progress.setValue(100)

        self.start_button.setText("ESCANEJAR")
        self.start_button.setEnabled(True)

        self.show_scan_result(response)


    def show_scan_result(self, response: dict):
        if response.get("status") != "ok":
            QMessageBox.critical(
                self,
                "Error d'escaneig",
                response.get("message", "Error desconegut."),
            )
            return

        data = response.get("data") or {}
        scanned_files = data.get("scanned_files", 0)
        detections = data.get("detections", [])

        self.result_list.addItem(f"Fitxers escanejats: {scanned_files}")
        self.result_list.addItem(f"Deteccions: {len(detections)}")

        for detection in detections:
            path = detection.get("path", "")
            engine = detection.get("engine", "")
            name = detection.get("name", "")
            severity = detection.get("severity", "")
            confidence = detection.get("confidence", "")
            category = detection.get("category", "")

            self.result_list.addItem(
                f"[{engine}] {name} | severity={severity} | confidence={confidence} | category={category} | {path}"
            )

        QMessageBox.information(
            self,
            "Escaneig complet",
            f"Escaneig finalitzat.\nFitxers escanejats: {scanned_files}\nDeteccions: {len(detections)}",
        )

    def create_heuristic_tab(self):
        return self.simple_tab("Anàlisi heurística (pendent)", "Opció per activar/desactivar heurística")

    def create_monitor_tab(self):
        return self.simple_tab("Monitorització en temps real (pendent)", "Panell d'esdeveniments")

    def create_quarantine_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Fitxers en quarantena"))
        quarantine_list = QListWidget()
        layout.addWidget(quarantine_list)
        layout.addWidget(QPushButton("Restaurar"))
        layout.addWidget(QPushButton("Eliminar"))
        widget.setLayout(layout)
        return widget

    def create_history_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Historial d'escaneigs"))
        history_list = QListWidget()
        layout.addWidget(history_list)
        layout.addWidget(QPushButton("Exportar informe"))
        widget.setLayout(layout)
        return widget

    def create_settings_tab(self):
        return self.simple_tab("Configuració", "Botó per actualitzar signatures")

    def simple_tab(self, text1, text2):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel(text1))
        layout.addWidget(QLabel(text2))
        widget.setLayout(layout)
        return widget