from pathlib import Path
from datetime import datetime

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
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
)
from PyQt6.QtGui import QIcon, QFont, QPixmap
from PyQt6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve, QEvent
from PyQt6.QtWidgets import QTextEdit

from app.controllers.scan_controller import ScanController
from app.controllers.scan_worker import ScanWorker
from app.controllers.monitor_controller import MonitorController

BASE_DIR = Path(__file__).resolve().parents[2]
GUI_DIR = BASE_DIR / "gui"


class AsphylaxUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.scan_controller = ScanController()
        self.selected_scan_path = None
        self.scan_worker = None
        self.monitor_controller = MonitorController()
        self.monitoring_path = "C:/"
        self.monitor_rows = {}
        self.monitor_scanned_files = 0
        self.monitor_threats = 0

        self.setWindowTitle("Asphylax Antivirus")
        self.setGeometry(200, 200, 1200, 750)
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
        self.result_list.setMinimumHeight(350)
        self.result_list.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        layout.addWidget(self.result_list, stretch=1)

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

        effect = QGraphicsOpacityEffect(self.progress)
        self.progress.setGraphicsEffect(effect)

        fade = QPropertyAnimation(effect, b"opacity")
        fade.setDuration(500)
        fade.setStartValue(0)
        fade.setEndValue(1)
        fade.start()
        self.fade_animation = fade

        self.animation = QPropertyAnimation(self.start_button, b"size")
        self.animation.setDuration(500)
        self.animation.setStartValue(self.start_button.size())
        self.animation.setEndValue(QSize(160, 160))
        self.animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.animation.setLoopCount(-1)
        self.animation.start()

        self.scan_worker = ScanWorker(self.selected_scan_path)
        self.scan_worker.progress_changed.connect(self.update_scan_progress)
        self.scan_worker.scan_finished.connect(self.finish_scan)
        self.scan_worker.start()

    def update_scan_progress(self, percent: int):
        self.progress.setValue(percent)

    def finish_scan(self, response: dict):
        self.progress.setValue(100)

        if hasattr(self, "animation"):
            self.animation.stop()

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
        total_detections = data.get("total_detections", 0)
        final_score = data.get("final_score", 0)
        classification = data.get("classification", "clean")
        files = data.get("files", [])

        self.result_list.clear()

        self.result_list.addItem(f"Fitxers escanejats: {scanned_files}")
        self.result_list.addItem(f"Fitxers amb deteccions: {len(files)}")
        self.result_list.addItem(f"Deteccions totals: {total_detections}")
        self.result_list.addItem(f"Score global: {final_score}")
        self.result_list.addItem(f"Classificació global: {classification}")
        self.result_list.addItem("")

        for file_result in files:
            path = file_result.get("path", "")
            file_score = file_result.get("final_score", 0)
            file_classification = file_result.get("classification", "clean")
            detections = file_result.get("detections", [])

            self.result_list.addItem(
                f"FITXER: {path}"
            )
            self.result_list.addItem(
                f"   Score: {file_score} | Classificació: {file_classification}"
            )

            for detection in detections:
                engine = detection.get("engine", "")
                name = detection.get("name", "")
                severity = detection.get("severity", "")
                confidence = detection.get("confidence", "")
                category = detection.get("category", "")

                self.result_list.addItem(
                    f"   - [{engine}] {name} | severity={severity} | confidence={confidence} | category={category}"
                )

            self.result_list.addItem("")

        QMessageBox.information(
            self,
            "Escaneig complet",
            f"Escaneig finalitzat.\n"
            f"Fitxers escanejats: {scanned_files}\n"
            f"Fitxers amb deteccions: {len(files)}\n"
            f"Deteccions totals: {total_detections}\n"
            f"Classificació: {classification}",
        )

    def create_heuristic_tab(self):
        return self.simple_tab("Anàlisi heurística", "Motor heurístic actiu dins l'escaneig principal.")

    def create_monitor_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        title = QLabel("Monitorització en temps real")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        self.monitor_status_label = QLabel("🟡 La protecció en temps real està desactivada")
        self.monitor_status_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        layout.addWidget(self.monitor_status_label)

        stats_layout = QHBoxLayout()

        self.monitor_files_label = QLabel("Fitxers analitzats: 0")
        self.monitor_threats_label = QLabel("Amenaces detectades: 0")
        self.monitor_path_label = QLabel(f"Ruta sota vigilància: {self.monitoring_path}")

        stats_layout.addWidget(self.monitor_files_label)
        stats_layout.addWidget(self.monitor_threats_label)
        stats_layout.addWidget(self.monitor_path_label)

        layout.addLayout(stats_layout)

        buttons_layout = QHBoxLayout()

        select_button = QPushButton("Canviar ruta")
        select_button.clicked.connect(self.select_monitor_path)
        buttons_layout.addWidget(select_button)

        self.monitor_toggle_button = QPushButton("Activar protecció")
        self.monitor_toggle_button.clicked.connect(self.toggle_monitoring)
        buttons_layout.addWidget(self.monitor_toggle_button)

        layout.addLayout(buttons_layout)

        self.monitor_table = QTableWidget()
        self.monitor_table.setColumnCount(6)
        self.monitor_table.setHorizontalHeaderLabels([
            "Hora",
            "Acció",
            "Fitxer",
            "Estat",
            "Score",
            "Resultat",
        ])

        self.monitor_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.monitor_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.monitor_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.monitor_table.setMinimumHeight(400)
        self.monitor_table.cellClicked.connect(self.show_monitor_cell_details)
        self.monitor_table.viewport().installEventFilter(self)

        layout.addWidget(self.monitor_table, stretch=1)

        self.monitor_details = QTextEdit()
        self.monitor_details.setReadOnly(True)
        self.monitor_details.setMinimumHeight(90)
        self.monitor_details.setMaximumHeight(120)
        self.monitor_details.setVisible(False)
        self.monitor_details.setPlaceholderText(
            "Fes clic en una cel·la per veure el contingut complet..."
        )

        layout.addWidget(self.monitor_details)

        widget.setLayout(layout)
        return widget

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
        return self.simple_tab("Configuració", "Opcions de configuració del motor.")

    def simple_tab(self, text1, text2):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel(text1))
        layout.addWidget(QLabel(text2))
        widget.setLayout(layout)
        return widget
    
    def select_monitor_path(self):
        path = QFileDialog.getExistingDirectory(
            self,
            "Selecciona una carpeta o disc per monitoritzar",
            self.monitoring_path,
        )

        if path:
            self.monitoring_path = path
            self.monitor_path_label.setText(f"Ruta sota vigilància: {path}")

    def toggle_monitoring(self):
        if self.monitor_controller.monitor.running:
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def start_monitoring(self):
        if not self.monitoring_path:
            QMessageBox.warning(
                self,
                "Ruta no seleccionada",
                "Selecciona una ruta abans d'iniciar la monitorització.",
            )
            return

        self.monitor_controller.start_monitoring(
            self.monitoring_path,
            self.handle_monitor_event,
        )

        self.monitor_status_label.setText("🟢 Protecció en temps real activada")
        self.monitor_toggle_button.setText("Aturar protecció")


    def stop_monitoring(self):
        self.monitor_controller.stop_monitoring()

        self.monitor_status_label.setText("🟡 La protecció en temps real està desactivada")
        self.monitor_toggle_button.setText("Activar protecció")

    def handle_monitor_event(self, path: str, action: str):
        response = self.monitor_controller.scan_changed_file(path)

        self.monitor_scanned_files += 1
        self.monitor_files_label.setText(f"Fitxers analitzats: {self.monitor_scanned_files}")

        now = datetime.now().strftime("%H:%M:%S")

        status = "clean"
        score = 0
        result_text = "Sense deteccions"

        if response.get("status") != "ok":
            status = "error"
            result_text = response.get("message", "Error desconegut")
        else:
            data = response.get("data") or {}
            files = data.get("files", [])

            if files:
                file_result = files[0]
                status = file_result.get("classification", "unknown")
                score = file_result.get("final_score", 0)

                detections = file_result.get("detections", [])
                if detections:
                    result_text = " | ".join(
                        f"[{d.get('engine', '')}] {d.get('name', '')}"
                        for d in detections
                    )

                if status in ["suspicious", "malware"]:
                    self.monitor_threats += 1
                    self.monitor_threats_label.setText(
                        f"Amenaces detectades: {self.monitor_threats}"
                    )

        self.update_monitor_table(
            path=path,
            time=now,
            action=action,
            status=status,
            score=score,
            result=result_text,
        )

    def update_monitor_table(self, path: str, time: str, action: str, status: str, score: int, result: str):
        if path in self.monitor_rows:
            row = self.monitor_rows[path]
        else:
            row = self.monitor_table.rowCount()
            self.monitor_table.insertRow(row)
            self.monitor_rows[path] = row

        self.monitor_table.setItem(row, 0, QTableWidgetItem(time))
        self.monitor_table.setItem(row, 1, QTableWidgetItem(action))
        self.monitor_table.setItem(row, 2, QTableWidgetItem(path))
        self.monitor_table.setItem(row, 3, QTableWidgetItem(status))
        self.monitor_table.setItem(row, 4, QTableWidgetItem(str(score)))
        self.monitor_table.setItem(row, 5, QTableWidgetItem(result))


    def show_monitor_cell_details(self, row: int, column: int):
        item = self.monitor_table.item(row, column)

        if item is None:
            self.monitor_details.clear()
            self.monitor_details.setVisible(False)
            return

        column_name = self.monitor_table.horizontalHeaderItem(column).text()
        value = item.text()

        self.monitor_details.setPlainText(f"{column_name}:\n{value}")
        self.monitor_details.setVisible(True)


    def eventFilter(self, source, event):
        if source == self.monitor_table.viewport():
            if event.type() == QEvent.Type.MouseButtonPress:
                item = self.monitor_table.itemAt(event.pos())

                if item is None:
                    self.monitor_table.clearSelection()
                    self.monitor_details.clear()
                    self.monitor_details.setVisible(False)

        return super().eventFilter(source, event)