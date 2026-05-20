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
    QCheckBox,
    QSpinBox,
    QDoubleSpinBox,
    QTextEdit,
    QApplication,
)

from PyQt6.QtGui import QIcon, QFont, QPixmap, QPalette, QColor
from PyQt6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve, QEvent
from PyQt6.QtWidgets import QTextEdit

from app.controllers.scan_controller import ScanController
from app.controllers.scan_worker import ScanWorker
from app.controllers.monitor_controller import MonitorController
from app.controllers.quarantine_controller import QuarantineController
from app.controllers.history_controller import HistoryController
from app.controllers.config_controller import ConfigController

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
        self.quarantine_controller = QuarantineController()
        self.selected_quarantine_file = None
        self.history_controller = HistoryController()
        self.config_controller = ConfigController()
        self.current_config = None
        self.setWindowTitle("Asphylax Antivirus")
        self.setGeometry(200, 200, 1200, 750)
        self.setWindowIcon(QIcon(str(GUI_DIR / "icons" / "logo.svg")))

        self.current_mode = self.detect_system_theme()
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
        resolved_mode = self.resolve_theme(mode)

        style_file = GUI_DIR / (
            "style_dark.qss" if resolved_mode == "dark" else "style_light.qss"
        )

        with style_file.open("r", encoding="utf-8") as f:
            self.setStyleSheet(f.read())

        self.current_mode = mode

    def change_mode(self, index):
        selected = "dark" if index == 1 else "light"
        self.current_mode = selected
        self.apply_style(selected)
        self.refresh_all_table_colors()

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

        title = QLabel("Quarantena")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        self.quarantine_selected_label = QLabel("Cap fitxer seleccionat")
        layout.addWidget(self.quarantine_selected_label)

        buttons_layout = QHBoxLayout()

        select_file_button = QPushButton("Seleccionar fitxer")
        select_file_button.clicked.connect(self.select_file_for_quarantine)
        buttons_layout.addWidget(select_file_button)

        quarantine_button = QPushButton("Enviar a quarantena")
        quarantine_button.clicked.connect(self.quarantine_selected_file)
        buttons_layout.addWidget(quarantine_button)

        refresh_button = QPushButton("Actualitzar llista")
        refresh_button.clicked.connect(self.load_quarantine_list)
        buttons_layout.addWidget(refresh_button)

        restore_button = QPushButton("Restaurar seleccionat")
        restore_button.clicked.connect(self.restore_selected_quarantine)
        buttons_layout.addWidget(restore_button)

        delete_button = QPushButton("Eliminar definitivament")
        delete_button.clicked.connect(self.delete_selected_quarantine)
        buttons_layout.addWidget(delete_button)


        layout.addLayout(buttons_layout)

        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(5)
        self.quarantine_table.setHorizontalHeaderLabels([
            "ID",
            "Nom",
            "Ruta original",
            "Data",
            "Estat",
        ])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.quarantine_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.quarantine_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.quarantine_table, stretch=1)

        widget.setLayout(layout)
        return widget

    def create_history_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        title = QLabel("Historial")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        refresh_button = QPushButton("Actualitzar historial")
        refresh_button.clicked.connect(self.load_history_list)
        layout.addWidget(refresh_button)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Data",
            "Acció",
            "Fitxer",
            "Resultat",
            "Score",
            "Detalls",
        ])

        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        layout.addWidget(self.history_table, stretch=1)

        widget.setLayout(layout)
        return widget

    def create_settings_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        title = QLabel("Configuració")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        self.config_yara_size = QSpinBox()
        self.config_yara_size.setRange(0, 4096)
        self.config_yara_size.setSuffix(" MB")

        self.config_heuristics_enabled = QCheckBox("Activar heurística")
        self.config_pe_enabled = QCheckBox("Activar anàlisi PE")
        self.config_monitoring_enabled = QCheckBox("Activar monitorització")

        self.config_base64_length = QSpinBox()
        self.config_base64_length.setRange(1, 10000)

        self.config_entropy_threshold = QDoubleSpinBox()
        self.config_entropy_threshold.setRange(0.0, 10.0)
        self.config_entropy_threshold.setDecimals(2)

        self.config_excluded_paths = QTextEdit()
        self.config_excluded_paths.setPlaceholderText("Una ruta per línia")

        self.config_excluded_extensions = QTextEdit()
        self.config_excluded_extensions.setPlaceholderText("Una extensió per línia, ex: .tmp")
        self.config_theme = QComboBox()
        self.config_theme.addItems(["system", "light", "dark"])
        self.config_auto_quarantine_enabled = QCheckBox("Activar quarantena automàtica")

        self.config_auto_quarantine_level = QComboBox()
        self.config_auto_quarantine_level.addItems(["malware", "suspicious"])

        layout.addWidget(QLabel("Tema visual"))
        layout.addWidget(self.config_theme)

        layout.addWidget(QLabel("Mida màxima YARA"))
        layout.addWidget(self.config_yara_size)

        layout.addWidget(self.config_heuristics_enabled)

        layout.addWidget(QLabel("Longitud mínima Base64"))
        layout.addWidget(self.config_base64_length)

        layout.addWidget(QLabel("Llindar d'entropia"))
        layout.addWidget(self.config_entropy_threshold)

        layout.addWidget(self.config_pe_enabled)
        layout.addWidget(self.config_monitoring_enabled)

        layout.addWidget(self.config_auto_quarantine_enabled)
        layout.addWidget(QLabel("Nivell mínim per quarantena automàtica"))
        layout.addWidget(self.config_auto_quarantine_level)

        layout.addWidget(QLabel("Rutes excloses"))
        layout.addWidget(self.config_excluded_paths)

        layout.addWidget(QLabel("Extensions excloses"))
        layout.addWidget(self.config_excluded_extensions)

        buttons_layout = QHBoxLayout()

        load_button = QPushButton("Carregar configuració")
        load_button.clicked.connect(self.load_config_from_agent)
        buttons_layout.addWidget(load_button)

        save_button = QPushButton("Guardar configuració")
        save_button.clicked.connect(self.save_config_to_agent)
        buttons_layout.addWidget(save_button)

        layout.addLayout(buttons_layout)

        widget.setLayout(layout)
        return widget


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
        
        excluded_paths = []
        excluded_extensions = []

        config_response = self.config_controller.get_config()

        if config_response.get("status") == "ok":
            config = config_response.get("data") or {}
            exclusions = config.get("exclusions", {})

            excluded_paths = exclusions.get("paths", [])
            excluded_extensions = exclusions.get("extensions", [])

        self.monitor_controller.start_monitoring(
            self.monitoring_path,
            self.handle_monitor_event,
            excluded_paths=excluded_paths,
            excluded_extensions=excluded_extensions,
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
        self.apply_row_color(self.monitor_table, row, status)

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
    

    def select_file_for_quarantine(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Selecciona un fitxer per enviar a quarantena",
        )

        if path:
            self.selected_quarantine_file = path
            self.quarantine_selected_label.setText(path)


    def quarantine_selected_file(self):
        if not self.selected_quarantine_file:
            QMessageBox.warning(
                self,
                "Cap fitxer seleccionat",
                "Selecciona primer un fitxer.",
            )
            return

        response = self.quarantine_controller.quarantine_file(
            self.selected_quarantine_file
        )

        if response.get("status") != "ok":
            QMessageBox.critical(
                self,
                "Error de quarantena",
                response.get("message", "Error desconegut."),
            )
            return

        QMessageBox.information(
            self,
            "Quarantena",
            "El fitxer s'ha enviat correctament a quarantena.",
        )

        self.selected_quarantine_file = None
        self.quarantine_selected_label.setText("Cap fitxer seleccionat")

        self.load_quarantine_list()

    def load_quarantine_list(self):
        response = self.quarantine_controller.list_quarantine()

        if response.get("status") != "ok":
            QMessageBox.critical(
                self,
                "Error",
                response.get("message", "No s'ha pogut carregar la quarantena."),
            )
            return

        entries = response.get("data") or []

        self.quarantine_table.setRowCount(0)

        for entry in entries:
            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)

            self.quarantine_table.setItem(row, 0, QTableWidgetItem(entry.get("id", "")))
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(entry.get("filename", "")))
            self.quarantine_table.setItem(row, 2, QTableWidgetItem(entry.get("original_path", "")))
            self.quarantine_table.setItem(row, 3, QTableWidgetItem(entry.get("quarantined_at", "")))
            self.quarantine_table.setItem(row, 4, QTableWidgetItem(entry.get("status", "")))
            self.apply_row_color(self.quarantine_table, row, entry.get("status", ""))

    def restore_selected_quarantine(self):
        selected_row = self.quarantine_table.currentRow()

        if selected_row < 0:
            QMessageBox.warning(
                self,
                "Cap entrada seleccionada",
                "Selecciona primer una entrada de la taula.",
            )
            return

        id_item = self.quarantine_table.item(selected_row, 0)

        if id_item is None:
            QMessageBox.warning(
                self,
                "ID no trobat",
                "No s'ha pogut obtenir l'ID de quarantena.",
            )
            return

        quarantine_id = id_item.text()

        response = self.quarantine_controller.restore_quarantine(quarantine_id)

        if response.get("status") != "ok":
            QMessageBox.critical(
                self,
                "Error restaurant",
                response.get("message", "No s'ha pogut restaurar el fitxer."),
            )
            return

        QMessageBox.information(
            self,
            "Fitxer restaurat",
            "El fitxer s'ha restaurat correctament.",
        )

        self.load_quarantine_list()    

    
    def delete_selected_quarantine(self):
        selected_row = self.quarantine_table.currentRow()

        if selected_row < 0:
            QMessageBox.warning(
                self,
                "Cap entrada seleccionada",
                "Selecciona primer una entrada de la taula.",
            )
            return

        id_item = self.quarantine_table.item(selected_row, 0)

        if id_item is None:
            QMessageBox.warning(
                self,
                "ID no trobat",
                "No s'ha pogut obtenir l'ID de quarantena.",
            )
            return

        quarantine_id = id_item.text()

        confirm = QMessageBox.question(
            self,
            "Confirmar eliminació",
            "Segur que vols eliminar definitivament aquest fitxer de quarantena?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if confirm != QMessageBox.StandardButton.Yes:
            return

        response = self.quarantine_controller.delete_quarantine(quarantine_id)

        if response.get("status") != "ok":
            QMessageBox.critical(
                self,
                "Error eliminant",
                response.get("message", "No s'ha pogut eliminar el fitxer."),
            )
            return

        QMessageBox.information(
            self,
            "Fitxer eliminat",
            "El fitxer s'ha eliminat definitivament.",
        )

        self.load_quarantine_list()

    
    def load_history_list(self):
        response = self.history_controller.list_history()

        if response.get("status") != "ok":
            QMessageBox.critical(
                self,
                "Error",
                response.get("message", "No s'ha pogut carregar l'historial."),
            )
            return

        entries = response.get("data") or []

        self.history_table.setRowCount(0)

        for entry in entries:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)

            self.history_table.setItem(row, 0, QTableWidgetItem(entry.get("timestamp", "")))
            self.history_table.setItem(row, 1, QTableWidgetItem(entry.get("action", "")))
            self.history_table.setItem(row, 2, QTableWidgetItem(entry.get("path", "") or ""))
            self.history_table.setItem(row, 3, QTableWidgetItem(entry.get("result", "")))
            self.history_table.setItem(row, 4, QTableWidgetItem(str(entry.get("score", ""))))
            self.history_table.setItem(row, 5, QTableWidgetItem(entry.get("details", "")))
            self.apply_row_color(self.history_table, row, entry.get("result", ""))


    def load_config_from_agent(self):
        response = self.config_controller.get_config()

        if response.get("status") != "ok":
            QMessageBox.critical(
                self,
                "Error",
                response.get("message", "No s'ha pogut carregar la configuració."),
            )
            return

        config = response.get("data") or {}
        self.current_config = config

        ui = config.get("ui", {})
        theme = ui.get("theme", "system")

        index = self.config_theme.findText(theme)
        if index >= 0:
            self.config_theme.setCurrentIndex(index)


        self.config_yara_size.setValue(config.get("max_yara_file_size_mb", 25))

        heuristics = config.get("heuristics", {})
        self.config_heuristics_enabled.setChecked(heuristics.get("enabled", True))
        self.config_base64_length.setValue(heuristics.get("base64_min_length", 80))
        self.config_entropy_threshold.setValue(heuristics.get("entropy_threshold", 7.2))

        pe_analysis = config.get("pe_analysis", {})
        self.config_pe_enabled.setChecked(pe_analysis.get("enabled", True))

        monitoring = config.get("monitoring", {})
        self.config_monitoring_enabled.setChecked(monitoring.get("enabled", True))

        exclusions = config.get("exclusions", {})
        self.config_excluded_paths.setPlainText(
            "\n".join(exclusions.get("paths", []))
        )
        self.config_excluded_extensions.setPlainText(
            "\n".join(exclusions.get("extensions", []))
        )

        auto_quarantine = config.get("auto_quarantine", {})
        self.config_auto_quarantine_enabled.setChecked(
            auto_quarantine.get("enabled", False)
        )

        level = auto_quarantine.get("minimum_classification", "malware")
        index = self.config_auto_quarantine_level.findText(level)
        if index >= 0:
            self.config_auto_quarantine_level.setCurrentIndex(index)


    def save_config_to_agent(self):
        if self.current_config is None:
            QMessageBox.warning(
                self,
                "Configuració no carregada",
                "Carrega primer la configuració abans de guardar.",
            )
            return

        config = self.current_config

        config["max_yara_file_size_mb"] = self.config_yara_size.value()

        config["heuristics"]["enabled"] = self.config_heuristics_enabled.isChecked()
        config["heuristics"]["base64_min_length"] = self.config_base64_length.value()
        config["heuristics"]["entropy_threshold"] = self.config_entropy_threshold.value()

        config["pe_analysis"]["enabled"] = self.config_pe_enabled.isChecked()

        config["monitoring"]["enabled"] = self.config_monitoring_enabled.isChecked()

        config["exclusions"]["paths"] = [
            line.strip()
            for line in self.config_excluded_paths.toPlainText().splitlines()
            if line.strip()
        ]

        config["exclusions"]["extensions"] = [
            line.strip()
            for line in self.config_excluded_extensions.toPlainText().splitlines()
            if line.strip()
        ]

        if "ui" not in config:
            config["ui"] = {}

        config["ui"]["theme"] = self.config_theme.currentText()
        self.apply_style(config["ui"]["theme"])
        self.refresh_all_table_colors()

        if "auto_quarantine" not in config:
            config["auto_quarantine"] = {}

        config["auto_quarantine"]["enabled"] = self.config_auto_quarantine_enabled.isChecked()
        config["auto_quarantine"]["minimum_classification"] = self.config_auto_quarantine_level.currentText()

        response = self.config_controller.save_config(config)

        if response.get("status") != "ok":
            QMessageBox.critical(
                self,
                "Error",
                response.get("message", "No s'ha pogut guardar la configuració."),
            )
            return

        QMessageBox.information(
            self,
            "Configuració",
            "Configuració guardada correctament.",
        )    

    
    def detect_system_theme(self):
        palette = QApplication.instance().palette()
        window_color = palette.color(QPalette.ColorRole.Window)

        brightness = (
            window_color.red() * 0.299
            + window_color.green() * 0.587
            + window_color.blue() * 0.114
        )

        return "dark" if brightness < 128 else "light"


    def resolve_theme(self, theme):
        if theme == "system":
            return self.detect_system_theme()

        return theme
    

    def status_color(self, value: str):
        value = (value or "").lower()
        theme = self.resolve_theme(self.current_mode)

        if theme == "dark":
            colors = {
                "clean": "#143d2b",
                "suspicious": "#4a3b12",
                "malware": "#4a1f24",
                "quarantined": "#4a3212",
                "restored": "#163a45",
                "deleted": "#333333",
                "error": "#5a1f24",
            }
            default = "#2b2b2b"
        else:
            colors = {
                "clean": "#d4edda",
                "suspicious": "#fff3cd",
                "malware": "#f8d7da",
                "quarantined": "#ffe5b4",
                "restored": "#d1ecf1",
                "deleted": "#e2e3e5",
                "error": "#f5c6cb",
            }
            default = "#ffffff"

        return QColor(colors.get(value, default))


    def apply_row_color(self, table, row: int, status: str):
        background = self.status_color(status)
        theme = self.resolve_theme(self.current_mode)
        foreground = QColor("#ffffff") if theme == "dark" else QColor("#111111")

        for column in range(table.columnCount()):
            item = table.item(row, column)
            if item is not None:
                item.setBackground(background)
                item.setForeground(foreground)


    def refresh_all_table_colors(self):
        if hasattr(self, "monitor_table"):
            self.recolor_table_by_column(self.monitor_table, 3)

        if hasattr(self, "quarantine_table"):
            self.recolor_table_by_column(self.quarantine_table, 4)

        if hasattr(self, "history_table"):
            self.recolor_table_by_column(self.history_table, 3)


    def recolor_table_by_column(self, table, status_column: int):
        for row in range(table.rowCount()):
            item = table.item(row, status_column)

            if item is None:
                continue

            status = item.text()
            self.apply_row_color(table, row, status)