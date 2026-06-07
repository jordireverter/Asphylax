import math
from pathlib import Path
from datetime import datetime

from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGraphicsOpacityEffect,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QFrame,
    QLabel,
    QListWidget,
    QMessageBox,
    QPushButton,
    QScrollArea,
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

from PyQt6.QtGui import QBrush, QColor, QFont, QIcon, QLinearGradient, QPainter, QPainterPath, QPalette, QPen, QPixmap, QRadialGradient
from PyQt6.QtCore import Qt, QRectF, QSize, QPropertyAnimation, QEasingCurve, QEvent, QTimer, pyqtProperty, pyqtSignal, pyqtSlot

from app.controllers.scan_controller import ScanController
from app.controllers.scan_worker import ScanWorker
from app.controllers.monitor_controller import MonitorController
from app.controllers.quarantine_controller import QuarantineController
from app.controllers.history_controller import HistoryController
from app.controllers.config_controller import ConfigController
from app.controllers.quick_scan_worker import QuickScanWorker

BASE_DIR = Path(__file__).resolve().parents[2]
GUI_DIR = BASE_DIR / "gui"

class LiquidScanButton(QPushButton):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self._progress = 0
        self._wave_phase = 0.0
        self._scanning = False

        self.wave_timer = QTimer(self)
        self.wave_timer.setInterval(33)
        self.wave_timer.timeout.connect(self.advance_wave)

    def get_progress(self) -> int:
        return self._progress

    def set_progress(self, value: int):
        self._progress = max(0, min(100, int(value)))
        self.update()

    progress = pyqtProperty(int, fget=get_progress, fset=set_progress)

    def set_scanning(self, scanning: bool):
        self._scanning = scanning
        if scanning:
            self.wave_timer.start()
        else:
            self.wave_timer.stop()
            self._wave_phase = 0.0
        self.update()

    def advance_wave(self):
        self._wave_phase = (self._wave_phase + 0.18) % (math.pi * 2)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(4, 4, -4, -4)
        diameter = min(rect.width(), rect.height())
        circle = QRectF(
            rect.center().x() - diameter / 2,
            rect.center().y() - diameter / 2,
            diameter,
            diameter,
        )

        active = self.isEnabled() or self._scanning
        rim_color = QColor("#e15a5a") if active else QColor("#b8b8b8")

        sphere_gradient = QRadialGradient(
            circle.center().x() - circle.width() * 0.24,
            circle.center().y() - circle.height() * 0.28,
            circle.width() * 0.82,
        )
        sphere_gradient.setColorAt(0.0, QColor("#ef7777") if active else QColor("#c9c9c9"))
        sphere_gradient.setColorAt(0.45, QColor("#c94343") if active else QColor("#8f8f8f"))
        sphere_gradient.setColorAt(1.0, QColor("#702020") if active else QColor("#5f5f5f"))

        painter.setPen(QPen(rim_color, 2))
        painter.setBrush(QBrush(sphere_gradient))
        painter.drawEllipse(circle)

        if self._scanning or self._progress > 0:
            level = circle.bottom() - (circle.height() * self._progress / 100.0)
            wave_path = QPainterPath()
            wave_path.moveTo(circle.left(), circle.bottom())
            wave_path.lineTo(circle.left(), level)

            steps = 72
            for step in range(steps + 1):
                x = circle.left() + (circle.width() * step / steps)
                normalized = step / steps
                y = level
                y += math.sin(normalized * math.pi * 2.2 + self._wave_phase) * 9.0
                y += math.sin(normalized * math.pi * 5.2 + self._wave_phase * 0.75) * 3.0
                wave_path.lineTo(x, y)

            wave_path.lineTo(circle.right(), circle.bottom())
            wave_path.closeSubpath()

            clip = QPainterPath()
            clip.addEllipse(circle)
            painter.save()
            painter.setClipPath(clip)
            painter.setPen(Qt.PenStyle.NoPen)

            liquid_gradient = QLinearGradient(circle.left(), level, circle.left(), circle.bottom())
            liquid_gradient.setColorAt(0.0, QColor("#b94a64"))
            liquid_gradient.setColorAt(0.52, QColor("#7e1834"))
            liquid_gradient.setColorAt(1.0, QColor("#3e0818"))
            painter.setBrush(QBrush(liquid_gradient))
            painter.drawPath(wave_path)

            foam_color = QColor("#e8b6c3")
            foam_color.setAlpha(95)
            painter.setPen(QPen(foam_color, 2))
            foam_path = QPainterPath()
            for step in range(steps + 1):
                x = circle.left() + (circle.width() * step / steps)
                normalized = step / steps
                y = level
                y += math.sin(normalized * math.pi * 2.2 + self._wave_phase) * 9.0
                y += math.sin(normalized * math.pi * 5.2 + self._wave_phase * 0.75) * 3.0
                if step == 0:
                    foam_path.moveTo(x, y)
                else:
                    foam_path.lineTo(x, y)
            painter.drawPath(foam_path)

            bubble_color = QColor("#ffd9e0")
            bubble_color.setAlpha(70)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(bubble_color))
            for idx, size in enumerate((4, 3, 5, 2)):
                bx = circle.left() + circle.width() * (0.28 + idx * 0.13)
                by = circle.bottom() - ((self._wave_phase * 18 + idx * 23) % max(circle.height() * 0.55, 1))
                if by > level + 10:
                    painter.drawEllipse(QRectF(bx, by, size, size))
            painter.restore()

        gloss = QRadialGradient(
            circle.left() + circle.width() * 0.32,
            circle.top() + circle.height() * 0.28,
            circle.width() * 0.28,
        )
        gloss.setColorAt(0.0, QColor(255, 255, 255, 105))
        gloss.setColorAt(1.0, QColor(255, 255, 255, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(gloss))
        painter.drawEllipse(circle.adjusted(circle.width() * 0.16, circle.height() * 0.12, -circle.width() * 0.50, -circle.height() * 0.58))

        painter.setPen(QPen(QColor("white")))
        painter.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        label = f"{self._progress}%" if self._scanning else self.text()
        painter.drawText(circle, Qt.AlignmentFlag.AlignCenter, label)

class AsphylaxUI(QMainWindow):
    # â”€â”€ Signals (per actualitzacions segures des de fils de fons) â”€â”€
    monitor_event_signal = pyqtSignal(str, str)  # path, action

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
        self.progress_animation = None
        self.quick_progress_value = 0
        
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
        name_label.setStyleSheet("color: #d84a4a; margin-left: 10px;")
        header_layout.addWidget(name_label)

        header_layout.addStretch()

        mode_selector = QComboBox()
        mode_selector.addItems(["Clar", "Fosc"])
        mode_selector.currentIndexChanged.connect(self.change_mode)
        header_layout.addWidget(mode_selector)

        main_layout.addLayout(header_layout)

        self.tabs = QTabWidget()
        self.tabs.setIconSize(QSize(22, 22))
        self.tabs.addTab(self.create_scan_tab(), QIcon(str(GUI_DIR / "icons" / "scan.svg")), "Escaneig")
        self.tabs.addTab(self.create_monitor_tab(), QIcon(str(GUI_DIR / "icons" / "monitor.svg")), "Monitorització")
        self.tabs.addTab(self.create_quarantine_tab(), QIcon(str(GUI_DIR / "icons" / "quarantine.svg")), "Quarantena")
        self.tabs.addTab(self.create_history_tab(), QIcon(str(GUI_DIR / "icons" / "history.svg")), "Historial")
        self.tabs.addTab(self.create_settings_tab(), QIcon(str(GUI_DIR / "icons" / "settings.svg")), "Configuració")

        # Escolta activa de pestanyes per actualitzar de forma automàtica al canviar de tab
        self.tabs.currentChanged.connect(self.on_tab_changed)

        main_layout.addWidget(self.tabs)

        # Connexió de seguretat thread-safe per al monitor natiu
        self.monitor_event_signal.connect(self.on_monitor_event_received)

        self.table_refresh_timer = QTimer(self)
        self.table_refresh_timer.setInterval(5000)
        self.table_refresh_timer.timeout.connect(self.refresh_visible_live_tab)
        self.table_refresh_timer.start()

        self.quick_progress_timer = QTimer(self)
        self.quick_progress_timer.setInterval(180)
        self.quick_progress_timer.timeout.connect(self.advance_quick_scan_progress)

    def on_tab_changed(self, index: int):
        """Executa l'actualització automatitzada en segon pla segons el tab seleccionat."""
        tab_text = self.tabs.tabText(index)
        if tab_text == "Quarantena":
            self.load_quarantine_list()
        elif tab_text == "Historial":
            self.load_history_list()
        elif tab_text == "Configuració":
            self.load_config_from_agent()

    def refresh_visible_live_tab(self):
        if not hasattr(self, "tabs"):
            return
        tab_text = self.tabs.tabText(self.tabs.currentIndex())
        if tab_text == "Quarantena":
            self.load_quarantine_list(silent=True)
        elif tab_text == "Historial":
            self.load_history_list(silent=True)

    def format_timestamp(self, raw_date: str) -> str:
        """Converteix timestamps UTC/ISO a hora local del sistema."""
        if not raw_date:
            return ""

        try:
            normalized_date = raw_date.strip()

            # Rust pot enviar timestamps acabats en Z
            if normalized_date.endswith("Z"):
                normalized_date = normalized_date[:-1] + "+00:00"

            parsed_datetime = datetime.fromisoformat(normalized_date)

            # Si el timestamp porta zona horÃ ria (+00:00), el convertim a hora local
            if parsed_datetime.tzinfo is not None:
                parsed_datetime = parsed_datetime.astimezone()

            return parsed_datetime.strftime("%d-%m-%Y %H:%M:%S")

        except Exception:
            return raw_date

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
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel("Escaneig Antivirus")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.scan_type = QComboBox()
        self.scan_type.setObjectName("scanModeSelector")
        self.scan_type.setMinimumWidth(280)
        self.scan_type.addItems(["Escaneig ràpid", "Escaneig focalitzat"])
        self.scan_type.currentTextChanged.connect(self.update_scan_mode_ui)
        layout.addWidget(self.scan_type, alignment=Qt.AlignmentFlag.AlignCenter)

        self.scan_path_panel = QWidget()
        self.scan_path_panel.setObjectName("scanPathPanel")
        self.scan_path_panel.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.scan_path_panel.setMaximumWidth(760)
        scan_path_layout = QHBoxLayout()
        scan_path_layout.setContentsMargins(10, 10, 10, 10)
        scan_path_layout.setSpacing(10)

        self.selected_path_label = QLabel("Sense ruta seleccionada: s'escanejarà C:/")
        self.selected_path_label.setObjectName("routeLabel")
        scan_path_layout.addWidget(self.selected_path_label, stretch=1)

        self.select_path_button = QPushButton("Seleccionar ruta")
        self.select_path_button.clicked.connect(self.select_scan_path)
        scan_path_layout.addWidget(self.select_path_button)
        self.scan_path_panel.setLayout(scan_path_layout)
        layout.addWidget(self.scan_path_panel)
        layout.setAlignment(self.scan_path_panel, Qt.AlignmentFlag.AlignCenter)

        self.start_button = LiquidScanButton("ESCANEJAR")
        self.start_button.setObjectName("scanPrimaryButton")
        self.start_button.setFixedSize(180, 180)
        self.start_button.clicked.connect(self.start_scan)
        layout.addWidget(self.start_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.result_list = QListWidget()
        self.result_list.setMinimumHeight(350)
        self.result_list.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        layout.addWidget(self.result_list, stretch=1)

        widget.setLayout(layout)
        self.update_scan_mode_ui(self.scan_type.currentText())
        return widget
    def select_scan_path(self):
        path = QFileDialog.getExistingDirectory(self, "Selecciona una carpeta per escanejar")
        if path:
            self.selected_scan_path = path
            self.selected_path_label.setText(path)

    def update_scan_mode_ui(self, mode: str):
        is_focused_scan = mode == "Escaneig focalitzat"
        if hasattr(self, "scan_path_panel"):
            self.scan_path_panel.setVisible(is_focused_scan)
        if is_focused_scan and not self.selected_scan_path:
            self.selected_path_label.setText("Sense ruta seleccionada: s'escanejarà C:/")

    def start_scan(self):
        if self.scan_type.currentText() == "Escaneig ràpid":
            self.start_quick_scan()
            return

        if not self.selected_scan_path:
            self.selected_scan_path = "C:/"
            self.selected_path_label.setText("C:/")

        self.set_progress_smooth(0)
        self.result_list.clear()

        self.start_button.setEnabled(False)
        self.start_button.set_scanning(True)

        self.scan_worker = ScanWorker(self.selected_scan_path)
        self.scan_worker.progress_changed.connect(self.update_scan_progress)
        self.scan_worker.scan_finished.connect(self.finish_scan)
        self.scan_worker.start()

    def update_scan_progress(self, percent: int):
        self.set_progress_smooth(percent)

    def finish_scan(self, response: dict):
        self.set_progress_smooth(100)
        self.quick_progress_timer.stop()
        QTimer.singleShot(850, self.reset_scan_button)
        self.start_button.setEnabled(True)
        self.show_scan_result(response)

    def reset_scan_button(self):
        self.start_button.set_scanning(False)
        self.start_button.progress = 0

    def set_progress_smooth(self, percent: int):
        target = max(0, min(100, percent))
        if self.progress_animation is not None:
            self.progress_animation.stop()

        self.progress_animation = QPropertyAnimation(self.start_button, b"progress", self)
        self.progress_animation.setDuration(520)
        self.progress_animation.setStartValue(self.start_button.progress)
        self.progress_animation.setEndValue(target)
        self.progress_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.progress_animation.start()

    def advance_quick_scan_progress(self):
        if self.quick_progress_value < 35:
            self.quick_progress_value += 3
        elif self.quick_progress_value < 70:
            self.quick_progress_value += 2
        elif self.quick_progress_value < 92:
            self.quick_progress_value += 1
        self.set_progress_smooth(self.quick_progress_value)

    def show_scan_result(self, response: dict):
        if response.get("status") != "ok":
            QMessageBox.critical(
                self, "Error d'escaneig", response.get("message", "Error desconegut."),
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

            self.result_list.addItem(f"FITXER: {path}")
            self.result_list.addItem(f"   Score: {file_score} | Classificació: {file_classification}")

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
            f"Deteccions totals: {total_detections}\n"
            f"Classificació: {classification}",
        )

    def create_monitor_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title = QLabel("Monitorització en temps real")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        status_group = QGroupBox("Estat")
        status_layout = QVBoxLayout()
        status_layout.setSpacing(10)

        self.monitor_status_label = QLabel("Protecció desactivada")
        self.monitor_status_label.setObjectName("statusInactive")
        self.monitor_status_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        status_layout.addWidget(self.monitor_status_label)

        stats_layout = QHBoxLayout()
        self.monitor_files_label = QLabel("Fitxers analitzats: 0")
        self.monitor_threats_label = QLabel("Amenaces detectades: 0")
        self.monitor_path_label = QLabel(f"Ruta sota vigilància: {self.monitoring_path}")
        for label in (self.monitor_files_label, self.monitor_threats_label, self.monitor_path_label):
            label.setObjectName("metricCard")
            label.setMinimumHeight(42)
        self.monitor_path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        stats_layout.addWidget(self.monitor_files_label)
        stats_layout.addWidget(self.monitor_threats_label)
        stats_layout.addWidget(self.monitor_path_label, stretch=1)
        status_layout.addLayout(stats_layout)

        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        select_button = QPushButton("Canviar ruta")
        select_button.clicked.connect(self.select_monitor_path)
        buttons_layout.addWidget(select_button)

        self.monitor_toggle_button = QPushButton("Activar protecció")
        self.monitor_toggle_button.clicked.connect(self.toggle_monitoring)
        buttons_layout.addWidget(self.monitor_toggle_button)
        status_layout.addLayout(buttons_layout)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        self.monitor_table = QTableWidget()
        self.monitor_table.setColumnCount(6)
        self.monitor_table.setHorizontalHeaderLabels([
            "Hora", "Acció", "Fitxer", "Estat", "Score", "Resultat",
        ])
        self.monitor_table.setTextElideMode(Qt.TextElideMode.ElideRight)

        header = self.monitor_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)

        self.monitor_table.setColumnWidth(0, 75)
        self.monitor_table.setColumnWidth(1, 70)
        self.monitor_table.setColumnWidth(3, 75)
        self.monitor_table.setColumnWidth(4, 60)
        self.monitor_table.setAlternatingRowColors(True)
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
        self.monitor_details.setPlaceholderText("Fes clic en una cel·la per veure el contingut complet...")
        layout.addWidget(self.monitor_details)

        widget.setLayout(layout)
        return widget
    def create_quarantine_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title = QLabel("Quarantena")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        actions_group = QGroupBox("Accions")
        actions_layout = QVBoxLayout()
        self.quarantine_selected_label = QLabel("Cap fitxer seleccionat")
        self.quarantine_selected_label.setObjectName("metricCard")
        self.quarantine_selected_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        actions_layout.addWidget(self.quarantine_selected_label)

        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        select_file_button = QPushButton("Seleccionar fitxer")
        select_file_button.clicked.connect(self.select_file_for_quarantine)
        buttons_layout.addWidget(select_file_button)

        quarantine_button = QPushButton("Enviar a quarantena")
        quarantine_button.clicked.connect(self.quarantine_selected_file)
        buttons_layout.addWidget(quarantine_button)

        restore_button = QPushButton("Restaurar seleccionat")
        restore_button.clicked.connect(self.restore_selected_quarantine)
        buttons_layout.addWidget(restore_button)

        delete_button = QPushButton("Eliminar definitivament")
        delete_button.clicked.connect(self.delete_selected_quarantine)
        buttons_layout.addWidget(delete_button)
        actions_layout.addLayout(buttons_layout)
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)

        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(5)
        self.quarantine_table.setHorizontalHeaderLabels([
            "Data", "ID", "Nom", "Ruta original", "Estat",
        ])
        self.quarantine_table.setTextElideMode(Qt.TextElideMode.ElideRight)

        q_header = self.quarantine_table.horizontalHeader()
        q_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        q_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        q_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        q_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        q_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)

        self.quarantine_table.setColumnWidth(0, 140)
        self.quarantine_table.setColumnWidth(1, 245)
        self.quarantine_table.setColumnWidth(2, 160)
        self.quarantine_table.setColumnWidth(4, 90)
        self.quarantine_table.setAlternatingRowColors(True)
        self.quarantine_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.quarantine_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.quarantine_table.cellClicked.connect(self.show_quarantine_cell_details)
        self.quarantine_table.viewport().installEventFilter(self)

        layout.addWidget(self.quarantine_table, stretch=1)

        self.quarantine_details = QTextEdit()
        self.quarantine_details.setReadOnly(True)
        self.quarantine_details.setMinimumHeight(90)
        self.quarantine_details.setMaximumHeight(120)
        self.quarantine_details.setVisible(False)
        self.quarantine_details.setPlaceholderText("Fes clic en una cel·la per veure el contingut complet de la quarantena...")
        layout.addWidget(self.quarantine_details)

        widget.setLayout(layout)
        return widget
    def create_history_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title = QLabel("Historial de Seguretat")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        self.history_status_label = QLabel("S'actualitza automàticament mentre aquesta pestanya és visible")
        self.history_status_label.setObjectName("mutedLabel")
        layout.addWidget(self.history_status_label)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Data", "Acció", "Fitxer", "Resultat", "Score", "Detalls",
        ])
        self.history_table.setTextElideMode(Qt.TextElideMode.ElideRight)

        h_header = self.history_table.horizontalHeader()
        h_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        h_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        h_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        h_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        h_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        h_header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)

        self.history_table.setColumnWidth(0, 140)
        self.history_table.setColumnWidth(1, 160)
        self.history_table.setColumnWidth(3, 90)
        self.history_table.setColumnWidth(4, 55)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.cellClicked.connect(self.show_history_cell_details)
        self.history_table.viewport().installEventFilter(self)

        layout.addWidget(self.history_table, stretch=1)

        self.history_details = QTextEdit()
        self.history_details.setReadOnly(True)
        self.history_details.setMinimumHeight(90)
        self.history_details.setMaximumHeight(120)
        self.history_details.setVisible(False)
        self.history_details.setPlaceholderText("Fes clic en una cel·la per veure el contingut complet de l'historial...")
        layout.addWidget(self.history_details)

        widget.setLayout(layout)
        return widget
    def create_settings_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        title = QLabel("Configuració")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        content_layout = QVBoxLayout()
        content_layout.setSpacing(12)
        content_layout.setContentsMargins(0, 0, 0, 0)

        self.config_yara_size = QSpinBox()
        self.config_yara_size.setRange(0, 4096)
        self.config_yara_size.setSuffix(" MB")
        self.config_yara_size.setMinimumWidth(120)

        self.config_heuristics_enabled = QCheckBox("Activar heurística")
        self.config_pe_enabled = QCheckBox("Activar anàlisi PE")
        self.config_monitoring_enabled = QCheckBox("Activar monitorització")

        self.config_base64_length = QSpinBox()
        self.config_base64_length.setRange(1, 10000)
        self.config_base64_length.setMinimumWidth(120)

        self.config_entropy_threshold = QDoubleSpinBox()
        self.config_entropy_threshold.setRange(0.0, 10.0)
        self.config_entropy_threshold.setDecimals(2)
        self.config_entropy_threshold.setSingleStep(0.1)
        self.config_entropy_threshold.setMinimumWidth(120)

        self.config_excluded_paths = self.create_config_text_edit("Una ruta per lÃ­nia", 90)

        self.config_excluded_extensions = self.create_config_text_edit("Una extensiÃ³ per lÃ­nia, ex: .tmp", 70)
        self.config_theme = QComboBox()
        self.config_theme.addItems(["system", "light", "dark"])
        self.config_auto_quarantine_enabled = QCheckBox("Activar quarantena automÃ tica")

        self.config_auto_quarantine_level = QComboBox()
        self.config_auto_quarantine_level.addItems(["malware", "suspicious"])

        self.config_quick_max_size = QSpinBox()
        self.config_quick_max_size.setRange(1, 4096)
        self.config_quick_max_size.setSuffix(" MB")

        self.config_quick_max_depth = QSpinBox()
        self.config_quick_max_depth.setRange(0, 12)

        self.config_quick_yara_timeout = QSpinBox()
        self.config_quick_yara_timeout.setRange(1, 120)
        self.config_quick_yara_timeout.setSuffix(" s")

        self.config_quick_extensions = self.create_config_text_edit("Una extensiÃ³ per lÃ­nia, ex: .exe", 90)
        self.config_quick_excluded_dirs = self.create_config_text_edit("Una carpeta per lÃ­nia, ex: node_modules", 90)

        general_form = QFormLayout()
        general_form.addRow("Tema visual", self.config_theme)
        general_form.addRow("Mida mÃ xima YARA", self.config_yara_size)
        content_layout.addWidget(self.create_config_group("General", general_form))

        engines_form = QFormLayout()
        engines_form.addRow(self.config_heuristics_enabled)
        engines_form.addRow("Longitud mÃ­nima Base64", self.config_base64_length)
        engines_form.addRow("Llindar d'entropia", self.config_entropy_threshold)
        engines_form.addRow(self.config_pe_enabled)
        engines_form.addRow(self.config_monitoring_enabled)
        content_layout.addWidget(self.create_config_group("Motors", engines_form))

        quick_form = QFormLayout()
        quick_form.addRow("Mida mÃ xima", self.config_quick_max_size)
        quick_form.addRow("Profunditat", self.config_quick_max_depth)
        quick_form.addRow("Timeout YARA", self.config_quick_yara_timeout)
        quick_form.addRow("Extensions", self.config_quick_extensions)
        quick_form.addRow("Carpetes excloses", self.config_quick_excluded_dirs)
        content_layout.addWidget(self.create_config_group("Escaneig rÃ pid", quick_form))

        quarantine_form = QFormLayout()
        quarantine_form.addRow(self.config_auto_quarantine_enabled)
        quarantine_form.addRow("Nivell mÃ­nim", self.config_auto_quarantine_level)
        content_layout.addWidget(self.create_config_group("Quarantena", quarantine_form))

        exclusions_form = QFormLayout()
        exclusions_form.addRow("Rutes", self.config_excluded_paths)
        exclusions_form.addRow("Extensions", self.config_excluded_extensions)
        content_layout.addWidget(self.create_config_group("Exclusions globals", exclusions_form))

        content_layout.addStretch()
        content.setLayout(content_layout)
        scroll.setWidget(content)
        layout.addWidget(scroll, stretch=1)

        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        save_button = QPushButton("Guardar configuració")
        save_button.clicked.connect(self.save_config_to_agent)
        buttons_layout.addWidget(save_button)

        layout.addLayout(buttons_layout)
        widget.setLayout(layout)
        return widget

    def create_config_group(self, title: str, form: QFormLayout) -> QGroupBox:
        group = QGroupBox(title)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setFormAlignment(Qt.AlignmentFlag.AlignTop)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)
        form.setContentsMargins(12, 12, 12, 12)
        group.setLayout(form)
        return group

    def create_config_text_edit(self, placeholder: str, height: int) -> QTextEdit:
        text_edit = QTextEdit()
        text_edit.setPlaceholderText(placeholder)
        text_edit.setMinimumHeight(height)
        text_edit.setMaximumHeight(height)
        return text_edit

    def simple_tab(self, text1, text2):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel(text1))
        layout.addWidget(QLabel(text2))
        widget.setLayout(layout)
        return widget
    
    def select_monitor_path(self):
        path = QFileDialog.getExistingDirectory(
            self, "Selecciona una carpeta o disc per monitoritzar", self.monitoring_path,
        )
        if path:
            self.monitoring_path = path
            self.monitor_path_label.setText(f"Ruta sota vigilÃ ncia: {path}")

    def toggle_monitoring(self):
        if self.monitor_controller.monitor.running:
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def start_monitoring(self):
        if not self.monitoring_path:
            QMessageBox.warning(self, "Ruta no seleccionada", "Selecciona una ruta abans d'iniciar la monitorització.")
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
        self.monitor_status_label.setText("Protecció en temps real activada")
        self.monitor_status_label.setObjectName("statusActive")
        self.monitor_status_label.style().unpolish(self.monitor_status_label)
        self.monitor_status_label.style().polish(self.monitor_status_label)
        self.monitor_toggle_button.setText("Aturar protecciÃ³")

    def stop_monitoring(self):
        self.monitor_controller.stop_monitoring()
        self.monitor_status_label.setText("Protecció desactivada")
        self.monitor_status_label.setObjectName("statusInactive")
        self.monitor_status_label.style().unpolish(self.monitor_status_label)
        self.monitor_status_label.style().polish(self.monitor_status_label)
        self.monitor_toggle_button.setText("Activar protecciÃ³")

    def handle_monitor_event(self, path: str, action: str):
        self.monitor_event_signal.emit(path, action)

    @pyqtSlot(str, str)
    def on_monitor_event_received(self, path: str, action: str):
        response = self.monitor_controller.scan_changed_file(path)
        self.monitor_scanned_files += 1
        self.monitor_files_label.setText(f"Fitxers analitzats: {self.monitor_scanned_files}")

        now = datetime.now().astimezone().strftime("%H:%M:%S")
        status = "clean"
        score = 0
        result_text = "Sense deteccions (Segur)"

        if response.get("status") != "ok":
            status = "error"
            result_text = response.get("message", "Error de connexiÃ³ amb l'agent.")
        else:
            data = response.get("data") or {}
            files = data.get("files", [])

            if files:
                file_result = files[0]
                status = file_result.get("classification", "unknown")
                score = file_result.get("final_score", 0)
                detections = file_result.get("detections", [])
                if detections:
                    result_text = " | ".join(f"[{d.get('engine', '')}] {d.get('name', '')}" for d in detections)

                if status in ["suspicious", "malware", "quarantined"]:
                    self.monitor_threats += 1
                    self.monitor_threats_label.setText(f"Amenaces detectades: {self.monitor_threats}")
            else:
                status = "clean"
                score = 0
                result_text = "Net (Filtre Bloom + YARA OK)"

        self.update_monitor_table(path=path, time=now, action=action, status=status, score=score, result=result_text)

    def update_monitor_table(self, path: str, time: str, action: str, status: str, score: int, result: str):
        if path in self.monitor_rows:
            row = self.monitor_rows[path]
        else:
            row = self.monitor_table.rowCount()
            self.monitor_table.insertRow(row)
            self.monitor_rows[path] = row

        self.monitor_table.setItem(row, 0, QTableWidgetItem(str(time)))
        self.monitor_table.setItem(row, 1, QTableWidgetItem(str(action)))
        self.monitor_table.setItem(row, 2, QTableWidgetItem(str(path)))
        self.monitor_table.setItem(row, 3, QTableWidgetItem(str(status)))
        self.monitor_table.setItem(row, 4, QTableWidgetItem(str(score)))
        self.monitor_table.setItem(row, 5, QTableWidgetItem(str(result)))
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

    def show_quarantine_cell_details(self, row: int, column: int):
        item = self.quarantine_table.item(row, column)
        if item is None:
            self.quarantine_details.clear()
            self.quarantine_details.setVisible(False)
            return
        column_name = self.quarantine_table.horizontalHeaderItem(column).text()
        value = item.text()
        self.quarantine_details.setPlainText(f"{column_name}:\n{value}")
        self.quarantine_details.setVisible(True)

    def show_history_cell_details(self, row: int, column: int):
        item = self.history_table.item(row, column)
        if item is None:
            self.history_details.clear()
            self.history_details.setVisible(False)
            return
        column_name = self.history_table.horizontalHeaderItem(column).text()
        value = item.text()
        self.history_details.setPlainText(f"{column_name}:\n{value}")
        self.history_details.setVisible(True)

    def eventFilter(self, source, event):
        if event.type() == QEvent.Type.MouseButtonPress:
            if source == self.monitor_table.viewport():
                item = self.monitor_table.itemAt(event.pos())
                if item is None:
                    self.monitor_table.clearSelection()
                    self.monitor_details.clear()
                    self.monitor_details.setVisible(False)
            
            elif source == self.quarantine_table.viewport():
                item = self.quarantine_table.itemAt(event.pos())
                if item is None:
                    self.quarantine_table.clearSelection()
                    self.quarantine_details.clear()
                    self.quarantine_details.setVisible(False)
            
            elif source == self.history_table.viewport():
                item = self.history_table.itemAt(event.pos())
                if item is None:
                    self.history_table.clearSelection()
                    self.history_details.clear()
                    self.history_details.setVisible(False)

        return super().eventFilter(source, event)
    
    def select_file_for_quarantine(self):
        path, _ = QFileDialog.getOpenFileName(self, "Selecciona un fitxer per enviar a quarantena")
        if path:
            self.selected_quarantine_file = path
            self.quarantine_selected_label.setText(path)

    def quarantine_selected_file(self):
        if not self.selected_quarantine_file:
            QMessageBox.warning(self, "Cap fitxer seleccionat", "Selecciona primer un fitxer.")
            return

        response = self.quarantine_controller.quarantine_file(self.selected_quarantine_file)
        if response.get("status") != "ok":
            QMessageBox.critical(self, "Error de quarantena", response.get("message", "Error desconegut."))
            return

        QMessageBox.information(self, "Quarantena", "El fitxer s'ha enviat correctament a quarantena.")
        self.selected_quarantine_file = None
        self.quarantine_selected_label.setText("Cap fitxer seleccionat")
        self.load_quarantine_list()

    def load_quarantine_list(self, silent: bool = False):
        response = self.quarantine_controller.list_quarantine()
        if response.get("status") != "ok":
            if not silent:
                QMessageBox.critical(self, "Error", response.get("message", "No s'ha pogut carregar la quarantena."))
            return

        entries = response.get("data") or []
        self.quarantine_table.setRowCount(0)

        for entry in entries:
            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)

            formatted_date = self.format_timestamp(entry.get("quarantined_at", ""))
            
            self.quarantine_table.setItem(row, 0, QTableWidgetItem(formatted_date))
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(entry.get("id", "")))
            self.quarantine_table.setItem(row, 2, QTableWidgetItem(entry.get("filename", "")))
            self.quarantine_table.setItem(row, 3, QTableWidgetItem(entry.get("original_path", "")))
            self.quarantine_table.setItem(row, 4, QTableWidgetItem(entry.get("status", "")))
            self.apply_row_color(self.quarantine_table, row, entry.get("status", ""))

    def restore_selected_quarantine(self):
        selected_row = self.quarantine_table.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "Cap entrada seleccionada", "Selecciona primer una entrada de la taula.")
            return

        id_item = self.quarantine_table.item(selected_row, 1)
        if id_item is None:
            QMessageBox.warning(self, "ID no trobat", "No s'ha pogut obtenir l'ID de quarantena.")
            return

        quarantine_id = id_item.text()
        response = self.quarantine_controller.restore_quarantine(quarantine_id)

        if response.get("status") != "ok":
            QMessageBox.critical(self, "Error restaurant", response.get("message", "No s'ha pogut restaurar el fitxer."))
            return

        QMessageBox.information(self, "Fitxer restaurat", "El fitxer s'ha restaurat correctament.")
        self.load_quarantine_list()    

    def delete_selected_quarantine(self):
        selected_row = self.quarantine_table.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "Cap entrada seleccionada", "Selecciona primer una entrada de la taula.")
            return

        id_item = self.quarantine_table.item(selected_row, 1)
        if id_item is None:
            QMessageBox.warning(self, "ID no trobat", "No s'ha pogut obtenir l'ID de quarantena.")
            return

        quarantine_id = id_item.text()
        confirm = QMessageBox.question(
            self, "Confirmar eliminaciÃ³", "Segur que vols eliminar definitivament aquest fitxer de quarantena?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        response = self.quarantine_controller.delete_quarantine(quarantine_id)
        if response.get("status") != "ok":
            QMessageBox.critical(self, "Error eliminant", response.get("message", "No s'ha pogut eliminar el fitxer."))
            return

        QMessageBox.information(self, "Fitxer eliminat", "El fitxer s'ha eliminat definitivament.")
        self.load_quarantine_list()

    def load_history_list(self, silent: bool = False):
        response = self.history_controller.list_history()
        if response.get("status") != "ok":
            if not silent:
                QMessageBox.critical(self, "Error", response.get("message", "No s'ha pogut carregar l'historial."))
            return

        entries = response.get("data") or []
        self.history_table.setRowCount(0)

        for entry in entries:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)

            formatted_date = self.format_timestamp(entry.get("timestamp", ""))

            self.history_table.setItem(row, 0, QTableWidgetItem(formatted_date))
            self.history_table.setItem(row, 1, QTableWidgetItem(entry.get("action", "")))
            self.history_table.setItem(row, 2, QTableWidgetItem(entry.get("path", "") or ""))
            self.history_table.setItem(row, 3, QTableWidgetItem(entry.get("result", "")))
            self.history_table.setItem(row, 4, QTableWidgetItem(str(entry.get("score", ""))))
            self.history_table.setItem(row, 5, QTableWidgetItem(entry.get("details", "")))
            self.apply_row_color(self.history_table, row, entry.get("result", ""))

    def load_config_from_agent(self):
        response = self.config_controller.get_config()
        if response.get("status") != "ok":
            QMessageBox.critical(self, "Error", response.get("message", "No s'ha pogut carregar la configuració."))
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
        self.config_excluded_paths.setPlainText("\n".join(exclusions.get("paths", [])))
        self.config_excluded_extensions.setPlainText("\n".join(exclusions.get("extensions", [])))

        auto_quarantine = config.get("auto_quarantine", {})
        self.config_auto_quarantine_enabled.setChecked(auto_quarantine.get("enabled", False))

        level = auto_quarantine.get("minimum_classification", "malware")
        index = self.config_auto_quarantine_level.findText(level)
        if index >= 0:
            self.config_auto_quarantine_level.setCurrentIndex(index)

        quick_scan = config.get("quick_scan", {})
        self.config_quick_max_size.setValue(quick_scan.get("max_file_size_mb", 20))
        self.config_quick_max_depth.setValue(quick_scan.get("max_depth", 2))
        self.config_quick_yara_timeout.setValue(quick_scan.get("yara_timeout_secs", 5))
        self.config_quick_extensions.setPlainText("\n".join(quick_scan.get("extensions", [])))
        self.config_quick_excluded_dirs.setPlainText("\n".join(quick_scan.get("excluded_dirs", [])))

    def save_config_to_agent(self):
        if self.current_config is None:
            QMessageBox.warning(self, "Configuració no carregada", "Carrega primer la configuració abans de guardar.")
            return

        config = self.current_config
        config["max_yara_file_size_mb"] = self.config_yara_size.value()
        config.setdefault("heuristics", {})
        config["heuristics"]["enabled"] = self.config_heuristics_enabled.isChecked()
        config["heuristics"]["base64_min_length"] = self.config_base64_length.value()
        config["heuristics"]["entropy_threshold"] = self.config_entropy_threshold.value()
        config.setdefault("pe_analysis", {})
        config["pe_analysis"]["enabled"] = self.config_pe_enabled.isChecked()
        config.setdefault("monitoring", {})
        config["monitoring"]["enabled"] = self.config_monitoring_enabled.isChecked()

        config.setdefault("exclusions", {})
        config["exclusions"]["paths"] = [line.strip() for line in self.config_excluded_paths.toPlainText().splitlines() if line.strip()]
        config["exclusions"]["extensions"] = [line.strip() for line in self.config_excluded_extensions.toPlainText().splitlines() if line.strip()]

        config.setdefault("quick_scan", {})
        config["quick_scan"]["max_file_size_mb"] = self.config_quick_max_size.value()
        config["quick_scan"]["max_depth"] = self.config_quick_max_depth.value()
        config["quick_scan"]["yara_timeout_secs"] = self.config_quick_yara_timeout.value()
        config["quick_scan"]["extensions"] = [line.strip() for line in self.config_quick_extensions.toPlainText().splitlines() if line.strip()]
        config["quick_scan"]["excluded_dirs"] = [line.strip() for line in self.config_quick_excluded_dirs.toPlainText().splitlines() if line.strip()]

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
            QMessageBox.critical(self, "Error", response.get("message", "No s'ha pogut guardar la configuració."))
            return

        QMessageBox.information(self, "Configuració", "Configuració guardada correctament.")    

    def detect_system_theme(self):
        palette = QApplication.instance().palette()
        window_color = palette.color(QPalette.ColorRole.Window)
        brightness = (window_color.red() * 0.299 + window_color.green() * 0.587 + window_color.blue() * 0.114)
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
                "clean": "#143d2b", "suspicious": "#4a3b12", "malware": "#4a1f24",
                "quarantined": "#4a3212", "restored": "#163a45", "deleted": "#333333", "error": "#5a1f24",
            }
            default = "#2b2b2b"
        else:
            colors = {
                "clean": "#d4edda", "suspicious": "#fff3cd", "malware": "#f8d7da",
                "quarantined": "#ffe5b4", "restored": "#d1ecf1", "deleted": "#e2e3e5", "error": "#f5c6cb",
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

    def start_quick_scan(self):
        self.result_list.clear()
        self.start_button.setEnabled(False)
        self.start_button.set_scanning(True)
        self.quick_progress_value = 0
        self.set_progress_smooth(0)
        self.quick_progress_timer.start()

        self.quick_scan_worker = QuickScanWorker()
        self.quick_scan_worker.scan_finished.connect(self.finish_scan)
        self.quick_scan_worker.start()




