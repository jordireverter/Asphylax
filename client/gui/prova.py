
import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel,
    QPushButton, QTabWidget, QProgressBar, QListWidget, QMessageBox, QComboBox, QHBoxLayout, QGraphicsOpacityEffect
)
from PyQt6.QtGui import QIcon, QFont, QPixmap
from PyQt6.QtCore import Qt, QTimer, QSize, QPropertyAnimation, QEasingCurve


class AsphylaxUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Asphylax Antivirus")
        self.setGeometry(200, 200, 1100, 650)
        self.setWindowIcon(QIcon("icons/logo.svg"))

        # Mode inicial
        self.current_mode = "light"
        self.apply_style(self.current_mode)

        # Layout principal
        main_layout = QVBoxLayout()
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # Header amb logo i selector mode
        header_layout = QHBoxLayout()
        logo_label = QLabel()
        pixmap = QPixmap("icons/logo.svg").scaled(40, 40, Qt.AspectRatioMode.KeepAspectRatio)
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

        # Pestanyes
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_scan_tab(), QIcon("icons/scan.svg"), "Escaneig")
        self.tabs.addTab(self.create_heuristic_tab(), QIcon("icons/heuristic.svg"), "Heurística")
        self.tabs.addTab(self.create_monitor_tab(), QIcon("icons/monitor.svg"), "Monitorització")
        self.tabs.addTab(self.create_quarantine_tab(), QIcon("icons/quarantine.svg"), "Quarantena")
        self.tabs.addTab(self.create_history_tab(), QIcon("icons/history.svg"), "Historial")
        self.tabs.addTab(self.create_settings_tab(), QIcon("icons/settings.svg"), "Configuració")
        main_layout.addWidget(self.tabs)

    def apply_style(self, mode):
        style_file = "style_dark.qss" if mode == "dark" else "style_light.qss"
        with open(style_file, "r") as f:
            self.setStyleSheet(f.read())

    def change_mode(self, index):
        self.current_mode = "dark" if index == 1 else "light"
        self.apply_style(self.current_mode)

    # Pestanya Escaneig
    def create_scan_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("Escaneig Antivirus")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Botó START gran i rodó amb ombra
        self.start_button = QPushButton("START")
        self.start_button.setFixedSize(150, 150)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #FF0000;
                color: white;
                border-radius: 75px;
                font-size: 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #8B0000;
            }
        """)
        self.start_button.clicked.connect(self.start_scan)
        layout.addWidget(self.start_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # Desplegable per tipus d’escaneig
        self.scan_type = QComboBox()
        self.scan_type.addItems(["Escaneig ràpid", "Escaneig complet", "Escaneig focalitzat"])
        layout.addWidget(self.scan_type, alignment=Qt.AlignmentFlag.AlignCenter)

        # Barra de progrés (oculta inicialment)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        widget.setLayout(layout)
        return widget

    # Pestanyes simulades
    def create_heuristic_tab(self):
        return self.simple_tab("Anàlisi heurística (simulada)", "Opció per activar/desactivar heurística")

    def create_monitor_tab(self):
        return self.simple_tab("Monitorització en temps real (simulada)", "Panell d'esdeveniments")

    def create_quarantine_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Fitxers en quarantena"))
        quarantine_list = QListWidget()
        quarantine_list.addItem("example.infected")
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
        history_list.addItem("25/11/2025 - Cap amenaça trobada")
        history_list.addItem("20/11/2025 - 2 fitxers sospitosos")
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

    # Simulació escaneig amb animació
    def start_scan(self):
        self.progress.setVisible(True)

        # Fade-in barra
        effect = QGraphicsOpacityEffect(self.progress)
        self.progress.setGraphicsEffect(effect)
        fade = QPropertyAnimation(effect, b"opacity")
        fade.setDuration(500)
        fade.setStartValue(0)
        fade.setEndValue(1)
        fade.start()

        # Animació pulsació botó
        self.animation = QPropertyAnimation(self.start_button, b"size")
        self.animation.setDuration(500)
        self.animation.setStartValue(self.start_button.size())
        self.animation.setEndValue(QSize(160, 160))
        self.animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.animation.setLoopCount(-1)
        self.animation.start()

        # Inici escaneig
        self.progress.setValue(0)
        self.start_button.setText("0%")
        self.files = ["Fitxer1", "Fitxer2", "Fitxer3", "Fitxer4"]
        self.index = 0

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_scan)
        self.timer.start(100)

    def update_scan(self):
        if self.index < len(self.files):
            percent = int((self.index / len(self.files)) * 100)
            self.progress.setValue(percent)
            self.start_button.setText(f"{percent}%")
            self.index += 1
        else:
            self.timer.stop()
            self.progress.setValue(100)
            self.start_button.setText("100%")
            self.animation.stop()
            QMessageBox.information(self, "Escaneig complet", "L'escaneig ha finalitzat.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AsphylaxUI()
    window.show()
    sys.exit(app.exec())
