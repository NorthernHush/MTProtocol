#!/usr/bin/env python3
# main.py
import sys
import os
import subprocess
import json
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QComboBox, QSpinBox, QCheckBox, QPushButton,
    QTextEdit, QFileDialog, QFrame, QSizePolicy
)
from PyQt6.QtCore import QProcess, Qt, QUrl, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QDesktopServices, QColor, QPalette, QIcon


class Worker(QObject):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.process = None

    def start_scan(self, cmd):
        self.process = QProcess()
        self.process.setProgram(cmd[0])
        self.process.setArguments(cmd[1:])
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.on_finished)
        self.process.start()

    def handle_stdout(self):
        data = self.process.readAllStandardOutput()
        text = bytes(data).decode('utf-8', errors='replace').strip()
        if text:
            self.log_signal.emit(text)

    def handle_stderr(self):
        data = self.process.readAllStandardError()
        text = bytes(data).decode('utf-8', errors='replace').strip()
        if text:
            self.log_signal.emit(f"⚠️ STDERR: {text}")

    def on_finished(self):
        self.finished_signal.emit()

    def stop(self):
        if self.process and self.process.state() == QProcess.ProcessState.Running:
            self.process.kill()
            self.process.waitForFinished(2000)


class OxxyenQuantumGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🌌 OXXYEN QUANTUM SECURITY — Supreme Sentinel")
        self.resize(1200, 800)
        self.setStyleSheet(self.get_dark_theme())
        self.worker = Worker()
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_scan_finished)
        self.scanning = False

        # Центральный виджет
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Заголовок
        title = QLabel("🌌 OXXYEN QUANTUM SECURITY<br><small>Supreme Sentinel v20.1 • 2000+ AI-Powered Rules</small>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #bb86fc; margin-bottom: 10px;")
        main_layout.addWidget(title)

        # Панель управления
        control_frame = QFrame()
        control_frame.setStyleSheet("background: #1e1e2e; border-radius: 12px; padding: 15px;")
        control_layout = QVBoxLayout(control_frame)

        # Путь
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("📁 Путь к проекту:"))
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Выберите директорию проекта...")
        self.path_edit.setStyleSheet("padding: 8px; border-radius: 6px;")
        browse_btn = QPushButton("📂")
        browse_btn.setFixedWidth(40)
        browse_btn.clicked.connect(self.browse_path)
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(browse_btn)
        control_layout.addLayout(path_layout)

        # Опции
        options_layout = QHBoxLayout()
        options_layout.addWidget(QLabel("🧵 Потоки:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 64)
        self.threads_spin.setValue(16)
        options_layout.addWidget(self.threads_spin)

        options_layout.addWidget(QLabel("🎯 Режим:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Проект", "Директория", "Файл"])
        options_layout.addWidget(self.mode_combo)
        control_layout.addLayout(options_layout)

        # Чекбоксы
        checks_layout = QHBoxLayout()
        self.check_crypto = QCheckBox("🔐 Глубокий криптоанализ")
        self.check_ai = QCheckBox("🤖 AI-анализ")
        self.check_quantum = QCheckBox("⚛️ Квантовая проверка")
        self.check_all = QCheckBox("💫 Все отчёты")
        self.check_all.setChecked(True)
        checks_layout.addWidget(self.check_crypto)
        checks_layout.addWidget(self.check_ai)
        checks_layout.addWidget(self.check_quantum)
        checks_layout.addWidget(self.check_all)
        control_layout.addLayout(checks_layout)

        main_layout.addWidget(control_frame)

        # Кнопки
        btn_layout = QHBoxLayout()
        self.btn_scan = QPushButton("🚀 ЗАПУСТИТЬ СКАНИРОВАНИЕ")
        self.btn_stop = QPushButton("⏹️ ОСТАНОВИТЬ")
        self.btn_stop.setEnabled(False)
        self.btn_html = QPushButton("🌐 HTML-ОТЧЁТ")
        self.btn_md = QPushButton("📄 MD-ОТЧЁТ")
        self.btn_json = QPushButton("📊 JSON-ОТЧЁТ")
        btn_layout.addWidget(self.btn_scan)
        btn_layout.addWidget(self.btn_stop)
        btn_layout.addWidget(self.btn_html)
        btn_layout.addWidget(self.btn_md)
        btn_layout.addWidget(self.btn_json)
        main_layout.addLayout(btn_layout)

        # Лог
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("JetBrains Mono", 10))
        self.log_view.setStyleSheet("""
            QTextEdit {
                background: #11111b;
                color: #cdd6f4;
                border-radius: 10px;
                padding: 12px;
            }
        """)
        main_layout.addWidget(self.log_view)

        # Подключения
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_html.clicked.connect(lambda: self.open_report("quantum_security_audit.html"))
        self.btn_md.clicked.connect(lambda: self.open_report("quantum_security_audit_report.md"))
        self.btn_json.clicked.connect(lambda: self.open_report("quantum_security_audit.json"))

        # Темы
        theme_layout = QHBoxLayout()
        self.dark_btn = QPushButton("🌙 Тёмная")
        self.light_btn = QPushButton("☀️ Светлая")
        self.dark_btn.clicked.connect(lambda: self.set_theme("dark"))
        self.light_btn.clicked.connect(lambda: self.set_theme("light"))
        theme_layout.addWidget(self.dark_btn)
        theme_layout.addWidget(self.light_btn)
        main_layout.addLayout(theme_layout)

    def get_dark_theme(self):
        return """
            QMainWindow { background: #121212; }
            QLabel { color: #e0e0e0; }
            QLineEdit, QSpinBox {
                background: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #333;
                border-radius: 6px;
                padding: 6px;
            }
            QCheckBox { color: #bb86fc; spacing: 10px; }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #6a11cb, stop:1 #2575fc);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #7a21db, stop:1 #3585ff);
            }
            QFrame { background: #1e1e2e; }
        """

    def get_light_theme(self):
        return """
            QMainWindow { background: #f5f5f5; }
            QLabel { color: #333; }
            QLineEdit, QSpinBox {
                background: white;
                color: #333;
                border: 1px solid #ccc;
                border-radius: 6px;
                padding: 6px;
            }
            QCheckBox { color: #6a11cb; spacing: 10px; }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #6a11cb, stop:1 #2575fc);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #7a21db, stop:1 #3585ff);
            }
            QFrame { background: white; border: 1px solid #eee; }
            QTextEdit {
                background: white;
                color: #333;
                border: 1px solid #ddd;
            }
        """

    def set_theme(self, theme):
        if theme == "dark":
            self.setStyleSheet(self.get_dark_theme())
        else:
            self.setStyleSheet(self.get_light_theme())

    def browse_path(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите проект")
        if path:
            self.path_edit.setText(path)

    def log(self, msg):
        self.log_view.append(msg)
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())

    def start_scan(self):
        path = self.path_edit.text().strip()
        if not path:
            self.log("❌ Укажите путь к проекту!")
            return
        if not os.path.exists(path):
            self.log(f"❌ Путь не существует: {path}")
            return

        args = ["./meshsec_quantum_max"]
        args += ["--quantum-scan-project", path]
        if self.check_all.isChecked():
            args.append("--quantum-all-reports")

        self.log(f"🚀 Запуск: {' '.join(args)}")
        self.scanning = True
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.worker.start_scan(args)

    def stop_scan(self):
        if self.scanning:
            self.log("⏹️ Остановка сканирования...")
            self.worker.stop()
            self.scanning = False
            self.btn_scan.setEnabled(True)
            self.btn_stop.setEnabled(False)

    def on_scan_finished(self):
        self.scanning = False
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.log("✅ Сканирование завершено!")
        self.log("📄 Сгенерированы отчёты:")
        self.log("   - quantum_security_audit.html")
        self.log("   - quantum_security_audit_report.md")
        self.log("   - quantum_security_audit.json")

    def open_report(self, filename):
        full = Path(filename).resolve()
        if full.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(full)))
        else:
            self.log(f"⚠️ Отчёт не найден: {full}")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = OxxyenQuantumGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()