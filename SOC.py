"""SOC Security Center: educational Linux log-monitoring prototype."""

import hashlib
import html
import json
import re
import select
import sqlite3
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

from PyQt5.QtCore import QThread, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QTextCursor, QTextCharFormat
from PyQt5.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QHBoxLayout, QInputDialog,
    QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox,
    QPlainTextEdit, QTextEdit, QPushButton, QSplitter, QTabWidget,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

APP_NAME = "SOC Security Center"
DATA_DIR = Path.home() / ".local" / "share" / "soc-security-center"
DB_PATH = DATA_DIR / "soc.db"
BASELINE_PATH = DATA_DIR / "file_baseline.json"

MAX_LOGS = 5000
LOG_TRIM_BATCH = 1000
MAX_ALERTS = 2000
EVENT_RETENTION_DAYS = 7
MAX_EVENT_STORAGE_MB = 500
MAX_EVENT_STORAGE_BYTES = MAX_EVENT_STORAGE_MB * 1024 * 1024
CLEANUP_EVERY_EVENTS = 1000
CLEANUP_INTERVAL_SECONDS = 3600

BG = "#07110B"
PANEL = "#0D1B12"
GREEN = "#39FF88"
WHITE = "#E6F4EA"
BLUE = "#64B5F6"
YELLOW = "#FFD54F"
RED = "#FF5252"

SEVERITY_COLORS = {'INFO': BLUE, 'WARNING': YELLOW, 'CRITICAL': RED}

FAILED_LOGIN_RE = re.compile(
    r"failed password|authentication failure|authentication failed|"
    r"failed publickey|invalid user|maximum authentication attempts",
    re.I)
SUCCESS_LOGIN_RE = re.compile(
    r"accepted password|accepted publickey|session opened for user",
    re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

NETWORK_RE = re.compile(
    r"\b(ssh|sshd|ufw|firewall|network|connection|port|tcp|udp|sudo)\b",
    re.I)

MITRE_RULES = {
    "FAILED-LOGIN": ("T1110", "Brute Force"),
    "SSH-BRUTE-FORCE": ("T1110", "Brute Force"),
    "SSH-SUCCESS-AFTER-FAILURES": ("T1078", "Valid Accounts"),
    "SUDO-ACTIVITY": ("T1548.003", "Sudo and Sudo Caching"),
    "FILE-INTEGRITY-CHANGE": (
        "T1565.001", "Stored Data Manipulation"
    ),
}


def now_text():
    return datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')


def safe_text(value):
    return str(value if value is not None else '').replace('\x00', '').strip()


def extract_ip(message):
    for candidate in IP_RE.findall(message):
        try:
            octets = [int(part) for part in candidate.split(".")]
            if len(octets) == 4 and all(
                0 <= octet <= 255 for octet in octets
            ):
                return candidate
        except ValueError:
            pass
    return ""


class Database:
    """SQLite storage with retention limits for ordinary log events."""

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(DB_PATH))
        self.connection.row_factory = sqlite3.Row
        self.events_since_cleanup = 0
        self.last_cleanup = time.monotonic()

        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                priority INTEGER,
                message TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                explanation TEXT NOT NULL,
                mitre_id TEXT NOT NULL DEFAULT '',
                mitre_name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'Offen',
                notes TEXT NOT NULL DEFAULT '',
                fingerprint TEXT NOT NULL UNIQUE
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Offen',
                description TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp);
        """)

        self.connection.commit()
        self.cleanup_events()

    def add_event(self, event):
        self.connection.execute(
            """
            INSERT INTO events(timestamp, source, priority, message)
            VALUES (?, ?, ?, ?)
            """,
            (
                event["time"], event["source"],
                event.get("priority", 6), event["message"],
            ))
        self.connection.commit()
        self.events_since_cleanup += 1

        if (
            self.events_since_cleanup >= CLEANUP_EVERY_EVENTS
            or time.monotonic() - self.last_cleanup
            >= CLEANUP_INTERVAL_SECONDS
        ):
            self.cleanup_events()

    def _event_payload_bytes(self):
        row = self.connection.execute("""
            SELECT COALESCE(SUM(
                length(CAST(timestamp AS BLOB)) +
                length(CAST(source AS BLOB)) +
                length(CAST(message AS BLOB)) + 64
            ), 0) AS total
            FROM events
        """).fetchone()

        return int(row["total"] or 0)

    def cleanup_events(self, force_vacuum=False):
        cutoff = (
            datetime.now() - timedelta(days=EVENT_RETENTION_DAYS)
        ).strftime("%Y-%m-%d %H:%M:%S")

        self.connection.execute(
            "DELETE FROM events WHERE substr(timestamp, 1, 19) < ?",
            (cutoff,))

        while self._event_payload_bytes() > MAX_EVENT_STORAGE_BYTES:
            cursor = self.connection.execute("""
                DELETE FROM events
                WHERE id IN (
                    SELECT id FROM events ORDER BY id ASC LIMIT 1000)
            """)
            if cursor.rowcount <= 0:
                break

        self.connection.commit()
        self.events_since_cleanup = 0
        self.last_cleanup = time.monotonic()

        db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
        threshold = MAX_EVENT_STORAGE_BYTES + 50 * 1024 * 1024

        if force_vacuum or db_size > threshold:
            self.connection.execute("VACUUM")

    def storage_info(self):
        db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
        return db_size, self._event_payload_bytes()

    def add_alert(self, alert):
        mitre_id, mitre_name = MITRE_RULES.get(
            alert["rule"], ("", "Keine spezifische Zuordnung"))

        raw = "|".join((
            alert["time"], alert["rule"], alert["source"],
            alert["message"], alert["severity"],
        ))
        fingerprint = hashlib.sha256(raw.encode('utf-8', errors='replace')).hexdigest()

        cursor = self.connection.execute("""
            INSERT OR IGNORE INTO alerts (
                timestamp, severity, rule, source, message,
                explanation, mitre_id, mitre_name, fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["time"], alert["severity"], alert["rule"],
            alert["source"], alert["message"], alert["explanation"],
            mitre_id, mitre_name, fingerprint,
        ))

        self.connection.commit()
        return cursor.lastrowid if cursor.rowcount else None

    def update_alert(self, alert_id, status, notes):
        self.connection.execute(
            "UPDATE alerts SET status=?, notes=? WHERE id=?",
            (status, notes, alert_id))
        self.connection.commit()

    def alerts(self, limit=MAX_ALERTS):
        return self.connection.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def add_incident(self, title, severity, description):
        self.connection.execute(
            """
            INSERT INTO incidents(created_at, title, severity, description)
            VALUES (?, ?, ?, ?)
            """,
            (now_text(), title, severity, description))
        self.connection.commit()

    def incidents(self):
        return self.connection.execute('SELECT * FROM incidents ORDER BY id DESC').fetchall()

    def update_incident(self, incident_id, status, notes):
        self.connection.execute(
            "UPDATE incidents SET status=?, notes=? WHERE id=?",
            (status, notes, incident_id))
        self.connection.commit()

    def close(self):
        self.connection.close()


class DetectionEngine:
    """Heuristic rules provide indicators, not proof of an attack."""

    def __init__(self):
        self.failed_by_ip = defaultdict(deque)
        self.recent_failed_by_ip = defaultdict(deque)

    @staticmethod
    def make_alert(event, severity, rule, explanation):
        return {
            "time": event["time"],
            "severity": severity,
            "rule": rule,
            "source": event["source"],
            "message": event["message"],
            "explanation": explanation,
        }

    def analyze(self, event):
        message = safe_text(event.get("message", ""))
        if not message:
            return []

        low = message.lower()

        if "soc_test" in low:
            return [self.make_alert(
                event, "INFO", "SOC-TEST-MESSAGE",
                "Eigene Testmeldung erkannt; dies ist kein Angriffsnachweis.",
            )]

        alerts = []
        ip = extract_ip(message)
        current_time = datetime.now()

        if FAILED_LOGIN_RE.search(message):
            if ip:
                history = self.failed_by_ip[ip]
                history.append(current_time)
                cutoff = current_time - timedelta(minutes=5)

                while history and history[0] < cutoff:
                    history.popleft()

                recent = self.recent_failed_by_ip[ip]
                recent.append(current_time)
                cutoff_recent = current_time - timedelta(minutes=10)

                while recent and recent[0] < cutoff_recent:
                    recent.popleft()

                if len(history) >= 5:
                    alerts.append(self.make_alert(
                        event, "CRITICAL", "SSH-BRUTE-FORCE",
                        f"Mindestens {len(history)} fehlgeschlagene "
                        f"Anmeldeereignisse mit Bezug zu {ip} in fünf "
                        "Minuten. Möglicher Brute-Force-Indikator; "
                        "Quelle und Kontext prüfen.",
                    ))
                else:
                    alerts.append(self.make_alert(
                        event, "WARNING", "FAILED-LOGIN",
                        "Fehlgeschlagene Authentifizierung. "
                        "Häufigkeit und Herkunft prüfen.",
                    ))
            else:
                alerts.append(self.make_alert(
                    event, "WARNING", "FAILED-LOGIN",
                    "Fehlgeschlagene Authentifizierung; "
                    "keine IP sicher extrahiert.",
                ))

        elif SUCCESS_LOGIN_RE.search(message):
            if ip:
                recent = self.recent_failed_by_ip[ip]
                cutoff = current_time - timedelta(minutes=10)

                while recent and recent[0] < cutoff:
                    recent.popleft()

                if recent:
                    alerts.append(self.make_alert(
                        event, "CRITICAL", "SSH-SUCCESS-AFTER-FAILURES",
                        f"Erfolgreiche Anmeldung mit Bezug zu {ip} nach "
                        "vorherigen Fehlschlägen innerhalb von zehn "
                        "Minuten. Zugriff prüfen.",
                    ))
                else:
                    alerts.append(self.make_alert(
                        event, "INFO", "SSH-LOGIN-SUCCESS",
                        "Erfolgreiche Anmeldung protokolliert.",
                    ))
            else:
                alerts.append(self.make_alert(
                    event, "INFO", "SSH-LOGIN-SUCCESS",
                    "Erfolgreiche Anmeldung protokolliert.",
                ))

        if re.search(r"\bsudo:", low):
            alerts.append(self.make_alert(
                event, "INFO", "SUDO-ACTIVITY",
                "sudo-Aktivität protokolliert; administrativen "
                "Zugriff prüfen.",
            ))

        if re.search(
            r"kernel panic|out of memory|possible break-in attempt", low
        ):
            alerts.append(self.make_alert(
                event, "CRITICAL", "CRITICAL-SYSTEM",
                "Kritische Systemmeldung. Originalmeldung und "
                "Systemzustand prüfen.",
            ))
        elif re.search(
            r"segfault|failed to start|service .* failed|"
            r"apparmor=.*denied|permission denied",
            low,
        ):
            alerts.append(self.make_alert(
                event, "WARNING", "SYSTEM-WARNING",
                "Auffällige Systemmeldung; Kontext untersuchen.",
            ))

        return alerts


class JournalReader(QThread):
    event_received = pyqtSignal(dict)
    status_changed = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True
        self.process = None

    def run(self):
        command = ['journalctl', '-n', '200', '-f', '--no-pager', '-o', 'json']

        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1)
        except Exception as error:
            self.status_changed.emit(f'journalctl konnte nicht starten: {error}')
            return

        self.status_changed.emit("Live-Journal verbunden")

        try:
            while self.running and self.process.poll() is None:
                ready, _, _ = select.select([self.process.stdout], [], [], 0.5)
                if not ready:
                    continue

                line = self.process.stdout.readline()
                if not line:
                    continue

                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue

                message = safe_text(raw.get("MESSAGE", ""))
                if not message:
                    continue

                try:
                    priority = int(raw.get("PRIORITY", 6))
                except (ValueError, TypeError):
                    priority = 6

                event_time = now_text()
                stamp = raw.get("__REALTIME_TIMESTAMP")

                if stamp:
                    try:
                        event_time = datetime.fromtimestamp(
                            int(stamp) / 1_000_000
                        ).astimezone().strftime(
                            "%Y-%m-%d %H:%M:%S %Z")
                    except (ValueError, TypeError, OSError):
                        pass

                self.event_received.emit({
                    "time": event_time,
                    "priority": priority,
                    "source": safe_text(
                        raw.get("SYSLOG_IDENTIFIER")
                        or raw.get("_COMM")
                        or raw.get("_SYSTEMD_UNIT")
                        or "system"
                    ),
                    "message": message,
                })

        except Exception as error:
            if self.running:
                self.status_changed.emit(f'Journal-Lesefehler: {error}')
        finally:
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()

            self.status_changed.emit("Live-Journal beendet")

    def stop(self):
        self.running = False
        if self.process and self.process.poll() is None:
            self.process.terminate()
        self.wait(3000)


class FileIntegrityMonitor:
    """SHA-256 baseline for explicitly selected files."""

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.path = BASELINE_PATH

        try:
            self.baseline = json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            self.baseline = {}

    @staticmethod
    def digest(path):
        hasher = hashlib.sha256()
        with open(path, "rb") as file:
            for chunk in iter(
                lambda: file.read(1024 * 1024), b""
            ):
                hasher.update(chunk)
        return hasher.hexdigest()

    def save(self):
        self.path.write_text(
            json.dumps(self.baseline, indent=2, ensure_ascii=False),
            encoding="utf-8")

    def add_files(self, paths):
        for path in paths:
            resolved = str(Path(path).expanduser().resolve())
            self.baseline[resolved] = self.digest(resolved)
        self.save()

    def remove_file(self, path):
        self.baseline.pop(str(Path(path).resolve()), None)
        self.save()

    def check(self):
        changes = []

        for path, old_hash in self.baseline.items():
            try:
                new_hash = self.digest(path)
            except OSError:
                new_hash = None

            if new_hash != old_hash:
                changes.append((path, new_hash is None, new_hash))

        return changes


class LogExplorer(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SOC – Log-Explorer")
        self.resize(1050, 680)
        self.file_path = None
        self.lines = []
        self.filtered_indices = []

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        toolbar = QHBoxLayout()

        self.open_button = QPushButton("Logdatei öffnen")
        self.reload_button = QPushButton("Neu laden")
        self.save_button = QPushButton("Treffer speichern")

        toolbar.addWidget(self.open_button)
        toolbar.addWidget(self.reload_button)
        toolbar.addWidget(self.save_button)
        layout.addLayout(toolbar)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Suchbegriff …")
        layout.addWidget(self.search)

        splitter = QSplitter()
        self.line_list = QListWidget()
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        splitter.addWidget(self.line_list)
        splitter.addWidget(self.detail)
        splitter.setSizes([420, 630])
        layout.addWidget(splitter)

        self.status = QLabel("Öffne eine Logdatei.")
        layout.addWidget(self.status)

        self.open_button.clicked.connect(self.open_file)
        self.reload_button.clicked.connect(self.load_file)
        self.save_button.clicked.connect(self.save_results)
        self.search.textChanged.connect(self.apply_filter)
        self.line_list.currentRowChanged.connect(self.show_line)

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Logdatei auswählen", "/var/log",
            "Logdateien (*.log *.txt *.log.*);;Alle Dateien (*)")
        if path:
            self.file_path = path
            self.load_file()

    def load_file(self):
        if not self.file_path:
            return
        try:
            with open(
                self.file_path, "r", encoding="utf-8", errors="replace"
            ) as file:
                self.lines = file.readlines()
            self.apply_filter()
        except OSError as error:
            QMessageBox.warning(
                self, "Lesefehler",
                f"{error}\nFür manche Dateien in /var/log "
                "sind Leserechte nötig.")

    def apply_filter(self):
        term = self.search.text().lower().strip()
        self.line_list.clear()
        self.filtered_indices = []

        for index, line in enumerate(self.lines):
            if term and term not in line.lower():
                continue
            self.filtered_indices.append(index)
            self.line_list.addItem(f'Zeile {index + 1}: {line.strip()[:130]}')

        self.status.setText(
            f"{self.file_path or ''} | {len(self.filtered_indices)} "
            f"Treffer / {len(self.lines)} Zeilen")

    def show_line(self, row):
        if row < 0 or row >= len(self.filtered_indices):
            self.detail.clear()
            return
        index = self.filtered_indices[row]
        self.detail.setPlainText(
            f"Datei: {self.file_path}\nZeile: {index + 1}\n\n"
            f"{self.lines[index]}")

    def save_results(self):
        if not self.filtered_indices:
            QMessageBox.information(self, 'Keine Treffer', 'Keine Treffer zum Speichern.')
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Treffer speichern", "soc_log_treffer.txt",
            "Textdateien (*.txt)")
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as file:
                for index in self.filtered_indices:
                    file.write(f'Zeile {index + 1}: {self.lines[index]}')
            QMessageBox.information(self, 'Gespeichert', f'Gespeichert: {path}')
        except OSError as error:
            QMessageBox.warning(self, 'Speicherfehler', str(error))


class SOCWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1400, 900)

        self.db = Database()
        self.engine = DetectionEngine()
        self.integrity = FileIntegrityMonitor()
        self.integrity_alert_states = {}
        self.log_cache = deque(maxlen=MAX_LOGS)
        self.total_events = 0
        self.paused = False
        self.explorer = None

        self.reader = JournalReader()
        self.reader.event_received.connect(self.handle_event)
        self.reader.status_changed.connect(self.show_status)

        self.build_ui()
        self.apply_theme()
        self.populate_alerts()
        self.populate_incidents()
        self.refresh_integrity_list()
        self.update_storage_label()
        self.reader.start()

        self.integrity_timer = QTimer(self)
        self.integrity_timer.timeout.connect(self.check_integrity)
        self.integrity_timer.start(30000)

        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(3000)

        self.storage_timer = QTimer(self)
        self.storage_timer.timeout.connect(self.update_storage_label)
        self.storage_timer.start(60 * 1000)

        self.maintenance_timer = QTimer(self)
        self.maintenance_timer.timeout.connect(self.run_storage_maintenance)
        self.maintenance_timer.start(60 * 60 * 1000)

    def build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        core = QVBoxLayout(central)

        header = QHBoxLayout()
        title = QLabel("🛡 SOC SECURITY CENTER")
        title.setFont(QFont("Sans Serif", 16, QFont.Bold))
        title.setStyleSheet(f"color: {GREEN};")

        self.event_label = QLabel("Ereignisse: 0")
        self.alert_label = QLabel("Alerts: 0")
        self.storage_label = QLabel("Logs: Speicher wird geprüft …")
        self.pause_button = QPushButton("Pause")
        self.clear_button = QPushButton("Ansicht leeren")
        self.export_button = QPushButton("Export")
        self.explorer_button = QPushButton("Log-Explorer")

        for widget in (
            title, self.event_label, self.alert_label,
            self.storage_label, self.pause_button, self.clear_button,
            self.export_button, self.explorer_button,
        ):
            header.addWidget(widget)

        core.addLayout(header)
        self.tabs = QTabWidget()
        core.addWidget(self.tabs)

        # QTextEdit unterstützt unterschiedlich gefärbte Zeilen.
        self.all_logs = QTextEdit()
        self.all_logs.setReadOnly(True)
        self.all_logs.setLineWrapMode(QTextEdit.NoWrap)
        self.all_logs.setPlaceholderText("Warte auf Systemmeldungen …")
        self.all_logs.document().setMaximumBlockCount(MAX_LOGS + LOG_TRIM_BATCH)

        self.network_logs = QTextEdit()
        self.network_logs.setReadOnly(True)
        self.network_logs.setLineWrapMode(QTextEdit.NoWrap)
        self.network_logs.setPlaceholderText('Warte auf Netzwerkereignisse …')
        self.network_logs.document().setMaximumBlockCount(MAX_LOGS + LOG_TRIM_BATCH)

        self.tabs.addTab(self.all_logs, "ALL LOGS")
        self.tabs.addTab(self.network_logs, "NETWORK")
        self.all_logs.setToolTip('System weiß, Netzwerk grün, erkannte Alerts rot.')
        self.network_logs.setToolTip('Gefilterte Netzwerkereignisse werden grün angezeigt.')

        alerts_page = QWidget()
        alerts_layout = QVBoxLayout(alerts_page)
        self.alert_table = QTableWidget(0, 6)
        self.alert_table.setHorizontalHeaderLabels([
            "ID", "Zeit", "Schweregrad", "Regel", "Quelle", "Status"
        ])
        self.alert_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.alert_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.alert_table.setColumnWidth(0, 55)
        self.alert_table.setColumnWidth(1, 180)
        self.alert_table.setColumnWidth(2, 100)
        self.alert_table.setColumnWidth(3, 245)
        self.alert_table.setColumnWidth(4, 160)
        self.alert_table.horizontalHeader().setStretchLastSection(True)
        alerts_layout.addWidget(self.alert_table)

        alert_controls = QHBoxLayout()
        self.alert_status = QComboBox()
        self.alert_status.addItems(['Offen', 'In Prüfung', 'Gelöst', 'Fehlalarm'])
        self.alert_notes = QLineEdit()
        self.alert_notes.setPlaceholderText("Analystennotiz …")
        self.save_alert_button = QPushButton("Status/Notiz speichern")

        alert_controls.addWidget(QLabel("Status:"))
        alert_controls.addWidget(self.alert_status)
        alert_controls.addWidget(self.alert_notes, 1)
        alert_controls.addWidget(self.save_alert_button)
        alerts_layout.addLayout(alert_controls)
        self.tabs.addTab(alerts_page, "ALERTS")

        incident_page = QWidget()
        incident_layout = QVBoxLayout(incident_page)
        self.incident_table = QTableWidget(0, 5)
        self.incident_table.setHorizontalHeaderLabels([
            "ID", "Erstellt", "Titel", "Schweregrad", "Status"
        ])
        self.incident_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.incident_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.incident_table.horizontalHeader().setStretchLastSection(True)
        incident_layout.addWidget(self.incident_table)

        incident_controls = QHBoxLayout()
        self.incident_status = QComboBox()
        self.incident_status.addItems(['Offen', 'In Prüfung', 'Gelöst', 'Fehlalarm'])
        self.incident_notes = QLineEdit()
        self.incident_notes.setPlaceholderText("Vorfallnotiz …")
        self.new_incident_button = QPushButton("Neuen Vorfall anlegen")
        self.save_incident_button = QPushButton("Vorfall speichern")

        incident_controls.addWidget(QLabel("Status:"))
        incident_controls.addWidget(self.incident_status)
        incident_controls.addWidget(self.incident_notes, 1)
        incident_controls.addWidget(self.new_incident_button)
        incident_controls.addWidget(self.save_incident_button)
        incident_layout.addLayout(incident_controls)
        self.tabs.addTab(incident_page, "VORFÄLLE")

        integrity_page = QWidget()
        integrity_layout = QVBoxLayout(integrity_page)
        integrity_layout.addWidget(QLabel(
            "SHA-256-Überwachung ausgewählter Dateien. "
            "Änderungen werden nicht automatisch akzeptiert."
        ))
        self.integrity_list = QListWidget()
        integrity_layout.addWidget(self.integrity_list)

        integrity_controls = QHBoxLayout()
        self.add_files_button = QPushButton("Dateien hinzufügen")
        self.remove_file_button = QPushButton("Datei entfernen")
        self.check_files_button = QPushButton("Jetzt prüfen")

        for widget in (
            self.add_files_button, self.remove_file_button,
            self.check_files_button,
        ):
            integrity_controls.addWidget(widget)

        integrity_layout.addLayout(integrity_controls)
        self.tabs.addTab(integrity_page, "DATEIINTEGRITÄT")

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(280)
        self.details.setMaximumHeight(360)
        core.addWidget(QLabel("ALERT-DETAILS"))
        core.addWidget(self.details)

        self.pause_button.clicked.connect(self.toggle_pause)
        self.clear_button.clicked.connect(self.clear_view)
        self.export_button.clicked.connect(self.export_data)
        self.explorer_button.clicked.connect(self.open_explorer)
        self.alert_table.itemSelectionChanged.connect(self.show_alert_details)
        self.save_alert_button.clicked.connect(self.save_alert_workflow)
        self.incident_table.itemSelectionChanged.connect(self.load_incident_selection)
        self.new_incident_button.clicked.connect(self.new_incident)
        self.save_incident_button.clicked.connect(self.save_incident_workflow)
        self.add_files_button.clicked.connect(self.add_integrity_files)
        self.remove_file_button.clicked.connect(self.remove_integrity_file)
        self.check_files_button.clicked.connect(self.check_integrity)

    def apply_theme(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background: {BG};
                color: {WHITE};
                font-size: 12px;
            }}
            QTabWidget::pane {{
                border: 1px solid #24432E;
                background: {PANEL};
            }}
            QTabBar::tab {{
                background: {PANEL};
                color: {WHITE};
                padding: 8px 12px;
            }}
            QTabBar::tab:selected {{
                color: {GREEN};
                border-bottom: 2px solid {GREEN};
            }}
            QPlainTextEdit, QTextEdit, QLineEdit, QListWidget,
            QTableWidget, QComboBox {{
                background: {PANEL};
                color: {WHITE};
                border: 1px solid #24432E;
                selection-background-color: #1B5E35;
            }}
            QPushButton {{
                background: #12301D;
                color: {GREEN};
                border: 1px solid #28613B;
                border-radius: 5px;
                padding: 7px;
            }}
            QPushButton:hover {{
                background: #1B472A;
            }}
            QHeaderView::section {{
                background: #12301D;
                color: {GREEN};
                padding: 5px;
                border: 1px solid #24432E;
            }}
        """)

    def populate_alerts(self):
        self.alert_table.setRowCount(0)
        for alert in self.db.alerts():
            self.insert_alert_row(alert)
        self.alert_label.setText(f'Alerts: {self.alert_table.rowCount()}')

    def insert_alert_row(self, alert):
        row = self.alert_table.rowCount()
        self.alert_table.insertRow(row)

        values = [
            str(alert["id"]), alert["timestamp"], alert["severity"],
            alert["rule"], alert["source"], alert["status"],
        ]

        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setForeground(QColor(SEVERITY_COLORS.get(alert['severity'], WHITE)))
            self.alert_table.setItem(row, column, item)

    def populate_incidents(self):
        self.incident_table.setRowCount(0)
        for incident in self.db.incidents():
            row = self.incident_table.rowCount()
            self.incident_table.insertRow(row)
            values = [
                str(incident["id"]), incident["created_at"],
                incident["title"], incident["severity"],
                incident["status"],
            ]
            for column, value in enumerate(values):
                self.incident_table.setItem(row, column, QTableWidgetItem(value))

    def handle_event(self, event):
        self.total_events += 1
        self.log_cache.append(event)

        try:
            self.db.add_event(event)
        except sqlite3.Error as error:
            self.show_status(f'Datenbankfehler beim Speichern des Logs: {error}')

        if not self.paused:
            line = f"[{event['time']}] [{event['source']}] {event['message']}"

            alerts = self.engine.analyze(event)

            if event.get("priority", 6) <= 3:
                alerts.append({
                    "time": event["time"],
                    "severity": "WARNING",
                    "rule": "HIGH-JOURNAL-PRIORITY",
                    "source": event["source"],
                    "message": event["message"],
                    "explanation": (
                        "Hohe Journald-Priorität. Kann ein "
                        "Systemproblem sein und ist nicht automatisch "
                        "ein Sicherheitsvorfall."
                    ),
                })

            # Priorität: Alert rot, sonst Netzwerk grün, sonst System weiß.
            if alerts:
                color = RED
            elif NETWORK_RE.search(event["message"]):
                color = GREEN
            else:
                color = WHITE

            self.append_numbered_log(self.all_logs, line, color)

            if NETWORK_RE.search(event["message"]):
                self.append_numbered_log(self.network_logs, line, GREEN)

            for alert in alerts:
                self.add_alert(alert)

        self.event_label.setText(f'Ereignisse: {self.total_events}')

    @staticmethod
    def append_numbered_log(widget, line, color):
        """Append one escaped, color-coded log entry."""
        cursor = widget.textCursor()
        cursor.movePosition(QTextCursor.End)

        if widget.document().blockCount() > 0:
            cursor.insertBlock()

        number = widget.document().blockCount()
        safe_line = html.escape(line)

        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.insertText(f"{number:>5} | {line}", fmt)

        widget.setTextCursor(cursor)

        # Keep the live view bounded without rebuilding its formatting.
        document = widget.document()
        if document.blockCount() > MAX_LOGS:
            trim_count = max(LOG_TRIM_BATCH, document.blockCount() - MAX_LOGS)
            cursor = QTextCursor(document)
            cursor.movePosition(QTextCursor.Start)

            for _ in range(trim_count):
                cursor.select(QTextCursor.BlockUnderCursor)
                cursor.removeSelectedText()
                cursor.deleteChar()

            widget.setTextCursor(widget.textCursor())

    def add_alert(self, alert):
        try:
            alert_id = self.db.add_alert(alert)
        except sqlite3.Error as error:
            self.show_status(f'Datenbankfehler beim Alert: {error}')
            return

        if alert_id is None:
            return

        row = self.db.connection.execute(
            "SELECT * FROM alerts WHERE id=?", (alert_id,)
        ).fetchone()

        self.insert_alert_row(row)
        self.alert_label.setText(f'Alerts: {self.alert_table.rowCount()}')

        if alert["severity"] == "CRITICAL":
            self.statusBar().showMessage(f"CRITICAL: {alert['rule']}", 10000)

    def selected_alert_id(self):
        row = self.alert_table.currentRow()
        if row < 0 or self.alert_table.item(row, 0) is None:
            return None
        try:
            return int(self.alert_table.item(row, 0).text())
        except ValueError:
            return None

    @staticmethod
    def investigation_steps(alert):
        rule = alert["rule"]

        steps = {
            "FAILED-LOGIN": [
                "Prüfe, ob Benutzername und Anmeldeversuch erwartet waren.",
                "Vergleiche Quelle und Häufigkeit mit weiteren Ereignissen.",
                "Bei unbekanntem Zugriff SSH-Konfiguration und Kontosicherheit prüfen.",
            ],
            "SSH-BRUTE-FORCE": [
                "Prüfe Quell-IP und Zahl der Fehlversuche.",
                "Suche nach erfolgreichen Anmeldungen derselben IP.",
                "Prüfe Konten und SSH-Logs; blockiere nicht ohne Kontextprüfung.",
            ],
            "SSH-SUCCESS-AFTER-FAILURES": [
                "Prüfe, ob der erfolgreiche Login erwartet war.",
                "Vergleiche IP, Benutzerkonto und vorherige Fehlversuche.",
                "Bei unbekanntem Zugriff Sitzungen, Schlüssel und Logs prüfen.",
            ],
            "SSH-LOGIN-SUCCESS": [
                "Prüfe Benutzer, Quell-IP und Zeitpunkt.",
                "Suche nach vorherigen Fehlversuchen und sudo-Aktivitäten.",
            ],
            "SUDO-ACTIVITY": [
                "Prüfe Benutzer und ausgeführten sudo-Befehl.",
                "Vergleiche die Aktion mit geplanten administrativen Arbeiten.",
            ],
            "FILE-INTEGRITY-CHANGE": [
                "Prüfe, welche Datei geändert wurde.",
                "Vergleiche Dateiinhalt, Zeit und SHA-256-Hash.",
                "Aktualisiere die Baseline erst nach Bestätigung.",
            ],
            "CRITICAL-SYSTEM": [
                "Prüfe Originalmeldung und benachbarte Systemereignisse.",
                "Kontrolliere Systemzustand und betroffenen Dienst.",
            ],
            "SYSTEM-WARNING": [
                "Prüfe die betroffene Anwendung oder den Dienst.",
                "Untersuche Updates, Fehlkonfigurationen oder Ausfälle.",
            ],
            "HIGH-JOURNAL-PRIORITY": [
                "Lies die Originalmeldung und bestimme den betroffenen Dienst.",
                "Prüfe Wiederholungen und Auswirkungen.",
            ],
            "SOC-TEST-MESSAGE": [
                "Dies ist eine eigene Testmeldung, kein Angriffsnachweis.",
                "Markiere den Alert nach dem Test als Gelöst oder dokumentiere ihn.",
            ],
        }

        return steps.get(rule, [
            "Prüfe die Originalmeldung und benachbarte Ereignisse.",
            "Vergleiche Quelle, Zeitpunkt und betroffene Dienste.",
            "Dokumentiere die Entscheidung.",
        ])

    def related_event_timeline(self, alert):
        timestamp = safe_text(alert["timestamp"])[:19]

        try:
            alert_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return ["Zeitstempel konnte nicht ausgewertet werden."]

        start = (alert_time - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
        end = (alert_time + timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')

        ip = extract_ip(alert["message"])

        rows = self.db.connection.execute("""
            SELECT timestamp, source, priority, message
            FROM events
            WHERE substr(timestamp, 1, 19) BETWEEN ? AND ?
            ORDER BY timestamp ASC, id ASC
            LIMIT 250
        """, (start, end)).fetchall()

        if not rows:
            return ['Keine passenden gespeicherten Logereignisse im Zeitfenster.']

        if ip:
            same_ip = [event for event in rows if ip in event['message']]
            if same_ip:
                rows = same_ip

        timeline = []
        for event in rows[-20:]:
            marker = ""
            if (
                event["source"] == alert["source"]
                and event["message"] == alert["message"]
            ):
                marker = "  ← Alert-Quelle"

            timeline.append(
                f"{event['timestamp']} | {event['source']} | "
                f"P{event['priority']} | {event['message']}{marker}")

        return timeline

    def show_alert_details(self):
        alert_id = self.selected_alert_id()
        if alert_id is None:
            self.details.clear()
            return

        row = self.db.connection.execute(
            "SELECT * FROM alerts WHERE id=?", (alert_id,)
        ).fetchone()
        if not row:
            return

        steps_text = "\n".join(
            f"{index}. {step}"
            for index, step in enumerate(
                self.investigation_steps(row), start=1))
        timeline_text = '\n'.join(self.related_event_timeline(row))
        mitre = (
            f"{row['mitre_id']} – {row['mitre_name']}"
            if row["mitre_id"]
            else "Keine spezifische Zuordnung")

        details_text = (
            f"ALERT #{row['id']}\n"
            f"ZEIT: {row['timestamp']}\n"
            f"SCHWEREGRAD: {row['severity']}\n"
            f"REGEL: {row['rule']}\n"
            f"QUELLE: {row['source']}\n"
            f"STATUS: {row['status']}\n"
            f"MITRE ATT&CK: {mitre}\n\n"
            f"WARUM WURDE DER ALERT AUSGELÖST?\n"
            f"{row['explanation']}\n\n"
            f"UNTERSUCHUNGSSCHRITTE\n{steps_text}\n\n"
            f"EREIGNIS-ZEITLINIE (± 5 MINUTEN)\n"
            f"{timeline_text}\n\n"
            f"ORIGINAL-LOG\n{row['message']}\n\n"
            f"ANALYSTENNOTIZ\n{row['notes'] or 'Noch keine Notiz.'}\n\n"
            "Ein Alert ist ein Erkennungshinweis, kein automatischer Beweis.")

        self.details.setPlainText(details_text)
        self.alert_status.setCurrentText(row["status"])
        self.alert_notes.setText(row["notes"])

    def save_alert_workflow(self):
        alert_id = self.selected_alert_id()
        if alert_id is None:
            QMessageBox.information(self, 'Kein Alert', 'Bitte zuerst einen Alert auswählen.')
            return

        status = self.alert_status.currentText()
        notes = self.alert_notes.text().strip()
        self.db.update_alert(alert_id, status, notes)

        for row in range(self.alert_table.rowCount()):
            if self.alert_table.item(row, 0).text() == str(alert_id):
                item = QTableWidgetItem(status)
                item.setForeground(QColor(RED))
                self.alert_table.setItem(row, 5, item)
                break

        self.show_alert_details()
        self.show_status("Alert-Status und Notiz gespeichert.")

    def new_incident(self):
        title, accepted = QInputDialog.getText(self, 'Neuer Vorfall', 'Titel:')
        if not accepted or not title.strip():
            return

        severity, accepted = QInputDialog.getItem(
            self, "Schweregrad", "Schweregrad:",
            ["INFO", "WARNING", "CRITICAL"], 1, False)
        if not accepted:
            return

        description, accepted = QInputDialog.getMultiLineText(
            self, "Beschreibung", "Beschreibung:")
        if not accepted:
            return

        self.db.add_incident(title.strip(), severity, description.strip())
        self.populate_incidents()
        self.show_status("Vorfall angelegt.")

    def selected_incident_id(self):
        row = self.incident_table.currentRow()
        if row < 0 or self.incident_table.item(row, 0) is None:
            return None
        try:
            return int(self.incident_table.item(row, 0).text())
        except ValueError:
            return None

    def load_incident_selection(self):
        incident_id = self.selected_incident_id()
        if incident_id is None:
            return

        row = self.db.connection.execute(
            "SELECT * FROM incidents WHERE id=?", (incident_id,)
        ).fetchone()
        if row:
            self.incident_status.setCurrentText(row["status"])
            self.incident_notes.setText(row["notes"])

    def save_incident_workflow(self):
        incident_id = self.selected_incident_id()
        if incident_id is None:
            QMessageBox.information(self, 'Kein Vorfall', 'Bitte zuerst einen Vorfall auswählen.')
            return

        self.db.update_incident(
            incident_id,
            self.incident_status.currentText(),
            self.incident_notes.text().strip())
        self.populate_incidents()
        self.show_status("Vorfallstatus und Notiz gespeichert.")

    def refresh_integrity_list(self):
        self.integrity_list.clear()
        for path in sorted(self.integrity.baseline):
            self.integrity_list.addItem(path)

    def add_integrity_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Dateien auswählen", str(Path.home()), "Alle Dateien (*)")
        if not paths:
            return

        try:
            self.integrity.add_files(paths)
        except OSError as error:
            QMessageBox.warning(self, "Dateifehler", str(error))
            return

        self.refresh_integrity_list()
        self.show_status(f'{len(paths)} Datei(en) als Baseline gespeichert.')

    def remove_integrity_file(self):
        item = self.integrity_list.currentItem()
        if not item:
            return

        path = item.text()
        answer = QMessageBox.question(
            self, "Überwachung entfernen",
            f"Datei aus der Baseline entfernen?\n{path}")
        if answer != QMessageBox.Yes:
            return

        self.integrity.baseline.pop(path, None)
        self.integrity.save()
        self.refresh_integrity_list()

    def check_integrity(self):
        changes = self.integrity.check()
        current_states = {}

        for path, missing, new_hash in changes:
            state = "MISSING" if missing else new_hash
            current_states[path] = state

            if self.integrity_alert_states.get(path) == state:
                continue

            message = (
                f"Datei: {path}; "
                + (
                    "Datei fehlt oder ist nicht lesbar"
                    if missing
                    else "SHA-256 weicht von der Baseline ab"))

            self.add_alert({
                "time": now_text(),
                "severity": "WARNING",
                "rule": "FILE-INTEGRITY-CHANGE",
                "source": "file-integrity",
                "message": message,
                "explanation": (
                    "Eine überwachte Datei fehlt, ist nicht lesbar "
                    "oder wurde geändert. Die Baseline wurde nicht "
                    "automatisch angepasst."
                ),
            })

        self.integrity_alert_states = current_states
        self.show_status(f'Dateiintegrität geprüft: {len(changes)} Änderung(en) erkannt.')

    def clear_view(self):
        self.all_logs.clear()
        self.network_logs.clear()
        self.show_status(
            "Nur die sichtbare Logansicht wurde geleert. "
            "Gespeicherte Daten bleiben erhalten.")

    def export_data(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "SOC-Daten exportieren", "soc_export.json",
            "JSON-Dateien (*.json)")
        if not path:
            return

        try:
            data = {
                "exported_at": now_text(),
                "events": [
                    dict(row)
                    for row in self.db.connection.execute(
                        "SELECT * FROM events ORDER BY id DESC LIMIT 5000")
                ],
                "alerts": [dict(row) for row in self.db.alerts()],
                "incidents": [
                    dict(row) for row in self.db.incidents()
                ],
            }

            with open(path, "w", encoding="utf-8") as file:
                json.dump(data, file, indent=2, ensure_ascii=False)

            QMessageBox.information(self, 'Export', f'Export gespeichert:\n{path}')
        except (OSError, sqlite3.Error) as error:
            QMessageBox.warning(self, "Exportfehler", str(error))

    def open_explorer(self):
        if self.explorer is None:
            self.explorer = LogExplorer(self)
        self.explorer.show()
        self.explorer.raise_()
        self.explorer.activateWindow()

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_button.setText('Weiter' if self.paused else 'Pause')
        self.show_status('Anzeige pausiert' if self.paused else 'Anzeige fortgesetzt')

    def show_status(self, message):
        self.statusBar().showMessage(message, 7000)

    def update_storage_label(self):
        try:
            db_size, event_bytes = self.db.storage_info()
            db_mb = db_size / (1024 * 1024)
            events_mb = event_bytes / (1024 * 1024)

            self.storage_label.setText(
                f"DB: {db_mb:.1f} MB | "
                f"Logdaten: {events_mb:.1f}/{MAX_EVENT_STORAGE_MB} MB | "
                f"{EVENT_RETENTION_DAYS} Tage")
            self.storage_label.setToolTip(
                f"Datenbank: {DB_PATH}\n"
                f"Normale Logs: maximal {MAX_EVENT_STORAGE_MB} MB "
                "geschätzte Nutzdaten\n"
                f"Aufbewahrung: {EVENT_RETENTION_DAYS} Tage\n"
                "Alerts und Vorfälle bleiben bei der Log-Bereinigung erhalten.")
        except sqlite3.Error as error:
            self.storage_label.setText('DB-Speicherstatus nicht verfügbar')
            self.show_status(f"Speicherstatusfehler: {error}")

    def run_storage_maintenance(self):
        try:
            self.db.cleanup_events()
            self.update_storage_label()
            self.show_status('Log-Bereinigung abgeschlossen; Alerts und Vorfälle bleiben erhalten.')
        except sqlite3.Error as error:
            self.show_status(f"Fehler bei der Log-Bereinigung: {error}")

    def update_status(self):
        self.statusBar().showMessage(
            f"Live-Monitor | Ereignisse: {self.total_events} | "
            f"Alerts gespeichert: {self.alert_table.rowCount()}")

    def closeEvent(self, event):
        self.integrity_timer.stop()
        self.status_timer.stop()
        self.storage_timer.stop()
        self.maintenance_timer.stop()

        if self.reader.isRunning():
            self.reader.stop()

        self.db.close()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    window = SOCWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
