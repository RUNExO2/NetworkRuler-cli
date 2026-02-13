from logs import log_action, log_event, log_error, log_exception, log_debug, log_method_entry, log_method_exit
import sys, os, json, subprocess, time, threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QLabel, QComboBox, QCheckBox, QFileDialog,
    QInputDialog, QListWidget, QListWidgetItem, QCompleter, QSystemTrayIcon, QMenu,
    QAction, QColorDialog, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractScrollArea, QSplitter, QFrame, QAbstractItemView
)
from PyQt5.QtCore import (
    Qt, QTimer, QTime, QEvent, QPropertyAnimation, QThread, pyqtSignal
)
from PyQt5.QtGui import QFont, QIcon, QColor, QFontDatabase, QPixmap, QPalette
import process_viewer as pv
# Use built-in libraries for GeoIP lookup
from urllib.request import urlopen, URLError
import json
from collections import deque
import time
import psutil # Ensure psutil is available for process data
from PyQt5.QtWidgets import QAbstractItemView

# Try importing NetworkRuler_cli, handle potential errors
try:
    import NetworkRuler_cli as nr
except Exception:
    # If import fails, define dummy functions needed by the GUI
    class DummyNetworkRuler:
        log_debug('Enter Class: DummyNetworkRuler')
        def log_activity(self, activity):
        log_method_entry("log_activity")
            log_debug(f"LOG (CLI not available): {activity}")
        def handle_net_commands(self, cmd):
        log_method_entry("handle_net_commands")
            log_debug(f"CLI Command not available: {' '.join(cmd)}")
        def throttle_process(self, *args):
        log_method_entry("throttle_process")
            log_debug("Throttle command not available.")
        def schedule_throttle(self, *args):
        log_method_entry("schedule_throttle")
            log_debug("Schedule throttle not available.")
        def save_profile(self, *args):
        log_method_entry("save_profile")
            log_debug("Save profile not available.")
        def load_profile(self, *args):
        log_method_entry("load_profile")
            log_debug("Load profile not available.")
        def set_alias(self, *args):
        log_method_entry("set_alias")
            log_debug("Set alias not available.")
        def install_path(self):
        log_method_entry("install_path")
            log_debug("Install path not available.")
        def get_target_ips(self, *args):
        log_method_entry("get_target_ips")
            log_debug("Get target IPs not available.")
        log_method_exit("get_target_ips")
            return []
        def stealth_mode(self):
        log_method_entry("stealth_mode")
            log_debug("Stealth mode not available.")
        def test_wireless_signals(self):
        log_method_entry("test_wireless_signals")
            log_debug("Signal test not available.")
        psutil = psutil # Provide psutil fallback if nr import failed

    nr = DummyNetworkRuler()


        log_method_exit("test_wireless_signals")
class TerminalWidget(QTextEdit):
    log_debug('Enter Class: TerminalWidget')
    def __init__(self):
    log_method_entry("__init__")
        super().__init__()
        self.setReadOnly(True)
        # Keep the specific terminal font as requested or intended by original code
        # The QSS will style colors and borders
        self.setFont(QFont("JetBrains Mono", 10))

    def appendOutput(self, text):
    log_method_entry("appendOutput")
        # Ensure smooth appending and scrolling
        self.append(text)
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

    log_method_exit("appendOutput")
# Helper class for GeoIP lookup in a thread
class GeoIPLookupThread(QThread):
    log_debug('Enter Class: GeoIPLookupThread')
    result_ready = pyqtSignal(str, dict) # Signal to send IP and result dict back to GUI
    error_occurred = pyqtSignal(str, str) # Signal to send IP and error message

    def __init__(self, ip, parent=None):
    log_method_entry("__init__")
        super().__init__(parent)
        self.ip = ip

    def run(self):
    log_method_entry("run")
        # Avoid looking up private or loopback IPs
        if self.ip.startswith('10.') or self.ip.startswith('172.16.') or \
           self.ip.startswith('192.168.') or self.ip == '127.0.0.1' or self.ip == '::1':
            self.result_ready.emit(self.ip, {"country": "Local/Private", "city": "N/A"})
    log_method_exit("run")
            return

        url = f"http://ip-api.com/json/{self.ip}"
        try:
            with urlopen(url, timeout=5) as response: # Add a timeout
                if response.getcode() == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    if data.get("status") == "success":
                        self.result_ready.emit(self.ip, data)
                    else:
                        self.error_occurred.emit(self.ip, data.get("message", "API lookup failed"))
                else:
                     self.error_occurred.emit(self.ip, f"HTTP Error: {response.getcode()}")
        except URLError as e:
            self.error_occurred.emit(self.ip, f"Network Error: {e.reason}")
        except json.JSONDecodeError:
             self.error_occurred.emit(self.ip, "API returned invalid JSON")
        except Exception as e:
            self.error_occurred.emit(self.ip, f"An unexpected error occurred: {e}")


class NetshPanel(QWidget):
    log_debug('Enter Class: NetshPanel')
    def __init__(self, terminal):
    log_method_entry("__init__")
        super().__init__()
        self.terminal = terminal
        self.layout = QVBoxLayout()
        self.buttons = [
            ("Flush DNS", ["-f", "dns"]),
            ("Register DNS", ["-r", "dns"]),
            ("Release IP", ["-d", "ip"]),
            ("Renew IP", ["-renew", "ip"]),
            ("Show Full IP Config", ["-s", "config"]),
            ("Show IP Interfaces", ["-s", "interfaces"]),
            ("Show Firewall", ["-show", "firewall"]),
            ("Reset Firewall", ["-reset", "firewall"]),
            ("Enable Firewall", ["-on", "firewall"]),
            ("Disable Firewall", ["-off", "firewall"]),
            ("Netsh Interfaces", ["-s", "interfaces", "netsh"]),
            ("Show IP Assignments", ["-s", "address"]),
            ("Reset Winsock", ["-reset", "winsock"]),
            ("Reset TCP/IP", ["-reset", "tcp"]),
            ("Reset Proxy", ["-reset", "proxy"]),
            ("Show Proxy", ["-show", "proxy"]),
            ("Disable Proxy", ["-off", "proxy"])
        ]
        for text, cmd in self.buttons:
            btn = QPushButton(text)
            btn.clicked.connect(lambda checked, c=cmd: self.runNetsh(c))
            self.layout.addWidget(btn)
        self.layout.addStretch(1) # Add stretch to push buttons to top
        self.setLayout(self.layout)

    def runNetsh(self, cmd):
    log_method_entry("runNetsh")
        try:
            self.terminal.appendOutput(f"Executing: {' '.join(cmd)}")
            nr.handle_net_commands(cmd)
            nr.log_activity("Executed: " + " ".join(cmd))
        except Exception as e:
            self.terminal.appendOutput(f"Error executing {' '.join(cmd)}: {e}")


    log_method_exit("runNetsh")
class ProcessViewerPanel(QWidget):
    log_debug('Enter Class: ProcessViewerPanel')
    def __init__(self, terminal):
    log_method_entry("__init__")
        super().__init__()
        self.terminal = terminal
        self.layout = QVBoxLayout()

        # Top Section: Filter and Process List
        self.filterEdit = QLineEdit()
        self.filterEdit.setPlaceholderText("Filter processes")
        self.filterEdit.textChanged.connect(self.filterProcesses)
        self.layout.addWidget(self.filterEdit)

        self.listWidget = QListWidget()
        self.layout.addWidget(self.listWidget, 2) # Give process list more space

        # Buttons below the list
        btnLayout = QHBoxLayout()
        self.infoBtn = QPushButton("Process Info")
        self.infoBtn.clicked.connect(self.getProcessInfo)
        btnLayout.addWidget(self.infoBtn)
        self.treeBtn = QPushButton("Process Tree")
        self.treeBtn.clicked.connect(self.showProcessTree)
        btnLayout.addWidget(self.treeBtn)
        self.openFilesBtn = QPushButton("Open Files")
        self.openFilesBtn.clicked.connect(self.openFiles)
        btnLayout.addWidget(self.openFilesBtn)
        self.envBtn = QPushButton("Env Variables")
        self.envBtn.clicked.connect(self.showEnv)
        btnLayout.addWidget(self.envBtn)
        self.suspendBtn = QPushButton("Suspend")
        self.suspendBtn.clicked.connect(self.suspendProc)
        btnLayout.addWidget(self.suspendBtn)
        self.resumeBtn = QPushButton("Resume")
        self.resumeBtn.clicked.connect(self.resumeProc)
        btnLayout.addWidget(self.resumeBtn)
        self.priorityBtn = QPushButton("Set Priority")
        self.priorityBtn.clicked.connect(self.setPriority)
        btnLayout.addWidget(self.priorityBtn)
        self.monitorBtn = QPushButton("Monitor (System)") # Renamed to clarify it's system monitor
        self.monitorBtn.clicked.connect(self.monitorSystem)
        btnLayout.addWidget(self.monitorBtn)
        self.layout.addLayout(btnLayout)

        # Splitter for lower sections (Connections and History)
        self.bottomSplitter = QSplitter(Qt.Vertical)
        self.layout.addWidget(self.bottomSplitter, 1) # Give splitter some space

        # Connections Section (within splitter)
        connectionsFrame = QFrame()
        connectionsLayout = QVBoxLayout(connectionsFrame)
        connectionsLayout.setContentsMargins(0,0,0,0) # Remove frame margins

        self.connectionsLabel = QLabel("Network Connections for Selected Process")
        self.connectionsLabel.setAlignment(Qt.AlignCenter)
        connectionsLayout.addWidget(self.connectionsLabel)

        self.connectionsTable = QTableWidget()
        self.connectionsTable.setColumnCount(7) # Local Addr, Remote Addr, State, PID, Process Name, Country, City
        self.connectionsTable.setHorizontalHeaderLabels(["Local Address", "Remote Address", "State", "PID", "Process Name", "Country", "City"])
        self.connectionsTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.connectionsTable.verticalHeader().setVisible(False) # Hide row numbers
        self.connectionsTable.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.connectionsTable.setEditTriggers(QAbstractItemView.NoEditTriggers) # Make table read-only
        self.connectionsTable.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.connectionsTable.setSelectionMode(QAbstractItemView.SingleSelection)
        connectionsLayout.addWidget(self.connectionsTable)
        self.bottomSplitter.addWidget(connectionsFrame) # Add connections frame to splitter

        # Resource History Section (within splitter)
        historyFrame = QFrame()
        historyLayout = QVBoxLayout(historyFrame)
        historyLayout.setContentsMargins(0,0,0,0) # Remove frame margins

        self.historyLabel = QLabel("Resource Usage History for Selected Process")
        self.historyLabel.setAlignment(Qt.AlignCenter)
        historyLayout.addWidget(self.historyLabel)

        self.historyTextEdit = QTextEdit() # Use QTextEdit for potential multi-line history
        self.historyTextEdit.setReadOnly(True)
        self.historyTextEdit.setPlaceholderText("Select a process to view history...")
        historyLayout.addWidget(self.historyTextEdit)
        self.bottomSplitter.addWidget(historyFrame) # Add history frame to splitter

        # Set initial sizes for the splitter panes (optional, but helps)
        self.bottomSplitter.setSizes([400, 300]) # Example: Connections 400px, History 300px

        self.setLayout(self.layout)

        # --- New Functionality Related Members ---
        self.history_timer = QTimer(self)
        self.history_timer.timeout.connect(self.updateProcessHistory)
        self.history_data = deque(maxlen=15) # Store last 15 samples (CPU%, Mem MB)
        self.selected_pid_history = None # PID for which history is being tracked

        self.geoip_threads = {} # Keep track of running GeoIP threads

        # Connect signals
        self.listWidget.currentItemChanged.connect(self.onProcessSelectionChanged)

        # Initial process list load might block GUI, run in thread or delayed
        QTimer.singleShot(100, self.refreshProcessList) # Use a timer to not block startup

    def refreshProcessList(self):
    log_method_entry("refreshProcessList")
        self.listWidget.clear()
        self.connectionsTable.setRowCount(0) # Clear connections table on refresh
        self.historyTextEdit.clear() # Clear history display
        self.stopProcessHistory() # Stop history timer

        try:
            # Check if process_viewer has a list function, fallback to psutil if needed
            # The provided code uses pv.get_process_list and falls back to psutil
            processes = pv.get_process_list() if hasattr(pv, "get_process_list") else []
            if not processes:
                import psutil # Ensure psutil is available if fallback is used
                processes = [(p.pid, p.name()) for p in psutil.process_iter()]

            for pid, name in processes:
                self.listWidget.addItem(f"{pid} - {name}")
        except Exception as e:
            self.terminal.appendOutput(f"Error refreshing process list: {e}")

    def filterProcesses(self, text):
    log_method_entry("filterProcesses")
        for index in range(self.listWidget.count()):
            item = self.listWidget.item(index)
            item.setHidden(text.lower() not in item.text().lower())

    def getSelectedPID(self):
    log_method_entry("getSelectedPID")
        item = self.listWidget.currentItem()
        if item:
            try:
                 # Safely extract PID, handle potential errors in string format
                 text = item.text()
                 if " - " in text:
    log_method_exit("getSelectedPID")
                     return int(text.split(" - ")[0])
                 return int(text) # Handle case where only PID is shown
            except ValueError:
                 self.terminal.appendOutput(f"Could not parse PID from item text: {item.text()}")
                 return None
        return None

    # --- New Functionality Handlers ---

    def onProcessSelectionChanged(self, current, previous):
    log_method_entry("onProcessSelectionChanged")
        """Handle logic when the selected process in the list changes."""
        # Stop previous history monitoring
        self.stopProcessHistory()
        # Clear old connections and history data
        self.connectionsTable.setRowCount(0)
        self.historyTextEdit.clear()
        self.history_data.clear()
        self.selected_pid_history = None # Reset monitored PID

        if current:
            pid = self.getSelectedPID()
            if pid is not None:
                try:
                    # Attempt to get process object for connections and history
                    process = psutil.Process(pid)

                    # Update connections table
                    self.updateConnectionsTable(process)

                    # Start history monitoring for the new process
                    self.selected_pid_history = pid
                    self.startProcessHistory()

                except psutil.NoSuchProcess:
                    self.terminal.appendOutput(f"Selected process {pid} no longer exists.")
                    self.connectionsTable.setRowCount(0) # Clear table
                    self.historyTextEdit.clear() # Clear history
                except Exception as e:
                    self.terminal.appendOutput(f"Error handling process selection for PID {pid}: {e}")
        else:
            # No process selected, clear everything
            self.connectionsTable.setRowCount(0)
            self.historyTextEdit.clear()
            self.stopProcessHistory()


    def updateConnectionsTable(self, process):
    log_method_entry("updateConnectionsTable")
        """Populate the connections table for the given psutil Process object."""
        self.connectionsTable.setRowCount(0) # Clear existing rows
        self.connectionsTable.setHorizontalHeaderLabels(["Local Address", "Remote Address", "State", "PID", "Process Name", "Country", "City"]) # Ensure headers are correct

        try:
            process_name = process.name()
            connections = process.connections(kind='inet') # Get internet connections (TCP/UDP IPv4/IPv6)

            for i, conn in enumerate(connections):
                self.connectionsTable.insertRow(i)
                # Local Address
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                self.connectionsTable.setItem(i, 0, QTableWidgetItem(local_addr))

                # Remote Address
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                self.connectionsTable.setItem(i, 1, QTableWidgetItem(remote_addr))

                # State
                self.connectionsTable.setItem(i, 2, QTableWidgetItem(conn.status or "N/A"))

                # PID
                self.connectionsTable.setItem(i, 3, QTableWidgetItem(str(conn.pid) if conn.pid else "N/A"))

                 # Process Name
                self.connectionsTable.setItem(i, 4, QTableWidgetItem(process_name))

                # GeoIP Placeholders
                country_item = QTableWidgetItem("Looking up...")
                city_item = QTableWidgetItem("Looking up...")
                self.connectionsTable.setItem(i, 5, country_item)
                self.connectionsTable.setItem(i, 6, city_item)

                # Start GeoIP lookup thread for remote IP if available and not private
                if conn.raddr and conn.raddr.ip:
                    remote_ip = conn.raddr.ip
                    if remote_ip not in self.geoip_threads: # Prevent multiple lookups for the same IP
                        thread = GeoIPLookupThread(remote_ip)
                        thread.result_ready.connect(self.handleGeoIPResult)
                        thread.error_occurred.connect(self.handleGeoIPError)
                        thread.finished.connect(thread.deleteLater) # Clean up thread when done
                        self.geoip_threads[remote_ip] = thread
                        thread.start()
                    else:
                        # If lookup already started for this IP, just set placeholder
                        pass # Placeholders are already set above

        except psutil.NoSuchProcess:
             self.terminal.appendOutput(f"Error: Process {process.pid} disappeared while fetching connections.")
             self.connectionsTable.setRowCount(0)
        except psutil.AccessDenied:
            self.terminal.appendOutput(f"Error: Access denied to fetch connections for process {process.pid}. (Try running as administrator)")
            self.connectionsTable.setRowCount(0)
        except Exception as e:
            self.terminal.appendOutput(f"Error updating connections table for PID {process.pid}: {e}")
            self.connectionsTable.setRowCount(0)


    def handleGeoIPResult(self, ip, data):
    log_method_entry("handleGeoIPResult")
        """Update the connections table with GeoIP results."""
        # Find all rows that have this IP in the Remote Address column
        for row in range(self.connectionsTable.rowCount()):
            remote_addr_item = self.connectionsTable.item(row, 1)
            if remote_addr_item and remote_addr_item.text().startswith(ip):
                country = data.get("countryName", data.get("country", "N/A")) # Use countryName or country key
                city = data.get("city", "N/A")
                self.connectionsTable.setItem(row, 5, QTableWidgetItem(country))
                self.connectionsTable.setItem(row, 6, QTableWidgetItem(city))
        # Remove thread from tracking dictionary
        if ip in self.geoip_threads:
            del self.geoip_threads[ip]


    def handleGeoIPError(self, ip, message):
    log_method_entry("handleGeoIPError")
        """Update the connections table cells to show the error."""
        for row in range(self.connectionsTable.rowCount()):
            remote_addr_item = self.connectionsTable.item(row, 1)
            if remote_addr_item and remote_addr_item.text().startswith(ip):
                 self.connectionsTable.setItem(row, 5, QTableWidgetItem("Error"))
                 self.connectionsTable.setItem(row, 6, QTableWidgetItem(message))
        # Remove thread from tracking dictionary
        if ip in self.geoip_threads:
            del self.geoip_threads[ip]

    def startProcessHistory(self):
    log_method_entry("startProcessHistory")
        """Starts the timer for updating process history."""
        if self.selected_pid_history is not None:
             self.terminal.appendOutput(f"Starting history monitoring for PID {self.selected_pid_history}...")
             self.historyTextEdit.setPlaceholderText(f"Monitoring history for PID {self.selected_pid_history}...")
             # Check every 2 seconds
             self.history_timer.start(2000)


    def stopProcessHistory(self):
    log_method_entry("stopProcessHistory")
        """Stops the timer for updating process history."""
        if self.history_timer.isActive():
            self.history_timer.stop()
            if self.selected_pid_history is not None:
                 self.terminal.appendOutput(f"Stopped history monitoring for PID {self.selected_pid_history}.")
            self.historyTextEdit.setPlaceholderText("Select a process to view history...")
            self.selected_pid_history = None
            self.history_data.clear() # Clear data on stop
            self.historyTextEdit.clear() # Clear display


    def updateProcessHistory(self):
    log_method_entry("updateProcessHistory")
        """Fetch and update CPU/Memory history for the selected process."""
        if self.selected_pid_history is None:
            self.stopProcessHistory() # Should not happen if timer is active, but safety check
    log_method_exit("updateProcessHistory")
            return

        try:
            p = psutil.Process(self.selected_pid_history)
            cpu_percent = p.cpu_percent(interval=None) # Non-blocking if interval=None
            mem_info = p.memory_info()
            mem_mb = mem_info.rss / (1024 * 1024) # Resident Set Size in MB

            # Append current data to history deque
            self.history_data.append((time.strftime("%H:%M:%S"), cpu_percent, mem_mb))

            # Update the history text display
            history_text = "Time     | CPU (%) | Mem (MB)\n"
            history_text += "-----------------------------------\n"
            # Display history from oldest to newest
            for timestamp, cpu, mem in self.history_data:
                 history_text += f"{timestamp} | {cpu:>7.2f} | {mem:>8.2f}\n"

            self.historyTextEdit.setText(history_text)

        except psutil.NoSuchProcess:
            self.terminal.appendOutput(f"Process {self.selected_pid_history} ended. Stopping history monitoring.")
            self.stopProcessHistory() # Stop monitoring if process is gone
            self.connectionsTable.setRowCount(0) # Also clear connections
        except psutil.AccessDenied:
            self.terminal.appendOutput(f"Access denied to get history for process {self.selected_pid_history}. Stopping monitoring. (Try running as administrator)")
            self.stopProcessHistory()
        except Exception as e:
            self.terminal.appendOutput(f"Error fetching history for PID {self.selected_pid_history}: {e}")
            # Optionally stop history on persistent errors
            # self.stopProcessHistory()


    # --- Existing Button Handlers (Refactored) ---

    def run_process_viewer_command(self, command_func, *args, requires_pid=True):
    log_method_entry("run_process_viewer_command")
        """Helper to run pv commands and log."""
        pid = self.getSelectedPID() if requires_pid else None
        if requires_pid and pid is None:
             self.terminal.appendOutput("No process selected.")
    log_method_exit("run_process_viewer_command")
             return

        try:
            # Call the process_viewer function - assuming they print to stdout
            # which is captured by the main terminal
            if requires_pid:
                command_func(pid, *args)
                activity = f"{command_func.__name__} for PID: {pid}"
            else:
                command_func(*args)
                activity = f"{command_func.__name__}"

            self.terminal.appendOutput(f"Executed: {activity}")
            nr.log_activity(activity)

        except Exception as e:
            pid_str = f" PID {pid}" if requires_pid else ""
            self.terminal.appendOutput(f"Error executing {command_func.__name__}{pid_str}: {e}")


    def getProcessInfo(self):
    log_method_entry("getProcessInfo")
        self.run_process_viewer_command(pv.process_info, requires_pid=True)

    def showProcessTree(self):
    log_method_entry("showProcessTree")
         self.run_process_viewer_command(pv.process_tree, requires_pid=False)

    def openFiles(self):
    log_method_entry("openFiles")
        self.run_process_viewer_command(pv.open_files, requires_pid=True)

    def showEnv(self):
    log_method_entry("showEnv")
        self.run_process_viewer_command(pv.env_vars, requires_pid=True)

    def suspendProc(self):
    log_method_entry("suspendProc")
        self.run_process_viewer_command(pv.suspend_process, requires_pid=True)

    def resumeProc(self):
    log_method_entry("resumeProc")
        self.run_process_viewer_command(pv.resume_process, requires_pid=True)

    def setPriority(self):
    log_method_entry("setPriority")
        pid = self.getSelectedPID()
        if pid is not None:
            level, ok = QInputDialog.getText(self, "Set Priority", "Enter priority (low, below, normal, above, high, realtime):")
            if ok and level:
                # Pass level as an argument to the command function
                self.run_process_viewer_command(pv.set_priority, level, requires_pid=True)
        else:
            self.terminal.appendOutput("No process selected.")


    def monitorSystem(self):
    log_method_entry("monitorSystem")
        self.run_process_viewer_command(pv.system_monitor, requires_pid=False)


    log_method_exit("monitorSystem")
class LiveMonitorPanel(QWidget):
    log_debug('Enter Class: LiveMonitorPanel')
    def __init__(self, terminal):
    log_method_entry("__init__")
        super().__init__()
        self.terminal = terminal
        self.layout = QVBoxLayout()

        # Use specific labels for upload/download
        self.uploadLabel = QLabel("Upload: -- MB/s")
        self.downloadLabel = QLabel("Download: -- MB/s")
        self.uploadLabel.setAlignment(Qt.AlignLeft)
        self.downloadLabel.setAlignment(Qt.AlignLeft)
        self.layout.addWidget(self.uploadLabel)
        self.layout.addWidget(self.downloadLabel)

        btnLayout = QHBoxLayout()
        self.startBtn = QPushButton("Start Monitor")
        self.startBtn.clicked.connect(self.startMonitoring)
        btnLayout.addWidget(self.startBtn)

        self.stopBtn = QPushButton("Stop Monitor")
        self.stopBtn.clicked.connect(self.stopMonitoring)
        self.stopBtn.setEnabled(False) # Disable stop initially
        btnLayout.addWidget(self.stopBtn)
        self.layout.addLayout(btnLayout)

        self.layout.addStretch(1) # Push controls to top

        self.setLayout(self.layout)
        self.timer = QTimer()
        self.timer.timeout.connect(self.updateMonitor)
        self.monitoring = False

        self.previous_sent = 0
        self.previous_recv = 0
        self.last_update_time = time.time()


    def startMonitoring(self):
    log_method_entry("startMonitoring")
        if not self.monitoring:
            self.monitoring = True
            self.startBtn.setEnabled(False)
            self.stopBtn.setEnabled(True)
            self.uploadLabel.setText("Upload: Calculating...")
            self.downloadLabel.setText("Download: Calculating...")

            # Initialize counters before starting timer
            try:
                counters = nr.psutil.net_io_counters()
                self.previous_sent = counters.bytes_sent
                self.previous_recv = counters.bytes_recv
                self.last_update_time = time.time()
                self.timer.start(1000) # Update every 1000ms (1 second)
                self.terminal.appendOutput("Live monitoring started.")
                nr.log_activity("Live monitoring started")
            except Exception as e:
                 self.terminal.appendOutput(f"Error starting monitor: {e}")
                 self.stopMonitoring() # Stop if failed to init

    def updateMonitor(self):
    log_method_entry("updateMonitor")
        try:
            current_counters = nr.psutil.net_io_counters()
            current_time = time.time()

            sent_delta = current_counters.bytes_sent - self.previous_sent
            recv_delta = current_counters.bytes_recv - self.previous_recv
            time_delta = current_time - self.last_update_time

            if time_delta > 0:
                sent_speed = (sent_delta / time_delta) / (1024 * 1024) # MB/s
                recv_speed = (recv_delta / time_delta) / (1024 * 1024) # MB/s
                self.uploadLabel.setText(f"Upload: {sent_speed:.2f} MB/s")
                self.downloadLabel.setText(f"Download: {recv_speed:.2f} MB/s")
            else:
                 self.uploadLabel.setText("Upload: 0.00 MB/s")
                 self.downloadLabel.setText("Download: 0.00 MB/s")

            self.previous_sent = current_counters.bytes_sent
            self.previous_recv = current_counters.bytes_recv
            self.last_update_time = current_time

            #nr.log_activity("Live monitor updated") # Logging every second is too chatty
        except Exception as e:
            self.uploadLabel.setText("Upload: Error")
            self.downloadLabel.setText("Download: Error")
            self.terminal.appendOutput(f"Error updating monitor: {e}")
            self.stopMonitoring() # Stop on error

    def stopMonitoring(self):
    log_method_entry("stopMonitoring")
        self.timer.stop()
        self.monitoring = False
        self.startBtn.setEnabled(True)
        self.stopBtn.setEnabled(False)
        self.uploadLabel.setText("Upload: -- MB/s")
        self.downloadLabel.setText("Download: -- MB/s")
        self.terminal.appendOutput("Live monitoring stopped.")
        nr.log_activity("Live monitoring stopped")


    log_method_exit("stopMonitoring")
class ThrottlePanel(QWidget):
    log_debug('Enter Class: ThrottlePanel')
    def __init__(self, terminal):
    log_method_entry("__init__")
        super().__init__()
        self.terminal = terminal
        self.layout = QVBoxLayout()
        self.procEdit = QLineEdit()
        self.procEdit.setPlaceholderText("Process name (e.g., chrome.exe)")
        self.layout.addWidget(self.procEdit)
        self.speedEdit = QLineEdit()
        self.speedEdit.setPlaceholderText("Speed in Mbps (e.g., 5)")
        self.layout.addWidget(self.speedEdit)
        self.startEdit = QLineEdit()
        self.startEdit.setPlaceholderText("Start time (HH:MM)")
        self.layout.addWidget(self.startEdit)
        self.endEdit = QLineEdit()
        self.endEdit.setPlaceholderText("End time (HH:MM)")
        self.layout.addWidget(self.endEdit)
        btnLayout = QHBoxLayout()
        self.nowBtn = QPushButton("Throttle Now")
        self.nowBtn.clicked.connect(self.throttleNow)
        btnLayout.addWidget(self.nowBtn)
        self.scheduleBtn = QPushButton("Schedule Throttle")
        self.scheduleBtn.clicked.connect(self.scheduleThrottle)
        btnLayout.addWidget(self.scheduleBtn)
        self.layout.addLayout(btnLayout)
        self.layout.addStretch(1)
        self.setLayout(self.layout)

    def throttleNow(self):
    log_method_entry("throttleNow")
        proc = self.procEdit.text().strip()
        speed = self.speedEdit.text().strip()
        if not proc or not speed:
            self.terminal.appendOutput("Error: Process name and speed are required.")
    log_method_exit("throttleNow")
            return
        try:
            mb = int(speed)
            # Throttle runs in CLI, which might block, so thread is appropriate
            # Note: The CLI throttle implementation seems to run indefinitely blocking the thread
            # This is a limitation of the CLI code's design for throttling.
            # A proper GUI throttle would manage the WinDivert handle directly in the GUI process.
            # Sticking to calling the CLI function as requested.
            threading.Thread(target=nr.throttle_process, args=(proc, mb), daemon=True).start() # Use daemon=True so thread doesn't prevent app exit
            self.terminal.appendOutput(f"Attempting to throttle {proc} to {speed} Mbps...")
            nr.log_activity(f"Attempting Throttle Now: {proc} {speed}")
        except ValueError:
             self.terminal.appendOutput("Error: Invalid speed format. Please enter a number in Mbps.")
        except Exception as e:
            self.terminal.appendOutput(f"Error initiating throttle: {e}")


    def scheduleThrottle(self):
    log_method_entry("scheduleThrottle")
        proc = self.procEdit.text().strip()
        speed = self.speedEdit.text().strip()
        start = self.startEdit.text().strip()
        end = self.endEdit.text().strip()
        if not proc or not speed or not start or not end:
             self.terminal.appendOutput("Error: Process, speed, start time, and end time are required.")
    log_method_exit("scheduleThrottle")
             return
        try:
            mb = int(speed)
            tstart = QTime.fromString(start, "HH:mm")
            tend = QTime.fromString(end, "HH:mm")
            if not tstart.isValid() or not tend.isValid():
                 self.terminal.appendOutput("Error: Invalid time format. Use HH:MM (e.g., 14:30).")
                 return

            # Note: The CLI's schedule_throttle only checks if *now* is within the time range.
            # It doesn't set up a persistent schedule or timer.
            # This GUI function will just call the CLI function which will execute *if* the time is right *at that moment*.
            # A true scheduler would require a background process or system scheduler integration, or a QTimer loop checking the time.
            # Sticking to the provided CLI function's behavior for now.
            # The CLI function is likely blocking, so run in a thread.
            threading.Thread(target=nr.schedule_throttle, args=(proc, mb, tstart.toPyTime(), tend.toPyTime()), daemon=True).start()
            self.terminal.appendOutput(f"Called schedule throttle function for {proc} from {start} to {end}.")
            self.terminal.appendOutput("Note: This only works if the application is running and the current time is within the scheduled window when this button is clicked, and the throttle process finishes before the end time.")
            nr.log_activity(f"Called scheduled throttle: {proc} {speed} {start}-{end}")
        except ValueError:
             self.terminal.appendOutput("Error: Invalid speed format. Please enter a number in Mbps.")
        except Exception as e:
            self.terminal.appendOutput(f"Error scheduling throttle: {e}")


class ProfileManagerPanel(QWidget):
    log_debug('Enter Class: ProfileManagerPanel')
    def __init__(self, terminal):
    log_method_entry("__init__")
        super().__init__()
        self.terminal = terminal
        self.layout = QVBoxLayout()
        self.nameEdit = QLineEdit()
        self.nameEdit.setPlaceholderText("Profile name")
        self.layout.addWidget(self.nameEdit)
        self.settingsEdit = QLineEdit()
        self.settingsEdit.setPlaceholderText("Settings/Commands (comma-separated)")
        self.layout.addWidget(self.settingsEdit)
        btnLayout = QHBoxLayout()
        self.saveBtn = QPushButton("Save Profile")
        self.saveBtn.clicked.connect(self.saveProfile)
        btnLayout.addWidget(self.saveBtn)
        self.loadBtn = QPushButton("Load Profile")
        self.loadBtn.clicked.connect(self.loadProfile)
        btnLayout.addWidget(self.loadBtn)
        self.layout.addLayout(btnLayout)
        self.jsonView = QTextEdit()
        self.jsonView.setReadOnly(True)
        self.jsonView.setPlaceholderText("Drag and drop a .json profile file here, or load a profile by name.")
        self.layout.addWidget(self.jsonView)
        self.setAcceptDrops(True) # Enable drag and drop for this panel
        self.setLayout(self.layout)

    def saveProfile(self):
    log_method_entry("saveProfile")
        name = self.nameEdit.text().strip()
        settings = self.settingsEdit.text().strip()
        if not name or not settings:
            self.terminal.appendOutput("Error: Profile name and settings/commands are required.")
    log_method_exit("saveProfile")
            return
        try:
            # The CLI save_profile expects a comma-separated string and history=None by default
            # It then splits the settings string into commands for the 'commands' list in the JSON
            # We'll pass the settings string as is to match the CLI function signature
            nr.save_profile(name, settings)
            self.terminal.appendOutput(f"Profile saved: {name}")
            nr.log_activity(f"Profile saved: {name}")
        except Exception as e:
            self.terminal.appendOutput(f"Error saving profile {name}: {e}")

    def loadProfile(self):
    log_method_entry("loadProfile")
        name = self.nameEdit.text().strip()
        if not name:
            self.terminal.appendOutput("Error: Profile name is required to load.")
    log_method_exit("loadProfile")
            return
        try:
            # The CLI load_profile prints messages directly and executes commands
            # We want to load the data into the jsonView *before* executing if possible, or separately.
            # Let's first try to just load the file content into the view, and then call the CLI load function which does the execution.
            profile_path = os.path.join("profiles", name + ".json")
            data = ""
            if os.path.exists(profile_path):
                with open(profile_path, "r", encoding="utf-8") as f:
                    data = f.read()
                # Optional: Validate JSON before displaying
                try:
                    json.loads(data)
                    self.jsonView.setText(data)
                    self.terminal.appendOutput(f"Profile data loaded into viewer: {name}. Attempting execution via CLI...")
                    # Now call the CLI function to execute commands in the profile (might block, run in thread?)
                    # The CLI load_profile calls main() which is potentially blocking depending on commands.
                    # Running the entire load in a thread is safer.
                    threading.Thread(target=nr.load_profile, args=(name,), daemon=True).start()
                    # Terminal output will show execution results as the CLI prints.
                    nr.log_activity(f"Profile load and execution initiated for: {name}")
                except json.JSONDecodeError:
                     self.jsonView.setText(f"Error: Profile file is not valid JSON: {profile_path}")
                     self.terminal.appendOutput(f"Error: Profile file '{name}' is not valid JSON.")
                     nr.log_activity(f"Attempted to load invalid JSON profile: {name}")

            else:
                 self.jsonView.setText(f"Profile file not found: {profile_path}")
                 self.terminal.appendOutput(f"Error: Profile '{name}' not found.")
                 nr.log_activity(f"Attempted to load non-existent profile: {name}")

        except Exception as e:
            self.terminal.appendOutput(f"Error loading or initiating profile execution for {name}: {e}")

    def dragEnterEvent(self, event):
    log_method_entry("dragEnterEvent")
        # Allow dragging URLs (files) onto the widget
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
    log_method_entry("dropEvent")
        # Handle dropping files
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path.lower().endswith(".json"):
                try:
                    with open(path, "r", encoding="utf-8") as f: # Read with encoding
                        data = f.read()
                    # Optionally validate if it looks like a profile JSON
                    profile_data = json.loads(data) # Basic validation
                    # Optional: Check for expected keys like "profile_name", "settings", "commands"
                    if not all(k in profile_data for k in ["profile_name", "settings", "commands"]):
                         raise ValueError("File does not appear to be a valid profile format.")

                    self.jsonView.setText(data)
                    self.terminal.appendOutput(f"Profile file content loaded into viewer: {path}")
                    # Set name edit to profile_name from JSON if available, fallback to file name
                    self.nameEdit.setText(profile_data.get("profile_name", os.path.splitext(os.path.basename(path))[0]))
                    nr.log_activity(f"Profile file content loaded from: {path}")
                except (json.JSONDecodeError, ValueError) as e:
                     self.terminal.appendOutput(f"Error: File is not a valid profile JSON ({e}): {path}")
                except Exception as e:
                    self.terminal.appendOutput(f"Error reading profile file {path}: {e}")
                finally:
                    event.acceptProposedAction() # Accept the drop even if there was an error reading
            else:
                event.ignore() # Ignore non-json files


    log_method_exit("dropEvent")
class UtilityPanel(QWidget):
    log_debug('Enter Class: UtilityPanel')
    def __init__(self, terminal):
    log_method_entry("__init__")
        super().__init__()
        self.terminal = terminal
        self.layout = QVBoxLayout()
        aliasLayout = QHBoxLayout()
        self.realEdit = QLineEdit()
        self.realEdit.setPlaceholderText("Real command (e.g., --list)")
        aliasLayout.addWidget(self.realEdit)
        self.aliasEdit = QLineEdit()
        self.aliasEdit.setPlaceholderText("Alias (e.g., l)")
        # Completer for example aliases (from original code)
        completer = QCompleter(["nr", "log", "stealth", "background", "--help", "proc"]) # Added 'proc'
        self.aliasEdit.setCompleter(completer)
        aliasLayout.addWidget(self.aliasEdit)
        self.setAliasBtn = QPushButton("Set Alias")
        self.setAliasBtn.clicked.connect(self.setAlias)
        aliasLayout.addWidget(self.setAliasBtn)
        self.layout.addLayout(aliasLayout)

        self.installBtn = QPushButton("Add to PATH")
        self.installBtn.clicked.connect(self.installPath)
        self.layout.addWidget(self.installBtn)

        # Get Target IPs Section
        ipLayout = QHBoxLayout()
        self.targetIpProcEdit = QLineEdit()
        self.targetIpProcEdit.setPlaceholderText("Process name for target IPs")
        ipLayout.addWidget(self.targetIpProcEdit)
        self.getIPBtn = QPushButton("Get Target IPs")
        self.getIPBtn.clicked.connect(self.getTargetIPs)
        ipLayout.addWidget(self.getIPBtn)
        self.layout.addLayout(ipLayout)


        self.stealthBtn = QPushButton("Stealth Mode (Hide Console)")
        self.stealthBtn.clicked.connect(self.enableStealth)
        self.layout.addWidget(self.stealthBtn)

        self.logBtn = QPushButton("Open Activity Log")
        self.logBtn.clicked.connect(self.openLog)
        self.layout.addWidget(self.logBtn)

        self.layout.addStretch(1)
        self.setLayout(self.layout)

    def setAlias(self):
    log_method_entry("setAlias")
        real = self.realEdit.text().strip()
        alias = self.aliasEdit.text().strip()
        if not real or not alias:
            self.terminal.appendOutput("Error: Both real command and alias are required.")
    log_method_exit("setAlias")
            return
        try:
            # The CLI set_alias saves to aliases.json
            nr.set_alias(real, alias)
            self.terminal.appendOutput(f"Alias set: '{alias}' -> '{real}'")
            nr.log_activity(f"Set alias: {alias} -> {real}")
        except Exception as e:
            self.terminal.appendOutput(f"Error setting alias: {e}")

    def installPath(self):
    log_method_entry("installPath")
        try:
            # The CLI install_path uses PowerShell, requires admin
            self.terminal.appendOutput("Attempting to add to system PATH (requires admin)...")
            # This might block or spawn a separate process, handle appropriately if needed
            threading.Thread(target=nr.install_path, daemon=True).start()
            self.terminal.appendOutput("Add to PATH command initiated.")
            nr.log_activity("Called install_path")
        except Exception as e:
            self.terminal.appendOutput(f"Error initiating add to PATH: {e}")

    def getTargetIPs(self):
    log_method_entry("getTargetIPs")
        proc = self.targetIpProcEdit.text().strip()
        if not proc:
             self.terminal.appendOutput("Error: Process name is required to get target IPs.")
    log_method_exit("getTargetIPs")
             return
        try:
            target_ips = set()
            found_proc_pid = None
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    if p.name().lower() == proc.lower():
                         found_proc_pid = p.pid # Get PID of the process by name
                         break # Assume first match or handle multiple? Let's use first for simplicity
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            if found_proc_pid is None:
                 self.terminal.appendOutput(f"Process '{proc}' not found.")
                 nr.log_activity(f"Attempted to get IPs for non-existent process: {proc}")
                 return

            # Now get connections for the found PID
            p = psutil.Process(found_proc_pid)
            for conn in p.connections(kind='inet'):
                 if conn.raddr and conn.raddr.ip:
                      target_ips.add(conn.raddr.ip)

            ip_list_str = ", ".join(list(target_ips)) if target_ips else "No target IPs found."
            self.terminal.appendOutput(f"Target IPs for {proc} (PID: {found_proc_pid}): {ip_list_str}")
            nr.log_activity(f"Got target IPs for {proc} (PID: {found_proc_pid})")

        except psutil.AccessDenied:
            self.terminal.appendOutput(f"Access denied to get connections for process {proc}. (Try running as administrator)")
            nr.log_activity(f"Access denied getting IPs for {proc}")
        except psutil.NoSuchProcess:
             self.terminal.appendOutput(f"Process {proc} disappeared.")
             nr.log_activity(f"Process disappeared while getting IPs for {proc}")
        except Exception as e:
            self.terminal.appendOutput(f"Error getting target IPs for {proc}: {e}")
            nr.log_activity(f"Error getting target IPs for {proc}: {e}")

    def enableStealth(self):
    log_method_entry("enableStealth")
        try:
            # This calls FreeConsole in the CLI. It might hide the CLI window if run externally,
            # but the GUI doesn't have a separate console window by default.
            # Its effect might be minimal or none when running the GUI.
            nr.stealth_mode()
            self.terminal.appendOutput("Stealth mode function called (hides console if present).")
            nr.log_activity("Stealth mode enabled")
        except Exception as e:
            self.terminal.appendOutput(f"Error enabling stealth mode: {e}")

    def openLog(self):
    log_method_entry("openLog")
        try:
            # Opens the activity_log.txt file using the default system application
            self.terminal.appendOutput("Attempting to open activity_log.txt...")
            log_file_path = "activity_log.txt" # Ensure this matches CLI log file name
            if os.path.exists(log_file_path):
                nr.log_activity("Opened activity log from GUI") # Log before attempting to open
                os.startfile(log_file_path)
            else:
                 self.terminal.appendOutput("Error: activity_log.txt not found.")

        except Exception as e:
            self.terminal.appendOutput(f"Error opening activity_log.txt: {e}")


    log_method_exit("openLog")
class SignalTestPanel(QWidget):
    log_debug('Enter Class: SignalTestPanel')
    def __init__(self, terminal):
    log_method_entry("__init__")
        super().__init__()
        self.terminal = terminal
        self.layout = QVBoxLayout()
        self.testBtn = QPushButton("Test Wireless Signals")
        self.testBtn.clicked.connect(self.testSignals)
        self.layout.addWidget(self.testBtn)
        self.layout.addStretch(1)
        self.setLayout(self.layout)

    def testSignals(self):
    log_method_entry("testSignals")
        try:
            # The CLI test_wireless_signals prints output directly
            self.terminal.appendOutput("Running wireless signal test via CLI...")
            # This call might block, run in a thread
            threading.Thread(target=nr.test_wireless_signals, daemon=True).start()
            nr.log_activity("Initiated wireless signal test")
        except Exception as e:
            self.terminal.appendOutput(f"Error initiating wireless signal test: {e}")

    log_method_exit("testSignals")
class CommandBuilderPanel(QWidget):
    log_debug('Enter Class: CommandBuilderPanel')
    def __init__(self, terminal):
    log_method_entry("__init__")
        super().__init__()
        self.terminal = terminal
        self.layout = QVBoxLayout()

        titleLabel = QLabel("Supported Commands")
        titleLabel.setFont(QFont("JetBrains Mono", 12, QFont.Bold))
        self.layout.addWidget(titleLabel)

        # List widget that displays all supported commands
        self.commandsList = QListWidget()
        commands = [
            "--list",
            "--kill <name|pid>",
            "--limit <process.exe> <speed_mbps>",
            "app --list [prefix]",
            "srv --list",
            "background app --limit <speed_mbps>",
            "monitor --live",
            "save <profile_name> <settings_string>",
            "load <profile_name>",
            "stealth",
            "log",
            "set-alias <alias> <real_command_string>",
            "install-path",
            "test --signals",
            "proc list [sort_key]",
            "proc info <PID>",
            "proc tree",
            "proc openfiles <PID>",
            "proc connections <PID>",
            "proc env <PID>",
            "proc suspend <PID>",
            "proc resume <PID>",
            "proc priority <PID> <level>",
            "proc monitor"
        ]
        for cmd in commands:
            QListWidgetItem(cmd, self.commandsList)
        self.layout.addWidget(self.commandsList)

        # Command editor for manual entry
        self.commandEditor = QLineEdit()
        self.commandEditor.setPlaceholderText("Or type a custom command here...")
        self.layout.addWidget(self.commandEditor)

        # Run button to execute the command
        self.runButton = QPushButton("Run Command")
        self.runButton.clicked.connect(self.runCommand)
        self.layout.addWidget(self.runButton)

        self.setLayout(self.layout)

    def runCommand(self):
    log_method_entry("runCommand")
        # Prefer text from editor; otherwise, from the selected list item.
        command = self.commandEditor.text().strip()
        if not command:
            selected = self.commandsList.currentItem()
            if selected:
                command = selected.text()
        if command:
            self.terminal.appendOutput(f"Executing: {command}")
            # For simulation, you might pass the command to the CLI main function:
            import sys
            import threading
            # Run command in a separate thread to avoid blocking GUI
            def run_cli():
            log_method_entry("run_cli")
                # Temporarily modify sys.argv for CLI processing
                original_argv = sys.argv
                sys.argv = ['nr'] + command.split()
                try:
                    from NetworkRuler_cli import main as cli_main
                    cli_main()
                except Exception as e:
                    self.terminal.appendOutput(f"Error executing command: {e}")
                finally:
                    sys.argv = original_argv
            threading.Thread(target=run_cli).start()
        else:
            self.terminal.appendOutput("No command selected or entered.")

    def runSequence(self):
    log_method_entry("runSequence")
        cmds_list = []
        # Extract commands from the sequence list items
        for index in range(self.sequenceList.count()):
            item_text = self.sequenceList.item(index).text().strip()
            if item_text:
                # Split item text into command parts (e.g., "-f dns" becomes ["-f", "dns"])
                cmds_list.extend(item_text.split())

        if not cmds_list:
            self.terminal.appendOutput("Error: No commands in sequence to run.")
    log_method_exit("runSequence")
            return

        try:
            # The CLI handle_net_commands expects a list of strings like ["-f", "dns", "-r", "dns"]
            self.terminal.appendOutput(f"Executing sequence via CLI: {' '.join(cmds_list)}")
            # This call might block, run in a thread
            threading.Thread(target=nr.handle_net_commands, args=(cmds_list,), daemon=True).start()
            nr.log_activity("Executed command sequence: " + " ".join(cmds_list))
        except Exception as e:
            self.terminal.appendOutput(f"Error initiating command sequence: {e}")


class ActionHistoryPanel(QWidget):
    log_debug('Enter Class: ActionHistoryPanel')
    def __init__(self, terminal):
    log_method_entry("__init__")
        super().__init__()
        self.terminal = terminal
        self.layout = QVBoxLayout()
        self.historyView = QTextEdit()
        self.historyView.setReadOnly(True)
        self.layout.addWidget(self.historyView, 1) # Give text view space
        self.exportBtn = QPushButton("Export History")
        self.exportBtn.clicked.connect(self.exportHistory)
        self.layout.addWidget(self.exportBtn)

        self.layout.addStretch(1)
        self.setLayout(self.layout)
        self.loadHistory() # Load history when panel is created

    def loadHistory(self):
    log_method_entry("loadHistory")
        history_file = "activity_log.txt"
        if os.path.exists(history_file):
            try:
                with open(history_file, "r", encoding="utf-8", errors='ignore') as f: # Use utf-8 and ignore errors for safety
                    self.historyView.setText(f.read())
            except Exception as e:
                self.historyView.setText(f"Error loading history: {e}")
                self.terminal.appendOutput(f"Error loading history file: {e}")
        else:
            self.historyView.setText("Activity log file not found.")
            self.terminal.appendOutput("Activity log file not found.")

    def exportHistory(self):
    log_method_entry("exportHistory")
        # Open a file dialog to get the save path
        path, _ = QFileDialog.getSaveFileName(self, "Save History", "", "Text Files (*.txt);;All Files (*)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f: # Save with utf-8 encoding
                    f.write(self.historyView.toPlainText())
                self.terminal.appendOutput(f"History exported to {path}")
                nr.log_activity(f"History exported to {path}")
            except Exception as e:
             self.terminal.appendOutput(f"Error exporting history to {path}: {e}")


    log_method_exit("exportHistory")
class MainWindow(QMainWindow):
    log_debug('Enter Class: MainWindow')
    def __init__(self):
    log_method_entry("__init__")
        super().__init__()
        self.setWindowTitle("Network Ruler GUI")
        # Set default size and position
        self.setGeometry(100, 100, 1000, 700) # Slightly smaller default size

        # Central widget and layout
        centralWidget = QWidget()
        mainLayout = QVBoxLayout()

        # Terminal output widget below tabs
        self.terminal = TerminalWidget()

        # Tab widget for different panels
        self.tabs = QTabWidget()
        self.tabs.addTab(NetshPanel(self.terminal), "Netsh Commands")
        self.process_viewer_panel = ProcessViewerPanel(self.terminal) # Store reference
        self.tabs.addTab(self.process_viewer_panel, "Process Viewer")
        liveMonitor = LiveMonitorPanel(self.terminal)
        self.tabs.addTab(liveMonitor, "Live Monitor")
        self.tabs.addTab(ThrottlePanel(self.terminal), "Throttle")
        self.tabs.addTab(ProfileManagerPanel(self.terminal), "Profile Manager")
        self.tabs.addTab(UtilityPanel(self.terminal), "Utilities")
        self.tabs.addTab(SignalTestPanel(self.terminal), "Signal Test")
        self.tabs.addTab(CommandBuilderPanel(self.terminal), "Command Builder")
        self.tabs.addTab(ActionHistoryPanel(self.terminal), "Action History")

        # Connect tab change signal for Live Monitor and Process Viewer history
        self.tabs.currentChanged.connect(self.handleTabChange)


        mainLayout.addWidget(self.tabs)

        # Label for terminal output
        terminalTitleLabel = QLabel("Terminal Output")
        terminalTitleLabel.setAlignment(Qt.AlignCenter)
        mainLayout.addWidget(terminalTitleLabel)
        mainLayout.addWidget(self.terminal, 1) # Give terminal stretch factor

        centralWidget.setLayout(mainLayout)
        self.setCentralWidget(centralWidget)

        # Initialize menu and tray icon
        self.initMenu()
        self.initTray()

        # Apply the new theme immediately
        self.setTheme("Cyber-Feminine Noir")

    def handleTabChange(self, index):
    log_method_entry("handleTabChange")
        """Handles logic when the selected tab changes."""
        # Find panels that need start/stop logic
        live_monitor_panel = None
        process_viewer_panel = None # Not strictly needed here if timer is only by selection, but good pattern

        for i in range(self.tabs.count()):
            widget = self.tabs.widget(i)
            if isinstance(widget, LiveMonitorPanel):
                live_monitor_panel = widget
            elif isinstance(widget, ProcessViewerPanel):
                 process_viewer_panel = widget # Use the stored reference
                 break # Found the panel we need

        # Manage Live Monitor
        if live_monitor_panel:
            if self.tabs.widget(index) is live_monitor_panel:
                # Start monitor when Live Monitor tab is selected
                live_monitor_panel.startMonitoring()
            else:
                # Stop monitor when switching away from Live Monitor tab
                live_monitor_panel.stopMonitoring()

        # Manage Process Viewer History Timer (It's managed by selection change *within* the panel,
        # but stopping it when the tab is hidden is also a good idea to save resources).
        if process_viewer_panel:
             if self.tabs.widget(index) is not process_viewer_panel:
                  process_viewer_panel.stopProcessHistory() # Stop timer when tab is hidden


    def initMenu(self):
    log_method_entry("initMenu")
        menuBar = self.menuBar()

        # Apply initial menu styling (will be overridden by main stylesheet potentially, but good practice)
        menuBar.setStyleSheet("""
            QMenuBar {
                background-color: transparent;
                font-size: 14px;
                font-family: 'Segoe UI', 'Arial', sans-serif; /* Use a theme-consistent font */
                color: #f5f5f5; /* Soft white */
            }
            QMenuBar::item {
                padding: 6px 14px;
                background: transparent;
                color: #f5f5f5; /* Soft white */
                border-radius: 8px;
            }
            QMenuBar::item:selected {
                background: #ff4f9f; /* Pink */
                color: #1a1a1a; /* Dark text */
                border-radius: 8px;
            }
            QMenu {
                background-color: #1a1a1a; /* Dark background */
                border: 1px solid #a020f0; /* Purple border */
                border-radius: 8px;
            }
            QMenu::item {
                padding: 8px 20px;
                font-size: 13px;
                color: #f5f5f5; /* Soft white */
                border-radius: 6px;
            }
            QMenu::item:selected {
                background-color: #a020f0; /* Purple */
                color: #f5f5f5; /* Soft white */
            }
             QMenu::separator {
                height: 1px;
                background: #333333; /* Divider color */
                margin-left: 10px;
                margin-right: 10px;
            }
        """)


        # Theme Menu
        themeMenu = menuBar.addMenu("Theme")
        # Add the new theme to the list
        themes = ["Cyber-Feminine Noir", "Red", "Black", "Light", "Purple", "Pink"]
        for theme in themes:
            action = QAction(theme, self)
            action.triggered.connect(lambda checked, t=theme: self.setTheme(t))
            themeMenu.addAction(action)

        # View Menu
        viewMenu = menuBar.addMenu("View")
        transparencyAction = QAction("Toggle Transparency (0.92)", self, checkable=True)
        transparencyAction.triggered.connect(self.toggleTransparency)
        viewMenu.addAction(transparencyAction)

        fontColorAction = QAction("Pick Font Color (Global)", self)
        fontColorAction.triggered.connect(self.pickFontColor)
        viewMenu.addAction(fontColorAction)

        wallpaperAction = QAction("Set Background Image", self)
        wallpaperAction.triggered.connect(self.setWallpaper)
        viewMenu.addAction(wallpaperAction)

        fontLoaderAction = QAction("Load Custom Font File", self)
        fontLoaderAction.triggered.connect(self.loadCustomFont)
        viewMenu.addAction(fontLoaderAction)

    def setTheme(self, theme):
    log_method_entry("setTheme")
        # Define the comprehensive Cyber-Feminine Noir QSS string
        cyber_feminine_noir_qss = """
            QWidget {
                background-color: #0d0d0d; /* Main Background */
                color: #f5f5f5; /* Default Text Color (Soft White) */
                font-family: 'Segoe UI', 'Arial', sans-serif; /* Choose a modern font */
                font-size: 13px;
                /* No global border-radius here, apply to specific widgets */
            }

            QMainWindow {
                border: none; /* MainWindow itself usually doesn't need a border/radius for standard window frames */
                background-color: #0d0d0d; /* Ensure main window background is dark */
            }

            /* General Container Styles (explicitly targeting common containers) */
            QWidget, QFrame, QGroupBox, QScrollArea > QWidget, QStackedWidget > QWidget {
                 background-color: #0d0d0d; /* Dark background for internal areas */
                 border: none; /* No borders by default for basic widgets/frames */
                 /* border-radius handles below for specific containers */
            }

             /* Specific Container with Borders/Radius */
            QTabWidget::pane {
                background-color: #0d0d0d; /* Dark background for the tab content area */
                border: 1px solid #333333; /* Subtle dark border around tab content */
                border-radius: 12px; /* Rounded corners for the content pane */
                margin: 0;
                padding: 10px;
            }

            QGroupBox {
                 border: 1px solid #333333; /* Subtle dark border for group boxes */
                 border-radius: 12px;
                 padding: 10px; /* Add padding inside group box */
                 margin-top: 1em; /* Space above group box */
            }

            QGroupBox::title {
                 subcontrol-origin: margin;
                 subcontrol-position: top center; /* Title above the border, centered */
                 padding: 0 3px;
                 color: #ff4f9f; /* Pink title color */
                 background-color: #0d0d0d; /* Match background */
            }


            /* Input Field Styles */
            QLineEdit, QTextEdit, QComboBox, QListWidget, QTableWidget, QHeaderView { /* Added QTableWidget, QHeaderView */
                background-color: #ffe4f7; /* Pastel Light Pink for input fields */
                color: #1a1a1a; /* Dark text on light fields */
                border: 1px solid #ffb6d9; /* Lighter pink border */
                border-radius: 8px; /* Slightly smaller radius for fields */
                padding: 5px;
            }

             QHeaderView::section { /* Style for table headers */
                 background-color: #ffb6d9; /* Match list/input background */
                 color: #1a1a1a;
                 padding: 5px;
                 border: 1px solid #ff4f9f; /* Pink border */
                 border-right: none; /* Remove right border between sections */
                 border-bottom: 2px solid #ff4f9f; /* Stronger pink bottom border */
             }
             QHeaderView::section:last {
                 border-right: 1px solid #ff4f9f; /* Add border back to last section */
             }
             QTableWidget {
                  gridline-color: #ffb6d9; /* Pastel pink grid lines */
             }
             QTableWidgetItem { /* Style for table cells */
                  padding: 5px;
             }

            /* Specific style for the read-only TerminalWidget */
            TerminalWidget { /* Use the actual class name or object name */
                background-color: #1a1a1a; /* Darker background for read-only terminal */
                color: #f5f5f5; /* Soft white text for terminal */
                border: 1px solid #a020f0; /* Purple border for terminal */
                border-radius: 8px;
                padding: 5px;
            }
             QTextEdit:read-only { /* Fallback/alternative selector */
                 background-color: #1a1a1a;
                 color: #f5f5f5;
                 border: 1px solid #a020f0;
                 border-radius: 8px;
                 padding: 5px;
             }


            /* Buttons (Primary Action - Pink) */
            QPushButton {
                background-color: #ff4f9f; /* Pink */
                color: #1a1a1a; /* Dark text on pink */
                border: 1px solid #a020f0; /* Purple border */
                border-radius: 14px; /* Rounded corners */
                padding: 8px 15px;
                font-weight: bold;
                /* No direct QSS transition property in standard PyQt QSS */
                /* Effects like glow need QGraphicsEffect programmatically */
            }

            /* Buttons (Secondary Action / Hover - Purple Glow Suggestion via Border/BG) */
            QPushButton:hover {
                background-color: #a020f0; /* Purple background on hover */
                color: #f5f5f5; /* Soft white text on purple */
                border: 2px solid #ff4f9f; /* Thicker Pink border on hover */
                padding: 7px 14px; /* Adjust padding due to thicker border */
            }

            /* Buttons (Pressed State) */
            QPushButton:pressed {
                background-color: #ff0033; /* Red on press */
                border-color: #f5f5f5;
                color: #f5f5f5;
            }

            /* Buttons (Disabled State) */
            QPushButton:disabled {
                background-color: #333333; /* Dark grey */
                color: #888888; /* Light grey text */
                border: 1px solid #555555;
            }


            /* Labels */
            QLabel {
                color: #f5f5f5; /* Default label color */
                padding: 0; /* Remove default padding if any */
                background: transparent; /* Ensure label background is transparent */
            }

            /* Terminal Title Label - Centered */
            QLabel[alignment="AlignCenter"] {
                color: #a020f0; /* Purple accent for terminal title and other centered titles */
                font-weight: bold;
                margin-top: 10px;
                margin-bottom: 5px;
            }


            /* QTabWidget Styling */
            QTabBar::tab {
                background: #1a1a1a; /* Dark background for inactive tabs */
                color: #f5f5f5; /* Soft white text for inactive tabs */
                border: 1px solid #333333; /* Subtle border */
                border-bottom-color: #ff4f9f; /* Pink bottom border separator */
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                padding: 8px 15px;
                margin-right: 2px; /* Space between tabs */
                /* No direct QSS transition for tabs */
            }

            QTabBar::tab:selected {
                background: #ff4f9f; /* Pink background for selected tab */
                color: #1a1a1a; /* Dark text for selected tab */
                border: 1px solid #ff4f9f; /* Pink border */
                border-bottom-color: #0d0d0d; /* Match pane background to hide separator */
                font-weight: bold;
            }

            QTabBar::tab:hover:!selected {
                background: #a020f0; /* Purple background on hover for unselected tabs */
                color: #f5f5f5; /* Soft white text on hover */
                border-color: #a020f0;
                border-bottom-color: #ff4f9f;
            }


            /* List Widget Styles */
            QListWidget {
                background-color: #ffe4f7; /* Pastel pink background */
                color: #1a1a1a; /* Dark text */
                border: 1px solid #ffb6d9;
                border-radius: 8px;
                padding: 5px;
                selection-background-color: #ff4f9f; /* Pink selection */
                selection-color: #1a1a1a; /* Dark text on selection */
                outline: none; /* Remove focus outline */
            }

            QListWidget::item {
                padding: 3px; /* Padding for list items */
            }

            QListWidget::item:selected {
                background-color: #ff4f9f; /* Pink selection */
                color: #1a1a1a; /* Dark text on selection */
            }

            QListWidget::item:hover {
                background-color: #a020f0; /* Purple on hover */
                color: #f5f5f5; /* Soft white text on hover */
            }

            /* QTableWidget Item Selected/Hover */
            QTableWidget::item:selected {
                background-color: #ff4f9f; /* Pink selection */
                color: #1a1a1a; /* Dark text */
            }
            QTableWidget::item:hover {
                 background-color: #a020f0; /* Purple on hover */
                 color: #f5f5f5; /* Soft white text */
            }

            /* Scrollbar Styling */
            QScrollBar:vertical, QScrollBar:horizontal {
                border: 1px solid #333333;
                background: #1a1a1a; /* Dark background */
                width: 12px; /* Vertical scrollbar width */
                height: 12px; /* Horizontal scrollbar height */
                margin: 0px;
                border-radius: 6px;
            }

            QScrollBar::handle:vertical {
                background: #ff4f9f; /* Pink handle */
                min-height: 20px;
                border-radius: 5px;
            }

            QScrollBar::handle:horizontal {
                background: #ff4f9f; /* Pink handle */
                min-width: 20px;
                border-radius: 5px;
            }

             QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical,
             QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                 background: #1a1a1a; /* Match track background */
             }

             QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
                 border: none; /* No default arrows */
             }
             QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                 border: none; /* No default lines */
                 background: none;
             }

              QScrollBar::left-arrow:horizontal, QScrollBar::right-arrow:horizontal {
                 border: none; /* No default arrows */
             }
             QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                 border: none; /* No default lines */
                 background: none;
             }

            QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {
                background: #a020f0; /* Purple on hover */
            }

             QScrollBar:vertical {
                 /* The track */
                 background: #1a1a1a;
                 width: 12px;
                 margin: 0px;
                 border-radius: 6px;
             }

             QScrollBar:horizontal {
                 /* The track */
                 background: #1a1a1a;
                 height: 12px;
                 margin: 0px;
                 border-radius: 6px;
             }


            /* Menu Bar and Menu Styling (already defined in initMenu, but ensure global styles don't clash) */
            /* Explicitly restyling here for robustness */
            QMenuBar {
                background-color: #1a1a1a; /* Dark background */
                color: #f5f5f5; /* Soft white text */
                border-bottom: 1px solid #a020f0; /* Purple bottom border */
                font-size: 14px;
            }

            QMenuBar::item {
                padding: 6px 14px;
                background: transparent;
                color: #f5f5f5;
                border-radius: 8px; /* Rounded corners for items */
            }

            QMenuBar::item:selected {
                background: #ff4f9f; /* Pink selected background */
                color: #1a1a1a; /* Dark text on selection */
                border-radius: 8px;
            }

            QMenu {
                background-color: #1a1a1a; /* Dark background for dropdown menu */
                border: 1px solid #a020f0; /* Purple border */
                border-radius: 8px; /* Rounded corners */
            }

            QMenu::item {
                padding: 8px 20px; /* More padding for menu items */
                font-size: 13px;
                color: #f5f5f5;
                border-radius: 6px; /* Slightly smaller radius for menu items */
            }

            QMenu::item:selected {
                background-color: #a020f0; /* Purple selected background */
                color: #f5f5f5; /* Soft white text on selection */
            }

            QMenu::separator {
                height: 1px;
                background: #333333; /* Divider color */
                margin-left: 10px;
                margin-right: 10px;
            }

            /* Tooltip */
            QToolTip {
                color: #1a1a1a; /* Dark text */
                background-color: #ffb6d9; /* Pastel pink background */
                border: 1px solid #ff4f9f; /* Pink border */
                border-radius: 6px;
                padding: 5px;
                opacity: 230; /* Slightly more opaque */
            }

            /* Splitter handles */
            QSplitter::handle {
                background: #333333; /* Dark grey handle */
                border: 1px solid #1a1a1a;
            }
            QSplitter::handle:vertical {
                height: 3px; /* Thin horizontal handle */
            }
             QSplitter::handle:horizontal {
                width: 3px; /* Thin vertical handle */
            }
            QSplitter::handle:pressed {
                background: #ff4f9f; /* Pink when pressed */
            }


        """


        themes = {
            "Cyber-Feminine Noir": cyber_feminine_noir_qss,
            "Red": """
                QWidget {
                    background-color: #0F0F0F;
                    color: #FF5555;
                    font-family: 'Segoe UI', 'Arial', sans-serif;
                    font-size: 13px;
                }
                QPushButton {
                    border-radius: 16px;
                    padding: 8px;
                    background-color: #8B0000;
                    color: #FFFFFF;
                    font-weight: 600;
                    border: 1px solid #FF4444;
                }
                QPushButton:hover {
                    background-color: #A30000;
                }
                QPushButton:disabled {
                    background-color: #330000;
                    color: #8B0000;
                    border: 1px solid #550000;
                }
                QTabWidget::pane {
                    border: 2px solid #FF5555;
                    border-radius: 12px;
                    background-color: #0F0F0F;
                }
                QTabBar::tab {
                    background: #330000;
                    color: #FF5555;
                    border: 1px solid #FF5555;
                    border-bottom-color: #0F0F0F;
                    border-top-left-radius: 8px;
                    border-top-right-radius: 8px;
                    padding: 8px 15px;
                    margin-right: 2px; /* Space between tabs */
                }
                 QTabBar::tab:selected {
                     background: #FF5555;
                     color: #FFFFFF;
                     border: 1px solid #FF5555;
                     border-bottom-color: #0F0F0F;
                     font-weight: bold;
                 }
                  QTabBar::tab:hover:!selected {
                    background: #A30000;
                    color: #FFB6D9; /* Use a lighter color on hover */
                    border-color: #A30000;
                    border-bottom-color: #FF5555;
                }
                 QLineEdit, QTextEdit, QComboBox, QListWidget, QTableWidget, QHeaderView {
                     background-color: #220000;
                     color: #FFB6D9;
                     border: 1px solid #FF4444;
                     border-radius: 8px;
                     padding: 5px;
                 }
                 QHeaderView::section {
                     background-color: #330000;
                     color: #FFB6D9;
                     border: 1px solid #FF4444;
                     border-right: none;
                     border-bottom: 2px solid #FF4444;
                 }
                 QHeaderView::section:last {
                     border-right: 1px solid #FF4444;
                 }
                 QTableWidget {
                      gridline-color: #FF4444;
                 }
                 TerminalWidget {
                     background-color: #1A0000;
                     color: #FF5555;
                     border: 1px solid #FF4444;
                     border-radius: 8px;
                     padding: 5px;
                 }
                 QListWidget::item:selected, QTableWidget::item:selected {
                     background-color: #FF5555;
                     color: #FFFFFF;
                 }
                 QListWidget::item:hover, QTableWidget::item:hover {
                     background-color: #A30000;
                     color: #FFB6D9;
                 }
                QMenuBar {
                    background-color: #1A0000;
                    color: #FF5555;
                }
                QMenuBar::item:selected {
                    background: #FF5555;
                    color: #FFFFFF;
                }
                 QMenu {
                    background-color: #1A0000;
                    border: 1px solid #FF4444;
                }
                 QMenu::item:selected {
                    background-color: #8B0000;
                    color: #FFFFFF;
                 }
                 QToolTip {
                     color: #FFFFFF;
                     background-color: #A30000;
                     border: 1px solid #FF4444;
                     border-radius: 6px;
                     padding: 5px;
                 }
                 QSplitter::handle { background: #330000; border: 1px solid #1A0000; }
                 QSplitter::handle:pressed { background: #FF5555; }
            """,
            "Black": """
                QWidget {
                    background-color: #0B0B0B;
                    color: #E0E0E0;
                    font-family: 'Segoe UI', 'Arial', sans-serif;
                    font-size: 13px;
                }
                QPushButton {
                    border-radius: 16px;
                    padding: 8px;
                    background-color: #1E1E1E;
                    color: #FFFFFF;
                    font-weight: 600;
                    border: 1px solid #2A2A2A;
                }
                QPushButton:hover {
                    background-color: #2A2A2A;
                }
                 QPushButton:disabled {
                    background-color: #101010;
                    color: #555555;
                    border: 1px solid #1E1E1E;
                }
                QTabWidget::pane {
                    border: 2px solid #333333;
                    border-radius: 12px;
                    background-color: #0B0B0B;
                }
                 QTabBar::tab {
                    background: #151515;
                    color: #E0E0E0;
                    border: 1px solid #333333;
                    border-bottom-color: #0B0B0B;
                    border-top-left-radius: 8px;
                    border-top-right-radius: 8px;
                    padding: 8px 15px;

                    margin-right: 2px;
                }
                 QTabBar::tab:selected {
                     background: #333333;
                     color: #FFFFFF;
                     border: 1px solid #333333;
                     border-bottom-color: #0B0B0B;
                     font-weight: bold;
                 }
                  QTabBar::tab:hover:!selected {
                    background: #2A2A2A;
                    color: #F0F0F0;
                    border-color: #2A2A2A;
                    border-bottom-color: #333333;
                }
                 QLineEdit, QTextEdit, QComboBox, QListWidget, QTableWidget, QHeaderView {
                     background-color: #1E1E1E;
                     color: #E0E0E0;
                     border: 1px solid #2A2A2A;
                     border-radius: 8px;
                     padding: 5px;
                 }
                 QHeaderView::section {
                     background-color: #2A2A2A;
                     color: #E0E0E0;
                     border: 1px solid #333333;
                     border-right: none;
                     border-bottom: 2px solid #333333;
                 }
                 QHeaderView::section:last {
                     border-right: 1px solid #333333;
                 }
                 QTableWidget {
                      gridline-color: #2A2A2A;
                 }
                 TerminalWidget {
                     background-color: #151515;
                     color: #E0E0E0;
                     border: 1px solid #2A2A2A;
                     border-radius: 8px;
                     padding: 5px;
                 }
                 QListWidget::item:selected, QTableWidget::item:selected {
                     background-color: #2A2A2A;
                     color: #FFFFFF;
                 }
                 QListWidget::item:hover, QTableWidget::item:hover {
                     background-color: #333333;
                     color: #F0F0F0;
                 }
                QMenuBar {
                    background-color: #151515;
                    color: #E0E0E0;
                }
                QMenuBar::item:selected {
                    background: #2A2A2A;
                    color: #FFFFFF;
                }
                 QMenu {
                    background-color: #151515;
                    border: 1px solid #2A2A2A;
                }
                 QMenu::item:selected {
                    background-color: #2A2A2A;
                    color: #FFFFFF;
                 }
                 QToolTip {
                     color: #E0E0E0;
                     background-color: #2A2A2A;
                     border: 1px solid #333333;
                     border-radius: 6px;
                     padding: 5px;
                 }
                 QSplitter::handle { background: #1E1E1E; border: 1px solid #0B0B0B; }
                 QSplitter::handle:pressed { background: #333333; }
            """,
            "Light": """
                QWidget {
                    background-color: #FAFAFA;
                    color: #1A1A1A;
                    font-family: 'Segoe UI', 'Arial', sans-serif;
                    font-size: 13px;
                }
                QPushButton {
                    border-radius: 16px;
                    padding: 8px;
                    background-color: #E0E0E0;
                    color: #000000;
                    font-weight: 600;
                    border: 1px solid #CCCCCC;
                }
                QPushButton:hover {
                    background-color: #D5D5D5;
                }
                 QPushButton:disabled {
                    background-color: #EEEEEE;
                    color: #AAAAAA;
                    border: 1px solid #DDDDDD;
                }
                QTabWidget::pane {
                    border: 2px solid #CCCCCC;
                    border-radius: 12px;
                    background-color: #FAFAFA;
                }
                QTabBar::tab {
                    background: #F0F0F0;
                    color: #1A1A1A;
                    border: 1px solid #CCCCCC;
                    border-bottom-color: #FAFAFA;
                    border-top-left-radius: 8px;
                    border-top-right-radius: 8px;
                    padding: 8px 15px;
                    margin-right: 2px;
                }
                 QTabBar::tab:selected {
                     background: #CCCCCC;
                     color: #000000;
                     border: 1px solid #CCCCCC;
                     border-bottom-color: #FAFAFA;
                     font-weight: bold;
                 }
                  QTabBar::tab:hover:!selected {
                    background: #D5D5D5;
                    color: #000000;
                    border-color: #D5D5D5;
                     border-bottom-color: #CCCCCC;
                }
                 QLineEdit, QTextEdit, QComboBox, QListWidget, QTableWidget, QHeaderView {
                     background-color: #FFFFFF;
                     color: #1A1A1A;
                     border: 1px solid #CCCCCC;
                     border-radius: 8px;
                     padding: 5px;
                 }
                 QHeaderView::section {
                     background-color: #E0E0E0;
                     color: #1A1A1A;
                     border: 1px solid #CCCCCC;
                     border-right: none;
                     border-bottom: 2px solid #CCCCCC;
                 }
                 QHeaderView::section:last {
                     border-right: 1px solid #CCCCCC;
                 }
                  QTableWidget {
                      gridline-color: #CCCCCC;
                 }
                 TerminalWidget {
                     background-color: #F0F0F0;
                     color: #1A1A1A;
                     border: 1px solid #CCCCCC;
                     border-radius: 8px;
                     padding: 5px;
                 }
                 QListWidget::item:selected, QTableWidget::item:selected {
                     background-color: #CCCCCC;
                     color: #000000;
                 }
                 QListWidget::item:hover, QTableWidget::item:hover {
                     background-color: #D5D5D5;
                     color: #1A1A1A;
                 }
                QMenuBar {
                    background-color: #F0F0F0;
                    color: #1A1A1A;
                }
                QMenuBar::item:selected {
                    background: #CCCCCC;
                    color: #000000;
                }
                 QMenu {
                    background-color: #F0F0F0;
                    border: 1px solid #CCCCCC;
                }
                 QMenu::item:selected {
                    background-color: #D5D5D5;
                    color: #1A1A1A;
                 }
                 QToolTip {
                     color: #1A1A1A;
                     background-color: #D5D5D5;
                     border: 1px solid #CCCCCC;
                     border-radius: 6px;
                     padding: 5px;
                 }
                 QSplitter::handle { background: #E0E0E0; border: 1px solid #FAFAFA; }
                 QSplitter::handle:pressed { background: #CCCCCC; }
            """,
            "Purple": """
                QWidget {
                    background-color: #1A0B2E;
                    color: #D6B4FC;
                     font-family: 'Segoe UI', 'Arial', sans-serif;
                     font-size: 13px;
                }
                QPushButton {
                    border-radius: 16px;
                    padding: 8px;
                    background-color: #5A00A0;
                    color: #FFFFFF;
                    font-weight: 600;
                    border: 1px solid #9D4EDD;
                }
                QPushButton:hover {
                    background-color: #7210B0;
                }
                 QPushButton:disabled {
                    background-color: #2A0540;
                    color: #5A00A0;
                    border: 1px solid #3A1B5E;
                }
                QTabWidget::pane {
                    border: 2px solid #B983FF;
                    border-radius: 12px;
                    background-color: #1A0B2E;
                }
                 QTabBar::tab {
                    background: #3A1B5E;
                    color: #D6B4FC;
                    border: 1px solid #9D4EDD;
                    border-bottom-color: #1A0B2E;
                    border-top-left-radius: 8px;
                    border-top-right-radius: 8px;
                    padding: 8px 15px;
                    margin-right: 2px;
                }
                 QTabBar::tab:selected {
                     background: #9D4EDD;
                     color: #FFFFFF;
                     border: 1px solid #9D4EDD;
                     border-bottom-color: #1A0B2E;
                     font-weight: bold;
                 }
                 QTabBar::tab:hover:!selected {
                    background: #7210B0;
                    color: #FFD9F7; /* Lighter pinkish */
                    border-color: #7210B0;
                     border-bottom-color: #9D4EDD;
                 }
                 QLineEdit, QTextEdit, QComboBox, QListWidget, QTableWidget, QHeaderView {
                     background-color: #2A1B3E;
                     color: #FFD9F7;
                     border: 1px solid #B983FF;
                     border-radius: 8px;
                     padding: 5px;
                 }
                 QHeaderView::section {
                     background-color: #3A1B5E;
                     color: #FFD9F7;
                     border: 1px solid #B983FF;
                     border-right: none;
                     border-bottom: 2px solid #B983FF;
                 }
                 QHeaderView::section:last {
                     border-right: 1px solid #B983FF;
                 }
                 QTableWidget {
                      gridline-color: #B983FF;
                 }
                 TerminalWidget {
                     background-color: #201035;
                     color: #D6B4FC;
                     border: 1px solid #9D4EDD;
                     border-radius: 8px;
                     padding: 5px;
                 }
                  QListWidget::item:selected, QTableWidget::item:selected {
                     background-color: #9D4EDD;
                     color: #FFFFFF;
                 }
                 QListWidget::item:hover, QTableWidget::item:hover {
                     background-color: #7210B0;
                     color: #FFD9F7;
                 }
                QMenuBar {
                    background-color: #201035;
                    color: #D6B4FC;
                }
                QMenuBar::item:selected {
                    background: #9D4EDD;
                    color: #FFFFFF;
                }
                 QMenu {
                    background-color: #201035;
                    border: 1px solid #9D4EDD;
                }
                 QMenu::item:selected {
                    background-color: #5A00A0;
                    color: #FFFFFF;
                 }
                 QToolTip {
                     color: #FFFFFF;
                     background-color: #7210B0;
                     border: 1px solid #9D4EDD;
                     border-radius: 6px;
                     padding: 5px;
                 }
                 QSplitter::handle { background: #3A1B5E; border: 1px solid #1A0B2E; }
                 QSplitter::handle:pressed { background: #9D4EDD; }
            """,
            "Pink": """
    QWidget {
        background-color: #2B0B1D;
        color: #FFB6D9;
         font-family: 'Segoe UI', 'Arial', sans-serif;
         font-size: 13px;
    }
    QPushButton {
        border-radius: 16px;
        padding: 8px;
        background-color: #FF69B4;
        color: #2B0B1D;
        font-weight: 600;
        border: 1px solid #FF85C1;
    }
    QPushButton:hover {
        background-color: #FFA0D1;
    }
    QPushButton:disabled {
        background-color: #4B1B3D;
        color: #FF69B4;
        border: 1px solid #6B2B4D;
    }
    QTabWidget::pane {
        border: 2px solid #FF69B4;
        border-radius: 12px;
         background-color: #2B0B1D;
    }
    QTabBar::tab {
        background: #3B1B2D;
        color: #FFB6D9;
        border: 1px solid #FF85C1;
        border-bottom-color: #2B0B1D;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        padding: 8px 15px;
        margin-right: 2px;
    }
    QTabBar::tab:selected {
        background: #FF69B4;
        color: #2B0B1D;
        border: 1px solid #FF69B4;
        border-bottom-color: #2B0B1D;
        font-weight: bold;
    }
    QTabBar::tab:hover:!selected {
        background: #FFA0D1;
        color: #4B1B3D;
        border-color: #FFA0D1;
         border-bottom-color: #FF69B4;
    }
    QLineEdit, QTextEdit, QComboBox, QListWidget, QTableWidget, QHeaderView {
        background-color: #FFD9F7;
        color: #2B0B1D;
        border: 1px solid #FFB6D9;
        border-radius: 8px;
        padding: 5px;
    }
    QHeaderView::section {
        background-color: #FFB6D9;
        color: #2B0B1D;
        border: 1px solid #FFD9F7;
        border-right: none;
        border-bottom: 2px solid #FFD9F7;
    }
    QHeaderView::section:last {
        border-right: 1px solid #FFD9F7;
    }
    QTableWidget {
         gridline-color: #FFD9F7;
    }
    TerminalWidget {
         background-color: #3B1B2D;
         color: #FFB6D9;
         border: 1px solid #FF85C1;
         border-radius: 8px;
         padding: 5px;
    }
     QListWidget::item:selected, QTableWidget::item:selected {
         background-color: #FF69B4;
         color: #2B0B1D;
     }
     QListWidget::item:hover, QTableWidget::item:hover {
         background-color: #FFA0D1;
         color: #4B1B3D;
     }
     QMenuBar {
        background-color: #3B1B2D;
        color: #FFB6D9;
    }
    QMenuBar::item:selected {
        background: #FF69B4;
        color: #2B0B1D;
    }
     QMenu {
        background-color: #3B1B2D;
        border: 1px solid #FF85C1;
    }
     QMenu::item:selected {
        background-color: #FF69B4;
        color: #2B0B1D;
     }
     QToolTip {
         color: #2B0B1D;
         background-color: #FFA0D1;
         border: 1px solid #FF69B4;
         border-radius: 6px;
         padding: 5px;
     }
     QSplitter::handle { background: #3B1B2D; border: 1px solid #2B0B1D; }
     QSplitter::handle:pressed { background: #FF69B4; }
    log_method_exit("setTheme")
"""
        }
        # Apply the selected theme QSS
        self.setStyleSheet(themes.get(theme, ""))

        # Re-apply specific menu bar style if needed after global QWidget style
        # (The global style might override MenuBar styles)
        self.menuBar().setStyleSheet(self.menuBar().styleSheet()) # This line might not be necessary if global style is specific enough

        # Re-apply specific terminal font if the global style overrode it
        # This assumes TerminalWidget class name is used in QSS correctly
        # Using findChild by object name might be more robust if class selector doesn't work
        self.terminal.setFont(QFont("JetBrains Mono", 10))


    def toggleTransparency(self, state):
    log_method_entry("toggleTransparency")
        # QSS does not control window opacity directly, use native window property
        self.setWindowOpacity(0.92 if state else 1.0)


    def pickFontColor(self):
    log_method_entry("pickFontColor")
        # Open color dialog
        color = QColorDialog.getColor(self.palette().color(QPalette.WindowText), self, "Select Global Font Color")
        if color.isValid():
            # This adds a color rule to the *existing* stylesheet
            current_style = self.styleSheet()
            # Remove existing QWidget color rule to avoid stacking (basic regex)
            import re
            new_style = re.sub(
                r"(QWidget\s*{.*?)\bcolor:\s*#[0-9a-fA-F]{3,6}\s*;",
                r"\1",
                current_style,
                flags=re.DOTALL
            )
            new_style = re.sub(
                r"(QWidget\s*{.*?)\bcolor:\s*\w+\s*;",
                r"\1",
                new_style,
                flags=re.DOTALL
            )
            # Find or create QWidget rule
            if "QWidget {" in new_style:
                new_style = new_style.replace("QWidget {", f"QWidget {{\n    color: {color.name()};", 1)
            else:
                new_style += f"\nQWidget {{\n    color: {color.name()};\n}}"
            self.setStyleSheet(new_style)
            self.terminal.appendOutput(f"Set global QWidget font color to {color.name()}. Note: Specific widget styles may override this.")
            self.terminal.setFont(QFont("JetBrains Mono", 10))


    def setWallpaper(self):
    log_method_entry("setWallpaper")
        # Open file dialog for image selection
        path, _ = QFileDialog.getOpenFileName(self, "Select Background Image", "", "Image Files (*.png *.jpg *.jpeg *.bmp *.gif);;All Files (*)")
        if path:
            # Set background image using QSS
            # This will override the background-color from the theme for the QWidget
            # Need to make sure other widgets (inputs, terminal, table, etc.) get their backgrounds back or are semi-transparent
            wallpaper_style = f"""
                QMainWindow {{
                    background-image: url("{path.replace(os.sep, '/').replace(' ', '%20')}"); /* Use URL format, handle spaces */
                    background-repeat: no-repeat;
                    background-position: center;
                    background-attachment: fixed; /* Fix background if scrollable */
                    background-size: cover; /* Or 'contain' or specific size */
                }}
                /* Apply semi-transparent backgrounds to main containers and panels */
                QWidget {{
                    background-color: rgba(13, 13, 13, 0.7); /* Semi-transparent dark background for most widgets */
                    /* inherit theme colors/fonts unless specified */
                }}
                 QTabWidget::pane {{
                     background-color: rgba(13, 13, 13, 0.7); /* Semi-transparent dark background for the tab content area */
                     border: 1px solid rgba(51, 51, 51, 0.7); /* Also semi-transparent border */
                     border-radius: 12px;
                     margin: 0;
                     padding: 10px;
                 }}
                TerminalWidget {{
                     background-color: rgba(26, 26, 26, 0.85); /* Semi-transparent dark background for terminal */
                     color: #f5f5f5; /* Keep terminal text color specific */
                     border: 1px solid rgba(160, 32, 240, 0.85); /* Semi-transparent purple border */
                     border-radius: 8px;
                     padding: 5px;
                 }}
                 QLineEdit, QTextEdit, QComboBox, QListWidget, QTableWidget {{
                      background-color: rgba(255, 228, 247, 0.9); /* Semi-transparent pastel light pink for inputs/lists/tables */
                      color: #1a1a1a; /* Keep dark text on these */
                     border: 1px solid rgba(255, 182, 217, 0.9); /* Semi-transparent border */
                     border-radius: 8px;
                     padding: 5px;
                 }}
                 QHeaderView::section {{
                     background-color: rgba(255, 182, 217, 0.9); /* Semi-transparent header background */
                     color: #1a1a1a; /* Keep dark text */
                     padding: 5px;
                     border: 1px solid rgba(255, 79, 159, 0.9); /* Semi-transparent pink border */
                     border-right: none; /* Remove right border between sections */
                     border-bottom: 2px solid rgba(255, 79, 159, 0.9); /* Stronger semi-transparent pink bottom border */
                 }}
                 QHeaderView::section:last {{
                    border-right: 1px solid rgba(255, 79, 159, 0.9);
                 }}
                 QTableWidget {{
                    gridline-color: rgba(255, 182, 217, 0.9);
                 }}

                QMenuBar {{
                    background-color: rgba(26, 26, 26, 0.9); /* Semi-transparent dark background for menus */
                    color: #f5f5f5;
                     border-bottom: 1px solid rgba(160, 32, 240, 0.8);
                }}
                QMenu {{
                    background-color: rgba(26, 26, 26, 0.9); /* Semi-transparent dark background for dropdown menu */
                     border: 1px solid rgba(160, 32, 240, 0.8);
                }}
                 QToolTip {{
                     color: #1a1a1a; /* Dark text */
                     background-color: rgba(255, 228, 247, 0.95); /* Semi-transparent pastel pink tooltip */
                     border: 1px solid rgba(255, 79, 159, 0.9);
                     border-radius: 6px;
                     padding: 5px;
                 }}
                 QSplitter::handle { background: rgba(51, 51, 51, 0.7); border: 1px solid rgba(26, 26, 26, 0.7); }
                 QSplitter::handle:pressed { background: rgba(255, 79, 159, 0.9); }


            """
            # Apply the custom wallpaper style
            self.setStyleSheet(wallpaper_style)
            self.terminal.appendOutput(f"Set background image to {path}. Note: Some widget backgrounds are set to semi-transparent.")
            # Re-apply terminal font as it might have been affected
            self.terminal.setFont(QFont("JetBrains Mono", 10))


    def loadCustomFont(self):
    log_method_entry("loadCustomFont")
        # Open file dialog for font selection
        path, _ = QFileDialog.getOpenFileName(self, "Select Font File", "", "Font Files (*.ttf *.otf *.woff *.woff2);;All Files (*)")
        if path:
            # Add font to QFontDatabase
            font_id = QFontDatabase.addApplicationFont(path)
            if font_id != -1:
                # Get the font families added
                font_families = QFontDatabase.applicationFontFamilies(font_id)
                if font_families:
                    font_name = font_families[0]
                    self.terminal.appendOutput(f"Loaded custom font: {font_name}. You can now use '{font_name}' in QSS or font settings.")
                    # Optionally, apply this font globally or to specific widgets
                    # Example: self.setStyleSheet(self.styleSheet() + f"\nQWidget {{ font-family: '{font_name}', sans-serif; }}")
                    # For now, just log and let user apply manually via QSS or future feature
                else:
                     self.terminal.appendOutput(f"Loaded font file but could not retrieve font family names: {path}")
            else:
                self.terminal.appendOutput(f"Error loading font file: {path}")


    def initTray(self):
    log_method_entry("initTray")
        # Initialize system tray icon
        # Provide a valid path to your tray icon image
        iconPath = os.path.join(os.path.dirname(__file__), "icon.png") # Look for icon.png next to the script

        # Check if the icon file exists, fallback to a standard theme icon or a default if not
        icon = QIcon(iconPath) if os.path.exists(iconPath) else QIcon.fromTheme("application-exit", QIcon()) # Fallback QIcon() is an empty icon

    log_method_exit("initTray")
        # If QIcon.fromTheme didn't work or returned an empty icon, use a default built-in one
        if icon.isNull():
             icon = self.style().standardIcon(self.style().SP_TitleBarMenuButton) # Example: Use a built-in standard icon
             if icon.isNull():
                 # As a last resort, create a minimal pixmap (a small colored square)
                 # This ensures there is *something* in the tray even if no icon file or theme icon is found
                 pixmap = QPixmap(16, 16)
                 pixmap.fill(QColor("purple")) # Fill with a color fitting the theme
                 icon = QIcon(pixmap)
                 if not icon.isNull():
                      self.terminal.appendOutput("Warning: icon.png not found, using a default colored square icon in tray.")
                 else:
                     self.terminal.appendOutput("Error: Could not load tray icon.")
                     # If icon is still null, tray won't show or will use a generic default

        if icon.isNull():
             self.tray = None # Cannot create tray icon without a valid icon
             self.terminal.appendOutput("System tray icon could not be initialized due to missing icon.")
             return


        self.tray = QSystemTrayIcon(icon, self)
        trayMenu = QMenu()

        # Actions for tray menu
        showAction = QAction("Show Window", self)
        showAction.triggered.connect(self.showNormal) # Show the window normally

        quitAction = QAction("Quit", self)
        # Use instance().quit() for clean application exit
        quitAction.triggered.connect(QApplication.instance().quit)

        # Add actions to menu
        trayMenu.addAction(showAction)
        trayMenu.addSeparator() # Add a separator line
        trayMenu.addAction(quitAction)

        # Set the context menu for the tray icon
        self.tray.setContextMenu(trayMenu)

        # Connect activated signal for double-click or single-click behavior
        # Common behavior is to show/hide on click
        # Check if the system supports ActivationReason
        if hasattr(QSystemTrayIcon, 'ActivationReason'):
             self.tray.activated.connect(self.onTrayIconActivated)
        # Show the tray icon
        self.tray.show()

    # Handler for tray icon activation (click/double-click)
    def onTrayIconActivated(self, reason):
    log_method_entry("onTrayIconActivated")
        # Qt::SystemTrayIcon::Trigger is usually a single click
        # Qt::SystemTrayIcon::DoubleClick is a double click
        # Qt::SystemTrayIcon::MiddleClick is a middle click
        if reason == QSystemTrayIcon.Trigger or reason == QSystemTrayIcon.DoubleClick:
            if self.isHidden() or self.isMinimized():
                self.showNormal() # Restore if hidden or minimized
                self.activateWindow() # Bring to front
            else:
                self.hide() # Hide the window if it's visible

    # Override closeEvent to hide to tray instead of closing
    def closeEvent(self, event):
    log_method_entry("closeEvent")
        # Check if tray icon exists and is visible
        if self.tray is not None and self.tray.isVisible():
            self.hide() # Hide the window
            event.ignore() # Ignore the close event
            self.terminal.appendOutput("Window minimized to system tray.")
        else:
            # If tray isn't available or visible, allow normal close and quit
            event.accept()
            QApplication.instance().quit() # Ensure application quits cleanly


    log_method_exit("closeEvent")
# Main application entry point
if __name__ == "__main__":
    # QApplication setup
    # Ensure high DPI scaling is handled
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling) # Enable high DPI scaling
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps) # Use high DPI pixmaps if available

    app = QApplication(sys.argv)

    # Set application icon (optional, uses window icon by default)
    # Look for app icon next to the script
    app_icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
    if os.path.exists(app_icon_path):
         app.setWindowIcon(QIcon(app_icon_path))


    # Create and show the main window
    win = MainWindow()
    win.show()

    # Start the application event loop
    sys.exit(app.exec_())
