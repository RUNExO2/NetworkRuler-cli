from __future__ import annotations

from typing import Literal

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QTableView,
    QWidget,
    QVBoxLayout,
)

from networkruler_core.process.models import ProcessActionResult, ProcessInfo
from networkruler_core.process.service import ProcessService
from networkruler_core.safety import SafetyContext
from networkruler_gui.screens.base import Screen, page_layout
from networkruler_gui.widgets import (
    DangerButton,
    PillBadge,
    PremiumCard,
    PrimaryButton,
    SafetyPreviewDialog,
    SearchField,
    SecondaryButton,
    SectionHeader,
    Toolbar,
)


class ProcessTableModel(QAbstractTableModel):
    def __init__(self, processes: list[ProcessInfo], show_advanced: bool = False, parent=None):
        super().__init__(parent)
        self.all_processes = processes
        self.show_advanced = show_advanced
        self.headers = ["Name", "CPU", "Memory", "Status"]
        if self.show_advanced:
            self.headers = ["PID", "Name", "CPU", "Memory", "Status", "User"]
        self._filter_processes()

    def set_advanced(self, advanced: bool):
        self.beginResetModel()
        self.show_advanced = advanced
        self.headers = ["PID", "Name", "CPU", "Memory", "Status", "User"] if advanced else ["Name", "CPU", "Memory", "Status"]
        self._filter_processes()
        self.endResetModel()

    def _filter_processes(self):
        system_procs = {
            'svchost.exe', 'System Idle Process', 'System', 'csrss.exe', 
            'smss.exe', 'services.exe', 'lsass.exe', 'wininit.exe', 
            'fontdrvhost.exe', 'dwm.exe', 'spoolsv.exe', 'explorer.exe'
        }
        if self.show_advanced:
            self.processes = self.all_processes
        else:
            self.processes = [p for p in self.all_processes if p.name not in system_procs]

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self.processes)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.headers)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        process = self.processes[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if not self.show_advanced:
                if col == 0:
                    return process.name
                if col == 1:
                    return f"{process.cpu_percent:.1f}%"
                if col == 2:
                    return f"{process.memory_percent:.1f}%"
                if col == 3:
                    return process.status or ""
            else:
                if col == 0:
                    return str(process.pid)
                if col == 1:
                    return process.name
                if col == 2:
                    return f"{process.cpu_percent:.1f}%"
                if col == 3:
                    return f"{process.memory_percent:.1f}%"
                if col == 4:
                    return process.status or ""
                if col == 5:
                    return process.username or ""
        elif role == Qt.ItemDataRole.UserRole and col == 0:
            return process.pid
        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if self.show_advanced and col in (0, 2, 3):
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            elif not self.show_advanced and col in (1, 2):
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.headers[section]
        return None

    def update_data(self, new_processes: list[ProcessInfo]):
        self.beginResetModel()
        self.all_processes = new_processes
        self._filter_processes()
        self.endResetModel()

    def get_process(self, row: int) -> ProcessInfo | None:
        if 0 <= row < len(self.processes):
            return self.processes[row]
        return None


class ProcessesScreen(Screen):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._processes: list[ProcessInfo] = []
        self._advanced_mode = False

        layout = page_layout(self)
        layout.addWidget(
            SectionHeader(
                "Apps & Performance",
                "See what is running on your PC and easily stop unresponsive applications.",
            )
        )

        toolbar = Toolbar()
        self.search = SearchField("Find an application...")
        refresh = PrimaryButton("Refresh List")
        refresh.clicked.connect(self.refresh)
        self.search.returnPressed.connect(self.refresh)
        toolbar.add_widget(self.search, 1)
        toolbar.add_widget(refresh)
        layout.addWidget(toolbar)

        body = QGridLayout()
        body.setSpacing(16)
        
        table_card = PremiumCard(compact=True)
        self.model = ProcessTableModel([], show_advanced=False)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(False) # As per new design system
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(32) # Compact density
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0 if not self._advanced_mode else 1, QHeaderView.ResizeMode.Stretch)
        self.table.selectionModel().selectionChanged.connect(self._show_selection)
        
        table_layout = QVBoxLayout()
        table_layout.addWidget(self.table)
        
        self.advanced_btn = SecondaryButton("Show System Processes ▼")
        self.advanced_btn.clicked.connect(self._toggle_advanced)
        table_layout.addWidget(self.advanced_btn)
        table_card.layout.addLayout(table_layout)
        
        body.addWidget(table_card, 0, 0)

        self.detail = PremiumCard()
        self.detail.layout.addWidget(QLabel("App Impact", objectName="SectionTitle"))
        self.detail_title = QLabel("Select an application")
        self.detail_title.setObjectName("ScreenTitle")
        self.detail_meta = QLabel("Application details will appear here.")
        self.detail_meta.setObjectName("MutedLabel")
        self.detail_meta.setWordWrap(True)
        self.status_pill = PillBadge("idle")
        self.detail.layout.addWidget(self.detail_title)
        self.detail.layout.addWidget(self.status_pill)
        self.detail.layout.addWidget(self.detail_meta)
        
        self.actions_container = QWidget()
        actions_layout = QVBoxLayout(self.actions_container)
        actions_layout.setContentsMargins(0, 16, 0, 0)
        
        self.force_stop_btn = DangerButton("Force Stop App")
        self.force_stop_btn.clicked.connect(lambda: self._process_action("kill"))
        self.pause_app_btn = SecondaryButton("Pause App Background Activity")
        self.pause_app_btn.clicked.connect(lambda: self._process_action("suspend"))
        self.resume_app_btn = SecondaryButton("Resume App Activity")
        self.resume_app_btn.clicked.connect(lambda: self._process_action("resume"))
        
        actions_layout.addWidget(self.force_stop_btn)
        actions_layout.addWidget(self.pause_app_btn)
        actions_layout.addWidget(self.resume_app_btn)
        
        self.advanced_actions_container = QWidget()
        advanced_actions_layout = QVBoxLayout(self.advanced_actions_container)
        advanced_actions_layout.setContentsMargins(0, 16, 0, 0)
        advanced_actions_layout.addWidget(QLabel("Technical Controls", objectName="SectionTitle"))
        self.priority = QComboBox()
        self.priority.addItems(["low", "below", "normal", "above", "high"])
        priority_button = SecondaryButton("Set CPU Priority")
        priority_button.clicked.connect(lambda: self._process_action("priority"))
        advanced_actions_layout.addWidget(self.priority)
        advanced_actions_layout.addWidget(priority_button)
        
        self.detail.layout.addWidget(self.actions_container)
        self.detail.layout.addWidget(self.advanced_actions_container)
        self.advanced_actions_container.setVisible(False)
        self.actions_container.setVisible(False)
        
        self.detail.layout.addStretch()
        body.addWidget(self.detail, 0, 1)
        body.setColumnStretch(0, 3)
        body.setColumnStretch(1, 1)
        layout.addLayout(body)

        self.refresh()

    def _toggle_advanced(self):
        self._advanced_mode = not self._advanced_mode
        self.advanced_btn.setText("Hide System Processes ▲" if self._advanced_mode else "Show System Processes ▼")
        self.model.set_advanced(self._advanced_mode)
        self.advanced_actions_container.setVisible(self._advanced_mode)
        self.table.horizontalHeader().setSectionResizeMode(0 if not self._advanced_mode else 1, QHeaderView.ResizeMode.Stretch)

    def refresh(self) -> None:
        self.run_task(
            lambda: ProcessService().list_processes(
                filter_text=self.search.text().strip() or None,
                sort_by="cpu",
            ),
            self._populate,
        )

    def _populate(self, processes: list[ProcessInfo]) -> None:
        self._processes = processes
        self.model.update_data(processes)
        self.table.resizeColumnsToContents()

    def _show_selection(self, *args) -> None:
        process = self._selected_process()
        if process is None:
            self.actions_container.setVisible(False)
            return
            
        self.actions_container.setVisible(True)
        self.detail_title.setText(f"{process.name}")
        
        impact = "Low"
        if process.cpu_percent > 20:
            impact = "High"
        elif process.cpu_percent > 5:
            impact = "Medium"
        
        self.detail_meta.setText(f"Impact: {impact}\nCPU: {process.cpu_percent:.1f}%\nMemory: {process.memory_percent:.1f}%" + (f"\nPID: {process.pid}" if self._advanced_mode else ""))
        self.status_pill.setText(process.status or "unknown")
        self.status_pill.set_tone("success" if process.status == "running" else "neutral")

    def _selected_process(self) -> ProcessInfo | None:
        selection = self.table.selectionModel().selectedRows()
        if not selection:
            return None
        row = selection[0].row()
        return self.model.get_process(row)

    def _process_action(self, action: Literal["kill", "suspend", "resume", "priority"]) -> None:
        process = self._selected_process()
        if process is None:
            self.show_error("Select an application first.")
            return

        def preview() -> ProcessActionResult:
            return self._execute_action(action, process.pid, SafetyContext(dry_run=True))

        self.run_task(
            preview,
            lambda result: self._confirm_and_execute(action, process.pid, result),
        )

    def _execute_action(self, action: str, pid: int, context: SafetyContext) -> ProcessActionResult:
        service = ProcessService()
        if action == "kill":
            return service.kill_process(pid, context)
        if action == "suspend":
            return service.suspend_process(pid, context)
        if action == "resume":
            return service.resume_process(pid, context)
        return service.set_priority(pid, self.priority.currentText(), context)

    def _confirm_and_execute(self, action: str, pid: int, preview: ProcessActionResult) -> None:
        if not SafetyPreviewDialog.confirm(
            parent=self,
            title="Confirm action",
            message="Are you sure you want to apply this action to the application?",
            payload=preview.to_dict(),
        ):
            return
        self.run_task(
            lambda: self._execute_action(action, pid, SafetyContext(yes=True)),
            self._show_action_result,
        )

    def _show_action_result(self, result: ProcessActionResult) -> None:
        title = "Application action"
        icon = QMessageBox.Icon.Information if result.ok else QMessageBox.Icon.Warning
        QMessageBox(
            icon,
            title,
            result.message,
            QMessageBox.StandardButton.Ok,
            self,
        ).exec()
        if result.ok and not result.safety.dry_run:
            self.refresh()
