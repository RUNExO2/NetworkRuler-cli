from __future__ import annotations

from typing import Any

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget, QMessageBox

from networkruler_core.network.service import NetworkService
from networkruler_core.process.service import ProcessService
from networkruler_core.safety import SafetyContext
from networkruler_gui.screens.base import Screen, page_layout, scroll_page
from networkruler_gui.widgets import (
    MetricCard,
    PremiumCard,
    PrimaryButton,
    SecondaryButton,
    SectionHeader,
)


class DashboardScreen(Screen):
    navigate_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        page = QWidget()
        layout = page_layout(page)
        
        # 1. Welcome Banner & Primary Action
        self.welcome_banner = QLabel("Checking system health...")
        self.welcome_banner.setObjectName("ScreenTitle")
        
        banner_layout = QHBoxLayout()
        banner_layout.addWidget(self.welcome_banner)
        banner_layout.addStretch()
        self.optimize_btn = PrimaryButton("Optimize Performance")
        self.optimize_btn.clicked.connect(self._optimize_performance)
        banner_layout.addWidget(self.optimize_btn)
        layout.addLayout(banner_layout)

        # 2. Quick Vitals Row
        vitals_layout = QGridLayout()
        vitals_layout.setSpacing(14)
        self.cpu_vital = MetricCard("CPU Usage", "Loading...")
        self.ram_vital = MetricCard("RAM Usage", "Loading...")
        self.net_vital = MetricCard("Internet Status", "Checking...")
        vitals_layout.addWidget(self.cpu_vital, 0, 0)
        vitals_layout.addWidget(self.ram_vital, 0, 1)
        vitals_layout.addWidget(self.net_vital, 0, 2)
        layout.addLayout(vitals_layout)

        # 3. Top Active Apps
        layout.addWidget(SectionHeader("Top Active Apps", "Applications using the most resources right now."))
        self.apps_container = QVBoxLayout()
        self.apps_container.setSpacing(8)
        
        apps_card = PremiumCard()
        apps_card.layout.addLayout(self.apps_container)
        layout.addWidget(apps_card)

        # 4. Advanced View Expander
        self.advanced_btn = SecondaryButton("Advanced View ▼")
        self.advanced_btn.clicked.connect(self._toggle_advanced)
        layout.addWidget(self.advanced_btn)
        
        self.advanced_panel = PremiumCard()
        self.advanced_panel.setVisible(False)
        self.uptime_label = QLabel("System Uptime: Loading...")
        self.uptime_label.setObjectName("MutedLabel")
        self.services_label = QLabel("Background Services: Loading...")
        self.services_label.setObjectName("MutedLabel")
        self.advanced_panel.layout.addWidget(QLabel("System Diagnostics", objectName="SectionTitle"))
        self.advanced_panel.layout.addWidget(self.uptime_label)
        self.advanced_panel.layout.addWidget(self.services_label)
        layout.addWidget(self.advanced_panel)
        
        layout.addStretch()

        root.addWidget(scroll_page(page))
        QTimer.singleShot(120, self.refresh)

    def refresh(self) -> None:
        self.run_task(_collect_dashboard_snapshot, self._apply_snapshot)

    def _apply_snapshot(self, snapshot: dict[str, Any]) -> None:
        if snapshot['cpu_val'] < 80:
            self.welcome_banner.setText("Your PC is running smoothly.")
        else:
            self.welcome_banner.setText("Your PC is under heavy load.")
        
        self.cpu_vital.set_value(f"{snapshot['cpu_val']:.1f}%", "CPU load")
        self.ram_vital.set_value(f"{snapshot['ram_val']:.1f}%", "Memory in use")
        self.net_vital.set_value(snapshot['net_status'], "Active connection")
        
        # Update apps container
        while self.apps_container.count():
            item = self.apps_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
        if not snapshot['top_apps']:
            empty_lbl = QLabel("No active user applications found.")
            empty_lbl.setObjectName("MutedLabel")
            self.apps_container.addWidget(empty_lbl)
        else:
            for app in snapshot['top_apps']:
                row = QHBoxLayout()
                name_lbl = QLabel(f"{app['name']} ({app['cpu']:.1f}% CPU)")
                name_lbl.setObjectName("SectionTitle")
                stop_btn = SecondaryButton("Stop")
                stop_btn.clicked.connect(lambda checked=False, pid=app['pid']: self._stop_app(pid))
                row.addWidget(name_lbl)
                row.addStretch()
                row.addWidget(stop_btn)
                
                w = QWidget()
                w.setLayout(row)
                self.apps_container.addWidget(w)
            
        self.uptime_label.setText(f"System Uptime: {snapshot['uptime']}")
        self.services_label.setText(f"Background Services: {snapshot['bg_services']} running")

    def _toggle_advanced(self):
        visible = not self.advanced_panel.isVisible()
        self.advanced_panel.setVisible(visible)
        self.advanced_btn.setText("Advanced View ▲" if visible else "Advanced View ▼")
        
    def _optimize_performance(self):
        QMessageBox.information(self, "Optimize Performance", "Memory caches cleared and unused background services suspended. (Placeholder action)")

    def _stop_app(self, pid: int):
        self.run_task(
            lambda: ProcessService().kill_process(pid, SafetyContext(yes=True, force=True)),
            lambda res: self.refresh()
        )


def _collect_dashboard_snapshot() -> dict[str, Any]:
    import psutil
    import time
    
    cpu_val = psutil.cpu_percent(interval=0.1)
    ram_val = psutil.virtual_memory().percent
    
    try:
        adapters = NetworkService().list_interfaces()
        active = [a for a in adapters if a.state == "Connected"]
        net_status = "Good" if active else "Offline"
    except Exception:
        net_status = "Unknown"
        
    procs = ProcessService().list_processes(sort_by="cpu")
    
    # Filter out common system processes to keep it user-friendly
    system_procs = {
        'svchost.exe', 'System Idle Process', 'System', 'csrss.exe', 
        'smss.exe', 'services.exe', 'lsass.exe', 'wininit.exe', 
        'fontdrvhost.exe', 'dwm.exe', 'spoolsv.exe', 'explorer.exe'
    }
    user_procs = [p for p in procs if p.name not in system_procs]
    
    top_apps = []
    for p in user_procs[:3]:
        top_apps.append({
            'name': p.name,
            'pid': p.pid,
            'cpu': p.cpu_percent
        })
        
    uptime = "Unknown"
    try:
        boot_time = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_time)
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        uptime = f"{hours}h {minutes}m"
    except Exception:
        pass
        
    bg_services = len([p for p in procs if p.name in system_procs])
        
    return {
        "cpu_val": cpu_val,
        "ram_val": ram_val,
        "net_status": net_status,
        "top_apps": top_apps,
        "uptime": uptime,
        "bg_services": bg_services
    }

