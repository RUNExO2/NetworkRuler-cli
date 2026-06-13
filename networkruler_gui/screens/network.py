from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from networkruler_core.network.models import NetworkActionResult
from networkruler_core.network.service import NetworkService
from networkruler_core.safety import SafetyContext
from networkruler_gui.screens.base import Screen, page_layout, scroll_page
from networkruler_gui.widgets import PremiumCard, SafetyPreviewDialog, SectionHeader, PrimaryButton, SecondaryButton, DangerButton


class NetworkScreen(Screen):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        page = QWidget()
        layout = page_layout(page)
        layout.addWidget(
            SectionHeader(
                "Network",
                "Check your internet connection and easily fix common issues.",
            )
        )

        # 1. Connection Status Hero
        self.hero_card = PremiumCard(hero=True)
        self.hero_layout = QVBoxLayout()
        self.hero_title = QLabel("Checking connection...")
        self.hero_title.setObjectName("ScreenTitle")
        self.hero_subtitle = QLabel("Please wait.")
        self.hero_subtitle.setObjectName("ScreenSubtitle")
        self.hero_layout.addWidget(self.hero_title)
        self.hero_layout.addWidget(self.hero_subtitle)
        self.hero_card.layout.addLayout(self.hero_layout)
        layout.addWidget(self.hero_card)
        
        # Action Row
        action_row = QHBoxLayout()
        self.repair_btn = PrimaryButton("Run Network Repair")
        self.repair_btn.clicked.connect(self._run_network_repair)
        action_row.addWidget(self.repair_btn)
        action_row.addStretch()
        layout.addLayout(action_row)

        # 2. Current Usage
        self.usage_card = PremiumCard()
        self.usage_card.layout.addWidget(QLabel("Current Usage", objectName="SectionTitle"))
        self.usage_label = QLabel("Loading...")
        self.usage_card.layout.addWidget(self.usage_label)
        layout.addWidget(self.usage_card)

        # 3. Bandwidth Hogs
        self.hogs_card = PremiumCard()
        self.hogs_card.layout.addWidget(QLabel("Bandwidth Hogs", objectName="SectionTitle"))
        self.hogs_label = QLabel("Per-app bandwidth monitoring is not available on this system.")
        self.hogs_label.setObjectName("MutedLabel")
        self.hogs_card.layout.addWidget(self.hogs_label)
        layout.addWidget(self.hogs_card)

        # 4. Advanced Network Tools Expander
        self.advanced_btn = SecondaryButton("Advanced Network Tools ▼")
        self.advanced_btn.clicked.connect(self._toggle_advanced)
        layout.addWidget(self.advanced_btn)
        
        self.advanced_panel = PremiumCard()
        self.advanced_panel.setVisible(False)
        self.ip_info = QLabel("Loading...")
        self.ip_info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.ip_info.setWordWrap(True)
        self.proxy_info = QLabel("Loading...")
        self.proxy_info.setWordWrap(True)
        
        advanced_grid = QGridLayout()
        
        flush_btn = SecondaryButton("Flush DNS")
        flush_btn.clicked.connect(lambda: self._advanced_action("Flush DNS", lambda ctx: NetworkService().flush_dns(ctx)))
        
        reset_proxy_btn = SecondaryButton("Reset Proxy")
        reset_proxy_btn.clicked.connect(lambda: self._advanced_action("Reset Proxy", lambda ctx: NetworkService().reset_proxy(ctx)))

        winsock_btn = DangerButton("Reset Winsock")
        winsock_btn.clicked.connect(lambda: self._advanced_action("Reset Winsock", lambda ctx: NetworkService().reset_winsock(ctx)))
        
        advanced_grid.addWidget(flush_btn, 0, 0)
        advanced_grid.addWidget(reset_proxy_btn, 0, 1)
        advanced_grid.addWidget(winsock_btn, 0, 2)
        
        self.advanced_panel.layout.addWidget(QLabel("IP Configuration", objectName="SectionTitle"))
        self.advanced_panel.layout.addWidget(self.ip_info)
        self.advanced_panel.layout.addWidget(QLabel("Proxy", objectName="SectionTitle"))
        self.advanced_panel.layout.addWidget(self.proxy_info)
        self.advanced_panel.layout.addWidget(QLabel("Advanced Actions", objectName="SectionTitle"))
        self.advanced_panel.layout.addLayout(advanced_grid)
        layout.addWidget(self.advanced_panel)

        layout.addStretch()
        root.addWidget(scroll_page(page))
        self.refresh()
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(5000)

    def _toggle_advanced(self):
        visible = not self.advanced_panel.isVisible()
        self.advanced_panel.setVisible(visible)
        self.advanced_btn.setText("Advanced Network Tools ▲" if visible else "Advanced Network Tools ▼")

    def refresh(self) -> None:
        self.run_task(_collect_network_snapshot, self._render_snapshot)

    def _render_snapshot(self, snapshot: dict[str, Any]) -> None:
        is_connected = snapshot.get("is_connected", False)
        connection_type = snapshot.get("connection_type", "Unknown")
        
        if is_connected:
            self.hero_title.setText(f"Connected via {connection_type}")
            self.hero_subtitle.setText(snapshot.get("active_interface_name", "Internet is available."))
        else:
            self.hero_title.setText("You are offline")
            self.hero_subtitle.setText("No active internet connection found.")
            
        self.usage_label.setText(f"{snapshot.get('bandwidth', '0')} bytes/sec received")
        self.ip_info.setText(snapshot.get("ip", "No IP data"))
        self.proxy_info.setText(snapshot.get("proxy", "No proxy data"))

    def _run_network_repair(self):
        self.run_task(
            lambda: NetworkService().flush_dns(SafetyContext(yes=True)),
            self._show_repair_result,
        )

    def _show_repair_result(self, result: NetworkActionResult) -> None:
        QMessageBox.information(
            self,
            "Network Repair",
            "Automatic network repair completed. (DNS flushed).",
            QMessageBox.StandardButton.Ok
        )
        self.refresh()

    def _advanced_action(
        self,
        title: str,
        action: Callable[[SafetyContext], NetworkActionResult],
    ) -> None:
        self.run_task(
            lambda: action(SafetyContext(dry_run=True)),
            lambda result: self._confirm_action(title, action, result),
        )

    def _confirm_action(
        self,
        title: str,
        action: Callable[[SafetyContext], NetworkActionResult],
        preview: NetworkActionResult,
    ) -> None:
        if not SafetyPreviewDialog.confirm(
            parent=self,
            title=f"Confirm {title}",
            message="Review this dry-run preview before applying the network action.",
            payload=preview.to_dict(),
        ):
            return
        self.run_task(
            lambda: action(SafetyContext(yes=True)),
            self._show_action_result,
        )

    def _show_action_result(self, result: NetworkActionResult) -> None:
        icon = QMessageBox.Icon.Information if result.ok else QMessageBox.Icon.Warning
        QMessageBox(
            icon,
            "Network action",
            result.message,
            QMessageBox.StandardButton.Ok,
            self,
        ).exec()
        if result.ok and not result.safety.dry_run:
            self.refresh()


def _collect_network_snapshot() -> dict[str, Any]:
    from networkruler_core.monitor.service import MonitorService
    service = NetworkService()
    
    is_connected = False
    connection_type = "Unknown"
    active_interface_name = ""
    bandwidth = "unavailable"
    
    try:
        interfaces = service.list_interfaces()
        active = [i for i in interfaces if i.state == "Connected"]
        if active:
            is_connected = True
            active_interface = active[0]
            active_interface_name = active_interface.name
            if "wi-fi" in active_interface.name.lower():
                connection_type = "Wi-Fi"
            elif "ethernet" in active_interface.name.lower():
                connection_type = "Ethernet"
            else:
                connection_type = "Network"
                
        ip = service.show_ip_config().raw[:500]
        proxy = service.show_proxy().raw[:500]
    except Exception as e:
        ip = str(e)
        proxy = str(e)

    try:
        sample = MonitorService().sample_bandwidth(interval=0.1)
        bandwidth = f"{sample.bytes_recv_per_sec:,.0f}"
    except Exception:
        bandwidth = "unavailable"
        
    return {
        "is_connected": is_connected,
        "connection_type": connection_type,
        "active_interface_name": active_interface_name,
        "bandwidth": bandwidth,
        "ip": ip,
        "proxy": proxy,
    }
