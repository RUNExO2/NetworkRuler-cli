from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QLabel,
    QSpinBox,
    QWidget,
)

from networkruler_core.exceptions import UnsupportedPlatformError
from networkruler_core.monitor.models import BandwidthSample, ProcessSample
from networkruler_core.monitor.service import MonitorService
from networkruler_core.network.service import NetworkService
from networkruler_gui.screens.base import Screen, page_layout
from networkruler_gui.widgets import (
    Card,
    LineChart,
    MetricCard,
    SecondaryButton,
    SectionHeader,
    Toolbar,
)


class MonitorScreen(Screen):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._paused = False
        self._bandwidth_busy = False
        self._process_busy = False

        layout = page_layout(self)
        layout.addWidget(
            SectionHeader(
                "Monitor",
                "Low-pressure live sampling for bandwidth and one selected process.",
            )
        )

        toolbar = Toolbar()
        self.adapter = QComboBox()
        self.adapter.addItem("All adapters", None)
        self.pid = QSpinBox()
        self.pid.setRange(0, 999999)
        self.pid.setSpecialValueText("No process")
        self.toggle = SecondaryButton("Pause")
        self.toggle.clicked.connect(self._toggle)
        toolbar.add_widget(_caption("Adapter"))
        toolbar.add_widget(self.adapter, 1)
        toolbar.add_widget(_caption("Process PID"))
        toolbar.add_widget(self.pid)
        toolbar.add_widget(self.toggle)
        layout.addWidget(toolbar)

        grid = QGridLayout()
        grid.setSpacing(14)
        self.recv = MetricCard("Download", "—", "bytes/sec")
        self.sent = MetricCard("Upload", "—", "bytes/sec")
        self.proc_cpu = MetricCard("Process CPU", "—", "select a PID")
        self.proc_mem = MetricCard("Process Memory", "—", "select a PID")
        grid.addWidget(self.recv, 0, 0)
        grid.addWidget(self.sent, 0, 1)
        grid.addWidget(self.proc_cpu, 0, 2)
        grid.addWidget(self.proc_mem, 0, 3)
        layout.addLayout(grid)

        chart_card = Card()
        chart_card.layout.addWidget(_title("Bandwidth flow"))
        chart_card.layout.addWidget(
            _muted("A lightweight live trace of received bytes per second.")
        )
        self.chart = LineChart()
        chart_card.layout.addWidget(self.chart)
        layout.addWidget(chart_card)

        process_card = Card()
        process_card.layout.addWidget(_title("Process monitor"))
        self.process_status = QLabel("Enter a PID to monitor CPU and memory.")
        self.process_status.setObjectName("MutedLabel")
        self.process_status.setWordWrap(True)
        process_card.layout.addWidget(self.process_status)
        layout.addWidget(process_card)
        layout.addStretch()

        self._load_adapters()
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._tick)
        self.timer.start()

    def _load_adapters(self) -> None:
        def load() -> list[str]:
            try:
                return [item.name for item in NetworkService().list_interfaces()]
            except (RuntimeError, UnsupportedPlatformError):
                return []

        self.run_task(load, self._apply_adapters)

    def _apply_adapters(self, names: list[str]) -> None:
        for name in names:
            self.adapter.addItem(name, name)

    def _toggle(self) -> None:
        self._paused = not self._paused
        self.toggle.setText("Resume" if self._paused else "Pause")

    def _tick(self) -> None:
        if self._paused:
            return
        if not self._bandwidth_busy:
            self._bandwidth_busy = True
            adapter = self.adapter.currentData()
            self.run_task(
                lambda: MonitorService().sample_bandwidth(
                    interval=0.25,
                    adapter=adapter,
                ),
                self._apply_bandwidth,
                self._bandwidth_error,
            )
        pid = self.pid.value()
        if pid and not self._process_busy:
            self._process_busy = True
            self.run_task(
                lambda: MonitorService().sample_process(pid, interval=0.25),
                self._apply_process,
                self._process_error,
            )

    def _apply_bandwidth(self, sample: BandwidthSample) -> None:
        self._bandwidth_busy = False
        self.recv.set_value(f"{sample.bytes_recv_per_sec:,.0f}", "bytes/sec")
        self.sent.set_value(f"{sample.bytes_sent_per_sec:,.0f}", "bytes/sec")
        self.chart.append_value(sample.bytes_recv_per_sec)

    def _bandwidth_error(self, message: str) -> None:
        self._bandwidth_busy = False
        self.recv.set_value("unavailable", message)

    def _apply_process(self, sample: ProcessSample) -> None:
        self._process_busy = False
        if not sample.alive:
            self.process_status.setText(sample.message or "Process is unavailable.")
            self.proc_cpu.set_value("—", "not alive")
            self.proc_mem.set_value("—", "not alive")
            return
        self.proc_cpu.set_value(f"{sample.cpu_percent:.1f}%", sample.name or "")
        self.proc_mem.set_value(f"{sample.memory_percent:.1f}%", sample.status or "")
        self.process_status.setText(
            f"{sample.name or sample.pid} is {sample.status or 'unknown'}."
        )

    def _process_error(self, message: str) -> None:
        self._process_busy = False
        self.process_status.setText(message)


def _title(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("SectionTitle")
    return label


def _caption(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("CaptionLabel")
    return label


def _muted(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("MutedLabel")
    label.setWordWrap(True)
    return label
