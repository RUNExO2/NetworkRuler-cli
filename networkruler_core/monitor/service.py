from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import psutil

from networkruler_core.monitor.models import BandwidthSample, ProcessSample


class MonitorService:
    def __init__(
        self,
        psutil_module: Any = psutil,
        *,
        clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._psutil = psutil_module
        self._clock = clock or __import__("time").time
        self._sleep = sleeper or __import__("time").sleep

    def sample_bandwidth(
        self,
        *,
        interval: float,
        adapter: str | None = None,
    ) -> BandwidthSample:
        self._validate_interval(interval)
        first = self._net_counters(adapter)
        self._sleep(interval)
        second = self._net_counters(adapter)
        return BandwidthSample(
            timestamp=self._clock(),
            adapter=adapter,
            bytes_sent_per_sec=(second.bytes_sent - first.bytes_sent) / interval,
            bytes_recv_per_sec=(second.bytes_recv - first.bytes_recv) / interval,
            total_bytes_sent=int(second.bytes_sent),
            total_bytes_recv=int(second.bytes_recv),
        )

    def bandwidth_samples(
        self,
        *,
        interval: float,
        adapter: str | None = None,
    ) -> Iterator[BandwidthSample]:
        self._validate_interval(interval)
        while True:
            yield self.sample_bandwidth(interval=interval, adapter=adapter)

    def sample_process(self, pid: int, *, interval: float) -> ProcessSample:
        self._validate_interval(interval)
        try:
            process = self._psutil.Process(pid)
            with process.oneshot():
                name = process.name()
                cpu = float(process.cpu_percent(interval=interval))
                memory = float(process.memory_percent())
                status = process.status()
            return ProcessSample(
                timestamp=self._clock(),
                pid=pid,
                name=name,
                cpu_percent=cpu,
                memory_percent=memory,
                status=status,
                alive=True,
            )
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return ProcessSample(
                timestamp=self._clock(),
                pid=pid,
                alive=False,
                message=f"Process {pid} is no longer running.",
            )
        except psutil.AccessDenied:
            return ProcessSample(
                timestamp=self._clock(),
                pid=pid,
                alive=False,
                message=f"Access denied for process {pid}.",
            )

    def process_samples(self, *, pid: int, interval: float) -> Iterator[ProcessSample]:
        self._validate_interval(interval)
        while True:
            sample = self.sample_process(pid, interval=interval)
            yield sample
            if not sample.alive:
                return

    def _net_counters(self, adapter: str | None):
        if adapter is None:
            return self._psutil.net_io_counters()
        counters = self._psutil.net_io_counters(pernic=True)
        try:
            return counters[adapter]
        except KeyError as error:
            raise ValueError(f"Adapter not found: {adapter}") from error

    def _validate_interval(self, interval: float) -> None:
        if interval <= 0:
            raise ValueError("Interval must be greater than 0.")

