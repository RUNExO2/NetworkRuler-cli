from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class BandwidthSample:
    timestamp: float
    bytes_sent_per_sec: float
    bytes_recv_per_sec: float
    total_bytes_sent: int
    total_bytes_recv: int
    adapter: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProcessSample:
    timestamp: float
    pid: int
    name: str | None = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    status: str | None = None
    alive: bool = True
    message: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

