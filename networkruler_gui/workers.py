from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot


class WorkerSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)


class CoreWorker(QRunnable):
    def __init__(self, task: Callable[[], Any]) -> None:
        super().__init__()
        self.task = task
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            result = self.task()
        except Exception as error:
            self._emit_safely(self.signals.failed, str(error))
            return
        self._emit_safely(self.signals.finished, result)

    def _emit_safely(self, signal, value: object) -> None:
        try:
            signal.emit(value)
        except RuntimeError:
            return


def run_worker(
    task: Callable[[], Any],
    *,
    on_result: Callable[[Any], None],
    on_error: Callable[[str], None] | None = None,
) -> CoreWorker:
    worker = CoreWorker(task)
    worker.signals.finished.connect(on_result)
    if on_error is not None:
        worker.signals.failed.connect(on_error)
    QThreadPool.globalInstance().start(worker)
    return worker
