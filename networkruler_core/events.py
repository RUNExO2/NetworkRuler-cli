import enum
from dataclasses import dataclass
from typing import Any, Callable

from PySide6.QtCore import QObject, Signal


class EventType(enum.Enum):
    COMMAND_REQUEST = "COMMAND_REQUEST"
    COMMAND_RESPONSE = "COMMAND_RESPONSE"
    STATE_MUTATION = "STATE_MUTATION"
    STATE_DIFF = "STATE_DIFF"
    ERROR_ALERT = "ERROR_ALERT"


@dataclass(frozen=True)
class Event:
    type: EventType
    payload: dict[str, Any]


class CentralEventBus(QObject):
    """
    The Central Event Bus utilizing Qt's native Signal/Slot mechanism.
    This guarantees thread safety when communicating between the 
    background execution engines and the Main GUI Thread.
    """
    # Core Signals
    on_command_request = Signal(Event)
    on_command_response = Signal(Event)
    on_state_mutation = Signal(Event)
    on_state_diff = Signal(Event)
    on_error_alert = Signal(Event)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)

    def dispatch(self, event: Event) -> None:
        """Routes the event to the appropriate signal based on its type."""
        if event.type == EventType.COMMAND_REQUEST:
            self.on_command_request.emit(event)
        elif event.type == EventType.COMMAND_RESPONSE:
            self.on_command_response.emit(event)
        elif event.type == EventType.STATE_MUTATION:
            self.on_state_mutation.emit(event)
        elif event.type == EventType.STATE_DIFF:
            self.on_state_diff.emit(event)
        elif event.type == EventType.ERROR_ALERT:
            self.on_error_alert.emit(event)


class StateManager(QObject):
    """
    The Single Source of Truth for application state.
    Listens for mutations, updates its internal tree, and broadcasts diffs.
    """
    def __init__(self, bus: CentralEventBus, parent: QObject | None = None):
        super().__init__(parent)
        self.bus = bus
        self._state = {
            "processes": [],
            "adapters": [],
            "elevation_state": False,
        }
        
        # Subscribe to mutations
        self.bus.on_state_mutation.connect(self.apply_mutation)

    def apply_mutation(self, event: Event) -> None:
        """Applies a mutation to the state tree and broadcasts a diff."""
        mutation_type = event.payload.get("action")
        
        if mutation_type == "UPDATE_PROCESS_LIST":
            self._state["processes"] = event.payload.get("data", [])
        elif mutation_type == "REMOVE_PROCESS":
            pid_to_remove = event.payload.get("pid")
            self._state["processes"] = [
                p for p in self._state["processes"] if getattr(p, 'pid', None) != pid_to_remove
            ]
            
        # Broadcast the new state to the UI ViewModels
        diff_event = Event(
            type=EventType.STATE_DIFF,
            payload={"updated_keys": [mutation_type], "state_snapshot": self._state}
        )
        self.bus.dispatch(diff_event)
