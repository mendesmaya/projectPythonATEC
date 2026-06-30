from typing import Optional
from datetime import datetime
from models import LogEvent, AuthFailureEvent

class ThreatAnalyzer:
    """
    The Central orchestrator class of the threat analysis system.
    Attributes:
        - __events_list: private list of all the events (M4_P00 §1.5)
    Methods:
        - detect_brute_force(): Dictionary-based analysis (M3 §1.4)
        - search_by_ip(): Search and sorting by risk level (UC10)
        - export_report(): Export to file (UC12)
    """

    def __init__(self) -> None:
        """
        Initializes the orchestrator with a private list of events.
        According to side notes from UC9:
        "This class has to have a private list (ex: self._events_list)"
        """
        self.__events_list: list[LogEvent] = []

        # Limite de falhas de autenticação para sinalizar brute force
        self.__BRUTE_FORCE_THRESHOLD: int = 5

    def add_event(self, event: LogEvent) -> None:
        """
        Adds a single security event to the internal list.

        Args:
            event (LogEvent): The event (or subevent) to add.
        """
        self.__events_list.append(event)

    def load_events_from_list(self, events: list[LogEvent]) -> None:
        """
        Loads a list of events to the orchestrator at once.

        Args:
            events (list[LogEvent]): List of events to add.
        """
        for event in events:
            self.add_event(event)