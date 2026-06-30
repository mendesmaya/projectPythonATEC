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
            event (LogEvent): The event (or subclass) to add.
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

    # --- UC7: Listagem de Eventos ---
    def list_events(self, filter_type: Optional[type] = None) -> None:
        """
        Shows events on the screen, globally or filtered by type.

        Uses isinstance() to filter by type.

        Args:
            filter_type (Optional[type]): Class for filtering (ex: AuthFailureEvent)
                if None, shows every event.
        """
        if not self.__events_list:
            print("  Nenhum evento carregado em memória.")
            return

        if filter_type is not None:
            filtered = [e for e in self.__events_list if isinstance(e, filter_type)]
            type_name = filter_type.__name__
        else:
            filtered = self.__events_list
            type_name = "Todos"

        print(f"\n  === Eventos: {type_name} ({len(filtered)} resultados) ===")

        if not filtered:
            print("  Nenhum evento encontrado para este filtro.")
            return

        for i, event in enumerate(filtered, start=1):
            # __str__ é chamado implicitamente pelo print() (UC7)
            print(f"  {i:>3}. {event}")
        
       # --- UC9: Deteção de Força Bruta ---
    def detect_brute_force(self) -> dict[str, int]:
        """
        Analises all events and detects potential brute force attacks.

        Uses a Dictionary for IP -> failure count mapping (M3 §1.4):
        "Iterate over the main list of objects, extract the IP from each 
        object (Key) and increment the corresponding integer Value by 1."

        Returns:
            dict[str, int]: Dictionary {ip: count} of suspicious IPS
                (only those that reach the threshold)
        """
        auth_failure_count: dict[str, int] = {}

        for event in self.__events_list:
            if isinstance(event, AuthFailureEvent):
                ip = event.ip_address
                auth_failure_count[ip] = auth_failure_count.get(ip, 0) + 1

        brute_force_ips: dict[str, int] = {
            ip: count
            for ip, count in auth_failure_count.items()
            if count >= self.__BRUTE_FORCE_THRESHOLD
        }

        return brute_force_ips
    
       # --- UC10: Pesquisa Forense por IP ---
    def search_by_ip(self, target_ip: str) -> list[LogEvent]:
        """
        Searches every event linked with a specific IP.

        Sorting: most critical risk first; in case of a tie, the most
        recent event first.

        Args:
            target_ip (str): The IP address to search for.

        Returns:
            list[LogEvent]: Events matching the IP, sorted by risk descending,
                and then by timestamp descending.
        """
        ip_events: list[LogEvent] = [
            event for event in self.__events_list
            if event.ip_address == target_ip
        ]

        if not ip_events:
            return []

        # sorted() com key= (lambda) - investigação autónoma
        # -calculate_risk(): negativo para ordenar descendente por risco
        sorted_events = sorted(
            ip_events,
            key=lambda e: (-e.calculate_risk(), e.timestamp),
            reverse=False
        )

        return sorted_events